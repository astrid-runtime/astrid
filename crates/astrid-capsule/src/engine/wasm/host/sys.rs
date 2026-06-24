//! `astrid:sys@1.0.0` host implementation, plus the additive
//! `astrid:sys@1.1.0` companion (one call, `capsule-set-epoch`).
//!
//! `trigger_hook` was removed from the kernel ABI when the
//! `astrid:capsule@0.1.0` world was split into per-domain packages —
//! capsule-to-capsule fan-out lives on the IPC bus
//! (`astrid-bus:hook@1.0.0`), not as a sys host call. Capsules that
//! need to dispatch hooks now publish `hook.trigger.v1` and aggregate
//! responses via subscriptions.

use crate::engine::wasm::bindings::astrid::sys1_0_0::host::{
    self as sys, CallerContext, CapabilityCheckRequest, CapabilityCheckResponse, ErrorCode,
    LogLevel,
};
use crate::engine::wasm::bindings::astrid::sys1_1_0::host as sys_v11;
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// Cap on a single `random-bytes` request, per the WIT contract.
const RANDOM_BYTES_CAP: u64 = 4096;

/// Cap on a single `sleep-ns` request (60 seconds in nanoseconds).
const SLEEP_NS_CAP: u64 = 60_000_000_000;

impl sys::Host for HostState {
    fn get_config(&mut self, key: String) -> Result<Option<String>, ErrorCode> {
        // Manifest-declared secrets route through the file-per-secret
        // store at invocation time, never through `self.config`. This
        // keeps plaintext secret material off disk and out of long-lived
        // host memory.
        //
        // Lookup precedence: per-invocation principal first, then host-
        // wide fall-through. Scope is operator-decided at
        // `astrid secret set --scope` time (not a manifest declaration),
        // so the kernel-side read path always tries both slots.
        if self.secret_env.contains(&key) {
            let value = resolve_secret(self, &key);
            return Ok(if value.is_empty() { None } else { Some(value) });
        }

        // Per-invocation env overlay: operator-written values for the
        // invoking principal, sourced from
        // `<home>/.config/env/<capsule>.env.json`. Installed by
        // `WasmEngine::invoke_interceptor` (and the recv-context
        // installer) when the invoking principal differs from the
        // capsule's load-time principal. Wins over `self.config`
        // (manifest defaults) so the gateway's
        // `POST /api/capsules/{id}/env/{field}` route is no longer
        // write-only for non-default principals.
        if let Some(overlay) = self.invocation_env_overlay.as_ref()
            && let Some(value) = overlay.get(&key)
        {
            return Ok(Some(value.clone()));
        }

        match self.config.get(&key) {
            None => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            Some(v) => Ok(Some(serde_json::to_string(v).unwrap_or_default())),
        }
    }

    fn get_caller(&mut self) -> Result<CallerContext, ErrorCode> {
        if let Some(ref msg) = self.caller_context {
            Ok(CallerContext {
                principal: msg.principal.clone(),
                source_id: msg.source_id.to_string(),
                timestamp: msg.timestamp.to_rfc3339(),
            })
        } else {
            Ok(CallerContext {
                principal: None,
                source_id: String::new(),
                timestamp: String::new(),
            })
        }
    }

    fn log(&mut self, level: LogLevel, message: String) {
        let capsule_id = self.capsule_id.as_str().to_owned();
        let log_file = self.effective_capsule_log().cloned();

        let level_str = match level {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or_else(|_| "0".to_string(), |d| format!("{:.3}", d.as_secs_f64()));

        let wrote_to_file = if let Some(log_file) = log_file {
            use std::io::Write;
            match log_file.lock() {
                Ok(mut f) => {
                    match writeln!(f, "{timestamp} {level_str} [{capsule_id}] {message}") {
                        Ok(()) => true,
                        Err(e) => {
                            // Write failed (e.g. disk full). Fall through to the
                            // tracing subscriber rather than dropping the line.
                            tracing::warn!(
                                capsule = %capsule_id,
                                error = %e,
                                "capsule log write failed; falling back to tracing subscriber"
                            );
                            false
                        },
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        capsule = %capsule_id,
                        error = %e,
                        "capsule log mutex poisoned; falling back to tracing subscriber"
                    );
                    false
                },
            }
        } else {
            false
        };

        // ERROR-level guest logs ALWAYS surface to the daemon's tracing
        // subscriber, even when also written to a per-capsule file. The SDK
        // `#[astrid::run]` macro logs a run loop's failure via `log::error`
        // before returning; without this, that reason lands ONLY in the
        // per-capsule file and the daemon log shows just a contextless
        // "Capsule run loop exited before signaling ready" — the silent crash
        // that is painful to diagnose. Lower levels stay file-only when a
        // capsule log captured them, to preserve the daemon log's signal.
        if should_emit_to_daemon_log(wrote_to_file, level) {
            match level {
                LogLevel::Trace => tracing::trace!(plugin = %capsule_id, "{message}"),
                LogLevel::Debug => tracing::debug!(plugin = %capsule_id, "{message}"),
                LogLevel::Info => tracing::info!(plugin = %capsule_id, "{message}"),
                LogLevel::Warn => tracing::warn!(plugin = %capsule_id, "{message}"),
                LogLevel::Error => tracing::error!(plugin = %capsule_id, "{message}"),
            }
        }
    }

    fn signal_ready(&mut self) {
        if let Some(tx) = &self.ready_tx {
            let _ = tx.send(true);
            tracing::debug!(capsule = %self.capsule_id, "Capsule signaled ready");
        }
    }

    fn clock_ms(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn clock_monotonic_ns(&mut self) -> u64 {
        // Use std::time::Instant via a process-anchor stored in HostState
        // (initialised at first call so the absolute value monotonically
        // increases from then on; differences are what matters).
        use std::sync::OnceLock;
        use std::time::Instant;
        static ANCHOR: OnceLock<Instant> = OnceLock::new();
        let anchor = *ANCHOR.get_or_init(Instant::now);
        u64::try_from(anchor.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn sleep_ns(&mut self, duration_ns: u64) -> Result<(), ErrorCode> {
        if duration_ns > SLEEP_NS_CAP {
            return Err(ErrorCode::TooLarge);
        }
        let cancel = self.cancel_token.clone();
        let rt = self.runtime_handle.clone();
        let sem = self.blocking_semaphore.clone();
        let duration = std::time::Duration::from_nanos(duration_ns);
        let cancelled = util::bounded_block_on(&rt, &sem, async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => false,
                () = cancel.cancelled() => true,
            }
        });
        if cancelled {
            Err(ErrorCode::Cancelled)
        } else {
            Ok(())
        }
    }

    fn random_bytes(&mut self, length: u64) -> Result<Vec<u8>, ErrorCode> {
        if length > RANDOM_BYTES_CAP {
            return Err(ErrorCode::TooLarge);
        }
        let len = usize::try_from(length).map_err(|_| ErrorCode::TooLarge)?;
        // Pull straight from the OS CSPRNG so the bytes match the WIT
        // contract's "OS-level CSPRNG" guarantee. `try_fill_bytes` (not
        // `fill_bytes`) so a practically-impossible entropy-source failure
        // fails secure as an error rather than panicking inside a host call.
        use rand::RngCore;
        let mut buf = vec![0u8; len];
        rand::rngs::OsRng
            .try_fill_bytes(&mut buf)
            .map_err(|e| ErrorCode::Unknown(format!("entropy source unavailable: {e}")))?;
        Ok(buf)
    }

    fn check_capsule_capability(
        &mut self,
        request: CapabilityCheckRequest,
    ) -> Result<CapabilityCheckResponse, ErrorCode> {
        let registry = self.capsule_registry.clone();
        let rt_handle = self.runtime_handle.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();

        let registry = registry.ok_or(ErrorCode::RegistryUnavailable)?;
        let Ok(source_uuid) = uuid::Uuid::parse_str(&request.source_uuid) else {
            // Fail-closed per the WIT contract.
            return Ok(CapabilityCheckResponse { allowed: false });
        };

        let allowed = util::bounded_block_on(&rt_handle, &blocking_semaphore, async {
            let reg = registry.read().await;
            let Some(capsule_id) = reg.find_by_uuid(&source_uuid) else {
                return false;
            };
            let Some(capsule) = reg.get(capsule_id) else {
                return false;
            };
            // The full capability namespace, not just `allow_prompt_injection`:
            // `CapabilitiesDef::has` is the per-name dual of the snapshot
            // `enumerate-capabilities` returns, so the two host fns agree on
            // what "held" means. Unknown names fail closed inside `has`.
            capsule.manifest().capabilities.has(&request.capability)
        });

        Ok(CapabilityCheckResponse { allowed })
    }

    fn enumerate_capabilities(&mut self) -> Vec<String> {
        // Infallible self-introspection (the WIT returns a bare `list<string>`,
        // no `result`). The held-capability snapshot is taken once at load
        // (`CapabilitiesDef::held_names`) and stored on `HostState`, so this
        // never consults `capsule_registry` — there is no `registry-
        // unavailable` failure mode to surface, and an empty list is the valid
        // "no capabilities" answer. The set is the list dual of a self
        // `check-capsule-capability`.
        self.capability_names.clone()
    }
}

impl sys_v11::Host for HostState {
    fn capsule_set_epoch(&mut self) -> u64 {
        // Mirror `check_capsule_capability`'s registry access: clone the handle,
        // then read it inside a bounded blocking section (the registry guards an
        // async `RwLock`). Read-only and infallible at the WIT boundary — if the
        // registry is unavailable we return 0, a value that cannot match any
        // populated cache's stored epoch and so biases the consumer toward a safe
        // refresh rather than stale reuse.
        let Some(registry) = self.capsule_registry.clone() else {
            return 0;
        };
        let rt_handle = self.runtime_handle.clone();
        let blocking_semaphore = self.blocking_semaphore.clone();
        util::bounded_block_on(&rt_handle, &blocking_semaphore, async move {
            registry.read().await.set_epoch()
        })
    }
}

/// Resolve a secret-typed env value through the file-per-secret store.
///
/// Precedence (operator-controlled at `astrid secret set --scope` time;
/// the kernel just follows the chain):
///
/// 1. **Per-agent** — `~/.astrid/secrets/<effective_principal>/<capsule>/<key>`.
/// 2. **Host-wide** — `~/.astrid/secrets/__host__/<capsule>/<key>`.
fn resolve_secret(state: &HostState, key: &str) -> String {
    use astrid_storage::{FileSecretStore, SecretStore};

    let capsule = state.capsule_id.as_str();
    let principal = state.effective_principal();

    let Ok(home) = astrid_core::dirs::AstridHome::resolve() else {
        tracing::warn!(
            security_event = true,
            %principal,
            capsule,
            key,
            "AstridHome::resolve failed during secret lookup"
        );
        return String::new();
    };
    let secrets_dir = home.secrets_dir();

    let try_get = |scope: &str| -> Option<String> {
        let store = FileSecretStore::new(secrets_dir.join(scope).join(capsule));
        match store.get(key) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(
                    security_event = true,
                    %principal,
                    capsule,
                    key,
                    scope,
                    error = %e,
                    "file secret-store read failed for secret-typed env key"
                );
                None
            },
        }
    };

    if let Some(v) = try_get(principal.as_str()) {
        return v;
    }
    if let Some(v) = try_get("__host__") {
        return v;
    }
    String::new()
}

/// Whether a guest log line should ALSO be emitted to the daemon's tracing
/// subscriber. Lines written to a per-capsule file are normally kept out of
/// the daemon log to preserve its signal-to-noise; ERROR-level lines are the
/// exception — they always surface, so a run-loop capsule's `run()` exiting
/// via `log::error` (the SDK macro logs it before returning) is visible in the
/// daemon log, not only the per-capsule file.
fn should_emit_to_daemon_log(wrote_to_file: bool, level: LogLevel) -> bool {
    !wrote_to_file || matches!(level, LogLevel::Error)
}

#[cfg(test)]
mod log_chain_tests {
    use std::sync::Arc;

    use super::*;
    use crate::engine::wasm::bindings::astrid::sys1_0_0::host::Host as SysHost;
    use crate::engine::wasm::test_fixtures::{minimal_host_state, open_log};

    fn make_host_state() -> crate::engine::wasm::host_state::HostState {
        minimal_host_state(tokio::runtime::Handle::current())
    }

    #[tokio::test]
    async fn log_routes_to_invocation_file_when_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let owner_log_path = tmp.path().join("owner.log");
        let alice_log_path = tmp.path().join("alice.log");
        let owner_log = open_log(&owner_log_path);
        let alice_log = open_log(&alice_log_path);

        let mut state = make_host_state();
        state.capsule_log = Some(owner_log);
        state.invocation_capsule_log = Some(alice_log);

        state.log(LogLevel::Info, "hello from alice".into());

        let alice_contents = std::fs::read_to_string(&alice_log_path).unwrap();
        let owner_contents = std::fs::read_to_string(&owner_log_path).unwrap();
        assert!(alice_contents.contains("hello from alice"));
        assert!(!owner_contents.contains("hello from alice"));
    }

    #[tokio::test]
    async fn log_falls_back_to_load_time_file_when_no_invocation() {
        let tmp = tempfile::tempdir().unwrap();
        let owner_log_path = tmp.path().join("owner.log");
        let owner_log = open_log(&owner_log_path);

        let mut state = make_host_state();
        state.capsule_log = Some(owner_log);

        state.log(LogLevel::Warn, "single-tenant line".into());

        let contents = std::fs::read_to_string(&owner_log_path).unwrap();
        assert!(contents.contains("single-tenant line"));
        assert!(contents.contains("WARN"));
    }

    #[tokio::test]
    async fn log_isolates_writes_across_sequential_invocations() {
        let tmp = tempfile::tempdir().unwrap();
        let alice_path = tmp.path().join("alice.log");
        let bob_path = tmp.path().join("bob.log");

        let mut state = make_host_state();

        state.invocation_capsule_log = Some(open_log(&alice_path));
        state.log(LogLevel::Info, "alice-msg".into());
        state.invocation_capsule_log = None;

        state.invocation_capsule_log = Some(open_log(&bob_path));
        state.log(LogLevel::Info, "bob-msg".into());
        state.invocation_capsule_log = None;

        let alice = std::fs::read_to_string(&alice_path).unwrap();
        let bob = std::fs::read_to_string(&bob_path).unwrap();
        assert!(alice.contains("alice-msg") && !alice.contains("bob-msg"));
        assert!(bob.contains("bob-msg") && !bob.contains("alice-msg"));
    }

    #[tokio::test]
    async fn log_survives_poisoned_mutex_without_dropping_message() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("poisoned.log");
        let log_file = open_log(&log_path);

        let poisoner = Arc::clone(&log_file);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("intentional panic to poison mutex");
        })
        .join();
        assert!(log_file.is_poisoned(), "precondition: mutex is poisoned");

        let mut state = make_host_state();
        state.capsule_log = Some(log_file);

        state.log(LogLevel::Error, "post-poison line".into());
    }

    #[test]
    fn error_logs_always_surface_to_daemon_log() {
        // The silent-run-loop-crash fix: an ERROR line surfaces to the daemon
        // log even when also captured by a per-capsule file, so a run loop
        // exiting via `log::error` is visible where operators look.
        assert!(should_emit_to_daemon_log(true, LogLevel::Error));
        assert!(should_emit_to_daemon_log(false, LogLevel::Error));
        // Lower levels stay file-only when a per-capsule file captured them.
        assert!(!should_emit_to_daemon_log(true, LogLevel::Warn));
        assert!(!should_emit_to_daemon_log(true, LogLevel::Info));
        // With no per-capsule file, everything still goes to the daemon log.
        assert!(should_emit_to_daemon_log(false, LogLevel::Warn));
        assert!(should_emit_to_daemon_log(false, LogLevel::Info));
    }
}

#[cfg(test)]
mod capability_introspection_tests {
    use crate::engine::wasm::bindings::astrid::sys1_0_0::host::Host as SysHost;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    /// `enumerate-capabilities` returns the load-time snapshot and never
    /// fails: the empty default is the valid "no capabilities" answer, and a
    /// populated snapshot (what `make_state` stores from
    /// `CapabilitiesDef::held_names`) round-trips verbatim and in order.
    #[tokio::test]
    async fn enumerate_returns_load_time_snapshot() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        assert!(
            state.enumerate_capabilities().is_empty(),
            "fail-closed default holds nothing"
        );

        state.capability_names = vec!["host_process".to_string(), "net_connect".to_string()];
        assert_eq!(
            state.enumerate_capabilities(),
            vec!["host_process".to_string(), "net_connect".to_string()],
        );
    }
}

#[cfg(test)]
mod capsule_set_epoch_tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use crate::engine::wasm::bindings::astrid::sys1_1_0::host::Host as SysEpochHost;
    use crate::engine::wasm::test_fixtures::minimal_host_state;
    use crate::registry::CapsuleRegistry;

    // `bounded_block_on` runs inside `block_in_place`, which requires a
    // multi-threaded runtime.

    /// Fail-safe: with no registry handle the host returns 0 — a value that
    /// cannot match any populated cache's stored epoch, so the consumer
    /// re-describes rather than serving a stale tool list.
    #[tokio::test(flavor = "multi_thread")]
    async fn returns_zero_when_registry_unavailable() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        assert!(
            state.capsule_registry.is_none(),
            "fixture starts without a registry handle"
        );
        assert_eq!(state.capsule_set_epoch(), 0);
    }

    /// The host call delegates to the live registry's `set_epoch`, so the two
    /// agree for the same loaded set (the hashing itself is covered by the
    /// registry unit tests).
    #[tokio::test(flavor = "multi_thread")]
    async fn delegates_to_the_registry_epoch() {
        let registry = CapsuleRegistry::new();
        let expected = registry.set_epoch();

        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.capsule_registry = Some(Arc::new(RwLock::new(registry)));

        assert_eq!(state.capsule_set_epoch(), expected);
    }
}

#[cfg(test)]
mod get_config_tests {
    use std::collections::HashMap;

    use crate::engine::wasm::bindings::astrid::sys1_0_0::host::Host as SysHost;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    fn make_host_state() -> crate::engine::wasm::host_state::HostState {
        minimal_host_state(tokio::runtime::Handle::current())
    }

    /// Regression for the v0.7 smoke-test gap: the gateway's
    /// `POST /api/capsules/{id}/env/{field}` route writes overrides
    /// to `<home>/.config/env/<capsule>.env.json`, but the kernel's
    /// `get_config` host-fn used to only consult the manifest
    /// defaults loaded into `self.config` at capsule boot — so the
    /// route was effectively write-only for any principal other
    /// than the load-time owner. The smoking gun was openai-compat:
    /// `base_url` overridden to `http://localhost:1234` (LM Studio)
    /// for a gateway-minted bearer still hit `api.openai.com` (the
    /// manifest default). With the per-invocation overlay wired in,
    /// the override now wins.
    #[tokio::test]
    async fn overlay_value_wins_over_manifest_default() {
        let mut state = make_host_state();
        state.config.insert(
            "base_url".into(),
            serde_json::Value::String("https://api.openai.com".into()),
        );

        let mut overlay = HashMap::new();
        overlay.insert("base_url".into(), "http://localhost:1234".into());
        state.invocation_env_overlay = Some(overlay);

        let value = state.get_config("base_url".into()).expect("host call");
        assert_eq!(value.as_deref(), Some("http://localhost:1234"));
    }

    #[tokio::test]
    async fn manifest_default_used_when_overlay_missing_key() {
        let mut state = make_host_state();
        state.config.insert(
            "base_url".into(),
            serde_json::Value::String("https://api.openai.com".into()),
        );

        // Overlay installed but missing `base_url` — must fall
        // through to manifest defaults rather than returning None.
        let mut overlay = HashMap::new();
        overlay.insert("model".into(), "qwen3.5".into());
        state.invocation_env_overlay = Some(overlay);

        let value = state.get_config("base_url".into()).expect("host call");
        assert_eq!(value.as_deref(), Some("https://api.openai.com"));
    }

    #[tokio::test]
    async fn no_overlay_falls_back_to_manifest_default() {
        let mut state = make_host_state();
        state
            .config
            .insert("model".into(), serde_json::Value::String("gpt-5.4".into()));

        // No overlay installed at all — single-tenant capsule load.
        assert!(state.invocation_env_overlay.is_none());

        let value = state.get_config("model".into()).expect("host call");
        assert_eq!(value.as_deref(), Some("gpt-5.4"));
    }
}
