use crate::engine::wasm::bindings::astrid::capsule::sys;
use crate::engine::wasm::bindings::astrid::capsule::types::{
    CallerContext, CapabilityCheckRequest, CapabilityCheckResponse, LogLevel,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// Trigger request sent by WASM capsules via `hooks::trigger`.
#[derive(serde::Deserialize)]
struct TriggerRequest {
    /// The hook/interceptor topic to fan out (e.g. `before_tool_call`).
    hook: String,
    /// Opaque JSON payload forwarded to each matching interceptor.
    payload: serde_json::Value,
}

impl sys::Host for HostState {
    fn get_config(&mut self, key: String) -> Result<String, String> {
        let value = self.config.get(&key).cloned();

        // Return the raw string value, not JSON-encoded.
        // serde_json::to_string wraps strings in quotes ("\"value\""),
        // causing double-encoding when the SDK's env::var reads it.
        let result = match value {
            Some(serde_json::Value::String(s)) => s,
            Some(v) => serde_json::to_string(&v).unwrap_or_default(),
            None => String::new(),
        };
        Ok(result)
    }

    fn get_caller(&mut self) -> Result<CallerContext, String> {
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

    fn trigger_hook(&mut self, request_json: String) -> Result<String, String> {
        let caller_id = self.capsule_id.clone();
        let registry = self.capsule_registry.clone();
        let rt_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let result_str = if let Some(registry) = registry {
            // Deserialize the trigger request from the WASM guest.
            let request: TriggerRequest = serde_json::from_str(&request_json)
                .map_err(|e| format!("invalid trigger request: {e}"))?;

            let payload_bytes = serde_json::to_vec(&request.payload).unwrap_or_default();

            // Fan out: find all capsules with interceptors matching the hook topic,
            // invoke each (skipping the caller to prevent infinite recursion),
            // and collect their responses.
            //
            // Step 1: Collect matching capsules under the registry read lock.
            let matches: Vec<(std::sync::Arc<dyn crate::capsule::Capsule>, String)> =
                util::bounded_block_on(&rt_handle, &host_semaphore, async {
                    let registry = registry.read().await;
                    let mut matches = Vec::new();

                    for capsule_id in registry.list() {
                        // Skip the calling capsule to prevent recursion.
                        if *capsule_id == caller_id {
                            continue;
                        }
                        if let Some(capsule) = registry.get(capsule_id) {
                            if !matches!(capsule.state(), crate::capsule::CapsuleState::Ready) {
                                continue;
                            }
                            // RFC cargo-like-manifest: read effective interceptors
                            // — [subscribe].handler entries merged with legacy
                            // [[interceptor]] blocks — so new-format capsules can
                            // service trigger_hook dispatch without legacy fallback.
                            for interceptor in capsule.manifest().effective_interceptors() {
                                if crate::topic::topic_matches(&request.hook, &interceptor.event) {
                                    matches.push((
                                        std::sync::Arc::clone(&capsule),
                                        interceptor.action,
                                    ));
                                }
                            }
                        }
                    }
                    matches
                });

            // Step 2: Dispatch each interceptor via spawned tasks and collect
            // results.
            let responses: Vec<serde_json::Value> =
                util::bounded_block_on(&rt_handle, &host_semaphore, async {
                    let mut join_set = tokio::task::JoinSet::new();

                    for (capsule, action) in matches {
                        let payload = payload_bytes.clone();
                        let hook = request.hook.clone();
                        join_set.spawn(async move {
                            match capsule.invoke_interceptor(&action, &payload, None) {
                                Ok(crate::capsule::InterceptResult::Continue(bytes))
                                    if bytes.is_empty() =>
                                {
                                    None
                                },
                                Ok(
                                    crate::capsule::InterceptResult::Continue(bytes)
                                    | crate::capsule::InterceptResult::Final(bytes),
                                ) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                                    Ok(val) => Some(val),
                                    Err(_) => {
                                        tracing::warn!(
                                            capsule_id = %capsule.id(),
                                            action = %action,
                                            "interceptor returned non-JSON response, skipping"
                                        );
                                        None
                                    },
                                },
                                Ok(crate::capsule::InterceptResult::Deny { reason }) => {
                                    tracing::warn!(
                                        capsule_id = %capsule.id(),
                                        action = %action,
                                        hook = %hook,
                                        reason = %reason,
                                        "interceptor denied during hook trigger"
                                    );
                                    None
                                },
                                Err(e) => {
                                    tracing::warn!(
                                        capsule_id = %capsule.id(),
                                        action = %action,
                                        hook = %hook,
                                        error = %e,
                                        "interceptor invocation failed during hook trigger"
                                    );
                                    None
                                },
                            }
                        });
                    }

                    let mut responses = Vec::new();
                    while let Some(result) = join_set.join_next().await {
                        if let Ok(Some(val)) = result {
                            responses.push(val);
                        }
                    }
                    responses
                });

            match serde_json::to_string(&responses) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize hook responses");
                    "[]".to_string()
                },
            }
        } else {
            // No registry available — return empty array (no subscribers).
            "[]".to_string()
        };

        Ok(result_str)
    }

    fn log(&mut self, level: LogLevel, message: String) {
        let capsule_id = self.capsule_id.as_str().to_owned();
        // Routes to the invoking principal's log when `invoke_interceptor`
        // installed one (cross-principal invocation), otherwise to the
        // capsule owner's load-time log, otherwise to the tracing subscriber.
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

        // Try the per-capsule log file first. If it's not available, or the
        // mutex is poisoned (panic in a prior log writer), emit a warning and
        // fall back to the tracing subscriber so the message still lands.
        let wrote_to_file = if let Some(log_file) = log_file {
            use std::io::Write;
            match log_file.lock() {
                Ok(mut f) => {
                    let _ = writeln!(f, "{timestamp} {level_str} [{capsule_id}] {message}");
                    true
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

        if !wrote_to_file {
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
            tracing::debug!(
                capsule = %self.capsule_id,
                "Capsule signaled ready"
            );
        }
    }

    fn clock_ms(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn check_capsule_capability(
        &mut self,
        request: CapabilityCheckRequest,
    ) -> Result<CapabilityCheckResponse, String> {
        let registry = self.capsule_registry.clone();
        let rt_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let allowed = if let Some(registry) = registry {
            if let Ok(source_uuid) = uuid::Uuid::parse_str(&request.source_uuid) {
                util::bounded_block_on(&rt_handle, &host_semaphore, async {
                    let reg = registry.read().await;
                    let Some(capsule_id) = reg.find_by_uuid(&source_uuid) else {
                        tracing::debug!(
                            uuid = %source_uuid,
                            capability = %request.capability,
                            "UUID not found in registry, denying capability"
                        );
                        return false;
                    };
                    let Some(capsule) = reg.get(capsule_id) else {
                        return false;
                    };
                    match request.capability.as_str() {
                        "allow_prompt_injection" => {
                            capsule.manifest().capabilities.allow_prompt_injection
                        },
                        other => {
                            tracing::warn!(
                                capability = %other,
                                "Unknown capability requested, denying"
                            );
                            false
                        },
                    }
                })
            } else {
                tracing::debug!(
                    uuid = %request.source_uuid,
                    "Malformed UUID in capability check, denying"
                );
                false
            }
        } else {
            false
        };

        Ok(CapabilityCheckResponse { allowed })
    }
}

// ---------------------------------------------------------------------------
// Chain tests: drive `sys::Host::log` synchronously on a HostState with
// manually-installed invocation fields, assert physical log file lives under
// the invoking principal's dir. Mirrors the pattern established in
// `host/fs.rs` for per-invocation VFS re-scoping (#549).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod log_chain_tests {
    use std::sync::Arc;

    use super::*;
    use crate::engine::wasm::bindings::astrid::capsule::sys::Host as SysHost;
    use crate::engine::wasm::test_fixtures::{minimal_host_state, open_log};

    /// Drive `log()` on a minimal HostState — no security gate, no VFS
    /// mounts, only the fields `log()` consults.
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
        assert!(
            !owner_contents.contains("hello from alice"),
            "owner log must not receive cross-principal write"
        );
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
        // Same HostState, invocation log swapped between calls — each call's
        // writes land in the file installed for that call.
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
        // If a prior writer panicked holding the log mutex, subsequent writes
        // must not silently vanish — they fall back to the tracing subscriber
        // after a warning. Asserted by exercising the non-panicking fallback
        // path: a poisoned lock must not cause `log()` itself to panic.
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("poisoned.log");
        let log_file = open_log(&log_path);

        // Poison the mutex by panicking inside a `lock()`.
        let poisoner = Arc::clone(&log_file);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("intentional panic to poison mutex");
        })
        .join();
        assert!(log_file.is_poisoned(), "precondition: mutex is poisoned");

        let mut state = make_host_state();
        state.capsule_log = Some(log_file);

        // Must not panic; must not silently drop (it warns and tracing-fallbacks).
        state.log(LogLevel::Error, "post-poison line".into());
    }
}
