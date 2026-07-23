//! Run a capsule's `install` / `upgrade` lifecycle hook.
//!
//! The lifecycle is one-shot: we spin up a fresh wasmtime instance,
//! invoke the relevant export, and tear down. The capsule sees a
//! per-install KV store and its own workspace root pointed at the
//! target directory.
//!
//! Caller hands us the WASM bytes directly (already content-addressed
//! in `bin/<hash>.wasm`). We don't read from a path because the
//! source / target split makes "the file at this path" ambiguous, and
//! the kernel-side handler should never re-resolve the binary by
//! filesystem walk — it should always come from the content store.
//!
//! ## Event bus
//!
//! Pass `Some(event_bus)` if the caller wants to subscribe to it
//! externally — the CLI uses this to attach an inline stdin elicit
//! handler so capsules can ask for `[env]`-style values during their
//! install hook. Kernel-side installs pass `None`: the dashboard
//! collects configuration through a separate gateway endpoint, and
//! we never want a daemon-side install hanging on a `recv()` that no
//! human will ever answer.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use astrid_capsule::engine::wasm::host_state::LifecyclePhase;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_events::EventBus;

/// Resolve operator `astrid:http` host policy from the global `[http]` config
/// section into the typed [`HttpLimits`](astrid_capsule::HttpLimits) for the
/// lifecycle hook's `HostState`. `[http]` is operator-only global policy, so the
/// global layer is the right source; an absent section / failed load yields the
/// host's historical constants (`HttpLimits::default`).
fn resolve_http_limits() -> astrid_capsule::HttpLimits {
    let http = match astrid_config::Config::load(None) {
        Ok(resolved) => resolved.config.http,
        Err(e) => {
            // Fail safe to host defaults, but NOT silently: a malformed global
            // config would otherwise diverge lifecycle HTTP policy from the
            // operator's intent with no signal.
            tracing::warn!(error = %e, "failed to load global [http] config for lifecycle HTTP limits; using host defaults");
            astrid_config::HttpSection::default()
        },
    };
    astrid_capsule::HttpLimits::from_config_values(
        http.default_timeout_secs,
        http.stream_connect_timeout_secs,
        http.stream_read_timeout_secs,
        http.header_deadline_secs,
        http.max_redirects,
        http.max_concurrent_streams,
        http.max_response_bytes,
    )
}

/// Run the capsule's lifecycle hook. No-op for non-WASM capsules.
///
/// * `target_dir` — the installed capsule's directory. Passed to the
///   lifecycle config as `workspace_root` so relative file access inside the
///   hook works as the capsule expects.
/// * `wasm_bytes` — the WASM binary, read once by the caller from
///   `bin/<hash>.wasm` after content addressing.
/// * `manifest` — the capsule's parsed manifest (carries the id).
/// * `phase` — `Install` or `Upgrade`.
/// * `previous_version` — `Some(v)` on upgrade, `None` on first
///   install.
/// * `external_bus` — caller-supplied event bus. `None` creates a
///   private bus visible only to this lifecycle dispatch.
///
/// # Errors
///
/// Propagates wasmtime / capsule-engine errors. The caller is
/// responsible for rolling back the target directory on failure.
pub fn run_lifecycle(
    target_dir: &Path,
    wasm_bytes: Vec<u8>,
    manifest: &CapsuleManifest,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
    external_bus: Option<EventBus>,
) -> anyhow::Result<()> {
    let principal = PrincipalId::default();
    let home = AstridHome::resolve().ok();
    run_lifecycle_in_scope(
        target_dir,
        wasm_bytes,
        manifest,
        home.as_ref(),
        &principal,
        phase,
        previous_version,
        external_bus,
    )
}

/// Run the capsule's lifecycle hook for an explicit principal and injected
/// Astrid home.
///
/// This is the principal-aware install path. The hook's `home://` mount, KV
/// namespace, secret store, and IPC identity are scoped to `target_principal`.
/// Lifecycle resource limits remain the engine's finite one-shot defaults; no
/// kernel profile or persistent quota ledger is available on this path.
#[allow(clippy::too_many_arguments)]
pub fn run_lifecycle_for_principal(
    target_dir: &Path,
    wasm_bytes: Vec<u8>,
    manifest: &CapsuleManifest,
    home: &AstridHome,
    target_principal: &PrincipalId,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
    external_bus: Option<EventBus>,
) -> anyhow::Result<()> {
    run_lifecycle_in_scope(
        target_dir,
        wasm_bytes,
        manifest,
        Some(home),
        target_principal,
        phase,
        previous_version,
        external_bus,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_lifecycle_in_scope(
    target_dir: &Path,
    wasm_bytes: Vec<u8>,
    manifest: &CapsuleManifest,
    home: Option<&AstridHome>,
    target_principal: &PrincipalId,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
    external_bus: Option<EventBus>,
) -> anyhow::Result<()> {
    let kv_store = Arc::new(astrid_storage::MemoryKvStore::new());
    let capsule_id = manifest.package.name.clone();
    let kv = astrid_storage::ScopedKvStore::new(
        kv_store,
        lifecycle_kv_namespace(target_principal, &capsule_id),
    )
    .context("failed to create scoped KV store")?;
    let event_bus = external_bus.unwrap_or_else(|| EventBus::with_capacity(128));

    // Reuse the current tokio runtime when there is one (CLI's
    // `#[tokio::main]`, kernel handler thread). Only build a new one
    // for standalone/test contexts.
    let (owned_rt, handle) = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        (None, handle)
    } else {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to build tokio runtime for lifecycle")?;
        let handle = rt.handle().clone();
        (Some(rt), handle)
    };

    let capsule_id_owned = astrid_capsule::capsule::CapsuleId::new(capsule_id.clone())
        .map_err(|e| anyhow::anyhow!("invalid capsule ID: {e}"))?;
    let secret_store = astrid_storage::build_secret_store(
        &lifecycle_secret_scope(&capsule_id, target_principal),
        kv.clone(),
        handle.clone(),
    );
    let secret_store = if let Some(legacy_scope) =
        legacy_lifecycle_secret_scope(&capsule_id, target_principal)
    {
        let legacy = astrid_storage::build_secret_store(&legacy_scope, kv.clone(), handle.clone());
        Arc::new(astrid_storage::ReadThroughSecretStore::new(
            secret_store,
            legacy,
        )) as Arc<dyn astrid_storage::SecretStore>
    } else {
        secret_store
    };
    let home_root = lifecycle_home_root(home, target_principal)?;
    let secret_env = manifest
        .env
        .iter()
        .filter(|(_, declaration)| declaration.env_type.eq_ignore_ascii_case("secret"))
        .map(|(key, _)| key.clone())
        .collect();
    let mut principal_context =
        astrid_capsule::engine::wasm::LifecyclePrincipalContext::new(target_principal.clone())
            .with_secret_env(secret_env);
    if let Some(home) = home {
        principal_context = principal_context.with_file_secret_root(home.secrets_dir());
    }

    let cfg = astrid_capsule::engine::wasm::LifecycleConfig {
        wasm_bytes,
        capsule_id: capsule_id_owned,
        workspace_root: target_dir.to_path_buf(),
        home_root,
        kv,
        event_bus: event_bus.clone(),
        config: std::collections::HashMap::new(),
        secret_store,
        // Resolve operator `[http]` host policy so a lifecycle hook's HTTP calls
        // honour the same limits as the live runtime. `[http]` is operator-only
        // global policy, so the global config layer is the right (and only)
        // source here; an absent section yields the host's historical constants.
        http_limits: resolve_http_limits(),
        // The standalone install path has no kernel audit log in scope;
        // sensitive lifecycle host calls fall back to observability tracing.
        audit_sink: None,
    };

    // `engine::wasm::run_lifecycle` is async — async wasmtime requires
    // it to `.await` instantiate_async / call_async. Drive the future
    // through the available runtime handle.
    let result = if let Some(rt) = &owned_rt {
        rt.block_on(astrid_capsule::engine::wasm::run_lifecycle_for_principal(
            cfg,
            phase,
            previous_version,
            principal_context,
        ))
    } else {
        tokio::task::block_in_place(|| {
            handle.block_on(astrid_capsule::engine::wasm::run_lifecycle_for_principal(
                cfg,
                phase,
                previous_version,
                principal_context,
            ))
        })
    };

    drop(event_bus);
    drop(owned_rt);

    result.map_err(|e| anyhow::anyhow!("lifecycle dispatch failed: {e}"))
}

fn lifecycle_kv_namespace(principal: &PrincipalId, capsule_id: &str) -> String {
    format!("{principal}:capsule:{capsule_id}")
}

fn lifecycle_secret_scope(capsule_id: &str, principal: &PrincipalId) -> String {
    format!("{capsule_id}:{principal}")
}

fn legacy_lifecycle_secret_scope(capsule_id: &str, principal: &PrincipalId) -> Option<String> {
    (*principal == PrincipalId::default()).then(|| capsule_id.to_owned())
}

fn lifecycle_home_root(
    home: Option<&AstridHome>,
    principal: &PrincipalId,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    let Some(home) = home else {
        return Ok(None);
    };
    let principal_home = home.principal_home(principal);
    principal_home
        .ensure()
        .with_context(|| format!("failed to provision lifecycle home for principal {principal}"))?;
    Ok(Some(principal_home.root().to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_resources_are_scoped_to_target_principal() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        let principal = PrincipalId::new("agent-alice").unwrap();

        assert_eq!(
            lifecycle_kv_namespace(&principal, "astrid-capsule-example"),
            "agent-alice:capsule:astrid-capsule-example"
        );
        assert_eq!(
            lifecycle_secret_scope("astrid-capsule-example", &principal),
            "astrid-capsule-example:agent-alice"
        );
        assert_eq!(
            lifecycle_home_root(Some(&home), &principal).unwrap(),
            Some(home.principal_home(&principal).root().to_path_buf())
        );
        assert_ne!(
            lifecycle_home_root(Some(&home), &principal).unwrap(),
            Some(
                home.principal_home(&PrincipalId::default())
                    .root()
                    .to_path_buf()
            )
        );
        assert!(
            home.principal_home(&principal).root().is_dir(),
            "fresh workspace installs must provision the target principal before mounting home://"
        );
        assert_eq!(
            legacy_lifecycle_secret_scope("astrid-capsule-example", &PrincipalId::default()),
            Some("astrid-capsule-example".into())
        );
        assert_eq!(
            legacy_lifecycle_secret_scope("astrid-capsule-example", &principal),
            None,
            "a non-default principal must never receive the legacy unscoped keychain"
        );
    }
}
