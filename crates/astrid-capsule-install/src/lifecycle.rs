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
use astrid_storage::RuntimePrincipalStore;

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
        None,
        None,
        phase,
        previous_version,
        external_bus,
    )
}

/// Run the capsule's lifecycle hook for an explicit principal and injected
/// Astrid home.
///
/// This is the principal-aware install path. The hook's KV namespace, secret
/// store, and IPC identity are scoped to `target_principal`; `home://` is
/// available only when an authorized durable principal store is threaded into
/// the engine context.
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
        None,
        None,
        phase,
        previous_version,
        external_bus,
    )
}

/// Run a lifecycle hook with the authoritative principal store and alias
/// directory. The immutable UID is resolved before any secret scope is built;
/// callers that only have a mutable alias must use this entry point rather
/// than deriving a namespace from alias text.
#[allow(clippy::too_many_arguments)]
pub fn run_lifecycle_for_principal_with_storage(
    target_dir: &Path,
    wasm_bytes: Vec<u8>,
    manifest: &CapsuleManifest,
    home: &AstridHome,
    target_principal: &PrincipalId,
    storage: &RuntimePrincipalStore,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
    external_bus: Option<EventBus>,
) -> anyhow::Result<()> {
    let directory = storage.principal_directory();
    let uid = directory
        .uid_for(target_principal)
        .map_err(|error| anyhow::anyhow!("resolve durable principal UID: {error}"))?;
    run_lifecycle_in_scope(
        target_dir,
        wasm_bytes,
        manifest,
        Some(home),
        target_principal,
        Some(uid),
        Some(storage.clone()),
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
    _home: Option<&AstridHome>,
    target_principal: &PrincipalId,
    principal_uid: Option<astrid_core::identity::PrincipalUid>,
    principal_storage: Option<RuntimePrincipalStore>,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
    external_bus: Option<EventBus>,
) -> anyhow::Result<()> {
    if principal_storage.is_none() && !manifest.env.is_empty() {
        anyhow::bail!(
            "lifecycle manifest declares environment state but no durable principal UID binding was supplied"
        );
    }
    let kv_store: Arc<dyn astrid_storage::KvStore> = principal_storage.as_ref().map_or_else(
        || Arc::new(astrid_storage::MemoryKvStore::new()) as Arc<dyn astrid_storage::KvStore>,
        |store| store.kv(),
    );
    let capsule_id = manifest.package.name.clone();
    let kv = astrid_storage::ScopedKvStore::new(
        Arc::clone(&kv_store),
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
    let secret_namespace = if let Some(uid) = principal_uid {
        astrid_storage::env::principal_secret_namespace(uid, &capsule_id)
    } else {
        // A no-env preview lifecycle may use an isolated host-only scope. It
        // is never an authority source and cannot be selected for manifests
        // that declare environment state (the guard above fails closed).
        astrid_storage::env::system_secret_namespace("lifecycle-ephemeral")
    };
    let secret_scope = astrid_storage::ScopedKvStore::new(Arc::clone(&kv_store), secret_namespace)
        .context("failed to create lifecycle secret control scope")?;
    let secret_store = astrid_storage::build_secret_store(
        &format!("{capsule_id}:{target_principal}"),
        secret_scope,
        handle.clone(),
    );
    // Lifecycle hooks use the same host-owned typed environment projection as
    // steady-state invocations.  Loading this snapshot here is what makes
    // daemon-staged `--var` values visible before an install/upgrade hook
    // executes; no native `.env` or PrincipalHome path is consulted.
    let config = lifecycle_config_values(
        principal_uid,
        &kv_store,
        &capsule_id,
        owned_rt.as_ref(),
        &handle,
    )?;
    let home_root = lifecycle_home_root();
    let secret_env = manifest
        .env
        .iter()
        .filter(|(_, declaration)| declaration.env_type.eq_ignore_ascii_case("secret"))
        .map(|(key, _)| key.clone())
        .collect();
    let principal_context =
        astrid_capsule::engine::wasm::LifecyclePrincipalContext::new(target_principal.clone())
            .with_secret_env(secret_env);
    let principal_context = if let Some(storage) = principal_storage {
        let directory = storage.principal_directory();
        principal_context.with_principal_storage(storage, directory)
    } else {
        principal_context
    };

    let cfg = astrid_capsule::engine::wasm::LifecycleConfig {
        wasm_bytes,
        capsule_id: capsule_id_owned,
        workspace_root: target_dir.to_path_buf(),
        home_root,
        kv,
        event_bus: event_bus.clone(),
        config,
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

fn lifecycle_home_root() -> Option<std::path::PathBuf> {
    // Native PrincipalHome is a released import source, never a lifecycle
    // authority. The engine mounts home:// only when its principal context
    // carries the UID-bound AstridFilesystem store.
    None
}

fn lifecycle_config_values(
    principal_uid: Option<astrid_core::identity::PrincipalUid>,
    kv_store: &Arc<dyn astrid_storage::KvStore>,
    capsule_id: &str,
    owned_rt: Option<&tokio::runtime::Runtime>,
    handle: &tokio::runtime::Handle,
) -> anyhow::Result<std::collections::HashMap<String, serde_json::Value>> {
    let Some(uid) = principal_uid else {
        return Ok(std::collections::HashMap::new());
    };
    let env_scope = astrid_storage::env::principal_env_store(Arc::clone(kv_store), uid, capsule_id)
        .context("failed to create lifecycle environment control scope")?;
    let read_env = astrid_storage::env::read_env(&env_scope);
    let values = if let Some(runtime) = owned_rt {
        runtime.block_on(read_env)
    } else {
        tokio::task::block_in_place(|| handle.block_on(read_env))
    }
    .context("failed to read lifecycle environment control scope")?;
    Ok(values
        .into_iter()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect())
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
        assert_eq!(lifecycle_home_root(), None);
        assert!(!home.principal_home(&principal).root().exists());
    }
}
