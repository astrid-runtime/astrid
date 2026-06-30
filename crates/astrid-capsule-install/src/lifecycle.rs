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
///   lifecycle config as `workspace_root` so `home://` resolution and
///   relative file access inside the hook work as the capsule expects.
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
    let kv_store = Arc::new(astrid_storage::MemoryKvStore::new());
    let capsule_id = manifest.package.name.clone();
    let kv = astrid_storage::ScopedKvStore::new(kv_store, format!("plugin:{capsule_id}"))
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
    let secret_store = astrid_storage::build_secret_store(&capsule_id, kv.clone(), handle.clone());
    let home_root = astrid_core::dirs::AstridHome::resolve().ok().map(|h| {
        h.principal_home(&astrid_core::PrincipalId::default())
            .root()
            .to_path_buf()
    });

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
        rt.block_on(astrid_capsule::engine::wasm::run_lifecycle(
            cfg,
            phase,
            previous_version,
        ))
    } else {
        tokio::task::block_in_place(|| {
            handle.block_on(astrid_capsule::engine::wasm::run_lifecycle(
                cfg,
                phase,
                previous_version,
            ))
        })
    };

    drop(event_bus);
    drop(owned_rt);

    result.map_err(|e| anyhow::anyhow!("lifecycle dispatch failed: {e}"))
}
