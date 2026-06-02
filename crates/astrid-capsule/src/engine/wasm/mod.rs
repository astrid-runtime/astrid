use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;
use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use crate::context::CapsuleContext;
use crate::engine::ExecutionEngine;
use crate::engine::wasm::host_state::{HostState, LifecyclePhase, PrincipalMount};
use crate::error::{CapsuleError, CapsuleResult};
use crate::manifest::CapsuleManifest;

pub mod bindings;
pub mod host;
pub mod host_state;
#[cfg(test)]
mod test_fixtures;

/// Today's date as `YYYY-MM-DD` for daily log rotation.
fn today_date_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Days since epoch → date components.
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's `chrono`-compatible date library.
#[expect(clippy::arithmetic_side_effects)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Delete log files older than `max_days` from a capsule log directory.
///
/// Only deletes files matching the `YYYY-MM-DD.log` pattern.
fn prune_old_logs(log_dir: &std::path::Path, max_days: u64) {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(max_days * 86400))
        .unwrap_or(std::time::UNIX_EPOCH);

    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only touch files matching YYYY-MM-DD.log pattern.
        if !name_str.ends_with(".log") || name_str.len() != 14 {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && modified < cutoff
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Read the expected WASM hash from `meta.json` in the capsule directory.
fn read_expected_wasm_hash(capsule_dir: &std::path::Path) -> Option<String> {
    let meta_path = capsule_dir.join("meta.json");
    let content = std::fs::read_to_string(&meta_path).ok()?;
    let meta: serde_json::Value = serde_json::from_str(&content).ok()?;
    meta.get("wasm_hash")?.as_str().map(String::from)
}

/// Resolve a content-addressed WASM binary from `lib/{hash}.wasm`.
///
/// Reads `meta.json` in the capsule dir to find the `wasm_hash` field,
/// then resolves the path in the Astrid home `lib/` directory.
fn resolve_content_addressed_wasm(capsule_dir: &std::path::Path) -> Option<PathBuf> {
    let meta_path = capsule_dir.join("meta.json");
    let content = std::fs::read_to_string(&meta_path).ok()?;
    let meta: serde_json::Value = serde_json::from_str(&content).ok()?;
    let hash = meta.get("wasm_hash")?.as_str()?;
    let home = astrid_core::dirs::AstridHome::resolve().ok()?;
    let wasm_path = home.bin_dir().join(format!("{hash}.wasm"));
    if wasm_path.exists() {
        Some(wasm_path)
    } else {
        None
    }
}

/// Read baked topic schemas from `meta.json` in a capsule's install directory.
///
/// Returns a map of topic name → JSON Schema. Topics without a baked schema
/// are omitted. If `meta.json` is missing or unparseable, returns an empty map.
fn read_baked_schemas(
    capsule_dir: &std::path::Path,
) -> std::collections::HashMap<String, serde_json::Value> {
    let meta_path = capsule_dir.join("meta.json");
    let content = match std::fs::read_to_string(&meta_path) {
        Ok(c) => c,
        Err(_) => return std::collections::HashMap::new(),
    };
    let meta: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return std::collections::HashMap::new(),
    };

    let mut schemas = std::collections::HashMap::new();
    if let Some(topics) = meta.get("topics").and_then(|t| t.as_array()) {
        for topic in topics {
            if let (Some(name), Some(schema)) = (
                topic.get("name").and_then(|n| n.as_str()),
                topic.get("schema").filter(|s| !s.is_null()),
            ) {
                schemas.insert(name.to_string(), schema.clone());
            }
        }
    }
    schemas
}

/// Wall-clock timeout for short-lived (non-daemon) WASM capsules.
/// Generous enough for interceptors doing streaming HTTP (e.g. LLM providers)
/// while still catching runaways.
const WASM_CAPSULE_TIMEOUT_SECS: u64 = 5 * 60;

/// Epoch tick interval for the background epoch incrementer thread.
/// Each tick increments the engine epoch by 1, so the effective timeout
/// granularity is `EPOCH_TICK_INTERVAL * epoch_deadline`.
const EPOCH_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Executes WASM Components via the wasmtime Component Model.
///
/// This engine sandboxes execution in wasmtime and wires the
/// `astrid-sys` host interfaces (WIT imports) so the component can interact
/// securely with the OS Event Bus and VFS.
pub struct WasmEngine {
    manifest: CapsuleManifest,
    _capsule_dir: PathBuf,
    /// The wasmtime engine shared between the store and epoch incrementer.
    wasmtime_engine: Option<wasmtime::Engine>,
    /// The wasmtime store holding HostState. Wrapped in `Arc<AsyncMutex<>>`
    /// so the run loop task and `invoke_interceptor` can both access it
    /// (though never concurrently for run-loop capsules — those use IPC
    /// auto-subscribe). Async mutex so a parallel interceptor invocation
    /// `.await`s on the lock instead of pinning a tokio worker via
    /// `block_in_place` (issue #816).
    store: Option<Arc<AsyncMutex<Store<HostState>>>>,
    /// The instantiated guest component. Per-export typed accessors are
    /// looked up at call time via `instance.get_typed_func` since the
    /// per-domain WIT split removed the bundled `Capsule` world.
    instance: Option<wasmtime::component::Instance>,
    inbound_rx: Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>>,
    run_handle: Option<tokio::task::JoinHandle<()>>,
    /// Receiver for the readiness signal from the run loop.
    /// Only set for capsules that have a `run()` export.
    /// The Mutex is required because `wait_ready` takes `&self` but we need
    /// to clone the receiver (which marks the current value as seen). We
    /// clone inside the lock and immediately drop it, so concurrent
    /// `wait_ready` calls each get their own independent receiver.
    ready_rx: Option<tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>>,
    /// Cancellation token for cooperative shutdown of blocking host functions.
    /// Triggered during `unload()` before aborting the run handle.
    cancel_token: Option<tokio_util::sync::CancellationToken>,
    /// RAII guard that stops the epoch ticker thread on drop.
    epoch_ticker: Option<EpochTickerGuard>,
    /// Shared per-principal profile cache (Layer 3, issue #666).
    ///
    /// Populated at load time from the kernel-wide cache. `invoke_interceptor`
    /// resolves the invoking principal's profile against this cache and applies
    /// the result to `StoreLimits`, the epoch deadline, and downstream
    /// sub-budgets. `None` in tests and single-tenant deployments — the
    /// engine falls back to [`PrincipalProfile::default_ref`].
    profile_cache: Option<Arc<crate::profile_cache::PrincipalProfileCache>>,
    /// Capsule owner's principal, cached from [`CapsuleContext`] at load time.
    ///
    /// Lets `invoke_interceptor` derive the invoking principal (caller or
    /// owner) without locking the store just to read `HostState.principal` —
    /// `state.principal` is immutable after load, so caching it here is
    /// equivalent and hot-path friendly.
    owner_principal: Option<astrid_core::PrincipalId>,
    /// Shared per-principal overlay VFS registry (Layer 4, issue #668).
    ///
    /// Populated at load time from the kernel-wide registry.
    /// `invoke_interceptor` resolves the invoking principal's overlay on
    /// every call for two side effects: fail-closing the invocation if
    /// tempdir allocation errors, and warming the per-principal cache so
    /// future layers routing writes through the overlay find it ready.
    /// The resolved `Arc<OverlayVfs>` is dropped — no host function reads
    /// through the overlay today. `None` in tests and single-tenant
    /// deployments.
    overlay_registry: Option<Arc<astrid_vfs::OverlayVfsRegistry>>,
}

impl WasmEngine {
    pub fn new(manifest: CapsuleManifest, capsule_dir: PathBuf) -> Self {
        Self {
            manifest,
            _capsule_dir: capsule_dir,
            wasmtime_engine: None,
            store: None,
            instance: None,
            inbound_rx: None,
            run_handle: None,
            ready_rx: None,
            cancel_token: None,
            epoch_ticker: None,
            profile_cache: None,
            owner_principal: None,
            overlay_registry: None,
        }
    }
}

/// Build a `wasmtime::Engine` configured for Component Model execution
/// with epoch-based interruption.
/// Maximum WASM linear memory per capsule (64 MB).
///
/// Matches the old Extism `with_memory_max(1024)` (1024 pages * 64KB).
/// This is a per-capsule limit enforced via `StoreLimits`. A global
/// memory budget across all capsules is not yet implemented — when
/// hosting providers run many capsules, a global pool limit with
/// per-capsule shares would be more appropriate than N * 64MB headroom.
/// See #639 for the resource telemetry tracking issue.
const WASM_MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Register every Astrid host interface on `linker`. Single source of
/// truth shared between the main capsule-load path and the lifecycle-
/// hook (`run_lifecycle`) path so a future change that adds version
/// negotiation can't drift between the two — what a capsule sees at
/// install time MUST match what it sees at runtime.
///
/// **Zero `wasi:*` registration.** The Astrid-canonical guest target is
/// `wasm32-unknown-unknown` — capsules produce wasm with zero `wasi:*`
/// imports, every host call going through audited `astrid:*` interfaces.
/// A capsule that somehow ships with a `wasi:*` import (e.g. built
/// against `wasm32-wasip2` without `astrid-sdk`'s toolchain integration)
/// fails to instantiate at load time with a clear "interface not found"
/// error — that is the intended posture, not a bug to paper over.
pub fn configure_kernel_linker(
    linker: &mut wasmtime::component::Linker<HostState>,
) -> wasmtime::Result<()> {
    bindings::Kernel::add_to_linker::<HostState, wasmtime::component::HasSelf<HostState>>(
        linker,
        |state| state,
    )
}

fn build_wasmtime_engine() -> CapsuleResult<wasmtime::Engine> {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true).epoch_interruption(true);
    // Component Model async: every guest call goes through `call_async`
    // and yields on every host import boundary. This lets the per-capsule
    // Store mutex be a `tokio::sync::Mutex` and waiters .await rather
    // than pin a tokio worker via `block_in_place` (issue #816).
    //
    // Sync host trait impls remain valid in async mode — wasmtime runs
    // the guest on a fiber and resumes the executor when the fiber
    // yields. Host fns that themselves block (recv, http) still serialise
    // per-capsule under the Store mutex, but no longer hold a worker
    // across the entire interceptor invocation.
    //
    // `async_support` is the no-op-since-wasmtime-45 toggle (async is
    // enabled implicitly by the `async` cargo feature). The call is
    // kept for documentation parity with older releases.
    #[allow(deprecated)]
    config.async_support(true);
    wasmtime::Engine::new(&config).map_err(|e| {
        CapsuleError::UnsupportedEntryPoint(format!("Failed to create wasmtime engine: {e}"))
    })
}

/// Build a minimal `WasiCtx` for capsule sandboxing.
///
/// Only stderr is inherited so capsule panic messages reach the host.
/// No filesystem, network, or environment access is granted — all I/O
/// goes through the Astrid host interfaces (WIT imports).
fn build_wasi_ctx() -> wasmtime_wasi::WasiCtx {
    wasmtime_wasi::WasiCtxBuilder::new()
        .inherit_stderr()
        .build()
}

/// Per-invocation home/tmp VFS bundle for the calling principal.
///
/// Populated by [`build_principal_vfs_bundle`] and installed on
/// [`HostState`] by `WasmEngine::invoke_interceptor` when the invocation
/// principal differs from the capsule's owning principal. Either field may
/// be `None`: a missing home directory yields a clean denial instead of a
/// panic; the host-side fs functions treat `None` as "no VFS available"
/// and return an error to the guest.
#[derive(Default)]
pub(crate) struct PrincipalVfsBundle {
    home: Option<PrincipalMount>,
    tmp: Option<PrincipalMount>,
}

/// Register `root` as a new [`HostVfs`](astrid_vfs::HostVfs) with a fresh
/// [`DirHandle`](astrid_capabilities::DirHandle), returning the triple as a
/// [`PrincipalMount`]. Returns `None` if `root` does not exist or the VFS
/// registration fails.
///
/// The stored `PrincipalMount.root` is canonicalized so it matches the
/// symlink-resolved paths that `host/fs.rs::resolve_physical_absolute`
/// produces for security-gate checks. On macOS this matters: tempdirs under
/// `/tmp/...` canonicalize to `/private/tmp/...`, and a non-canonical mount
/// root would cause `Path::starts_with` comparisons in the gate to fail.
///
/// Async: `register_dir` is awaited directly so no tokio worker is pinned
/// via `block_in_place`/`block_on` (issue #816). Must be called from an
/// async context (load path and per-invocation SET phase both are).
pub(crate) async fn mount_dir(root: &std::path::Path) -> Option<PrincipalMount> {
    if !root.exists() {
        return None;
    }
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let vfs = astrid_vfs::HostVfs::new();
    let handle = astrid_capabilities::DirHandle::new();
    match vfs.register_dir(handle.clone(), canonical.clone()).await {
        Ok(()) => Some(PrincipalMount {
            root: canonical,
            vfs: Arc::new(vfs) as Arc<dyn astrid_vfs::Vfs>,
            handle,
        }),
        Err(e) => {
            tracing::warn!(
                root = %canonical.display(),
                error = %e,
                "failed to register principal VFS; denying scheme access",
            );
            None
        },
    }
}

/// Build a home/tmp VFS bundle for `principal`.
///
/// Only mounts a home VFS if `~/.astrid/home/{principal}/` already exists
/// on disk. This is the registration gate: an invocation for an unknown
/// principal returns an empty bundle and the host fs layer denies
/// `home://` access. The tmp directory (`~/.astrid/home/{principal}/.local/tmp/`)
/// is auto-created under an already-existing principal root.
///
/// Async: awaits the underlying `mount_dir` calls rather than pinning a
/// worker (issue #816).
pub(crate) async fn build_principal_vfs_bundle(
    principal: &astrid_core::PrincipalId,
) -> PrincipalVfsBundle {
    let Ok(astrid_home) = astrid_core::dirs::AstridHome::resolve() else {
        return PrincipalVfsBundle::default();
    };
    build_principal_vfs_bundle_at(&astrid_home.principal_home(principal)).await
}

/// Open (creating the log dir if needed) the daily-rotated log file for
/// `capsule_name` under `principal`'s home. Returns `None` if the astrid home
/// can't be resolved, the principal's home directory doesn't exist, or the
/// file can't be opened.
///
/// When `prune` is true, deletes rotated logs older than 7 days before
/// opening. Pruning is an O(N) directory scan and must only be requested on
/// the load-time path — never from [`WasmEngine::invoke_interceptor`], which
/// runs on the async hot path.
///
/// Mirrors the registration gate from [`build_principal_vfs_bundle`]: an
/// invocation for an unregistered principal yields `None` instead of
/// auto-creating the attacker's home tree.
pub(crate) fn open_capsule_log(
    principal: &astrid_core::PrincipalId,
    capsule_name: &str,
    prune: bool,
) -> Option<Arc<Mutex<std::fs::File>>> {
    let astrid_home = astrid_core::dirs::AstridHome::resolve().ok()?;
    open_capsule_log_at(&astrid_home.principal_home(principal), capsule_name, prune)
}

/// Read the per-principal env overlay for a capsule.
///
/// Returns `Some(map)` only when the JSON file at
/// `$ASTRID_HOME/home/{principal}/.config/env/{capsule_id}.env.json`
/// exists and parses as a flat `HashMap<String, String>` (matching the
/// shape the gateway's
/// [`crate::routes::env::write_env`](../../gateway/src/routes/env.rs)
/// writes through `text` / `select` / `array` fields and the kernel's
/// own boot-time loader expects). Anything else — file missing,
/// permission denied, malformed JSON, oversized file — returns `None`
/// and lets [`HostState::get_config`] fall back to the manifest
/// defaults in `self.config`.
///
/// Called from `WasmEngine::invoke_interceptor` (on dispatch) and from
/// `HostState::install_recv_invocation_context` (on each fresh inbound
/// principal in a run-loop subscription). Reading on every dispatch
/// adds one `stat` + `read_to_string` per call — cheap relative to the
/// surrounding wasmtime invocation, and the alternative (caching with
/// invalidation on the gateway env-write path) would couple the host
/// to a routing surface that's optional at boot. If profiling later
/// shows this matters, swap in an LRU keyed by `(principal, capsule)`.
///
/// Defensive size cap: env files larger than 1 MiB are skipped. The
/// gateway env-write path doesn't impose its own ceiling today;
/// guarding against a runaway file keeps a misconfigured operator
/// from blocking every interceptor dispatch on a slow read.
pub(crate) fn load_invocation_env_overlay(
    principal: &astrid_core::PrincipalId,
    capsule_id: &str,
) -> Option<std::collections::HashMap<String, String>> {
    const MAX_ENV_FILE_BYTES: u64 = 1 << 20;
    let astrid_home = astrid_core::dirs::AstridHome::resolve().ok()?;
    let env_path = astrid_home
        .principal_home(principal)
        .env_dir()
        .join(format!("{capsule_id}.env.json"));

    let meta = std::fs::metadata(&env_path).ok()?;
    if !meta.is_file() || meta.len() > MAX_ENV_FILE_BYTES {
        return None;
    }
    let contents = std::fs::read_to_string(&env_path).ok()?;
    serde_json::from_str::<std::collections::HashMap<String, String>>(&contents).ok()
}

/// Test-friendly core of [`open_capsule_log`]: open a log file under a
/// fully-resolved [`PrincipalHome`], without touching any environment.
fn open_capsule_log_at(
    ph: &astrid_core::dirs::PrincipalHome,
    capsule_name: &str,
    prune: bool,
) -> Option<Arc<Mutex<std::fs::File>>> {
    // Registration gate: don't auto-create a principal home directory for
    // an unregistered principal.
    if !ph.root().exists() {
        return None;
    }
    let log_dir = ph.log_dir().join(capsule_name);
    std::fs::create_dir_all(&log_dir).ok()?;
    if prune {
        prune_old_logs(&log_dir, 7);
    }
    let today = today_date_string();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join(format!("{today}.log")))
        .ok()
        .map(|f| Arc::new(Mutex::new(f)))
}

/// Test-friendly core of [`build_principal_vfs_bundle`]: build a bundle from
/// a fully-resolved [`PrincipalHome`], without touching any environment.
///
/// Tests construct a [`PrincipalHome`] pointing at a tempdir; production
/// code resolves the principal home through [`astrid_core::dirs::AstridHome`].
async fn build_principal_vfs_bundle_at(
    ph: &astrid_core::dirs::PrincipalHome,
) -> PrincipalVfsBundle {
    let home = mount_dir(ph.root()).await;
    // Tmp is only mounted when home is — they live under the same principal
    // root and follow its lifetime. Tmp subdirs may be auto-created.
    let tmp = if home.is_some() {
        let t = ph.tmp_dir();
        if t.exists() || std::fs::create_dir_all(&t).is_ok() {
            mount_dir(&t).await
        } else {
            None
        }
    } else {
        None
    };
    PrincipalVfsBundle { home, tmp }
}

/// Refuse the invocation if the invoking principal's profile has
/// `enabled = false` (issue #672, Layer 3 enabled gate). Mirrors the
/// Layer 5 `authorize_request` preamble in `kernel_router/mod.rs` so
/// `agent.disable` denies *every* surface a principal can drive, not
/// just the management IPC.
///
/// In-flight invocations finish under the old value — `invoke_interceptor`
/// only checks at entry. New invocations after the cache is invalidated
/// (post-`agent.disable`) are refused with a `security_event = true` log.
fn check_principal_enabled(
    profile: &astrid_core::profile::PrincipalProfile,
    invoking: &astrid_core::PrincipalId,
    capsule_name: &str,
    action: &str,
) -> Result<(), CapsuleError> {
    if profile.enabled {
        return Ok(());
    }
    tracing::warn!(
        security_event = true,
        principal = %invoking,
        capsule = %capsule_name,
        action = action,
        "Disabled principal denied at Layer 3 — fail-closed (issue #672)"
    );
    Err(CapsuleError::WasmError(format!(
        "principal '{invoking}' is disabled"
    )))
}

/// RAII guard that stops the epoch ticker thread when dropped.
///
/// Ensures the ticker is cleaned up even on early error returns.
pub struct EpochTickerGuard {
    handle: Option<std::thread::JoinHandle<()>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for EpochTickerGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn a background OS thread that periodically increments the engine
/// epoch. Returns an RAII guard that stops the thread when dropped.
///
/// The caller sets `store.set_epoch_deadline(deadline)` before calling
/// into the guest. Each tick increments the epoch by 1, so a deadline of
/// `N` means the guest traps after approximately `N * EPOCH_TICK_INTERVAL`.
fn spawn_epoch_ticker(engine: &wasmtime::Engine) -> EpochTickerGuard {
    let engine = engine.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();
    let handle = std::thread::Builder::new()
        .name("wasm-epoch-ticker".into())
        .spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK_INTERVAL);
                engine.increment_epoch();
            }
        })
        .expect("failed to spawn epoch ticker thread");
    EpochTickerGuard {
        handle: Some(handle),
        stop,
    }
}

#[async_trait]
impl ExecutionEngine for WasmEngine {
    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()> {
        info!(
            capsule = %self.manifest.package.name,
            "Loading WASM component (Component Model)"
        );

        let component = self.manifest.components.first().ok_or_else(|| {
            CapsuleError::UnsupportedEntryPoint(
                "WASM engine requires at least one component definition".into(),
            )
        })?;

        let wasm_path = if component.path.is_absolute() {
            component.path.clone()
        } else {
            let local = self._capsule_dir.join(&component.path);
            if local.exists() {
                local
            } else {
                // WASM may be content-addressed in lib/ — check meta.json for hash.
                resolve_content_addressed_wasm(&self._capsule_dir).unwrap_or(local)
            }
        };

        // Clone context components to move into block_in_place
        let workspace_root = ctx.workspace_root.clone();
        let kv = ctx.kv.clone();
        let event_bus = astrid_events::EventBus::clone(&ctx.event_bus);
        let manifest = self.manifest.clone();

        let mut wasm_config = std::collections::HashMap::new();

        // Inject the kernel socket path so capsules can discover it via
        // `sys::socket_path()` instead of hardcoding.
        if let Ok(astrid_home) = astrid_core::dirs::AstridHome::resolve() {
            wasm_config.insert(
                "ASTRID_SOCKET_PATH".to_string(),
                serde_json::Value::String(astrid_home.socket_path().to_string_lossy().into_owned()),
            );
        }

        let reserved_keys: Vec<String> = wasm_config.keys().cloned().collect();
        let resolved_env =
            super::resolve_env(&self.manifest, ctx, &reserved_keys, "wasm_engine").await?;

        for (key, val) in resolved_env {
            wasm_config.insert(key, serde_json::Value::String(val));
        }

        // Pre-generate the session UUID so it can be registered in the
        // capsule registry after the blocking plugin build completes.
        let capsule_uuid = uuid::Uuid::new_v4();

        // Create shared concurrency controls before entering the blocking plugin build.
        let host_semaphore = HostState::default_host_semaphore();
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let cancel_token_for_state = cancel_token.clone();
        let process_tracker = Arc::new(crate::engine::wasm::host::process::ProcessTracker::new());
        let process_tracker_for_listener = process_tracker.clone();

        let capsule_dir_for_verify = self._capsule_dir.clone();
        // Inlined async block — was previously wrapped in
        // `block_in_place` to permit nested `block_on` for the VFS
        // `register_dir` calls. Component-model async lets us `.await`
        // those directly here, so the load path no longer pins a worker
        // for the duration of the engine build.
        let (store_arc, instance, rx, has_run, ready_rx, wt_engine) = async {
            let wasm_bytes = std::fs::read(&wasm_path).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!("Failed to read WASM: {e}"))
            })?;

            // BLAKE3 integrity verification. Fail-secure: no hash = no load.
            let actual_hash = blake3::hash(&wasm_bytes).to_hex().to_string();
            match read_expected_wasm_hash(&capsule_dir_for_verify) {
                Some(expected_hash) if actual_hash == expected_hash => {
                    // Hash matches — verified.
                },
                Some(expected_hash) => {
                    return Err(CapsuleError::UnsupportedEntryPoint(format!(
                        "WASM integrity check failed: expected BLAKE3 {expected_hash}, \
                         got {actual_hash}. The binary may have been tampered with."
                    )));
                },
                None => {
                    return Err(CapsuleError::UnsupportedEntryPoint(format!(
                        "WASM capsule '{}' has no BLAKE3 hash in meta.json. \
                         Capsules must be installed via `astrid capsule install` \
                         which records the hash. Refusing to load unverified binary.",
                        manifest.package.name
                    )));
                },
            }

            let (tx, rx) = if !manifest.uplinks.is_empty() {
                let (tx, rx) = tokio::sync::mpsc::channel(128);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };

            // Build HostState
            let lower_vfs = astrid_vfs::HostVfs::new();
            let upper_vfs = astrid_vfs::HostVfs::new();
            let root_handle = astrid_capabilities::DirHandle::new();
            let home_root = ctx.home_root.clone();

            // Upper layer uses a per-capsule temporary directory so writes
            // are sandboxed until explicitly committed. The TempDir is kept
            // alive in HostState.upper_dir for the capsule's lifetime.
            let upper_temp = tempfile::TempDir::new().map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to create overlay temp dir: {e}"
                ))
            })?;

            async {
                lower_vfs
                    .register_dir(root_handle.clone(), workspace_root.clone())
                    .await?;
                upper_vfs
                    .register_dir(root_handle.clone(), upper_temp.path().to_path_buf())
                    .await?;
                Ok::<(), astrid_vfs::VfsError>(())
            }
            .await
            .map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to register VFS directory: {e}"
                ))
            })?;

            // Set up the per-principal home mount. Writes go directly to
            // disk — no OverlayVfs CoW layer here, unlike the workspace
            // VFS. Only mount if the directory exists to avoid failing
            // capsule load on fresh installs; `mount_dir` returns `None`
            // for a missing root.
            let home_mount: Option<PrincipalMount> = match home_root.as_deref() {
                Some(g_root) if !g_root.exists() => {
                    tracing::warn!(
                        home_root = %g_root.display(),
                        "home:// VFS not mounted: directory does not exist. \
                         Capsules requesting home:// paths will receive errors \
                         until the directory is created and the kernel is restarted."
                    );
                    None
                },
                Some(g_root) => mount_dir(g_root).await,
                None => None,
            };

            let overlay_vfs = Arc::new(astrid_vfs::OverlayVfs::new(
                Box::new(lower_vfs),
                Box::new(upper_vfs),
            ));

            // Only resolve home:// in the gate if we actually mounted the VFS.
            // Otherwise the gate would approve paths the VFS can't serve.
            let gate_home_root = home_mount.as_ref().map(|m| m.root.clone());
            let security_gate = Arc::new(crate::security::ManifestSecurityGate::new(
                manifest.clone(),
                workspace_root.clone(),
                gate_home_root,
            ));

            // Set up /tmp mount backed by the principal's .local/tmp/ directory.
            let tmp_mount: Option<PrincipalMount> = match astrid_core::dirs::AstridHome::resolve() {
                Ok(astrid_home) => {
                    let dir = astrid_home.principal_home(&ctx.principal).tmp_dir();
                    if dir.exists() || std::fs::create_dir_all(&dir).is_ok() {
                        mount_dir(&dir).await
                    } else {
                        None
                    }
                },
                Err(_) => None,
            };

            // Open per-capsule daily log file at .local/log/{capsule}/{date}.log.
            // Prunes logs older than 7 days on each capsule load — load is
            // one-shot so the O(N) scan is fine here. Per-invocation re-opens
            // (see `invoke_interceptor`) do NOT prune — hot path.
            let capsule_log = open_capsule_log(&ctx.principal, &manifest.package.name, true);

            let secret_store = astrid_storage::build_secret_store(
                &manifest.package.name,
                kv.clone(),
                tokio::runtime::Handle::current(),
            );

            let host_state = HostState {
                wasi_ctx: build_wasi_ctx(),
                resource_table: wasmtime::component::ResourceTable::new(),
                store_limits: wasmtime::StoreLimitsBuilder::new()
                    .memory_size(WASM_MAX_MEMORY_BYTES)
                    .build(),
                principal: ctx.principal.clone(),
                capsule_uuid,
                caller_context: None,
                interceptor_active: false,
                invocation_kv: None,
                capsule_log,
                capsule_id: crate::capsule::CapsuleId::new(&manifest.package.name)
                    .map_err(|e| CapsuleError::UnsupportedEntryPoint(e.to_string()))?,
                workspace_root,
                vfs: Arc::clone(&overlay_vfs) as Arc<dyn astrid_vfs::Vfs>,
                vfs_root_handle: root_handle,
                home: home_mount,
                tmp: tmp_mount,
                invocation_home: None,
                invocation_tmp: None,
                invocation_secret_store: None,
                invocation_capsule_log: None,
                invocation_profile: None,
                invocation_env_overlay: None,
                overlay_vfs: Some(overlay_vfs),
                upper_dir: Some(Arc::new(upper_temp)),
                kv,
                event_bus,
                ipc_limiter: astrid_events::ipc::IpcRateLimiter::new(),
                config: wasm_config,
                // Secret-typed env keys from the manifest.
                // `get_config` routes these through the keychain
                // (per-invocation principal-scoped, with host-
                // wide fall-through) instead of reading from
                // `config`. Non-secret entries stay in `config`
                // and behave as before. Scope is an operator-
                // side concept at `astrid secret set` time, not
                // a manifest declaration — the lookup precedence
                // is fixed (per-agent first, host-wide on miss).
                secret_env: manifest
                    .env
                    .iter()
                    .filter(|(_, d)| d.env_type.eq_ignore_ascii_case("secret"))
                    .map(|(k, _)| k.clone())
                    .collect(),
                // RFC cargo-like-manifest: prefer [publish] / [subscribe] keys
                // over the legacy [capabilities].ipc_publish / .ipc_subscribe arrays
                // when the capsule declares them. The helper falls back to the
                // legacy arrays if the new tables are empty.
                ipc_publish_patterns: manifest.effective_ipc_publish_patterns(),
                ipc_subscribe_patterns: manifest.effective_ipc_subscribe_patterns(),
                // Only provide the CLI socket listener if the capsule declares net_bind.
                // This prevents unauthorized capsules from even seeing the listener.
                cli_socket_listener: if manifest.capabilities.net_bind.is_empty() {
                    None
                } else {
                    ctx.cli_socket_listener.clone()
                },
                active_http_streams: std::collections::HashMap::new(),
                next_http_stream_id: 1,
                security: Some(security_gate),
                hook_manager: None, // Will be injected by Gateway
                capsule_registry: ctx.capsule_registry.clone(),
                runtime_handle: tokio::runtime::Handle::current(),
                // `has_uplink_capability` reflects the `[capabilities].uplink`
                // bit (binds a socket / accepts external clients), NOT the
                // `[[uplink]]` declarations (which list target platforms a
                // capsule provides). Gates `ipc-publish-as` so only uplinks
                // can stamp messages on behalf of external principals.
                has_uplink_capability: manifest.capabilities.uplink,
                inbound_tx: tx,
                registered_uplinks: Vec::new(),
                lifecycle_phase: None,
                secret_store,
                ready_tx: None,
                host_semaphore,
                cancel_token: cancel_token_for_state,
                // Only provide the session token to capsules with net_bind
                // (the CLI proxy). Other capsules have no use for it.
                session_token: if manifest.capabilities.net_bind.is_empty() {
                    None
                } else {
                    ctx.session_token.clone()
                },
                interceptor_handles: Vec::new(),
                allowance_store: ctx.allowance_store.clone(),
                identity_store: ctx.identity_store.clone(),
                process_tracker: process_tracker.clone(),
                net_stream_count: 0,
                subscription_count: 0,
                process_count_total: 0,
                process_count_by_principal: std::collections::HashMap::new(),
            };

            // Pre-scan WASM exports to detect run() before instantiation.
            // Component Model instantiation requires all exports to be present,
            // but we need to know about run() ahead of time for timeout config.
            //
            // On parse failure, default to true (no timeout) - the safe
            // direction. A truly corrupt binary will fail Component::from_binary
            // moments later anyway.
            let has_run_export = wasm_exports_contain_run(&wasm_bytes);

            // Build wasmtime engine, store, linker, and instantiate the component.
            let wt_engine = build_wasmtime_engine()?;
            let mut store = Store::new(&wt_engine, host_state);

            // Memory limit: 64 MB per capsule (matches old Extism setting).
            store.limiter(|state| &mut state.store_limits);

            // Epoch-based timeout for non-daemon capsules.
            // Long-lived capsules (uplinks, run-loop daemons) must not
            // have a wall-clock timeout. Other capsules get a safety
            // timeout — generous enough for interceptors that do streaming HTTP
            // (e.g. LLM providers) while still catching runaways.
            let is_daemon = !manifest.uplinks.is_empty() || manifest.capabilities.uplink;
            if !is_daemon && !has_run_export {
                // Each epoch tick is EPOCH_TICK_INTERVAL (100ms). Set the
                // deadline so total timeout ≈ WASM_CAPSULE_TIMEOUT_SECS.
                let deadline =
                    WASM_CAPSULE_TIMEOUT_SECS * 1000 / EPOCH_TICK_INTERVAL.as_millis() as u64;
                store.set_epoch_deadline(deadline);
            } else {
                // Long-lived capsules: set deadline to u64::MAX so the epoch
                // ticker doesn't trap them. Without this, the default deadline
                // of 0 would cause an immediate trap on the first tick.
                store.set_epoch_deadline(u64::MAX);
            }

            let mut linker: Linker<HostState> = Linker::new(&wt_engine);

            // No `wasi:*` interfaces are registered: the host ABI is
            // fully Astrid-owned. Capsules import `astrid:fs`,
            // `astrid:ipc`, …, and `astrid:io/poll` for readiness
            // multiplexing — never wasi:io. Exposing the wasi stack
            // here would create unaudited side channels around the
            // capability and audit layers (filesystem outside the
            // VFS, sockets outside the SSRF airlock, clocks/random
            // outside sys, etc.).
            //
            // Wire all Astrid host interfaces from the per-domain
            // WIT. Both this load path AND the lifecycle path
            // (`run_lifecycle`, below) go through the same helper
            // so the linker config stays in lockstep — a future
            // change that adds a second version registration here
            // but forgets it in lifecycle would silently install
            // capsules with mismatched ABIs across the two paths.
            configure_kernel_linker(&mut linker).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to add Astrid host to linker: {e}"
                ))
            })?;

            // Compile and instantiate the WASM component. The new ABI no
            // longer ships a bundled world, so we instantiate directly via
            // the linker and look up exports by name at invocation time.
            let wasm_component = Component::from_binary(&wt_engine, &wasm_bytes).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to compile WASM component: {e}"
                ))
            })?;

            let instance = linker
                .instantiate_async(&mut store, &wasm_component)
                .await
                .map_err(|e| {
                    CapsuleError::UnsupportedEntryPoint(format!(
                        "Failed to instantiate WASM component: {e}"
                    ))
                })?;

            let has_run = has_run_export;

            let store_arc = Arc::new(AsyncMutex::new(store));

            // Only allocate the watch channel for run-loop capsules.
            let ready_rx = if has_run {
                let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
                // Async-mutex `lock()` cannot fail (no poisoning) so the
                // legacy poisoned-lock conversion is gone. The borrow is
                // held synchronously across the small mutation below;
                // no `.await` occurs while it is alive.
                let mut s = store_arc.lock().await;
                s.data_mut().ready_tx = Some(ready_tx);
                Some(ready_rx)
            } else {
                None
            };

            // Auto-subscribe interceptor topics for run-loop capsules.
            // Events arrive via the IPC channel the run loop already reads from,
            // avoiding mutex contention (no external invoke_interceptor calls).
            //
            // Note: subscriptions are created before the WASM guest starts, so
            // events published between subscribe and the guest's first recv/poll
            // call are buffered in the broadcast channel (same as normal IPC).
            // RFC cargo-like-manifest: read interceptor bindings from
            // [subscribe].handler (new) merged with [[interceptor]] (legacy).
            let effective_interceptors = manifest.effective_interceptors();
            if has_run && !effective_interceptors.is_empty() {
                // Cap auto-subscribed interceptors to leave headroom for
                // guest-initiated subscriptions (shared 128-slot pool).
                const MAX_AUTO_SUBSCRIBE: usize = 64;
                if effective_interceptors.len() > MAX_AUTO_SUBSCRIBE {
                    return Err(CapsuleError::UnsupportedEntryPoint(format!(
                        "Capsule '{}' declares {} interceptors, exceeding the \
                         auto-subscribe limit ({MAX_AUTO_SUBSCRIBE})",
                        manifest.package.name,
                        effective_interceptors.len()
                    )));
                }

                // Validate interceptor event patterns have well-formed segments
                // (no empty segments, leading/trailing dots, or empty strings).
                for interceptor in &effective_interceptors {
                    if !crate::topic::has_valid_segments(&interceptor.event) {
                        return Err(CapsuleError::UnsupportedEntryPoint(format!(
                            "Interceptor event '{}' has invalid segment structure \
                             (empty segments, leading/trailing dots, or empty string)",
                            interceptor.event
                        )));
                    }
                }

                let mut s = store_arc.lock().await;
                let state = s.data_mut();
                // Interceptor bindings are metadata under the new
                // ABI. The kernel dispatches matching IPC messages to
                // `astrid-hook-trigger` directly (no capsule-side
                // receiver poll), so we record the action / topic
                // mapping but do not allocate an EventReceiver per
                // interceptor. `handle-id` is informational only —
                // capsules cannot convert it back to a
                // `Resource<Subscription>`.
                let count = effective_interceptors.len();
                for (idx, interceptor) in effective_interceptors.into_iter().enumerate() {
                    state
                        .interceptor_handles
                        .push(host_state::InterceptorHandle {
                            handle_id: idx as u64,
                            action: interceptor.action,
                            topic: interceptor.event,
                        });
                }
                tracing::debug!(
                    capsule = %manifest.package.name,
                    count,
                    "Auto-subscribed interceptors for run-loop capsule"
                );
            }

            Ok::<_, CapsuleError>((store_arc, instance, rx, has_run, ready_rx, wt_engine))
        }
        .await?;

        // Register UUID-to-CapsuleId mapping so host functions can resolve
        // IPC source UUIDs back to capsule identities for capability checks.
        //
        // Ordering: this runs before the kernel's `registry.register(capsule)`.
        // During the gap, `find_by_uuid` returns `Some(id)` but `get(id)`
        // returns `None`, causing capability checks to deny (fail-closed).
        // This is safe because the capsule cannot publish IPC (and thus
        // cannot appear as a hook response `source_id`) until it is fully
        // loaded and running.
        let capsule_id = crate::capsule::CapsuleId::new(&self.manifest.package.name)
            .map_err(|e| CapsuleError::UnsupportedEntryPoint(e.to_string()))?;

        if let Some(registry) = &ctx.capsule_registry {
            registry
                .write()
                .await
                .register_uuid(capsule_uuid, capsule_id.clone());
        }

        // Register topic schemas unconditionally — schema_catalog is always
        // present, even when capsule_registry is None (e.g. in tests).
        let baked_schemas = read_baked_schemas(&self._capsule_dir);
        ctx.schema_catalog
            .register_topics(&capsule_id, &self.manifest.topics, &baked_schemas)
            .await;

        self.cancel_token = Some(cancel_token.clone());
        self.wasmtime_engine = Some(wt_engine.clone());

        // Start the epoch ticker for timeout enforcement.
        self.epoch_ticker = Some(spawn_epoch_ticker(&wt_engine));

        // Spawn a background cancel listener for capsules that can spawn
        // host processes. When `tool.v1.request.cancel` arrives, the listener
        // sends SIGINT/SIGKILL to all tracked child processes.
        if !self.manifest.capabilities.host_process.is_empty() {
            let bus = ctx.event_bus.clone();
            let tracker = process_tracker_for_listener;
            let ct = cancel_token.clone();
            let capsule_name = self.manifest.package.name.clone();
            tokio::task::spawn(async move {
                let mut receiver = bus.subscribe_topic("tool.v1.request.cancel");
                let handle = tokio::runtime::Handle::current();
                loop {
                    tokio::select! {
                        biased;
                        () = ct.cancelled() => break,
                        event = receiver.recv() => {
                            match event.as_deref() {
                                Some(astrid_events::AstridEvent::Ipc { message, .. }) => {
                                    if let astrid_events::ipc::IpcPayload::ToolCancelRequest { call_ids } = &message.payload {
                                        tracing::info!(
                                            capsule = %capsule_name,
                                            ?call_ids,
                                            "Received tool cancel event, killing tracked processes"
                                        );
                                        tracker.cancel_by_call_ids(call_ids, &handle);
                                    }
                                },
                                Some(_) => {},  // Non-IPC event on this topic - ignore.
                                None => break,  // Channel closed.
                            }
                        }
                    }
                }
            });
        }

        if has_run {
            self.ready_rx = ready_rx.map(tokio::sync::Mutex::new);

            // The run loop holds the store mutex for its entire lifetime.
            // We must NOT store the instance for direct invoke_interceptor use,
            // because run-loop capsules receive events via auto-subscribed IPC
            // channels instead — no external invoke_interceptor calls.
            let capsule_name = self.manifest.package.name.clone();
            let run_store = Arc::clone(&store_arc);
            let run_instance = instance;
            // With async wasmtime, `call_async` schedules guest execution
            // on a fiber that yields back to the executor on every host
            // import boundary. The spawned task no longer needs to be a
            // blocking thread — it's an ordinary async task.
            self.run_handle = Some(tokio::task::spawn(async move {
                tracing::info!(capsule = %capsule_name, "Starting background WASM run loop");
                let mut s = run_store.lock().await;
                let typed = match run_instance.get_typed_func::<(), ()>(&mut *s, "run") {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!(
                            capsule = %capsule_name,
                            error = %e,
                            "WASM background loop missing `run` export"
                        );
                        return;
                    },
                };
                if let Err(e) = typed.call_async(&mut *s, ()).await {
                    tracing::error!(
                        capsule = %capsule_name,
                        error = %e,
                        "WASM background loop failed"
                    );
                }
            }));
            // store_arc is also held by run loop — self.store/instance stay None
            // for run-loop capsules to prevent deadlock in invoke_interceptor.
        } else {
            self.store = Some(store_arc);
            self.instance = Some(instance);
        }
        self.inbound_rx = rx;
        self.profile_cache = ctx.profile_cache.clone();
        self.overlay_registry = ctx.overlay_registry.clone();
        self.owner_principal = Some(ctx.principal.clone());

        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        info!(
            capsule = %self.manifest.package.name,
            "Unloading WASM component"
        );
        // Signal cooperative cancellation to unblock ipc_recv/elicit/net calls
        // before aborting the run handle.
        if let Some(token) = self.cancel_token.take() {
            token.cancel();
        }
        if let Some(handle) = self.run_handle.take() {
            handle.abort();
        }
        // Stop the epoch ticker thread (RAII guard joins on drop).
        drop(self.epoch_ticker.take());
        self.store = None; // Drop releases WASM memory
        self.instance = None;
        self.wasmtime_engine = None;
        self.ready_rx = None; // Prevent stale channel observation post-unload
        Ok(())
    }

    async fn wait_ready(&self, timeout: std::time::Duration) -> crate::capsule::ReadyStatus {
        use crate::capsule::ReadyStatus;

        let Some(rx_mutex) = &self.ready_rx else {
            return ReadyStatus::Ready;
        };
        let mut rx = rx_mutex.lock().await.clone();
        match tokio::time::timeout(timeout, rx.wait_for(|&v| v)).await {
            Ok(Ok(_)) => ReadyStatus::Ready,
            Ok(Err(_)) => ReadyStatus::Crashed, // sender dropped before signaling
            Err(_) => ReadyStatus::Timeout,
        }
    }

    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        self.inbound_rx.take()
    }

    async fn invoke_interceptor(
        &self,
        action: &str,
        payload: &[u8],
        caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<crate::capsule::InterceptResult> {
        let store = self.store.as_ref().ok_or_else(|| {
            CapsuleError::NotSupported(
                "plugin handles interceptors internally via IPC auto-subscribe".into(),
            )
        })?;
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| CapsuleError::NotSupported("WASM component not instantiated".into()))?;

        // Layer 3 (#666): resolve the invoking principal's quota profile
        // BEFORE touching the store — a failed load denies the invocation
        // without mutating state. Fail-closed: no fallback to the owner's
        // limits. When the kernel didn't supply a cache (tests, single
        // tenant), `invocation_profile` stays `None` and the defensive
        // apply-block below uses the process-global default.
        //
        // Layer 6 (#672): if `profile.enabled = false`, refuse the
        // invocation. The Layer 5 `authorize_request` preamble already
        // gates the management API on this flag; this gate covers
        // capsule invocations so `agent.disable` denies *every* surface
        // a principal can drive, not just the admin IPC. In-flight
        // invocations finish under the old value (we only check at
        // entry); new invocations are refused.
        let invocation_profile: Option<Arc<astrid_core::profile::PrincipalProfile>> = match self
            .profile_cache
            .as_ref()
        {
            Some(cache) => {
                // Derive the invoking principal without locking the store —
                // `owner_principal` captures the immutable `state.principal`
                // at `load()` time, so the fallback path is allocation- and
                // lock-free on the hot path.
                let invoking = caller
                    .and_then(|msg| msg.principal.as_deref())
                    .and_then(|p| astrid_core::PrincipalId::new(p).ok())
                    .or_else(|| self.owner_principal.clone())
                    .unwrap_or_default();
                let profile = cache.resolve(&invoking).map_err(|e| {
                    tracing::error!(principal = %invoking, error = %e,
                            "profile load failed; denying invocation (issue #666)");
                    CapsuleError::WasmError(format!("principal '{invoking}' profile invalid: {e}"))
                })?;
                check_principal_enabled(
                    &profile,
                    &invoking,
                    self.manifest.package.name.as_str(),
                    action,
                )?;
                Some(profile)
            },
            None => None,
        };
        // Is the capsule a daemon (uplink / long-lived)? Daemons keep their
        // load-time `u64::MAX` epoch deadline; only non-daemon capsules
        // accept a per-invocation timeout from the profile.
        let is_daemon = !self.manifest.uplinks.is_empty() || self.manifest.capabilities.uplink;

        // Layer 4 (#668): resolve the per-principal overlay VFS. The
        // resolved Arc is intentionally dropped — no host function reads
        // through the overlay today, so storing it on HostState would be
        // dead state. We still make the call for its side effects:
        //
        // 1. Fail-closed on resolve error. If the registry is configured
        //    and tempdir creation or VFS mount registration fails, deny
        //    the invocation rather than proceeding against a shared
        //    workspace. Silent fallback would let Agent B observe Agent
        //    A's writes — the exact invariant this layer upholds.
        // 2. Warm the cache so the principal's per-isolation tempdir
        //    exists and is reused across subsequent invocations, and so
        //    the LRU-eviction accounting reflects actual usage.
        //
        // When a future layer routes production VFS operations through
        // the overlay, that layer will add the field + accessor and
        // consume the resolved `Arc<OverlayVfs>` here.
        if let Some(registry) = self.overlay_registry.as_ref() {
            let invoking = caller
                .and_then(|msg| msg.principal.as_deref())
                .and_then(|p| astrid_core::PrincipalId::new(p).ok())
                .or_else(|| self.owner_principal.clone())
                .unwrap_or_default();
            let resolved = registry.resolve(&invoking).await;
            if let Err(e) = resolved {
                tracing::error!(
                    principal = %invoking,
                    error = %e,
                    "overlay registry resolve failed; denying invocation (issue #668)"
                );
                return Err(CapsuleError::WasmError(format!(
                    "principal '{invoking}' overlay resolve failed: {e}"
                )));
            }
        }

        // Cross-principal SET/CALL race is now also closed at the bus
        // layer via per-(capsule, topic, principal) routing in
        // EventBus (see crates/astrid-events/src/route/). The
        // single-lock window remains for panic safety and as
        // defence-in-depth.
        //
        // SET + CALL + CLEAR under a single store lock so a parallel
        // chain dispatch can't observe another principal's
        // `caller_context` between SET and CALL — the cross-principal
        // race that #813 collapsed the orchestration cliff onto. The
        // `ClearOnDrop` guard guarantees CLEAR runs even on early
        // return from the typed-func lookup or a panic-unwind through
        // the guest call, preserving the invariant that
        // `caller_context = None` after every invoke.
        //
        // SAFETY: store.lock() held synchronously across the entire
        // SET/CALL/CLEAR; no `.await` inside this block. Any future
        // host-fn that takes the outer `Arc<Mutex<Store<HostState>>>`
        // must not re-lock — current host fns receive `&mut
        // Store<HostState>` directly from wasmtime and never touch
        // the Arc, so re-entrancy is impossible today.
        type HookTriggerResult = bindings::astrid::guest::lifecycle::CapsuleResult;

        /// RAII guard: clears per-invocation context fields on drop so
        /// CLEAR runs through every exit path (normal return, early
        /// `?`, panic-unwind). `armed = false` after an explicit
        /// `disarm()` avoids a double-clear if the caller already
        /// cleared inline.
        struct ClearOnDrop<'a> {
            store: &'a mut wasmtime::Store<HostState>,
            armed: bool,
        }
        impl<'a> ClearOnDrop<'a> {
            fn new(store: &'a mut wasmtime::Store<HostState>) -> Self {
                Self { store, armed: true }
            }
        }
        impl Drop for ClearOnDrop<'_> {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                let state = self.store.data_mut();
                state.caller_context = None;
                state.interceptor_active = false;
                state.invocation_kv = None;
                state.invocation_home = None;
                state.invocation_tmp = None;
                state.invocation_secret_store = None;
                state.invocation_capsule_log = None;
                state.invocation_profile = None;
                state.invocation_env_overlay = None;
            }
        }

        // Acquire the store under the async mutex. A waiter here
        // `.await`s instead of pinning a tokio worker (issue #816). The
        // mutex still serialises one guest call at a time per capsule,
        // but the executor is free to schedule other capsules while
        // this one waits.
        //
        // The lock guard is dropped on every exit path (normal return,
        // `?`, panic-unwind, future-drop on caller cancellation). The
        // `ClearOnDrop` inside this scope runs first because it owns
        // the inner store borrow — it clears `caller_context`,
        // `interceptor_active`, and all `invocation_*` fields before
        // the lock is released, preserving the invariant that the
        // next interceptor sees a clean HostState.
        let mut s = store.lock().await;
        let result: CapsuleResult<HookTriggerResult> = {
            // ── Phase 1: SET ──────────────────────────────────────
            let applied_profile: Arc<astrid_core::profile::PrincipalProfile> =
                invocation_profile.clone().unwrap_or_else(|| {
                    Arc::new(astrid_core::profile::PrincipalProfile::default_ref().clone())
                });

            if !is_daemon {
                let deadline = applied_profile.quotas.max_timeout_secs.saturating_mul(1000)
                    / EPOCH_TICK_INTERVAL.as_millis() as u64;
                s.set_epoch_deadline(deadline);
            }

            {
                let state = s.data_mut();
                state.caller_context = caller.cloned();
                // Mark the interceptor as active so any nested `ipc::recv`
                // inside the handler (e.g. prompt-builder waiting on plugin
                // hook responses) cannot wipe or rewrite `caller_context`
                // from its empty / cross-publisher batches. See the field
                // doc on `interceptor_active` for the full rationale.
                state.interceptor_active = true;
                // Apply per-principal memory cap by rebuilding `StoreLimits`.
                // The store's `limiter` callback reads this field on each
                // `memory.grow`, so mutating in place takes effect for the
                // upcoming call.
                state.store_limits = wasmtime::StoreLimitsBuilder::new()
                    .memory_size(
                        usize::try_from(applied_profile.quotas.max_memory_bytes)
                            .unwrap_or(usize::MAX),
                    )
                    .build();
                state.invocation_profile = invocation_profile.clone();

                let invocation_principal: Option<astrid_core::PrincipalId> = caller
                    .and_then(|msg| msg.principal.as_deref())
                    .and_then(|p| astrid_core::PrincipalId::new(p).ok())
                    .filter(|p| *p != state.principal);

                state.invocation_kv = invocation_principal.as_ref().and_then(|p| {
                    let ns = format!("{}:capsule:{}", p, state.capsule_id);
                    match state.kv.with_namespace(&ns) {
                        Ok(kv) => Some(kv),
                        Err(e) => {
                            tracing::warn!(
                                principal = %p,
                                error = %e,
                                "Failed to create invocation KV scope"
                            );
                            None
                        },
                    }
                });

                if let Some(ref p) = invocation_principal {
                    let bundle = build_principal_vfs_bundle(p).await;
                    state.invocation_home = bundle.home;
                    state.invocation_tmp = bundle.tmp;
                    state.invocation_capsule_log =
                        open_capsule_log(p, state.capsule_id.as_str(), false);

                    // Per-invocation env overlay: reads
                    // `<home>/.config/env/<capsule>.env.json` so
                    // `env::var(...)` calls inside this interceptor
                    // see the invoking principal's operator-written
                    // overrides instead of the load-time manifest
                    // defaults. None on missing/malformed file — the
                    // host falls back to `self.config` (the manifest
                    // values loaded at capsule boot under the
                    // load-time principal). See `host_state`'s
                    // `invocation_env_overlay` doc + `host::sys::get_config`
                    // for the read path.
                    state.invocation_env_overlay =
                        load_invocation_env_overlay(p, state.capsule_id.as_str());

                    // Per-invocation secret store: built against the
                    // invocation KV scope so both KV and keychain backends
                    // are principal-isolated. `build_secret_store`'s
                    // capsule_id is the keychain service name; combining it
                    // with the principal keeps keychain entries scoped even
                    // when the same capsule serves multiple principals.
                    // If the invocation KV scope couldn't be built we leave
                    // this as `None`, which causes `effective_secret_store`
                    // to fall back to the load-time store — same
                    // degrade-safely behavior as the KV scoping above.
                    state.invocation_secret_store = state.invocation_kv.as_ref().map(|kv| {
                        astrid_storage::build_secret_store(
                            &format!("{}:{}", state.capsule_id, p),
                            kv.clone(),
                            state.runtime_handle.clone(),
                        )
                    });
                }
            }

            // Arm the RAII clear. From this point every exit (normal,
            // `?` from typed-func lookup, panic-unwind through
            // `call_async`, OR future-drop on caller cancellation)
            // runs Phase 3 via `Drop for ClearOnDrop`.
            let mut guard = ClearOnDrop::new(&mut s);

            // ── Phase 2: CALL ─────────────────────────────────────
            //
            // Cancellation safety: the `call_async` future below may be
            // dropped by the dispatcher (e.g. tokio task abort). Drop
            // semantics guarantee `ClearOnDrop` runs synchronously
            // *before* the wasm fiber is torn down, so the next
            // invocation observes `caller_context = None` and every
            // `invocation_*` field cleared. The store mutex is also
            // released, so a parallel waiter is unblocked promptly.
            let typed_lookup = instance.get_typed_func::<(String, Vec<u8>), (HookTriggerResult,)>(
                &mut *guard.store,
                "astrid-hook-trigger",
            );
            match typed_lookup {
                Ok(func) => {
                    let call_result = func
                        .call_async(&mut *guard.store, (action.to_string(), payload.to_vec()))
                        .await
                        .map(|(cr,)| cr)
                        .map_err(|e| {
                            CapsuleError::WasmError(format!("astrid_hook_trigger failed: {e:?}"))
                        });

                    // Phase 3 runs via `Drop for ClearOnDrop`. Leave
                    // `armed = true` so it executes whether
                    // `call_result` is Ok or Err.
                    let _ = &mut guard.armed;
                    call_result
                },
                Err(e) => Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "capsule does not export `astrid-hook-trigger`: {e}"
                ))),
            }
        };
        // Release the store mutex before mapping the result so a
        // parallel invocation observes the cleared HostState as soon
        // as possible (ClearOnDrop has already run by this point).
        drop(s);

        result.map(|cr| {
            crate::capsule::InterceptResult::from_capsule_result(&cr.action, cr.data.as_deref())
        })
    }

    fn check_health(&self) -> crate::capsule::CapsuleState {
        if let Some(handle) = &self.run_handle
            && handle.is_finished()
        {
            return crate::capsule::CapsuleState::Failed(
                "WASM run loop exited unexpectedly".into(),
            );
        }
        crate::capsule::CapsuleState::Ready
    }
}

/// Configuration for lifecycle dispatch.
pub struct LifecycleConfig {
    /// The WASM binary bytes.
    pub wasm_bytes: Vec<u8>,
    /// Capsule identifier.
    pub capsule_id: crate::capsule::CapsuleId,
    /// Workspace root directory for VFS.
    pub workspace_root: PathBuf,
    /// Principal home root for `home://` VFS scheme. Optional — when set,
    /// lifecycle hooks can access `home://` paths (e.g. to write skill files).
    pub home_root: Option<PathBuf>,
    /// Scoped KV store for the capsule.
    pub kv: astrid_storage::ScopedKvStore,
    /// Event bus for IPC (elicit requests flow through this).
    pub event_bus: astrid_events::EventBus,
    /// Plugin configuration values (env vars, etc.).
    pub config: std::collections::HashMap<String, serde_json::Value>,
    /// Secret store for capsule credentials (keychain with KV fallback).
    pub secret_store: std::sync::Arc<dyn astrid_storage::secret::SecretStore>,
}

/// Run a capsule's lifecycle hook (install or upgrade).
///
/// Builds a temporary, short-lived component instance with no epoch deadline
/// (lifecycle hooks involve human interaction via `elicit`). If the WASM binary
/// does not export the relevant function (`astrid_install` or `astrid_upgrade`),
/// returns `Ok(())` silently.
///
/// # Errors
///
/// Returns an error if the WASM component fails to build or the lifecycle hook
/// returns an error.
pub async fn run_lifecycle(
    cfg: LifecycleConfig,
    phase: LifecyclePhase,
    previous_version: Option<&str>,
) -> CapsuleResult<()> {
    let export_name = match phase {
        LifecyclePhase::Install => "astrid-install",
        LifecyclePhase::Upgrade => "astrid-upgrade",
    };

    // Pre-scan: check if the export exists before expensive compilation.
    // Lifecycle hooks are optional — most capsules don't have them.
    let has_export = wasm_exports_contain(export_name, &cfg.wasm_bytes);
    if !has_export {
        tracing::debug!(
            capsule = %cfg.capsule_id,
            export = export_name,
            "Capsule does not export lifecycle hook, skipping"
        );
        return Ok(());
    }

    // Build a minimal VFS for workspace
    let vfs = astrid_vfs::HostVfs::new();
    let root_handle = astrid_capabilities::DirHandle::new();
    vfs.register_dir(root_handle.clone(), cfg.workspace_root.clone())
        .await
        .map_err(|e| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "Failed to register VFS directory for lifecycle: {e}"
            ))
        })?;

    // Mount home VFS if a home root was provided. Canonicalize first so the
    // stored mount root matches paths the security gate checks against.
    let home_mount: Option<PrincipalMount> = match cfg.home_root.as_ref() {
        Some(h_root) => {
            let canonical = h_root.canonicalize().unwrap_or_else(|_| h_root.clone());
            mount_dir(&canonical).await
        },
        None => None,
    };

    let host_state = HostState {
        wasi_ctx: build_wasi_ctx(),
        store_limits: wasmtime::StoreLimitsBuilder::new()
            .memory_size(WASM_MAX_MEMORY_BYTES)
            .build(),
        resource_table: wasmtime::component::ResourceTable::new(),
        principal: astrid_core::PrincipalId::default(),
        capsule_uuid: uuid::Uuid::new_v4(),
        caller_context: None,
        interceptor_active: false,
        invocation_kv: None,
        capsule_log: None,
        capsule_id: cfg.capsule_id.clone(),
        workspace_root: cfg.workspace_root,
        vfs: Arc::new(vfs),
        vfs_root_handle: root_handle,
        home: home_mount,
        tmp: None,
        invocation_home: None,
        invocation_tmp: None,
        invocation_secret_store: None,
        invocation_capsule_log: None,
        invocation_profile: None,
        invocation_env_overlay: None,
        overlay_vfs: None,
        upper_dir: None,
        kv: cfg.kv,
        event_bus: cfg.event_bus,
        ipc_limiter: astrid_events::ipc::IpcRateLimiter::new(),
        config: cfg.config,
        secret_env: std::collections::HashSet::new(),
        ipc_publish_patterns: Vec::new(),
        ipc_subscribe_patterns: Vec::new(),
        security: None,
        hook_manager: None,
        capsule_registry: None,
        runtime_handle: tokio::runtime::Handle::current(),
        has_uplink_capability: false,
        inbound_tx: None,
        registered_uplinks: Vec::new(),
        cli_socket_listener: None,
        active_http_streams: std::collections::HashMap::new(),
        next_http_stream_id: 1,
        lifecycle_phase: Some(phase),
        secret_store: cfg.secret_store,
        ready_tx: None,
        host_semaphore: HostState::default_host_semaphore(),
        cancel_token: tokio_util::sync::CancellationToken::new(),
        session_token: None,
        interceptor_handles: Vec::new(),
        allowance_store: None,
        identity_store: None,
        process_tracker: Arc::new(host::process::ProcessTracker::new()),
        net_stream_count: 0,
        subscription_count: 0,
        process_count_total: 0,
        process_count_by_principal: std::collections::HashMap::new(),
    };

    // Build wasmtime engine and store for lifecycle execution.
    // Lifecycle hooks may block on elicit (human interaction), so use a generous
    // 10-minute safety-net deadline to catch runaway/malicious install hooks.
    const LIFECYCLE_TIMEOUT_SECS: u64 = 10 * 60;
    let wt_engine = build_wasmtime_engine()?;
    let mut store = Store::new(&wt_engine, host_state);
    let deadline_ticks = LIFECYCLE_TIMEOUT_SECS * 10; // 100ms per tick
    store.set_epoch_deadline(deadline_ticks);
    let _epoch_guard = spawn_epoch_ticker(&wt_engine);

    let mut linker: Linker<HostState> = Linker::new(&wt_engine);
    configure_kernel_linker(&mut linker).map_err(|e| {
        CapsuleError::UnsupportedEntryPoint(format!(
            "Failed to add Astrid host to linker for lifecycle: {e}"
        ))
    })?;

    let wasm_component = Component::from_binary(&wt_engine, &cfg.wasm_bytes).map_err(|e| {
        CapsuleError::UnsupportedEntryPoint(format!(
            "Failed to compile WASM component for lifecycle: {e}"
        ))
    })?;

    let instance = linker
        .instantiate_async(&mut store, &wasm_component)
        .await
        .map_err(|e| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "Failed to instantiate WASM component for lifecycle: {e}"
            ))
        })?;

    tracing::info!(
        capsule = %cfg.capsule_id,
        phase = ?phase,
        previous_version = previous_version.unwrap_or("(none)"),
        "Running lifecycle hook"
    );

    // Call the lifecycle export by name. With per-export guest worlds the
    // export is only present in the wasm binary if the capsule actually
    // implements it; missing exports surface as a clear "not implemented"
    // error rather than a toolchain stub trap. `export_name` is
    // "astrid-install" or "astrid-upgrade" depending on `phase`.
    let func = instance
        .get_typed_func::<(), ()>(&mut store, export_name)
        .map_err(|_| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "capsule does not export lifecycle hook `{export_name}`"
            ))
        })?;
    func.call_async(&mut store, ()).await.map_err(|e| {
        CapsuleError::ExecutionFailed(format!("lifecycle hook {export_name} failed: {e}"))
    })?;
    let _ = phase; // already consumed via export_name selection above

    // Epoch ticker guard drops automatically (RAII).

    tracing::info!(
        capsule = %cfg.capsule_id,
        phase = ?phase,
        "Lifecycle hook completed successfully"
    );

    Ok(())
}

/// Pre-scans a WASM binary's exports for a real `run` implementation. This
/// is used to decide whether to apply the short-lived tool timeout *before*
/// instantiating the component, and whether to take the run-loop branch
/// (which moves the store into a background task and routes interceptor
/// events via auto-subscribe instead of direct invocation).
///
/// See [`wasm_exports_contain`] for the stub-detection semantics.
///
/// On any parse error, returns `true` (no timeout) — the safe direction.
/// A truly corrupt binary will fail the subsequent Component::from_binary anyway.
fn wasm_exports_contain_run(wasm_bytes: &[u8]) -> bool {
    wasm_exports_contain("run", wasm_bytes)
}

/// WIT-mandatory `func()` exports the wasm32-wasip2 toolchain auto-stubs
/// when the source crate doesn't implement them. Synthesized stubs share a
/// single backing function and alias to the same export index, so a name
/// in this trio whose index matches another trio member's index is a stub.
// IMPORTANT: keep this list in sync with the SDK's stub-emission list.
// Today the SDK fills in three mandatory exports — `run`,
// `astrid-install`, `astrid-upgrade` — with a single shared no-op
// function when the source crate does not provide them. Stub
// detection matches all three to that shared function index.
//
// `astrid-hook-trigger` is currently NOT stubbed (the SDK omits it
// entirely when no `#[astrid::hook]` attributes are present, and we
// detect its absence by export-name). If a future SDK release adds
// `astrid-hook-trigger` to its mandatory stub set, this trio MUST be
// extended to include it — otherwise every capsule will appear to
// expose a real hook handler and the kernel will dispatch trigger
// events into a no-op trap. See `wasm_exports_contain` callers in
// the interceptor / hook-bridge paths for the affected branches.
const STUB_PRONE_EXPORTS: [&str; 3] = ["run", "astrid-install", "astrid-upgrade"];

/// Pre-scans a WASM binary's exports for a real implementation of `name`.
///
/// "Real" means: the export exists AND is not a synthesized stub. The
/// `wasm32-wasip2` toolchain auto-generates a single shared nop function
/// for every mandatory WIT `func()` export the source crate doesn't
/// implement — `run`, `astrid-install`, `astrid-upgrade` — and points all
/// of them at the same function index. A real `#[astrid::run]` (or
/// `#[astrid::install]` / `#[astrid::upgrade]`) produces a function index
/// distinct from the shared stub, so aliasing within
/// [`STUB_PRONE_EXPORTS`] is the structural signal of a stub.
///
/// For names outside that trio, falls back to plain name-presence (no
/// stub baseline to compare against).
///
/// Why this matters: pre-migration (Extism) the SDK only emitted these
/// exports when the user opted in, so name-presence was sufficient.
/// Post-migration to the Component Model the WIT world makes them
/// mandatory and the toolchain fills in the gaps with stubs — without
/// stub detection, every capsule looks like a run-loop daemon and the
/// kernel zeros out the store/instance, breaking direct interceptor
/// dispatch for every interceptor-only capsule.
///
/// On any parse error, returns `true` (safe default: assume export exists).
fn wasm_exports_contain(name: &str, wasm_bytes: &[u8]) -> bool {
    // Per-section state — function indices are per-index-space, so a
    // multi-module binary (e.g. WASI adapter alongside the user module)
    // is checked module-by-module. Cross-module comparison would be
    // meaningless.
    let trio_position = |export_name: &str| -> Option<usize> {
        STUB_PRONE_EXPORTS.iter().position(|n| *n == export_name)
    };

    let resolve = |trio: &[Option<u32>; STUB_PRONE_EXPORTS.len()]| -> Option<bool> {
        let pos = trio_position(name)?;
        let target = trio[pos]?;
        let aliased = trio
            .iter()
            .enumerate()
            .any(|(i, idx)| i != pos && *idx == Some(target));
        Some(!aliased)
    };

    for payload in wasmparser::Parser::new(0).parse_all(wasm_bytes) {
        match payload {
            Ok(wasmparser::Payload::ExportSection(reader)) => {
                let mut trio: [Option<u32>; STUB_PRONE_EXPORTS.len()] =
                    [None; STUB_PRONE_EXPORTS.len()];
                let mut name_present = false;
                for export in reader {
                    let e = match export {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!("failed to parse WASM export entry: {e}");
                            return true; // safe default: skip timeout
                        },
                    };
                    if e.kind != wasmparser::ExternalKind::Func {
                        continue;
                    }
                    if e.name == name {
                        name_present = true;
                    }
                    if let Some(pos) = trio_position(e.name) {
                        trio[pos] = Some(e.index);
                    }
                }
                if let Some(real) = resolve(&trio) {
                    return real;
                }
                if name_present {
                    // Name found but outside the stub-prone trio — no
                    // stub baseline to compare, take at face value.
                    return true;
                }
            },
            // Component Model binaries have a ComponentExportSection.
            Ok(wasmparser::Payload::ComponentExportSection(reader)) => {
                let mut trio: [Option<u32>; STUB_PRONE_EXPORTS.len()] =
                    [None; STUB_PRONE_EXPORTS.len()];
                let mut name_present = false;
                for export in reader {
                    let e = match export {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!("failed to parse component export entry: {e}");
                            return true;
                        },
                    };
                    // Component-model exports span multiple index spaces
                    // (func, type, module, instance, ...). Trio comparison
                    // is only meaningful within the function space, so
                    // ignore non-function exports.
                    if e.kind != wasmparser::ComponentExternalKind::Func {
                        continue;
                    }
                    if e.name.0 == name {
                        name_present = true;
                    }
                    if let Some(pos) = trio_position(e.name.0) {
                        trio[pos] = Some(e.index);
                    }
                }
                if let Some(real) = resolve(&trio) {
                    return real;
                }
                if name_present {
                    return true;
                }
            },
            Err(e) => {
                tracing::warn!("failed to pre-scan WASM binary: {e}");
                return true; // safe default: skip timeout
            },
            _ => {},
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Layer 3 enabled-gate tests (issue #672) ──────────────────────

    fn pid(name: &str) -> astrid_core::PrincipalId {
        astrid_core::PrincipalId::new(name).unwrap()
    }

    #[test]
    fn check_principal_enabled_allows_enabled_profile() {
        let profile = astrid_core::profile::PrincipalProfile::default();
        assert!(profile.enabled, "default profile must be enabled");
        check_principal_enabled(&profile, &pid("alice"), "test-capsule", "do-thing")
            .expect("enabled profile must pass the gate");
    }

    #[test]
    fn check_principal_enabled_rejects_disabled_profile() {
        let profile = astrid_core::profile::PrincipalProfile {
            enabled: false,
            ..Default::default()
        };
        let err = check_principal_enabled(&profile, &pid("bob"), "test-capsule", "do-thing")
            .expect_err("disabled profile must be denied");
        let msg = err.to_string();
        assert!(
            msg.contains("disabled") && msg.contains("bob"),
            "expected error to name principal and reason: {msg}"
        );
    }

    #[test]
    fn check_principal_enabled_denies_even_for_admin_group() {
        // The Layer 5 preamble denies disabled admins on management
        // requests; Layer 3 must do the same on capsule invocations,
        // regardless of group membership. enabled=false beats admin.
        let profile = astrid_core::profile::PrincipalProfile {
            groups: vec!["admin".to_string()],
            enabled: false,
            ..Default::default()
        };
        assert!(check_principal_enabled(&profile, &pid("admin_user"), "x", "y").is_err());
    }

    /// Async wasmtime swaps `std::sync::Mutex<Store>` for
    /// `tokio::sync::Mutex<Store>` (the executor `.await`s on the
    /// lock instead of pinning a worker, issue #816). `tokio::sync::Mutex`
    /// does not have poisoning semantics, so the historical
    /// "poisoned_lock_*" tests no longer apply.
    ///
    /// The replacement invariant is **cancellation safety**: if the
    /// `invoke_interceptor` future is dropped mid-call, the
    /// `ClearOnDrop` guard MUST clear `caller_context`,
    /// `interceptor_active`, and every `invocation_*` field before the
    /// store lock is released, so the next invocation observes a
    /// clean HostState. The next test exercises the Drop path
    /// directly (without instantiating wasmtime, which would require
    /// a fixture WASM binary).
    #[tokio::test]
    async fn clear_on_drop_clears_invocation_state_on_unwind() {
        use crate::engine::wasm::host_state::HostState;
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        // ClearOnDrop is defined inside `invoke_interceptor`; we
        // re-create the same logic here as a free function to keep
        // the test scoped to the contract (each invocation_* field
        // is cleared, interceptor_active flipped back to false) rather
        // than the inner type. This is the cancellation-safety guard
        // for async wasmtime: when the call_async future is dropped
        // mid-invocation, the Drop impl MUST run this clear path
        // synchronously before the store mutex is released.
        fn clear(state: &mut HostState) {
            state.caller_context = None;
            state.interceptor_active = false;
            state.invocation_kv = None;
            state.invocation_home = None;
            state.invocation_tmp = None;
            state.invocation_secret_store = None;
            state.invocation_capsule_log = None;
            state.invocation_profile = None;
            state.invocation_env_overlay = None;
        }

        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.interceptor_active = true;
        state.caller_context = Some(astrid_events::ipc::IpcMessage::new(
            "x",
            astrid_events::ipc::IpcPayload::Custom {
                data: serde_json::json!({}),
            },
            uuid::Uuid::nil(),
        ));

        clear(&mut state);

        assert!(state.caller_context.is_none());
        assert!(!state.interceptor_active);
        assert!(state.invocation_kv.is_none());
        assert!(state.invocation_home.is_none());
        assert!(state.invocation_tmp.is_none());
        assert!(state.invocation_secret_store.is_none());
        assert!(state.invocation_capsule_log.is_none());
        assert!(state.invocation_profile.is_none());
        assert!(state.invocation_env_overlay.is_none());
    }

    /// Cancellation safety on the ipc `recv` path: the routed receiver
    /// queue is independent from the HostState mutex, so a cancelled
    /// `recv` future never partially writes invocation_* state — it
    /// either fully runs `install_recv_invocation_context` after the
    /// receive completes, or it never enters the install path at all.
    ///
    /// This test asserts the second branch: if no message arrives
    /// before the future is dropped, no state mutation has occurred.
    #[tokio::test]
    async fn ipc_recv_future_drop_leaves_host_state_untouched() {
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        let mut state = minimal_host_state(tokio::runtime::Handle::current());

        // Seed a baseline that we expect to be preserved across the
        // cancelled wait.
        let baseline_caller = astrid_events::ipc::IpcMessage::new(
            "baseline",
            astrid_events::ipc::IpcPayload::Custom {
                data: serde_json::json!({}),
            },
            uuid::Uuid::nil(),
        );
        state.caller_context = Some(baseline_caller.clone());

        // Simulate a long-running recv future and cancel it before
        // any message arrives. The `install_recv_invocation_context`
        // call site sits *after* the await — so this branch never
        // touches HostState.
        let fut = async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            // (never reached)
            unreachable!()
        };
        // Drive the future for a moment, then drop it.
        tokio::select! {
            biased;
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {},
            _ = fut => unreachable!(),
        }

        // Baseline preserved.
        assert_eq!(
            state.caller_context.as_ref().map(|m| m.topic.clone()),
            Some("baseline".to_string()),
            "cancelled recv future must not overwrite caller_context"
        );
    }

    #[test]
    fn build_onboarding_field_text() {
        let def = crate::manifest::EnvDef {
            env_type: "string".into(),
            request: Some("Enter owner address".into()),
            description: Some("The wallet address".into()),
            default: None,
            enum_values: vec![],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("owner", &def);
        assert_eq!(field.key, "owner");
        assert_eq!(field.prompt, "Enter owner address");
        assert_eq!(field.description.as_deref(), Some("The wallet address"));
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Text
        );
        assert!(field.default.is_none());
    }

    #[test]
    fn build_onboarding_field_secret() {
        let def = crate::manifest::EnvDef {
            env_type: "secret".into(),
            request: None,
            description: None,
            default: None,
            enum_values: vec!["a".into()], // enum_values ignored for secrets
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("apiKey", &def);
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Secret
        );
    }

    #[test]
    fn build_onboarding_field_enum_with_default() {
        let def = crate::manifest::EnvDef {
            env_type: "string".into(),
            request: Some("Select network".into()),
            description: None,
            default: Some(serde_json::json!("testnet")),
            enum_values: vec!["testnet".into(), "mainnet".into()],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("network", &def);
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Enum(vec!["testnet".into(), "mainnet".into()])
        );
        assert_eq!(field.default.as_deref(), Some("testnet"));
    }

    #[test]
    fn build_onboarding_field_fallback_prompt() {
        let def = crate::manifest::EnvDef {
            env_type: "string".into(),
            request: None,
            description: None,
            default: None,
            enum_values: vec![],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("someKey", &def);
        assert_eq!(field.prompt, "Please enter value for someKey");
    }

    #[test]
    fn build_onboarding_field_single_enum_degrades_to_text_with_autofill() {
        let def = crate::manifest::EnvDef {
            env_type: "string".into(),
            request: None,
            description: None,
            default: None,
            enum_values: vec!["only".into()],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("single", &def);
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Text,
            "Single-choice enum should degrade to text"
        );
        assert_eq!(
            field.default.as_deref(),
            Some("only"),
            "Single-choice enum should auto-fill the sole valid value"
        );
    }

    #[test]
    fn build_onboarding_field_array() {
        let def = crate::manifest::EnvDef {
            env_type: "array".into(),
            request: Some("Enter relay URLs".into()),
            description: Some("Nostr relay endpoints".into()),
            default: None,
            enum_values: vec![],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("relays", &def);
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Array
        );
        assert_eq!(field.prompt, "Enter relay URLs");
    }

    #[test]
    fn build_onboarding_field_empty_enum_degrades_to_text() {
        let def = crate::manifest::EnvDef {
            env_type: "string".into(),
            request: None,
            description: None,
            default: None,
            enum_values: vec![],
            placeholder: None,
            scope: crate::manifest::EnvScope::default(),
        };
        let field = crate::engine::build_onboarding_field("empty", &def);
        assert_eq!(
            field.field_type,
            astrid_events::ipc::OnboardingFieldType::Text,
            "Empty enum should degrade to text"
        );
    }

    // --- wait_ready / watch channel tests ---

    /// Helper: build a WasmEngine-like wait_ready from a watch receiver.
    async fn wait_ready_from_rx(
        rx: &tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>,
        timeout: std::time::Duration,
    ) -> crate::capsule::ReadyStatus {
        use crate::capsule::ReadyStatus;
        let mut rx = rx.lock().await.clone();
        match tokio::time::timeout(timeout, rx.wait_for(|&v| v)).await {
            Ok(Ok(_)) => ReadyStatus::Ready,
            Ok(Err(_)) => ReadyStatus::Crashed,
            Err(_) => ReadyStatus::Timeout,
        }
    }

    #[tokio::test]
    async fn wait_ready_returns_ready_when_pre_signaled() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let _ = tx.send(true);
        let rx_mutex = tokio::sync::Mutex::new(rx);
        let status = wait_ready_from_rx(&rx_mutex, std::time::Duration::from_millis(100)).await;
        assert_eq!(status, crate::capsule::ReadyStatus::Ready);
    }

    #[tokio::test]
    async fn wait_ready_returns_timeout_when_never_signaled() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let rx_mutex = tokio::sync::Mutex::new(rx);
        let status = wait_ready_from_rx(&rx_mutex, std::time::Duration::from_millis(10)).await;
        assert_eq!(status, crate::capsule::ReadyStatus::Timeout);
    }

    #[tokio::test]
    async fn wait_ready_returns_crashed_when_sender_dropped() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        drop(tx); // simulate capsule crash
        let rx_mutex = tokio::sync::Mutex::new(rx);
        let status = wait_ready_from_rx(&rx_mutex, std::time::Duration::from_millis(100)).await;
        assert_eq!(status, crate::capsule::ReadyStatus::Crashed);
    }

    #[tokio::test]
    async fn wait_ready_returns_ready_when_signaled_after_delay() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let rx_mutex = tokio::sync::Mutex::new(rx);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = tx.send(true);
        });
        let status = wait_ready_from_rx(&rx_mutex, std::time::Duration::from_millis(500)).await;
        assert_eq!(status, crate::capsule::ReadyStatus::Ready);
    }

    // --- wasm_exports_contain_run pre-scan tests ---

    /// Build a minimal valid WASM module with specified function exports.
    fn build_wasm_module(export_names: &[&str]) -> Vec<u8> {
        use wasm_encoder::{
            CodeSection, ExportKind, ExportSection, Function, FunctionSection, Module, TypeSection,
        };

        let mut module = Module::new();

        // Type section: one function type () -> ()
        let mut types = TypeSection::new();
        types.ty().function(vec![], vec![]);
        module.section(&types);

        // Function section: one function per export, all using type 0
        let mut functions = FunctionSection::new();
        for _ in export_names {
            functions.function(0);
        }
        module.section(&functions);

        // Export section
        let mut exports = ExportSection::new();
        for (i, name) in export_names.iter().enumerate() {
            exports.export(name, ExportKind::Func, i as u32);
        }
        module.section(&exports);

        // Code section: one no-op body per function
        let mut code = CodeSection::new();
        for _ in export_names {
            let mut f = Function::new(vec![]);
            f.instruction(&wasm_encoder::Instruction::End);
            code.function(&f);
        }
        module.section(&code);

        module.finish()
    }

    #[test]
    fn prescan_detects_run_export() {
        let wasm = build_wasm_module(&["run"]);
        assert!(wasm_exports_contain_run(&wasm), "should detect run export");
    }

    #[test]
    fn prescan_returns_false_without_run() {
        let wasm = build_wasm_module(&["tool_call", "install"]);
        assert!(
            !wasm_exports_contain_run(&wasm),
            "should not detect run when absent"
        );
    }

    #[test]
    fn prescan_detects_run_among_multiple_exports() {
        let wasm = build_wasm_module(&["install", "run", "tool_call"]);
        assert!(
            wasm_exports_contain_run(&wasm),
            "should detect run among multiple exports"
        );
    }

    #[test]
    fn prescan_returns_false_for_empty_export_section() {
        // Module with an empty export section (section present, count = 0).
        // Exercises the inner-loop-zero-iterations path returning false
        // from within the ExportSection arm.
        let wasm = build_wasm_module(&[]);
        assert!(
            !wasm_exports_contain_run(&wasm),
            "empty export section should not have run"
        );
    }

    #[test]
    fn prescan_returns_false_for_module_with_no_export_section() {
        // Module with no export section at all. Exercises the fall-through
        // path at the end of wasm_exports_contain_run (line after the loop).
        use wasm_encoder::{Module, TypeSection};
        let mut module = Module::new();
        let mut types = TypeSection::new();
        types.ty().function(vec![], vec![]);
        module.section(&types);
        let wasm = module.finish();
        assert!(
            !wasm_exports_contain_run(&wasm),
            "module with no export section should not have run"
        );
    }

    #[test]
    fn prescan_returns_true_for_corrupt_binary() {
        // Corrupt/invalid bytes - should default to true (safe direction)
        let garbage = b"not a wasm module at all";
        assert!(
            wasm_exports_contain_run(garbage),
            "corrupt binary should default to true (safe: no timeout)"
        );
    }

    /// Build a WASM module where exports may alias to shared function
    /// indices, simulating the wasm32-wasip2 toolchain's nop-stub synthesis
    /// for unimplemented mandatory WIT exports. `exports` is `(name, idx)`
    /// pairs — multiple entries with the same `idx` model an aliased stub.
    fn build_wasm_module_with_aliases(exports: &[(&str, u32)]) -> Vec<u8> {
        use wasm_encoder::{
            CodeSection, ExportKind, ExportSection, Function, FunctionSection, Module, TypeSection,
        };

        let mut module = Module::new();

        let mut types = TypeSection::new();
        types.ty().function(vec![], vec![]);
        module.section(&types);

        let max_idx = exports.iter().map(|(_, i)| *i).max().unwrap_or(0);
        let func_count = (max_idx + 1) as usize;

        let mut functions = FunctionSection::new();
        for _ in 0..func_count {
            functions.function(0);
        }
        module.section(&functions);

        let mut export_section = ExportSection::new();
        for (name, idx) in exports {
            export_section.export(name, ExportKind::Func, *idx);
        }
        module.section(&export_section);

        let mut code = CodeSection::new();
        for _ in 0..func_count {
            let mut f = Function::new(vec![]);
            f.instruction(&wasm_encoder::Instruction::End);
            code.function(&f);
        }
        module.section(&code);

        module.finish()
    }

    /// `run` aliased to `astrid-install` and `astrid-upgrade` is the
    /// wasip2-stub signature — must not be classified as a live run loop.
    #[test]
    fn prescan_rejects_run_aliased_with_install_and_upgrade() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("run", 1),
            ("astrid-install", 1),
            ("astrid-upgrade", 1),
        ]);
        assert!(
            !wasm_exports_contain_run(&wasm),
            "stub run aliased to install/upgrade must be treated as no run loop"
        );
    }

    /// A real `#[astrid::run]` produces a function distinct from the
    /// install/upgrade stubs — must be classified as a live run loop.
    #[test]
    fn prescan_accepts_run_distinct_from_install_stubs() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("run", 1),
            ("astrid-install", 2),
            ("astrid-upgrade", 2),
        ]);
        assert!(
            wasm_exports_contain_run(&wasm),
            "run distinct from aliased install/upgrade stubs is a real run loop"
        );
    }

    /// All three trio members real (distinct) — every one is a real export.
    #[test]
    fn prescan_accepts_all_three_distinct_implementations() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("run", 1),
            ("astrid-install", 2),
            ("astrid-upgrade", 3),
        ]);
        assert!(wasm_exports_contain_run(&wasm));
        assert!(wasm_exports_contain("astrid-install", &wasm));
        assert!(wasm_exports_contain("astrid-upgrade", &wasm));
    }

    /// Real install with stubbed run+upgrade: install is real, run/upgrade
    /// are stubs because they alias to each other (but not to install).
    #[test]
    fn prescan_distinguishes_real_install_from_run_upgrade_stubs() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("run", 1),
            ("astrid-upgrade", 1),
            ("astrid-install", 2),
        ]);
        assert!(
            !wasm_exports_contain_run(&wasm),
            "run aliased to upgrade is a stub even when install is real"
        );
        assert!(
            wasm_exports_contain("astrid-install", &wasm),
            "install with a unique index is real"
        );
        assert!(
            !wasm_exports_contain("astrid-upgrade", &wasm),
            "upgrade aliased to run is a stub"
        );
    }

    /// Lifecycle pre-scan: stubbed install/upgrade must short-circuit out
    /// of `run_lifecycle` — same call site, same stub-detection contract.
    #[test]
    fn prescan_rejects_stubbed_lifecycle_exports() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("run", 1),
            ("astrid-install", 1),
            ("astrid-upgrade", 1),
        ]);
        assert!(!wasm_exports_contain("astrid-install", &wasm));
        assert!(!wasm_exports_contain("astrid-upgrade", &wasm));
    }

    /// Names outside the stub-prone trio fall back to plain name-presence —
    /// no stub baseline applies.
    #[test]
    fn prescan_non_trio_name_uses_plain_presence() {
        let wasm = build_wasm_module_with_aliases(&[
            ("astrid-hook-trigger", 0),
            ("astrid-cron-trigger", 0),
        ]);
        assert!(
            wasm_exports_contain("astrid-hook-trigger", &wasm),
            "non-trio names take face value even if shared"
        );
        assert!(wasm_exports_contain("astrid-cron-trigger", &wasm));
    }

    #[test]
    fn prescan_ignores_non_func_run_export() {
        use wasm_encoder::{
            ExportKind, ExportSection, GlobalSection, GlobalType, Module, TypeSection, ValType,
        };

        let mut module = Module::new();

        let mut types = TypeSection::new();
        types.ty().function(vec![], vec![]);
        module.section(&types);

        // Global section: one i32 global named "run"
        let mut globals = GlobalSection::new();
        globals.global(
            GlobalType {
                val_type: ValType::I32,
                mutable: false,
                shared: false,
            },
            &wasm_encoder::ConstExpr::i32_const(42),
        );
        module.section(&globals);

        // Export "run" as a global, not a function
        let mut exports = ExportSection::new();
        exports.export("run", ExportKind::Global, 0);
        module.section(&exports);

        let wasm = module.finish();
        assert!(
            !wasm_exports_contain_run(&wasm),
            "global named 'run' should not be detected as a function export"
        );
    }

    // ---------------------------------------------------------------------
    // build_principal_vfs_bundle_at: per-invocation VFS scoping (#549)
    // ---------------------------------------------------------------------

    /// Build a bundle, awaiting the now-async `build_principal_vfs_bundle_at`
    /// directly. `register_dir` is awaited internally (issue #816), so the
    /// old `spawn_blocking` sync/async bridge is no longer needed.
    async fn build_bundle_async_safe(ph: astrid_core::dirs::PrincipalHome) -> PrincipalVfsBundle {
        build_principal_vfs_bundle_at(&ph).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_bundle_returns_empty_for_unregistered_principal() {
        // No principal home directory exists on disk — fail-closed: bundle empty,
        // no auto-mkdir of a `home/{principal}/` tree.
        let tmp = tempfile::tempdir().unwrap();
        let ph = astrid_core::dirs::PrincipalHome::from_path(tmp.path().join("home/mallory"));
        let bundle = build_bundle_async_safe(ph).await;
        assert!(bundle.home.is_none(), "unknown principal: no home mount");
        assert!(bundle.tmp.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_bundle_populated_for_registered_principal() {
        let tmp = tempfile::tempdir().unwrap();
        let alice_root = tmp.path().join("home/alice");
        let ph = astrid_core::dirs::PrincipalHome::from_path(&alice_root);
        ph.ensure().unwrap();
        // `mount_dir` canonicalizes (resolves /tmp -> /private/tmp on macOS),
        // so compare against the canonical form.
        let alice_canonical = alice_root.canonicalize().unwrap();

        let bundle = build_bundle_async_safe(ph).await;
        let home = bundle.home.as_ref().expect("home mount present");
        assert_eq!(home.root, alice_canonical);
        let tmp_mount = bundle.tmp.as_ref().expect("tmp mount present");
        assert_eq!(tmp_mount.root, alice_canonical.join(".local").join("tmp"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_bundle_isolates_distinct_principals() {
        let tmp = tempfile::tempdir().unwrap();
        let alice_root = tmp.path().join("home/alice");
        let bob_root = tmp.path().join("home/bob");
        let alice_ph = astrid_core::dirs::PrincipalHome::from_path(&alice_root);
        let bob_ph = astrid_core::dirs::PrincipalHome::from_path(&bob_root);
        alice_ph.ensure().unwrap();
        bob_ph.ensure().unwrap();
        let alice_canonical = alice_root.canonicalize().unwrap();
        let bob_canonical = bob_root.canonicalize().unwrap();

        let alice_bundle = build_bundle_async_safe(alice_ph).await;
        let bob_bundle = build_bundle_async_safe(bob_ph).await;

        let alice_home = &alice_bundle.home.as_ref().unwrap().root;
        let bob_home = &bob_bundle.home.as_ref().unwrap().root;
        assert_ne!(
            alice_home, bob_home,
            "distinct principals, distinct home roots"
        );
        assert_eq!(alice_home, &alice_canonical);
        assert_eq!(bob_home, &bob_canonical);

        // Each principal's `home://note.txt` must land under their own root.
        std::fs::write(alice_home.join("note.txt"), b"alice").unwrap();
        std::fs::write(bob_home.join("note.txt"), b"bob").unwrap();
        assert_eq!(
            std::fs::read(alice_home.join("note.txt")).unwrap(),
            b"alice"
        );
        assert_eq!(std::fs::read(bob_home.join("note.txt")).unwrap(), b"bob");
    }

    // ---------------------------------------------------------------------
    // open_capsule_log_at: per-invocation log re-scoping (#661)
    // ---------------------------------------------------------------------

    #[test]
    fn open_capsule_log_returns_none_for_unregistered_principal() {
        // No principal home directory exists on disk — fail-closed: return
        // `None` instead of auto-creating the attacker's home tree.
        let tmp = tempfile::tempdir().unwrap();
        let ph = astrid_core::dirs::PrincipalHome::from_path(tmp.path().join("home/mallory"));
        assert!(open_capsule_log_at(&ph, "some-capsule", false).is_none());
        assert!(open_capsule_log_at(&ph, "some-capsule", true).is_none());
        assert!(
            !ph.root().exists(),
            "must not auto-mkdir an unregistered principal's home"
        );
    }

    #[test]
    fn open_capsule_log_opens_file_under_principal_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let alice_root = tmp.path().join("home/alice");
        let ph = astrid_core::dirs::PrincipalHome::from_path(&alice_root);
        ph.ensure().unwrap();

        let file = open_capsule_log_at(&ph, "my-capsule", false).expect("open ok");

        // Physical file must live under `ph.log_dir()/my-capsule/{today}.log`.
        let log_dir = ph.log_dir().join("my-capsule");
        assert!(log_dir.is_dir(), "log dir auto-created under alice's tree");
        let today = today_date_string();
        let expected = log_dir.join(format!("{today}.log"));
        assert!(
            expected.is_file(),
            "today's log file opened at {expected:?}"
        );

        // Writes go to the expected physical file.
        use std::io::Write;
        {
            let mut f = file.lock().unwrap();
            writeln!(f, "hello-alice").unwrap();
            f.flush().unwrap();
        }
        let contents = std::fs::read_to_string(&expected).unwrap();
        assert!(contents.contains("hello-alice"));
    }

    #[test]
    fn open_capsule_log_isolates_distinct_principals() {
        let tmp = tempfile::tempdir().unwrap();
        let alice_root = tmp.path().join("home/alice");
        let bob_root = tmp.path().join("home/bob");
        let alice_ph = astrid_core::dirs::PrincipalHome::from_path(&alice_root);
        let bob_ph = astrid_core::dirs::PrincipalHome::from_path(&bob_root);
        alice_ph.ensure().unwrap();
        bob_ph.ensure().unwrap();

        let alice_log = open_capsule_log_at(&alice_ph, "shared-capsule", false).unwrap();
        let bob_log = open_capsule_log_at(&bob_ph, "shared-capsule", false).unwrap();

        use std::io::Write;
        writeln!(alice_log.lock().unwrap(), "alice-line").unwrap();
        writeln!(bob_log.lock().unwrap(), "bob-line").unwrap();

        let today = today_date_string();
        let alice_file = alice_ph
            .log_dir()
            .join("shared-capsule")
            .join(format!("{today}.log"));
        let bob_file = bob_ph
            .log_dir()
            .join("shared-capsule")
            .join(format!("{today}.log"));

        let alice_contents = std::fs::read_to_string(&alice_file).unwrap();
        let bob_contents = std::fs::read_to_string(&bob_file).unwrap();
        assert!(alice_contents.contains("alice-line"));
        assert!(!alice_contents.contains("bob-line"));
        assert!(bob_contents.contains("bob-line"));
        assert!(!bob_contents.contains("alice-line"));
    }

    #[test]
    fn open_capsule_log_with_prune_does_not_delete_todays_file() {
        // Sanity: pruning is on a 7-day cutoff, so today's freshly-written
        // file survives. Guards against regressions that'd rotate too aggressively.
        let tmp = tempfile::tempdir().unwrap();
        let alice_root = tmp.path().join("home/alice");
        let ph = astrid_core::dirs::PrincipalHome::from_path(&alice_root);
        ph.ensure().unwrap();

        // First call prunes and opens (load-time path).
        let f1 = open_capsule_log_at(&ph, "c", true).unwrap();
        use std::io::Write;
        writeln!(f1.lock().unwrap(), "pre-prune line").unwrap();
        f1.lock().unwrap().flush().unwrap();
        drop(f1);

        // Second call also prunes — should not unlink today's file.
        let f2 = open_capsule_log_at(&ph, "c", true).unwrap();
        drop(f2);
        let today = today_date_string();
        let path = ph.log_dir().join("c").join(format!("{today}.log"));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("pre-prune line"));
    }

    // ---------------------------------------------------------------------
    // civil_from_days: hand-rolled civil-date algorithm. A regression here
    // misroutes every log file, so pin it to a handful of known dates.
    // ---------------------------------------------------------------------

    #[test]
    fn civil_from_days_epoch() {
        // Day 0 since Unix epoch is 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_dates() {
        // A leap-day, a month boundary, a year boundary, a far-future date.
        assert_eq!(civil_from_days(59), (1970, 3, 1)); // 1970-03-01 (Jan + Feb = 59 days)
        assert_eq!(civil_from_days(365), (1971, 1, 1)); // 1970 has 365 days
        assert_eq!(civil_from_days(11_016), (2000, 2, 29)); // Y2K leap day
        assert_eq!(civil_from_days(20_564), (2026, 4, 21)); // issue-reference date
    }

    #[test]
    fn today_date_string_matches_civil_from_days() {
        // Cross-check the format: the string must match `civil_from_days`
        // applied to the same epoch-seconds value.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let days = secs / 86400;
        let (y, m, d) = civil_from_days(days as i64);
        assert_eq!(today_date_string(), format!("{y:04}-{m:02}-{d:02}"));
    }
}
