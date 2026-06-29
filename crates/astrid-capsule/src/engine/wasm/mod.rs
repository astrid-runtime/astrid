use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;
use wasmtime::Store;
use wasmtime::component::{Component, Linker};

use crate::context::CapsuleContext;
use crate::engine::ExecutionEngine;
use crate::engine::wasm::host_state::{
    ConnectionIdentity, HostState, LifecyclePhase, PrincipalMount,
};
use crate::error::{CapsuleError, CapsuleResult};
use crate::manifest::CapsuleManifest;

#[allow(unreachable_pub)]
pub(crate) mod bindings;
pub mod host;
pub mod host_state;
pub mod limits;
mod pool;
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
    /// Pool of `(Store, Instance)` pairs for a non-run-loop capsule.
    ///
    /// `invoke_interceptor` leases a free instance per call, so N principals'
    /// interceptors run concurrently instead of serialising through one Store
    /// (the throughput floor behind `astrid#813`; see `astrid#816` and
    /// [`pool`]). `None` for run-loop capsules — they keep one dedicated
    /// Store owned by `run_handle` and never go through this pool. The pool is
    /// dynamic: it warm-starts at `min_idle`, grows lazily toward the
    /// host-derived (operator-overridable) `instance_pool_size` max under load,
    /// and idle-evicts back down. Capsules carved out via the `host_process`
    /// capability are pinned to a single Store (live cross-invocation resource
    /// handles must never move to a second Store).
    pool: Option<pool::CapsuleInstancePool>,
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
    /// Per-principal accumulated interceptor CPU, in wasmtime fuel units
    /// (exact deterministic guest-instruction count).
    ///
    /// `invoke_interceptor` reads `get_fuel` before/after each guest call and
    /// charges the delta to the invoking principal. This is the measurement
    /// hook the operator question ("who is burning CPU?") needs — it feeds the
    /// per-invocation `astrid.sample` span today and `astrid top` (#66) later.
    ///
    /// **Shared, cross-capsule.** This handle is cloned from the kernel-owned
    /// [`FuelLedger`](crate::FuelLedger), so a principal's CPU is summed across
    /// *every* capsule it drives into one per-principal total — the
    /// prerequisite for a per-principal CPU budget. (It used to be a per-engine
    /// `HashMap`, which fragmented the same principal into N per-capsule
    /// sub-totals.) The ledger is sharded + atomic, never a single mutex, so it
    /// does not re-serialise the hot interceptor path (astrid#813/#817).
    ///
    /// TELEMETRY ONLY today: the windowed/decaying deny/throttle that consumes
    /// this aggregate is the deliberate FOLLOW-UP. The run-loop CPU bound stays
    /// enforced by the epoch-interrupt mechanism (not this ledger, not fuel).
    /// Keyed by the *invoking* principal (caller or owner).
    fuel_ledger: crate::FuelLedger,
    /// Shared per-principal **peak-memory** ledger, the RAM analogue of
    /// `fuel_ledger`: the per-Store [`StoreMemoryMeter`](crate::StoreMemoryMeter)
    /// records the high-water linear-memory size each invoking principal grows a
    /// Store to. Cloned from the kernel-owned ledger so a principal's peak is the
    /// max across every capsule it drives, filling
    /// `ResourceUsage::memory_bytes_peak_total`. Telemetry only.
    memory_ledger: crate::MemoryLedger,
    /// Shared per-principal CPU-**rate** limiter — the deny side of the budget
    /// (PR2), built on the same shared-handle model as `fuel_ledger`.
    ///
    /// `invoke_interceptor` consults [`over_budget`](
    /// crate::FuelRateLimiter::over_budget) BEFORE checking out a pooled
    /// instance, and feeds the exact post-hoc fuel via [`record`](
    /// crate::FuelRateLimiter::record) right after `fuel_ledger.charge`. Cloned
    /// from the kernel-owned limiter so a principal's 1-second CPU rate is
    /// throttled cross-capsule, not per-capsule. Keyed by the *invoking*
    /// principal (caller or owner), same as the ledger.
    ///
    /// Fail-OPEN on the window math (non-poisoning `parking_lot` + saturating
    /// arithmetic); the orthogonal exemption decision fails CLOSED.
    fuel_rate: crate::FuelRateLimiter,
    /// Live group config from [`CapsuleContext`].
    ///
    /// `invoke_interceptor` loads this for [`resolve_exemption`] so the CPU-rate
    /// deny gate observes runtime group mutations. `None` in tests /
    /// single-tenant => no exemption resolvable => the invoking principal is
    /// bounded (fail-secure), but still under the generous default budget.
    group_config: Option<Arc<ArcSwap<astrid_core::GroupConfig>>>,
    /// Host-derived (operator-overridable) concurrency ceilings for this
    /// capsule's host calls. Resolved once by the daemon and handed down the
    /// loader chain like the fuel handles; sizes the per-instance
    /// `blocking_semaphore` / `io_semaphore` at load time. `Default` (all
    /// host-derived) in tests.
    runtime_limits: limits::CapsuleRuntimeLimits,
    /// Resolved operator ceilings for the `astrid:http` host. A GLOBAL value
    /// (same for every capsule), resolved once by the daemon from the `[http]`
    /// config section and handed down the loader chain like `runtime_limits`;
    /// snapshotted onto every pooled `HostState` at load. `Default` (the host's
    /// historical constants) in tests.
    http_limits: limits::HttpLimits,
}

impl WasmEngine {
    /// Construct a WASM engine for one capsule.
    ///
    /// `fuel_ledger` is the kernel-owned, shared per-principal CPU ledger; the
    /// kernel passes the *same* handle to every capsule's engine so per-principal
    /// CPU is aggregated cross-capsule. Tests that don't care about aggregation
    /// pass `FuelLedger::default()` for an isolated ledger.
    ///
    /// `fuel_rate` is the matching kernel-owned, shared per-principal CPU-rate
    /// limiter (the deny side); pass `FuelRateLimiter::default()` for an
    /// isolated limiter in tests.
    ///
    /// `runtime_limits` is the host-derived (operator-overridable) concurrency
    /// ceiling pair the daemon resolves once and hands to every engine; pass
    /// [`CapsuleRuntimeLimits::default`](limits::CapsuleRuntimeLimits::default)
    /// for all-host-derived sizing in tests.
    ///
    /// `http_limits` is the resolved `astrid:http` host ceilings (timeouts,
    /// redirect/stream caps, buffered-body limit) from the `[http]` config
    /// section — a global value, the same for every engine; pass
    /// [`HttpLimits::default`](limits::HttpLimits::default) for the host's
    /// historical constants in tests.
    pub fn new(
        manifest: CapsuleManifest,
        capsule_dir: PathBuf,
        fuel_ledger: crate::FuelLedger,
        fuel_rate: crate::FuelRateLimiter,
        memory_ledger: crate::MemoryLedger,
        runtime_limits: limits::CapsuleRuntimeLimits,
        http_limits: limits::HttpLimits,
    ) -> Self {
        Self {
            manifest,
            _capsule_dir: capsule_dir,
            wasmtime_engine: None,
            pool: None,
            inbound_rx: None,
            run_handle: None,
            ready_rx: None,
            cancel_token: None,
            epoch_ticker: None,
            profile_cache: None,
            owner_principal: None,
            overlay_registry: None,
            fuel_ledger,
            memory_ledger,
            fuel_rate,
            group_config: None,
            runtime_limits,
            http_limits,
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

/// Default length (epoch ticks) of a bound run-loop's epoch deadline window
/// when the owner profile does not pin a tighter timeout.
///
/// One tick is [`EPOCH_TICK_INTERVAL`] (100 ms), so the default ~5 s window is
/// `5000 / 100 = 50` ticks. Each window the bound run-loop's
/// `epoch_deadline_callback` fires: a recv/accept loop (which set
/// `recv_yielded` since the last window) is re-extended and cooperatively
/// yields the tokio worker; a no-recv spinner accrues `no_yield_windows` and
/// is interrupt-trapped once it reaches [`MAX_NO_YIELD_WINDOWS`]. The window
/// is derived per-capsule from the owner quota `max_timeout_secs` (clamped to
/// this default) in [`resolve_run_loop_budget`]; this const is the fail-safe.
const DEFAULT_RUN_LOOP_WINDOW_TICKS: u64 = 50;

/// Number of consecutive windows a bound run-loop may burn CPU **without**
/// calling `recv` (i.e. without setting `recv_yielded`) before its epoch
/// callback returns [`UpdateDeadline::Interrupt`](wasmtime::UpdateDeadline) and
/// traps the guest.
///
/// A legitimate run loop calls `recv` every iteration, so it resets the
/// counter every window and is never trapped. A pure `loop {}` (or any
/// no-recv burner) never resets it and is interrupt-trapped after this many
/// windows. With the default window (~5 s) this is a ~15 s grace before a
/// runaway is killed — generous enough to never catch a healthy capsule, tight
/// enough to bound a genuine spinner.
const MAX_NO_YIELD_WINDOWS: u32 = 3;

/// Per-single-invocation fuel budget for a pooled interceptor call (10e9).
///
/// This is the per-invocation CPU **measurement** seed, NOT the run-loop CPU
/// bound (that is the epoch mechanism). `invoke_interceptor` re-seeds the
/// leased Store to this budget before the call and reads `get_fuel()` after;
/// `INTERCEPTOR_FUEL_BUDGET - get_fuel()` is the exact deterministic
/// guest-instruction count for the call, accumulated into the per-principal
/// `fuel_ledger`. The budget sits far above any legitimate one-prompt cost (a
/// prompt assembly is low-millions of instructions), so it also caps a runaway
/// single interceptor call. Because fuel is engine-wide, re-seeding per call
/// means one leaseholder cannot drain a pooled Store for the next.
const INTERCEPTOR_FUEL_BUDGET: u64 = 10_000_000_000;

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

/// Result returned by a guest `astrid-hook-trigger` export.
///
/// This is the Astrid-owned public wrapper around the generated
/// `astrid:guest/lifecycle.capsule-result` binding. The generated binding stays
/// private so Wasmtime bindgen changes do not become `astrid-capsule` API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookTriggerOutput {
    /// Hook action returned by the capsule.
    pub action: String,
    /// Optional hook payload returned by the capsule.
    pub data: Option<String>,
}

/// Call a component's `astrid-hook-trigger` export using the private generated
/// lifecycle binding.
///
/// # Errors
///
/// Returns an error if the export is missing or the guest call traps/fails.
pub fn call_hook_trigger(
    instance: &wasmtime::component::Instance,
    store: &mut wasmtime::Store<HostState>,
    function: &str,
    input_bytes: Vec<u8>,
) -> CapsuleResult<HookTriggerOutput> {
    type HookTriggerResult = bindings::astrid::guest::lifecycle::CapsuleResult;

    let func = instance
        .get_typed_func::<(String, Vec<u8>), (HookTriggerResult,)>(
            &mut *store,
            "astrid-hook-trigger",
        )
        .map_err(|e| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "capsule does not export `astrid-hook-trigger`: {e}"
            ))
        })?;

    func.call(store, (function.to_owned(), input_bytes))
        .map(|(cr,)| HookTriggerOutput {
            action: cr.action,
            data: cr.data,
        })
        .map_err(|e| CapsuleError::WasmError(format!("astrid-hook-trigger call failed: {e}")))
}

fn build_wasmtime_engine() -> CapsuleResult<wasmtime::Engine> {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true).epoch_interruption(true);
    // Fuel metering is the per-invocation CPU MEASUREMENT only (not the
    // run-loop CPU bound — that is the epoch mechanism below). Fuel counts
    // EXECUTED guest instructions independent of host-call yields, so
    // `get_fuel` before/after an interceptor call yields the exact
    // deterministic instruction count for that call, attributed to the
    // invoking principal in the per-principal fuel ledger. Enabling it
    // engine-wide means EVERY Store starts at 0 fuel and would trap on the
    // first instruction, so every Store-creation site below explicitly fuels
    // its store: interceptor pools are re-seeded to INTERCEPTOR_FUEL_BUDGET
    // per call, and run-loop / lifecycle Stores (whose CPU is bounded by the
    // epoch interrupt or are exempt) are fuelled to u64::MAX so fuel never
    // traps them. consume_fuel is incompatible with Winch; this build uses
    // cranelift (Cargo.toml feature), so it is supported.
    config.consume_fuel(true);
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

/// Resolved per-principal resource bound for a capsule's run-loop Store.
///
/// Computed once at load time by [`resolve_run_loop_budget`] and consumed by
/// both `make_state` (memory cap, baked into `StoreLimits` *before*
/// instantiation) and the run-loop Store setup (epoch deadline + interrupt
/// callback). Stores that are not bound run-loops (interceptor pools,
/// daemons, exempt run-loops) carry the placeholder defaults; the real
/// per-invocation interceptor caps are applied separately at invoke time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunLoopBudget {
    /// Whether this capsule's run-loop runs UNBOUNDED — the owner holds
    /// [`CAP_RESOURCES_UNBOUNDED`](astrid_core::CAP_RESOURCES_UNBOUNDED), the
    /// operator-granted [`CAP_NET_BIND`](astrid_core::CAP_NET_BIND) /
    /// [`CAP_UPLINK`](astrid_core::CAP_UPLINK) capability (admin holds all via
    /// `*`). Exempt Stores are never epoch-interrupt-trapped.
    exempt: bool,
    /// Whether this capsule is a bound (non-exempt) run-loop — the only class
    /// that gets the epoch interrupt callback + memory cap. When `false`,
    /// `window_ticks`/`mem_bytes` are placeholders the caller ignores for
    /// non-run-loop Stores.
    bound_run_loop: bool,
    /// Epoch deadline window, in [`EPOCH_TICK_INTERVAL`] ticks, for a bound
    /// run-loop. `None` for exempt/non-run-loop. The run-loop Store's epoch
    /// callback fires every `window_ticks` and re-arms the deadline to the
    /// same value (see [`epoch_decision`]).
    window_ticks: Option<u64>,
    /// Linear-memory ceiling for the run-loop Store (owner quota for a bound
    /// run-loop, [`WASM_MAX_MEMORY_BYTES`] otherwise).
    mem_bytes: usize,
}

/// Pure decision: does this load principal's profile exempt its capsule's
/// run-loop from the per-principal CPU+memory bound?
///
/// Exemption is purely **capability-driven**, resolved through the permission
/// system (groups → grants → revokes) against the owner principal's profile:
/// a holder of any capability in the shared
/// [`EXEMPT_CAPABILITIES`](astrid_core::EXEMPT_CAPABILITIES) list
/// ([`CAP_RESOURCES_UNBOUNDED`](astrid_core::CAP_RESOURCES_UNBOUNDED),
/// [`CAP_NET_BIND`](astrid_core::CAP_NET_BIND),
/// [`CAP_UPLINK`](astrid_core::CAP_UPLINK)) is exempt. admin holds all of them
/// via `*`, with no special-case group-name match. The kernel's read-path
/// mirror (`astrid quota`'s usage report) iterates the same list, so the
/// enforced and displayed answers cannot drift. The capsule-authored manifest
/// (`is_daemon` / `net_bind` / `uplink`) plays **no** part — a capsule cannot
/// self-exempt: it chooses neither its load principal nor its operator-owned
/// profile capabilities.
///
/// FAIL-SECURE: any missing input (no profile, no group config) → `false`
/// (bounded), never exempt. No I/O, no locking — the caller resolves the
/// profile + group snapshot beforehand, so this is unit-testable without
/// wasmtime.
pub(crate) fn resolve_exemption(
    owner_profile: Option<&astrid_core::profile::PrincipalProfile>,
    group_config: Option<&astrid_core::GroupConfig>,
    principal: &astrid_core::PrincipalId,
) -> bool {
    let (Some(profile), Some(groups)) = (owner_profile, group_config) else {
        // Fail-secure: an unidentifiable principal or an unthreaded group
        // config is NEVER exempt.
        return false;
    };
    let check = astrid_capabilities::CapabilityCheck::new(profile, groups, principal.clone());
    astrid_core::EXEMPT_CAPABILITIES
        .iter()
        .any(|&cap| check.has(cap))
}

/// The single catalogued, enforced audit-firehose capability. Holding it
/// grants the unscoped, cross-principal audit feed (every principal's
/// `astrid.v1.audit.entry` events); without it an audit subscription is
/// route-scoped to the subscriber's own principal.
///
/// This is the SAME string the gateway SSE firehose gates on
/// (`astrid-gateway`'s `events::AUDIT_FIREHOSE_CAP`) and the same one
/// catalogued in `astrid-core`'s capability grammar (scope Global, danger
/// Elevated). A capsule-local literal keeps the kernel/capsule dependency
/// boundary clean (the capsule must not reach into the gateway or grow the
/// core grammar surface for one internal reference); the value is pinned by
/// [`tests::audit_firehose_cap_literal_pinned`].
const AUDIT_FIREHOSE_CAP: &str = "audit:read_all";

/// Pure decision: does this load principal's profile hold the audit
/// firehose capability ([`AUDIT_FIREHOSE_CAP`])?
///
/// Resolved the PRIVILEGED way — the SAME permission-system path as
/// [`resolve_exemption`] (groups → grants → revokes against the owner
/// principal's profile + the live group config), NEVER from the
/// capsule-authored manifest. This is the load-bearing distinction from
/// [`HostState::has_uplink_capability`](crate::engine::wasm::host_state::HostState::has_uplink_capability),
/// which IS read straight off `manifest.capabilities.uplink`: the firehose
/// must not be a thing a capsule can self-grant in its own `Capsule.toml`.
/// admin holds it via `*`; revokes win over grants.
///
/// FAIL-SECURE: any missing input (no owner profile in tests / single-tenant,
/// or an unthreaded group config) → `false`, i.e. own-principal-only audit
/// scoping — the SECURE default — exactly as [`resolve_exemption`] fails
/// closed to bounded. No I/O, no locking: unit-testable without wasmtime.
pub(crate) fn resolve_audit_firehose(
    owner_profile: Option<&astrid_core::profile::PrincipalProfile>,
    group_config: Option<&astrid_core::GroupConfig>,
    principal: &astrid_core::PrincipalId,
) -> bool {
    let (Some(profile), Some(groups)) = (owner_profile, group_config) else {
        // Fail-secure: an unidentifiable principal or an unthreaded group
        // config NEVER gets the firehose — the audit subscription stays
        // scoped to the owner principal.
        return false;
    };
    astrid_capabilities::CapabilityCheck::new(profile, groups, principal.clone())
        .has(AUDIT_FIREHOSE_CAP)
}

/// The per-principal CPU-rate DENY decision, factored out of
/// `invoke_interceptor` so the production path and the unit tests run the
/// *exact same* function (no copies — same discipline as
/// [`resolve_run_loop_budget`]).
///
/// Returns `Some(reason)` when this invocation must be denied (the caller wraps
/// it in `Ok(InterceptResult::Deny { reason })`, NEVER `Err` — see the call
/// site), or `None` to admit. The decision composes the two orthogonal axes:
///
/// - **Exemption (fails CLOSED).** [`resolve_exemption`] returns `false`
///   (bounded) on any missing input, so an unidentifiable principal is gated;
///   the holders it exempts (unbounded / net_bind / uplink; admin via `*`) are
///   never denied here.
/// - **Budget.** `invocation_profile`'s `max_cpu_fuel_per_sec`, or
///   [`DEFAULT_MAX_CPU_FUEL_PER_SEC`](astrid_core::profile::DEFAULT_MAX_CPU_FUEL_PER_SEC)
///   when there is no profile (tests / single-tenant). `0` means UNLIMITED —
///   never deny-all.
/// - **Window (fails OPEN).** [`FuelRateLimiter::over_budget`](
///   crate::FuelRateLimiter::over_budget) is total (non-poisoning parking_lot +
///   saturating arithmetic); there is deliberately no deny-all-on-error path.
///
/// No I/O, no wasmtime — unit-testable directly.
fn cpu_rate_deny(
    fuel_rate: &crate::FuelRateLimiter,
    invocation_profile: Option<&astrid_core::profile::PrincipalProfile>,
    group_config: Option<&astrid_core::GroupConfig>,
    principal: &astrid_core::PrincipalId,
    now: std::time::Instant,
) -> Option<String> {
    // Exemption resolves the INVOKING principal's profile against the cached
    // group config — fail-CLOSED (bounded) on any missing input.
    if resolve_exemption(invocation_profile, group_config, principal) {
        return None;
    }
    let budget = invocation_profile
        .map(|p| p.quotas.max_cpu_fuel_per_sec)
        .unwrap_or(astrid_core::profile::DEFAULT_MAX_CPU_FUEL_PER_SEC);
    // 0 = unlimited; never deny-all. Window math fails OPEN (cannot fail).
    if budget > 0 && fuel_rate.over_budget(principal, budget, now) {
        return Some(format!(
            "principal '{principal}' exceeded CPU budget of {budget} fuel/sec"
        ));
    }
    None
}

/// Pure resolution of a capsule's run-loop resource bound from the owner
/// principal's profile and the live group config. Wraps [`resolve_exemption`]
/// and derives the bound run-loop's epoch window + memory cap. No I/O, no
/// locking. This isolates ALL fail-secure branching so it is unit-testable
/// without wasmtime.
///
/// FAIL-SECURE: every missing/error input lands on BOUNDED — a finite epoch
/// window + the 64 `MiB` default — for a non-exempt run-loop. Exemption is the
/// CAPABILITY axis only (see [`resolve_exemption`]); the manifest never grants
/// it.
pub(crate) fn resolve_run_loop_budget(
    owner_profile: Option<&astrid_core::profile::PrincipalProfile>,
    group_config: Option<&astrid_core::GroupConfig>,
    principal: &astrid_core::PrincipalId,
    has_run_export: bool,
) -> RunLoopBudget {
    let exempt = resolve_exemption(owner_profile, group_config, principal);
    let bound_run_loop = has_run_export && !exempt;

    // Epoch window for a bound run-loop, in EPOCH_TICK_INTERVAL ticks. Derived
    // from the owner quota `max_timeout_secs` (clamped to the default window),
    // fail-safe to DEFAULT_RUN_LOOP_WINDOW_TICKS. Finite either way; never a
    // sentinel — exemption is signalled by `exempt`, not by a giant window.
    let window_ticks = if bound_run_loop {
        let ticks = owner_profile
            .map(|p| {
                let secs = p.quotas.max_timeout_secs;
                let by_secs = secs.saturating_mul(1000) / EPOCH_TICK_INTERVAL.as_millis() as u64;
                // A pinned-shorter timeout tightens the window; never longer
                // than the default ~5 s so the worst-case starvation grace
                // (MAX_NO_YIELD_WINDOWS * window) stays bounded.
                by_secs.clamp(1, DEFAULT_RUN_LOOP_WINDOW_TICKS)
            })
            .unwrap_or(DEFAULT_RUN_LOOP_WINDOW_TICKS);
        Some(ticks.max(1))
    } else {
        None
    };

    // Memory cap for a bound run-loop: owner quota (default 64 MiB on
    // resolve-failure), clamped into usize. Non-bound Stores keep the
    // process default.
    let mem_bytes = if bound_run_loop {
        owner_profile
            .map(|p| usize::try_from(p.quotas.max_memory_bytes).unwrap_or(usize::MAX))
            .unwrap_or(WASM_MAX_MEMORY_BYTES)
    } else {
        WASM_MAX_MEMORY_BYTES
    };

    RunLoopBudget {
        exempt,
        bound_run_loop,
        window_ticks,
        mem_bytes,
    }
}

/// The action a bound run-loop's epoch callback takes when a deadline window
/// elapses, plus the new state to write back. Pure so it is unit-testable
/// without wasmtime; the production callback ([the run-loop Store setup])
/// applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EpochAction {
    /// Cooperatively yield the tokio worker and re-arm the deadline by
    /// `window_ticks`. Maps to
    /// [`UpdateDeadline::Yield`](wasmtime::UpdateDeadline::Yield).
    Yield(u64),
    /// Trap the guest. Maps to
    /// [`UpdateDeadline::Interrupt`](wasmtime::UpdateDeadline::Interrupt).
    Interrupt,
}

/// Pure epoch-deadline decision for a bound run-loop.
///
/// Called once per elapsed window with the run-loop's current
/// `(recv_yielded, no_yield_windows)`:
///
/// * If the guest called `recv` since the last window (`recv_yielded`), it is
///   a legitimate recv/accept loop: clear the flag, reset the no-yield counter
///   to 0, and **`Yield`** (cooperatively yield the worker + re-arm). Such a
///   loop is never trapped.
/// * Otherwise it burned the whole window without a single `recv`: increment
///   `no_yield_windows`. Once it reaches `max` (`MAX_NO_YIELD_WINDOWS`),
///   **`Interrupt`** (trap the runaway); below `max`, still **`Yield`** — so
///   even a pure `loop {}` cooperatively yields the worker every window and can
///   NEVER starve the daemon while it lives out its grace windows.
///
/// Returns `(action, new_recv_yielded, new_no_yield_windows)`.
pub(crate) fn epoch_decision(
    recv_yielded: bool,
    no_yield_windows: u32,
    window_ticks: u64,
    max: u32,
) -> (EpochAction, bool, u32) {
    if recv_yielded {
        // Legit recv/accept loop: reset and keep running.
        (EpochAction::Yield(window_ticks), false, 0)
    } else {
        let next = no_yield_windows.saturating_add(1);
        if next >= max {
            // Persistent no-recv spinner: trap it.
            (EpochAction::Interrupt, false, next)
        } else {
            // Still within the grace window — yield the worker (never starve)
            // and accrue toward the interrupt.
            (EpochAction::Yield(window_ticks), false, next)
        }
    }
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

        let wasm_hash = read_expected_wasm_hash(&self._capsule_dir)
            .map(crate::registry::WasmHash::from_raw)
            .unwrap_or_else(|| {
                crate::registry::WasmHash::synthetic(
                    &self.manifest.package.name,
                    &self.manifest.package.version,
                )
            });

        // Capsule identity, used as the IPC `source_id` (kernel-stamped, never
        // guest-settable) and the per-(capsule, topic, principal) route key.
        // DETERMINISTIC (uuid v5 from principal + capsule name + content hash)
        // so it is STABLE across daemon restarts. The principal segment is
        // critical because the loaded runtime owns principal-bound env/KV host
        // state even when the installed artifact hash is identical.
        //
        // Namespace is a dedicated, fixed Astrid value — NOT `Uuid::NAMESPACE_OID`
        // (reserved for ISO OIDs), so a capsule-name-derived id can never
        // semantically collide with an OID-derived uuid from another system.
        // Arbitrary but FIXED: changing it changes every capsule's identity, so
        // it must never change.
        const CAPSULE_ID_NAMESPACE: uuid::Uuid =
            uuid::Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);
        let capsule_uuid_seed = format!(
            "{}\0{}\0{}",
            ctx.principal,
            self.manifest.package.name,
            wasm_hash.as_str()
        );
        let capsule_uuid = uuid::Uuid::new_v5(&CAPSULE_ID_NAMESPACE, capsule_uuid_seed.as_bytes());

        // Create shared concurrency controls before entering the blocking
        // plugin build. The blocking semaphore (cores-2-ish) gates host calls
        // that pin a worker; the I/O semaphore (large, fd-clamped) gates async
        // host calls that free the worker — sized from the resolved per-host
        // limits so the LLM/HTTP path is not throttled by the blocking cap
        // (`astrid#816`). Both are cloned into every pooled `HostState` so the
        // ceilings are shared across the whole instance pool.
        let blocking_semaphore = self.runtime_limits.blocking_semaphore();
        let io_semaphore = self.runtime_limits.io_semaphore();
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let cancel_token_for_state = cancel_token.clone();
        let process_tracker = Arc::new(crate::engine::wasm::host::process::ProcessTracker::new());
        let process_tracker_for_listener = process_tracker.clone();
        // Host-owned persistent-process registry — one per engine, cloned
        // into every pooled `HostState` so a `process-id` survives instance
        // reset. Children are owned by the daemon runtime, NOT an instance.
        let persistent_registry = Arc::new(
            crate::engine::wasm::host::process::PersistentProcessRegistry::new(
                tokio::runtime::Handle::current(),
            ),
        );
        let persistent_registry_for_reaper = persistent_registry.clone();
        // Shared peak-memory ledger, cloned into every pooled `HostState`'s
        // `StoreMemoryMeter` so a principal's high-water linear memory sums
        // cross-capsule (the RAM analogue of the fuel ledger).
        let memory_ledger = self.memory_ledger.clone();

        let capsule_dir_for_verify = self._capsule_dir.clone();
        // Inlined async block — was previously wrapped in
        // `block_in_place` to permit nested `block_on` for the VFS
        // `register_dir` calls. Component-model async lets us `.await`
        // those directly here, so the load path no longer pins a worker
        // for the duration of the engine build.
        let (pool_opt, store_arc, run_instance, rx, has_run, ready_rx, wt_engine) = async {
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

            // Manifest-derived data + shared services, built once and cloned
            // into each pooled Store's HostState by `make_state` below.
            let capsule_id_val = crate::capsule::CapsuleId::new(&manifest.package.name)
                .map_err(|e| CapsuleError::UnsupportedEntryPoint(e.to_string()))?;
            // Secret-typed env keys from the manifest. `get_config` routes
            // these through the keychain (per-invocation principal-scoped,
            // host-wide fall-through) instead of `config`.
            let secret_env_set: std::collections::HashSet<String> = manifest
                .env
                .iter()
                .filter(|(_, d)| d.env_type.eq_ignore_ascii_case("secret"))
                .map(|(k, _)| k.clone())
                .collect();
            // RFC cargo-like-manifest: prefer [publish]/[subscribe] keys over
            // the legacy [capabilities] arrays (helper falls back if empty).
            let ipc_publish_v = manifest.effective_ipc_publish_patterns();
            let ipc_subscribe_v = manifest.effective_ipc_subscribe_patterns();
            // Only capsules declaring net_bind (the CLI proxy) get the socket
            // listener / session token.
            let cli_listener = if manifest.capabilities.net_bind.is_empty() {
                None
            } else {
                ctx.cli_socket_listener.clone()
            };
            let session_tok = if manifest.capabilities.net_bind.is_empty() {
                None
            } else {
                ctx.session_token.clone()
            };
            // `[capabilities].uplink` bit (binds a socket), gating ipc-publish-as.
            let has_uplink = manifest.capabilities.uplink;
            // Snapshot of the capsule's held capability names, fixed at load —
            // backs the infallible `enumerate-capabilities` host fn. Cloned per
            // pooled instance inside the `make_state` closure below.
            let capability_names = manifest.capabilities.held_names();
            // Operator-approved local-egress allowlist for this capsule,
            // snapshotted from the load context onto every pooled instance
            // (load-time-fixed, like `capability_names`).
            let local_egress = ctx.local_egress.clone();
            // Resolved `astrid:http` host ceilings — a GLOBAL Copy value (same
            // for every capsule), captured by the `make_state` move closure and
            // snapshotted onto every pooled instance like `local_egress`.
            let http_limits = self.http_limits;
            // One IPC rate limiter shared by every pooled instance, so the
            // per-capsule throughput budget is not multiplied by pool size.
            let ipc_limiter = Arc::new(astrid_events::ipc::IpcRateLimiter::new());
            // The CoW overlay upper-dir tempdir is shared by all instances.
            let upper_dir_arc = Arc::new(upper_temp);

            // ── Run-loop resource bound (CPU epoch interrupt + linear memory) ─
            //
            // Resolved at load time, BEFORE `make_state`, so the memory cap is
            // baked into `StoreLimits` *before* instantiation (a late post-pop
            // rebuild let the initial linear memory escape the cap). The CPU
            // bound is a wasmtime EPOCH deadline + interrupt callback on the
            // dedicated run-loop Store (see the run-loop Store setup below): a
            // recv/accept loop sets `recv_yielded` and is re-armed every
            // window; a no-recv spinner is interrupt-trapped after
            // MAX_NO_YIELD_WINDOWS, and even a pure `loop {}` cooperatively
            // yields the tokio worker every window (UpdateDeadline::Yield) so it
            // can never starve the daemon.
            //
            // Exemption is purely CAPABILITY-driven — a holder of
            // CAP_RESOURCES_UNBOUNDED / CAP_NET_BIND / CAP_UPLINK on its OWNER
            // principal profile (admin via `*`) — resolved through the
            // permission system against `ctx.profile_cache` + the live group
            // config. The capsule-authored manifest never grants exemption: a
            // capsule that merely declares `uplink`/`net_bind` without the
            // principal holding the granted capability is BOUNDED. The owner
            // principal is resolved SYNC and NON-FATALLY from
            // `ctx.profile_cache` (the load-time source — `self.profile_cache`
            // is only assigned later, after `make_state`); a missing cache
            // (tests / single-tenant) or resolve error falls through to BOUNDED
            // (fail-secure), never to exempt. See [`resolve_run_loop_budget`]
            // and [`resolve_exemption`] for the pure, unit-tested branching.
            let has_run_export = wasm_exports_contain_run(&wasm_bytes);
            let owner_profile: Option<Arc<astrid_core::profile::PrincipalProfile>> =
                ctx.profile_cache.as_ref().and_then(|cache| {
                    cache
                        .resolve(&ctx.principal)
                        .map_err(|e| {
                            tracing::warn!(
                                principal = %ctx.principal,
                                error = %e,
                                "owner profile resolve failed at load; bounding run-loop \
                                 with the default finite budget (fail-secure)"
                            );
                            e
                        })
                        .ok()
                });
            let load_group_config =
                crate::context::live_group_config_for(&ctx.group_config)
                    .map(|groups| groups.load_full())
                    .or_else(|| ctx.group_config.clone());
            let run_budget = resolve_run_loop_budget(
                owner_profile.as_deref(),
                load_group_config.as_ref().map(Arc::as_ref),
                &ctx.principal,
                has_run_export,
            );
            // Memory cap captured by `make_state` (Copy usize). For a bound
            // run-loop this is the owner quota; pool_size is 1 for run-loop
            // capsules so the single Store `make_state` builds IS the run-loop
            // Store. For interceptor pools it is the 64 MiB placeholder (the
            // real per-invocation cap is applied at invoke time).
            let run_loop_mem_bytes: usize = run_budget.mem_bytes;
            if run_budget.bound_run_loop {
                tracing::debug!(
                    capsule = %manifest.package.name,
                    principal = %ctx.principal,
                    window_ticks = ?run_budget.window_ticks,
                    mem_bytes = run_loop_mem_bytes,
                    resolved = owner_profile.is_some(),
                    "Bounding non-exempt run-loop CPU (epoch interrupt) + memory to owner profile quota"
                );
            }

            // ── Audit firehose (privileged, load-time, manifest-independent) ─
            //
            // Does the OWNER principal hold `audit:read_all`? Resolved the
            // SAME privileged way as the run-loop exemption above — against
            // the already-resolved `owner_profile` + the live group config,
            // NEVER the capsule manifest — so a capsule cannot self-grant the
            // firehose by listing the audit topic in its `Capsule.toml`
            // `ipc_subscribe` array (that array only grants the syntactic
            // right to NAME the topic; `check_subscribe_acl` enforces it).
            // Reuses `owner_profile` rather than re-resolving so there is no
            // second cache hit / duplicate warn-log. A Copy `bool` captured by
            // the `make_state` move closure below, beside `has_uplink`.
            // Fail-secure: `false` ⇒ audit subscriptions are scoped to the
            // owner principal. See [`resolve_audit_firehose`].
            let audit_firehose = resolve_audit_firehose(
                owner_profile.as_deref(),
                load_group_config.as_ref().map(Arc::as_ref),
                &ctx.principal,
            );

            // Per-instance `HostState` factory. Shared services clone (Arc or
            // cheap value clones); per-Store fields (`wasi_ctx`,
            // `resource_table`, the http-stream map, the resource-table-mirror
            // counters) are fresh per Store. The pool-safety audit confirmed
            // no pooled capsule relies on in-WASM-memory state surviving
            // across invocations, so distinct Stores per principal-invocation
            // are sound (issue #816).
            //
            // Owned (`move`) and `Arc`-wrapped so it is a `'static` factory the
            // dynamic pool keeps to lazily grow new instances long after this
            // load frame returns — not just a borrow used by the eager loop. The
            // shared state it needs from outside this block (the host semaphores,
            // the cancel token, the process tracker) and from `ctx` (principal,
            // registry, allowance/identity stores) is cloned into owned locals
            // first, so the `move` closure takes them without borrowing the
            // frame.
            let blocking_semaphore = blocking_semaphore.clone();
            let io_semaphore = io_semaphore.clone();
            let cancel_token_for_state = cancel_token_for_state.clone();
            let process_tracker = process_tracker.clone();
            let persistent_registry = persistent_registry.clone();
            let memory_ledger = memory_ledger.clone();
            let st_principal = ctx.principal.clone();
            let st_capsule_registry = ctx.capsule_registry.clone();
            let st_allowance_store = ctx.allowance_store.clone();
            let st_identity_store = ctx.identity_store.clone();
            let st_profile_cache = ctx.profile_cache.clone();
            // Shared across the whole pool so a verified per-connection
            // principal (issue #45/#852) bound on the accepting instance is
            // visible to whichever pooled instance later serves that
            // connection — same Arc-sharing rationale as `process_tracker`.
            let connection_principals: Arc<dashmap::DashMap<u32, ConnectionIdentity>> =
                Arc::new(dashmap::DashMap::new());
            // Lifecycle-tracking registry for the kernel connection counter:
            // an accept inserts and emits `client.v1.connect`, the matching
            // drop removes and emits `client.v1.disconnect`. Shared across the
            // pool for the same reason as `connection_principals` (drop may
            // land on a different instance than the accept).
            let client_connections: Arc<
                dashmap::DashMap<u32, astrid_core::principal::PrincipalId>,
            > = Arc::new(dashmap::DashMap::new());
            let make_state: Arc<dyn Fn() -> HostState + Send + Sync> = Arc::new(move || HostState {
                wasi_ctx: build_wasi_ctx(),
                resource_table: wasmtime::component::ResourceTable::new(),
                // Memory cap baked in BEFORE instantiation. For a bound
                // run-loop (pool_size 1) this is the owner quota, enforced on
                // the FIRST `memory.grow` during `instantiate_async` (the
                // store's `limiter` reads `store_meter`). For interceptor
                // pools this is the 64 MiB placeholder; the real per-invocation
                // cap is applied at invoke time.
                store_meter: crate::memory_ledger::StoreMemoryMeter::new(
                    run_loop_mem_bytes,
                    st_principal.clone(),
                    memory_ledger.clone(),
                ),
                principal: st_principal.clone(),
                capsule_uuid,
                caller_context: None,
                interceptor_active: false,
                invocation_kv: None,
                capsule_log: capsule_log.clone(),
                capsule_id: capsule_id_val.clone(),
                workspace_root: workspace_root.clone(),
                vfs: Arc::clone(&overlay_vfs) as Arc<dyn astrid_vfs::Vfs>,
                vfs_root_handle: root_handle.clone(),
                home: home_mount.clone(),
                tmp: tmp_mount.clone(),
                invocation_home: None,
                invocation_tmp: None,
                invocation_secret_store: None,
                invocation_capsule_log: None,
                invocation_profile: None,
                profile_cache: st_profile_cache.clone(),
                invocation_env_overlay: None,
                overlay_vfs: Some(Arc::clone(&overlay_vfs)),
                upper_dir: Some(Arc::clone(&upper_dir_arc)),
                kv: kv.clone(),
                event_bus: event_bus.clone(),
                ipc_limiter: Arc::clone(&ipc_limiter),
                config: wasm_config.clone(),
                secret_env: secret_env_set.clone(),
                ipc_publish_patterns: ipc_publish_v.clone(),
                ipc_subscribe_patterns: ipc_subscribe_v.clone(),
                cli_socket_listener: cli_listener.clone(),
                active_http_streams: std::collections::HashMap::new(),
                next_http_stream_id: 1,
                security: Some(
                    Arc::clone(&security_gate) as Arc<dyn crate::security::CapsuleSecurityGate>
                ),
                hook_manager: None, // Will be injected by Gateway
                capsule_registry: st_capsule_registry.clone(),
                runtime_handle: tokio::runtime::Handle::current(),
                has_uplink_capability: has_uplink,
                capability_names: capability_names.clone(),
                local_egress: local_egress.clone(),
                http_limits,
                audit_firehose,
                inbound_tx: tx.clone(),
                registered_uplinks: Vec::new(),
                lifecycle_phase: None,
                secret_store: secret_store.clone(),
                ready_tx: None,
                blocking_semaphore: blocking_semaphore.clone(),
                io_semaphore: io_semaphore.clone(),
                cancel_token: cancel_token_for_state.clone(),
                session_token: session_tok.clone(),
                interceptor_handles: Vec::new(),
                allowance_store: st_allowance_store.clone(),
                identity_store: st_identity_store.clone(),
                process_tracker: process_tracker.clone(),
                persistent_processes: persistent_registry.clone(),
                net_stream_count: 0,
                subscription_count: 0,
                process_count_total: 0,
                process_count_by_principal: std::collections::HashMap::new(),
                connection_principals: connection_principals.clone(),
                client_connections: client_connections.clone(),
                // No frame in flight at construction; both the ingress
                // principal and its authenticating device key_id are set per
                // framed read.
                ingress_principal: None,
                ingress_device_key_id: None,
                ingress_origin: None,
                // Run-loop epoch-interrupt state. `recv_yielded` is set true by
                // the ipc `recv` host fn each time the guest blocks on recv;
                // the bound run-loop's epoch callback reads + clears it to
                // distinguish a legit recv loop from a no-recv spinner.
                // `no_yield_windows` counts consecutive windows with no recv.
                recv_yielded: false,
                no_yield_windows: 0,
            });

            // Initial epoch deadline applied to every freshly-instantiated
            // pool Store below. This is a wall-clock placeholder, NOT the
            // bound run-loop CPU mechanism:
            //  - exempt (incl. exempt run-loops): u64::MAX — never epoch-trapped.
            //  - interceptor pool Stores: the existing finite default; the real
            //    per-invocation epoch is re-applied per call in
            //    `invoke_interceptor` (unchanged).
            //  - bound run-loops: this default is replaced in the run-loop
            //    Store setup with the per-WINDOW epoch deadline + interrupt
            //    callback (`epoch_decision`).
            let pool_epoch_deadline = if run_budget.exempt {
                u64::MAX
            } else {
                WASM_CAPSULE_TIMEOUT_SECS * 1000 / EPOCH_TICK_INTERVAL.as_millis() as u64
            };

            // Build the engine, linker, and compiled component ONCE; the pool
            // mints N instances from the same `InstancePre` without re-running
            // the linker per Store.
            //
            // No `wasi:*` interfaces are registered: the host ABI is fully
            // Astrid-owned. Both this load path AND `run_lifecycle` go through
            // the same `configure_kernel_linker` helper so the linker config
            // stays in lockstep across the two paths.
            let wt_engine = build_wasmtime_engine()?;
            let mut linker: Linker<HostState> = Linker::new(&wt_engine);
            configure_kernel_linker(&mut linker).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to add Astrid host to linker: {e}"
                ))
            })?;
            let wasm_component = Component::from_binary(&wt_engine, &wasm_bytes).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to compile WASM component: {e}"
                ))
            })?;
            let instance_pre = linker.instantiate_pre(&wasm_component).map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to pre-instantiate WASM component: {e}"
                ))
            })?;

            // Dynamic-pool sizing. Run-loop and `host_process` capsules are
            // pinned to a single Store regardless of the configured pool max:
            // run-loops own their dedicated Store; `host_process` capsules hold
            // live resource handles across invocations and must never lease a
            // second Store. Everyone else gets a dynamic pool that warm-starts
            // at `min_idle`, grows lazily toward `instance_pool_size` under
            // load, and is trimmed back to `min_idle` when idle (issue #816,
            // replacing the old fixed `INSTANCE_POOL_SIZE`).
            let is_single_store =
                has_run_export || !manifest.capabilities.host_process.is_empty();
            let (pool_max, pool_min_idle) = if is_single_store {
                (1, 1)
            } else {
                (
                    self.runtime_limits.instance_pool_size,
                    self.runtime_limits.instance_pool_min_idle(),
                )
            };

            // On-demand instance factory. The eager warm-start instances are
            // built through it too, so an eagerly-built and a lazily-grown
            // instance are identical (required for free checkout). The factory
            // outlives this frame, owning `make_state` and the compiled
            // component, so the pool can grow after load returns.
            let builder = pool::InstanceBuilder::new(
                wt_engine.clone(),
                instance_pre,
                Arc::clone(&make_state),
                pool_epoch_deadline,
                INTERCEPTOR_FUEL_BUDGET,
            );
            let mut initial_instances: Vec<pool::PooledInstance> =
                Vec::with_capacity(pool_min_idle);
            for _ in 0..pool_min_idle {
                initial_instances.push(builder.build().await?);
            }
            tracing::debug!(
                capsule = %manifest.package.name,
                pool_max,
                pool_min_idle,
                warm = initial_instances.len(),
                has_run = has_run_export,
                host_process = !manifest.capabilities.host_process.is_empty(),
                "Instantiated capsule instance pool"
            );

            let has_run = has_run_export;
            // Run-loop capsules pull one instance out as a dedicated,
            // mutex-guarded Store owned by the run loop; pooled capsules keep
            // the whole set for `invoke_interceptor` to lease from.
            let mut pool_opt: Option<pool::CapsuleInstancePool> = None;
            let mut store_arc: Option<Arc<AsyncMutex<Store<HostState>>>> = None;
            let mut run_instance: Option<wasmtime::component::Instance> = None;
            if has_run {
                let mut pi = initial_instances
                    .pop()
                    .expect("min_idle >= 1, so the run-loop instance exists");
                // The run-loop Store's memory cap is already baked into
                // `store_meter` by `make_state` (pool_size 1 ⇒ this IS the
                // run-loop Store) and was enforced during `instantiate_async`.
                // Fuel was seeded to INTERCEPTOR_FUEL_BUDGET above for
                // instantiation; the run loop is NOT fuel-bound, so re-seed it
                // to effectively-infinite (consume_fuel makes a 0-fuel Store
                // trap, and we never want a run loop to fuel-out). CPU is
                // bounded by the epoch interrupt below, not fuel.
                pi.store.set_fuel(u64::MAX).map_err(|e| {
                    CapsuleError::UnsupportedEntryPoint(format!("Failed to set run-loop fuel: {e}"))
                })?;
                // Apply the CPU bound: a wasmtime EPOCH deadline + interrupt
                // callback driven by the shared epoch ticker.
                if let Some(window_ticks) = run_budget.window_ticks {
                    // BOUND run-loop. The epoch ticker fires the callback every
                    // `window_ticks` of wall-clock. The callback runs the pure
                    // `epoch_decision`:
                    //   * a recv/accept loop sets `recv_yielded` (ipc recv host
                    //     fn) → the window resets the counter and `Yield`s
                    //     (cooperatively yields the worker, re-arms) — NEVER
                    //     trapped;
                    //   * a no-recv spinner accrues `no_yield_windows` and is
                    //     `Interrupt`-trapped once it reaches
                    //     MAX_NO_YIELD_WINDOWS — but still `Yield`s during the
                    //     grace windows, so even a pure `loop {}` cooperatively
                    //     yields the tokio worker every window and can NEVER
                    //     starve the daemon (the real worker-starvation fix).
                    //
                    // DOCUMENTED RESIDUAL: a `loop { recv(0); burn() }` spammer
                    // sets `recv_yielded` every iteration, so it is never
                    // trapped — but because every recv yields the worker it
                    // also cannot starve the daemon; it can burn one core. An
                    // OS cgroup is the recommended backstop for that case.
                    // `UpdateDeadline::Yield` is async-legal here because the
                    // run loop drives the guest via `call_async` (verified
                    // against wasmtime 45).
                    pi.store.set_epoch_deadline(window_ticks);
                    pi.store.epoch_deadline_callback(move |mut store_ctx| {
                        let st = store_ctx.data_mut();
                        let (action, recv_yielded, no_yield_windows) = epoch_decision(
                            st.recv_yielded,
                            st.no_yield_windows,
                            window_ticks,
                            MAX_NO_YIELD_WINDOWS,
                        );
                        st.recv_yielded = recv_yielded;
                        st.no_yield_windows = no_yield_windows;
                        Ok(match action {
                            EpochAction::Yield(ticks) => wasmtime::UpdateDeadline::Yield(ticks),
                            EpochAction::Interrupt => wasmtime::UpdateDeadline::Interrupt,
                        })
                    });
                } else {
                    // EXEMPT run-loop (CAP_RESOURCES_UNBOUNDED / CAP_NET_BIND /
                    // CAP_UPLINK on the owner principal): unbounded. No epoch
                    // callback and the deadline pinned to u64::MAX so the
                    // shared ticker never traps it.
                    pi.store.set_epoch_deadline(u64::MAX);
                }
                store_arc = Some(Arc::new(AsyncMutex::new(pi.store)));
                run_instance = Some(pi.instance);
            } else {
                // Free-checkout pools tear down each returned instance's
                // resource table so a cancelled/panicked invocation can't leak
                // a live handle into the next (possibly different-principal)
                // lease. The `host_process` carve-out (size 1) is the sole
                // exception: it holds `ManagedProcess` handles across
                // invocations, and never leases a second Store, so its table
                // must persist. See `pool::clear_on_return`.
                let reset_resources_on_return = manifest.capabilities.host_process.is_empty();
                pool_opt = Some(pool::CapsuleInstancePool::new(
                    initial_instances,
                    pool_max,
                    pool_min_idle,
                    reset_resources_on_return,
                    builder,
                    &cancel_token,
                ));
            }

            // Only allocate the watch channel for run-loop capsules.
            let ready_rx = if has_run {
                let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
                // Async-mutex `lock()` cannot fail (no poisoning) so the
                // legacy poisoned-lock conversion is gone. The borrow is
                // held synchronously across the small mutation below;
                // no `.await` occurs while it is alive.
                let mut s = store_arc.as_ref().expect("run-loop has store").lock().await;
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

                let mut s = store_arc.as_ref().expect("run-loop has store").lock().await;
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

            Ok::<_, CapsuleError>((
                pool_opt,
                store_arc,
                run_instance,
                rx,
                has_run,
                ready_rx,
                wt_engine,
            ))
        }
        .await?;

        // Register UUID-to-instance mapping so host functions can resolve IPC
        // source UUIDs back to the exact content-addressed capsule instance
        // that published a response.
        //
        // Ordering: this runs before the kernel's `registry.register(capsule)`.
        // During the gap, the hash may resolve before the kernel has finished
        // registering the instance; capability checks deny (fail-closed).
        // This is safe because the capsule cannot publish IPC (and thus
        // cannot appear as a hook response `source_id`) until it is fully
        // loaded and running.
        let capsule_id = crate::capsule::CapsuleId::new(&self.manifest.package.name)
            .map_err(|e| CapsuleError::UnsupportedEntryPoint(e.to_string()))?;
        if let Some(registry) = &ctx.capsule_registry {
            let mut registry = registry.write().await;
            registry.register_uuid(capsule_uuid, capsule_id.clone());
            registry.register_instance_uuid(capsule_uuid, wasm_hash, &ctx.principal);
        }

        // Register topic schemas unconditionally — schema_catalog is always
        // present, even when capsule_registry is None (e.g. in tests). Topics
        // are sourced from the [publish]/[subscribe] tables' wit refs.
        ctx.schema_catalog
            .register_topics(&capsule_id, &self.manifest)
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

            // Persistent-process reaper: sweep idle / over-lifetime /
            // exit-retention-elapsed entries on a timer, and reap the whole
            // registry on capsule unload (cancel). Same `host_process` gate as
            // the cancel listener — only those capsules have a live registry.
            let registry = persistent_registry_for_reaper;
            let ct = cancel_token.clone();
            tokio::task::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        biased;
                        () = ct.cancelled() => {
                            registry.shutdown();
                            break;
                        }
                        _ = tick.tick() => {
                            registry.reap_sweep();
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
            let run_store = Arc::clone(store_arc.as_ref().expect("run-loop has store"));
            let run_inst = run_instance.expect("run-loop has instance");
            // With async wasmtime, `call_async` schedules guest execution
            // on a fiber that yields back to the executor on every host
            // import boundary. The spawned task no longer needs to be a
            // blocking thread — it's an ordinary async task.
            self.run_handle = Some(tokio::task::spawn(async move {
                tracing::info!(capsule = %capsule_name, "Starting background WASM run loop");
                let mut s = run_store.lock().await;
                let typed = match run_inst.get_typed_func::<(), ()>(&mut *s, "run") {
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
            // The run loop owns the Store via `run_store`; `self.pool` stays
            // None so `invoke_interceptor` reports NotSupported for run-loop
            // capsules (they receive events through auto-subscribed IPC).
        } else {
            self.pool = pool_opt;
        }
        self.inbound_rx = rx;
        self.profile_cache = ctx.profile_cache.clone();
        self.overlay_registry = ctx.overlay_registry.clone();
        self.owner_principal = Some(ctx.principal.clone());
        // Cache the live group config handle so the CPU-rate deny gate can
        // resolve the invoking principal's exemption against runtime group
        // mutations. `None` in tests / single-tenant => no exemption resolvable
        // => the principal is bounded (fail-secure).
        self.group_config =
            crate::context::live_group_config_for(&ctx.group_config).or_else(|| {
                ctx.group_config
                    .as_ref()
                    .map(|groups| Arc::new(ArcSwap::from(Arc::clone(groups))))
            });

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
        // Drop the pool — releases every pooled Store's WASM memory. (Run-loop
        // capsules have `pool == None`; their Store is owned by the aborted
        // run_handle and dropped with it.)
        self.pool = None;
        self.wasmtime_engine = None;
        self.ready_rx = None; // Prevent stale channel observation post-unload
        Ok(())
    }

    fn request_cancel(&self) {
        if let Some(token) = &self.cancel_token {
            token.cancel();
        }
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
        let pool = self.pool.as_ref().ok_or_else(|| {
            CapsuleError::NotSupported(
                "plugin handles interceptors internally via IPC auto-subscribe".into(),
            )
        })?;

        // Invoking principal, derived once: used both for the quota profile
        // below and the per-invocation diagnostic span at the end. Lock-free
        // — `owner_principal` is the immutable load-time `state.principal`.
        let invoking_principal = caller
            .and_then(|msg| msg.principal.as_deref())
            .and_then(|p| astrid_core::PrincipalId::new(p).ok())
            .or_else(|| self.owner_principal.clone())
            .unwrap_or_default();

        // Per-invocation timing for the live "sample" view (#816
        // observability). Started before profile resolution + pool checkout so
        // the span captures the full kernel-side cost a caller waits on.
        let invoke_start = std::time::Instant::now();

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
        let invocation_profile: Option<Arc<astrid_core::profile::PrincipalProfile>> =
            match self.profile_cache.as_ref() {
                Some(cache) => {
                    let profile = cache.resolve(&invoking_principal).map_err(|e| {
                        tracing::error!(principal = %invoking_principal, error = %e,
                            "profile load failed; denying invocation (issue #666)");
                        CapsuleError::WasmError(format!(
                            "principal '{invoking_principal}' profile invalid: {e}"
                        ))
                    })?;
                    check_principal_enabled(
                        &profile,
                        &invoking_principal,
                        self.manifest.package.name.as_str(),
                        action,
                    )?;
                    Some(profile)
                },
                None => None,
            };

        // ── Per-principal CPU-rate DENY gate (PR2, security boundary) ──────
        //
        // The deny side of the per-principal CPU budget: if the invoking
        // principal has burned more than `max_cpu_fuel_per_sec` in the current
        // rolling 1-second window, refuse THIS invocation before it costs any
        // CPU (before pool checkout / fuel seeding). The `record` feed AFTER
        // the call (next to `fuel_ledger.charge`) is what populates the window;
        // this is purely the read, stamped with a fresh `Instant::now()` taken
        // HERE at the admission decision — NOT the earlier `invoke_start`.
        // `invoke_start` is captured at the very top of the invocation, before
        // the per-invocation setup and profile resolution that can hit disk
        // (`PrincipalProfile::load`); reusing it here would read the window
        // seconds in the past and can underflow `now < window_start` against a
        // window a concurrent `record` just stamped. The matching `record` is
        // stamped at call COMPLETION (see its call site), so a long call's fuel
        // lands in the live window rather than a stale one.
        //
        // Two orthogonal axes, deliberately opposite fail directions:
        //   • EXEMPTION fails CLOSED. `resolve_exemption` returns `false`
        //     (bounded) on any missing input — no profile, no group config — so
        //     an unidentifiable principal is *gated*, never waved through. The
        //     holders it DOES exempt are capability-driven (unbounded /
        //     net_bind / uplink; admin via `*`), the same set the run-loop
        //     bound exempts — resolved against the INVOKING principal's profile
        //     (`invocation_profile`, already in hand) and the cached group
        //     config.
        //   • The window MATH fails OPEN, and structurally cannot fail
        //     (`over_budget` is total: non-poisoning parking_lot + saturating
        //     arithmetic, no `?`, no panic path). There is deliberately NO
        //     deny-all-on-error branch here.
        //
        // CRITICAL — the deny is `Ok(InterceptResult::Deny { .. })`, NEVER
        // `Err`. The dispatcher HALTS the interceptor chain on `Ok(Deny)` but
        // CONTINUES it on `Err` (a broken capsule must not block the pipeline,
        // see dispatcher.rs). An `Err`-based deny would therefore be a SILENT
        // enforcement BYPASS — the chain would carry on as if nothing happened.
        let now = std::time::Instant::now();
        let live_group_config = self.group_config.as_ref().map(|groups| groups.load_full());
        if let Some(reason) = cpu_rate_deny(
            &self.fuel_rate,
            invocation_profile.as_deref(),
            live_group_config.as_ref().map(Arc::as_ref),
            &invoking_principal,
            now,
        ) {
            tracing::warn!(
                principal = %invoking_principal,
                capsule = %self.manifest.package.name,
                action,
                "CPU-rate budget exceeded; denying invocation (per-principal throttle)"
            );
            // CRITICAL: `Ok(Deny)`, never `Err` — the dispatcher halts the chain
            // on `Ok(Deny)` and CONTINUES on `Err`; an `Err`-deny is a silent
            // enforcement bypass.
            return Ok(crate::capsule::InterceptResult::Deny { reason });
        }

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
        // SET + CALL run on one leased pooled instance, so a parallel
        // invocation on a *different* pooled Store can never observe this
        // invocation's `caller_context` between SET and CALL — the
        // cross-principal race that #813 collapsed the orchestration cliff
        // onto. CLEAR (resetting every `invocation_*` field) and return-to-
        // pool are handled by `PoolCheckout::drop` (see [`pool`]), which runs
        // on every exit path — normal return, `?`, panic-unwind, and
        // future-drop on caller cancellation — preserving the invariant that
        // the next lease of this instance observes `caller_context = None`.
        //
        // SAFETY: each pooled Store is leased exclusively for the duration of
        // this call (the pool semaphore guarantees no two invocations share a
        // Store), so the SET/CALL state is private to this invocation.
        type HookTriggerResult = bindings::astrid::guest::lifecycle::CapsuleResult;

        // Lease a free pooled instance. A waiter here `.await`s for a permit
        // instead of pinning a tokio worker, and — unlike the old single Store
        // — up to the pool size of invocations run concurrently on independent
        // Stores (issue #816). `instance` (a `Copy` handle) is taken before
        // borrowing the store mutably for the SET/CALL block; `PoolCheckout`
        // clears the invocation state and returns the instance on drop.
        let checkout_start = std::time::Instant::now();
        let mut checkout = pool.checkout().await.ok_or_else(|| {
            // `checkout` returns `None` for any of: the capsule is unloading
            // (semaphore closed), a lazy pool-grow instantiation failed, or a
            // size-1 carve-out found no warm instance. The true cause is logged
            // at the checkout site; keep the surfaced error generic rather than
            // asserting "unloading", which misleads when the real cause was a
            // transient grow failure on a fully-loaded capsule.
            CapsuleError::NotSupported("no capsule instance available".into())
        })?;
        // Time spent waiting for a free pooled instance — a rising
        // `pool_wait_ms` is the signal the pool is saturated (all instances
        // busy), distinct from a slow guest call.
        let pool_wait_ms = checkout_start.elapsed().as_millis() as u64;
        let typed_instance = checkout.instance();
        let result: CapsuleResult<HookTriggerResult> = {
            let s = checkout.store_mut();
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

            // Per-invocation CPU: fuel is engine-wide, so re-seed the leased
            // Store to a known budget before the call. This (a) bounds a
            // runaway single interceptor call, and (b) makes
            // `INTERCEPTOR_FUEL_BUDGET - get_fuel()` after the call the EXACT
            // deterministic instruction count for THIS invocation, attributable
            // to the invoking principal — independent of whatever the previous
            // leaseholder of this pooled Store consumed. Errors only if fuel is
            // disabled (it is not); on the impossible error we leave fuel as-is
            // (fail-secure: a smaller budget traps sooner).
            let _ = s.set_fuel(INTERCEPTOR_FUEL_BUDGET);

            {
                let state = s.data_mut();
                state.caller_context = caller.cloned();
                // Mark the interceptor as active so any nested `ipc::recv`
                // inside the handler (e.g. prompt-builder waiting on plugin
                // hook responses) cannot wipe or rewrite `caller_context`
                // from its empty / cross-publisher batches. See the field
                // doc on `interceptor_active` for the full rationale.
                state.interceptor_active = true;
                // Re-target the per-Store memory meter for THIS invocation: the
                // principal's `max_memory_bytes` ceiling and the invoking
                // principal to attribute peak growth to (same principal the fuel
                // ledger charges). The store's `limiter` reads the meter on each
                // `memory.grow`, so mutating in place takes effect for the
                // upcoming call — independent of the previous leaseholder of
                // this pooled Store.
                state.store_meter.set(
                    usize::try_from(applied_profile.quotas.max_memory_bytes).unwrap_or(usize::MAX),
                    invoking_principal.clone(),
                );
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

            // ── Phase 2: CALL ─────────────────────────────────────
            //
            // Cancellation safety: the `call_async` future below may be
            // dropped by the dispatcher (e.g. tokio task abort). Dropping it
            // drops `checkout`, whose `Drop` synchronously runs Phase 3 CLEAR
            // *before* the wasm fiber is torn down and returns the instance to
            // the pool, so the next lease observes `caller_context = None` and
            // every `invocation_*` field cleared.
            let typed_lookup = typed_instance
                .get_typed_func::<(String, Vec<u8>), (HookTriggerResult,)>(
                    &mut *s,
                    "astrid-hook-trigger",
                );
            match typed_lookup {
                Ok(func) => func
                    .call_async(&mut *s, (action.to_string(), payload.to_vec()))
                    .await
                    .map(|(cr,)| cr)
                    .map_err(|e| {
                        CapsuleError::WasmError(format!("astrid_hook_trigger failed: {e:?}"))
                    }),
                Err(e) => Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "capsule does not export `astrid-hook-trigger`: {e}"
                ))),
            }
        };
        // Per-invocation CPU measurement: fuel counts DOWN from the seed, so
        // `seed - remaining` is the exact deterministic instruction count for
        // this call. Read while `checkout` is still alive (the `s` borrow above
        // has ended). Charge it to the invoking principal in the shared,
        // cross-capsule fuel ledger (telemetry only — the run-loop CPU bound is
        // ENFORCED by the epoch interrupt mechanism, not fuel; windowed
        // deny/throttle on this aggregate is the deliberate follow-up).
        let fuel_after = checkout.store_mut().get_fuel().unwrap_or(0);
        let fuel_used = INTERCEPTOR_FUEL_BUDGET.saturating_sub(fuel_after);
        self.fuel_ledger.charge(&invoking_principal, fuel_used);
        // Feed this call's fuel into the CPU-rate window stamped at the moment
        // the burn FINISHED, not `invoke_start`. The gate at the top reads the
        // window with a fresh admission-time `Instant::now()` (it asks what this
        // principal had burned *before* this call), but the fuel itself was
        // spent over the whole
        // call. A long call (interceptors run up to WASM_CAPSULE_TIMEOUT_SECS —
        // minutes, for LLM streaming) stamped at `invoke_start` lands its fuel
        // in a window that is already stale by the time it returns, so the next
        // invocation's `over_budget` roll discards it — a principal issuing
        // back-to-back >1s calls would never be throttled despite each call
        // burning up to 5x the per-second budget (INTERCEPTOR_FUEL_BUDGET vs
        // max_cpu_fuel_per_sec). Stamping at completion places the fuel in the
        // live window so the next call sees it.
        self.fuel_rate
            .record(&invoking_principal, fuel_used, std::time::Instant::now());
        // Drop the lease: Phase 3 CLEAR runs and the instance returns to the
        // pool, so a parallel invocation can lease it with clean state.
        drop(checkout);

        // ── Per-invocation diagnostic span (observability brick #1, #816) ──
        // The debug log carries the *principal* (greppable per handler — this
        // is exactly what distinguishes a cross-principal KV scope mismatch
        // from a same-principal visibility race) plus the timing breakdown:
        // `pool_wait_ms` (pool saturation) vs `invoke_ms` (full kernel-side
        // cost). Off by default at debug; enable via
        // `directives = ["astrid.sample=debug"]`. The metric stays
        // low-cardinality — `capsule` + `action` only, never `principal`,
        // which would explode label cardinality across thousands of agents.
        let invoke_ms = invoke_start.elapsed().as_millis() as u64;
        metrics::histogram!(
            "astrid_capsule_invocation_duration_seconds",
            "capsule" => self.manifest.package.name.clone(),
            "action" => action.to_string(),
        )
        .record(invoke_start.elapsed().as_secs_f64());
        tracing::debug!(
            target: "astrid.sample",
            capsule = %self.manifest.package.name,
            action,
            principal = %invoking_principal,
            pool_wait_ms,
            invoke_ms,
            fuel_used,
            ok = result.is_ok(),
            "interceptor invocation"
        );

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
    /// Resolved operator `astrid:http` host policy for the lifecycle hook's
    /// `HostState`. The caller (the install path) resolves it from the `[http]`
    /// config so lifecycle hooks (which may call `astrid:http`, e.g. to fetch a
    /// model list during onboarding) honour the same operator limits as the live
    /// runtime. [`HttpLimits::default`](limits::HttpLimits::default) reproduces
    /// the host's historical constants when no config is available.
    pub http_limits: limits::HttpLimits,
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
        // Lifecycle hooks (install/upgrade) run rarely and briefly; their memory
        // is not part of per-principal usage reporting, so a throwaway ledger is
        // fine — the cap is still enforced.
        store_meter: crate::memory_ledger::StoreMemoryMeter::new(
            WASM_MAX_MEMORY_BYTES,
            astrid_core::PrincipalId::default(),
            crate::MemoryLedger::default(),
        ),
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
        // Lifecycle hooks don't run the per-principal recv loop; no cache needed.
        profile_cache: None,
        invocation_env_overlay: None,
        overlay_vfs: None,
        upper_dir: None,
        kv: cfg.kv,
        event_bus: cfg.event_bus,
        ipc_limiter: Arc::new(astrid_events::ipc::IpcRateLimiter::new()),
        config: cfg.config,
        secret_env: std::collections::HashSet::new(),
        ipc_publish_patterns: Vec::new(),
        ipc_subscribe_patterns: Vec::new(),
        security: None,
        hook_manager: None,
        capsule_registry: None,
        runtime_handle: tokio::runtime::Handle::current(),
        has_uplink_capability: false,
        // Lifecycle hooks run a restricted, short-lived context and the
        // manifest capabilities are not plumbed into `LifecycleConfig`;
        // capability introspection is not exposed here (matches the
        // hard-coded `has_uplink_capability: false` above). Fail-closed.
        capability_names: Vec::new(),
        // Lifecycle (install/upgrade) hooks run briefly and do not carry a
        // local-egress exemption; the SSRF airlock applies in full.
        local_egress: Vec::new(),
        // Operator `astrid:http` host policy, resolved by the install path from
        // the `[http]` config and threaded in via `LifecycleConfig` so a
        // lifecycle hook's HTTP calls honour the same limits as the live runtime
        // (default = the host's historical constants when no config is present).
        http_limits: cfg.http_limits,
        // Lifecycle hooks never subscribe to the audit feed; fail-secure.
        audit_firehose: false,
        inbound_tx: None,
        registered_uplinks: Vec::new(),
        cli_socket_listener: None,
        active_http_streams: std::collections::HashMap::new(),
        next_http_stream_id: 1,
        lifecycle_phase: Some(phase),
        secret_store: cfg.secret_store,
        ready_tx: None,
        blocking_semaphore: HostState::default_blocking_semaphore(),
        io_semaphore: HostState::default_io_semaphore(),
        cancel_token: tokio_util::sync::CancellationToken::new(),
        session_token: None,
        interceptor_handles: Vec::new(),
        allowance_store: None,
        identity_store: None,
        process_tracker: Arc::new(host::process::ProcessTracker::new()),
        // Lifecycle hooks never spawn persistent processes (no run loop); a
        // throwaway registry satisfies the field. Reaped when this state drops.
        persistent_processes: Arc::new(host::process::PersistentProcessRegistry::new(
            tokio::runtime::Handle::current(),
        )),
        net_stream_count: 0,
        subscription_count: 0,
        process_count_total: 0,
        process_count_by_principal: std::collections::HashMap::new(),
        // Lifecycle hooks never accept socket connections; a throwaway
        // registry satisfies the field (issue #45/#852).
        connection_principals: Arc::new(dashmap::DashMap::new()),
        // Lifecycle hooks never accept inbound uplink connections; a throwaway
        // lifecycle registry satisfies the field.
        client_connections: Arc::new(dashmap::DashMap::new()),
        // Lifecycle hooks never forward client frames; no in-flight principal
        // or authenticating device.
        ingress_principal: None,
        ingress_device_key_id: None,
        ingress_origin: None,
        // Lifecycle hooks are not run loops; the epoch-interrupt run-loop
        // state is inert here but initialised for completeness.
        recv_yielded: false,
        no_yield_windows: 0,
    };

    // Build wasmtime engine and store for lifecycle execution.
    // Lifecycle hooks may block on elicit (human interaction), so use a generous
    // 10-minute safety-net deadline to catch runaway/malicious install hooks.
    const LIFECYCLE_TIMEOUT_SECS: u64 = 10 * 60;
    let wt_engine = build_wasmtime_engine()?;
    let mut store = Store::new(&wt_engine, host_state);
    let deadline_ticks = LIFECYCLE_TIMEOUT_SECS * 10; // 100ms per tick
    store.set_epoch_deadline(deadline_ticks);
    // Fuel is engine-wide (consume_fuel), so a fresh Store starts at 0 fuel and
    // would trap on the first instruction. Lifecycle hooks are operator-driven
    // and human-interactive (elicit) — they are bounded by the generous epoch
    // safety-net deadline above, NOT by a CPU rate — so fuel them to
    // effectively-infinite. The epoch deadline remains the runaway guard.
    store.set_fuel(u64::MAX).map_err(|e| {
        CapsuleError::UnsupportedEntryPoint(format!("Failed to set lifecycle fuel: {e}"))
    })?;
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
                    if e.name.name == name {
                        name_present = true;
                    }
                    if let Some(pos) = trio_position(e.name.name) {
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
    use astrid_events::ipc::Topic;

    // ── Layer 3 enabled-gate tests (issue #672) ──────────────────────

    fn pid(name: &str) -> astrid_core::PrincipalId {
        astrid_core::PrincipalId::new(name).unwrap()
    }

    // ── Run-loop resource-bound resolution (CPU epoch + memory) ──────────
    //
    // These exercise the pure fail-secure branching of `resolve_exemption` /
    // `resolve_run_loop_budget` without wasmtime — the SAME functions the
    // production load path calls (Defect 3: no copies). The capability
    // EXEMPTION axis (not the group-name string, not the capsule manifest) and
    // the fail-secure defaults are the security-critical invariants this
    // feature rests on.

    fn profile_with(
        groups: &[&str],
        grants: &[&str],
        revokes: &[&str],
    ) -> astrid_core::profile::PrincipalProfile {
        astrid_core::profile::PrincipalProfile {
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            grants: grants.iter().map(|s| (*s).to_string()).collect(),
            revokes: revokes.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        }
    }

    fn builtin_groups() -> astrid_core::GroupConfig {
        astrid_core::GroupConfig::builtin_only()
    }

    #[test]
    fn budget_admin_run_loop_is_exempt_via_capability() {
        // Admin holds `*`, which matches CAP_RESOURCES_UNBOUNDED — exempt with
        // NO special-case group-name match. This is the single-tenant `default`
        // principal's normal case.
        let p = profile_with(&["admin"], &[], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("default"), true);
        assert!(b.exempt, "admin must be exempt via the `*` capability");
        assert!(!b.bound_run_loop);
        assert_eq!(b.window_ticks, None);
    }

    #[test]
    fn budget_non_admin_run_loop_is_bounded() {
        let p = profile_with(&["agent"], &[], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert!(!b.exempt, "agent must NOT be exempt");
        assert!(b.bound_run_loop);
        // Default profile timeout (300s) clamps to the default window.
        assert_eq!(b.window_ticks, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS));
        assert_eq!(b.mem_bytes, WASM_MAX_MEMORY_BYTES);
    }

    #[test]
    fn budget_capability_grant_exempts_non_admin() {
        // A non-admin principal explicitly granted the unbounded capability is
        // exempt — proving the axis is the CAPABILITY, not the group.
        let p = profile_with(&["agent"], &[astrid_core::CAP_RESOURCES_UNBOUNDED], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert!(b.exempt, "explicit grant of the capability must exempt");
        assert!(!b.bound_run_loop);
    }

    #[test]
    fn budget_net_bind_capability_exempts_non_admin() {
        // FIX 1: the operator-GRANTED net_bind capability on the principal
        // profile exempts (the cli proxy case). This is a DIFFERENT axis from
        // the capsule manifest's `net_bind` field, which is untrusted and no
        // longer grants exemption.
        let p = profile_with(&["agent"], &[astrid_core::CAP_NET_BIND], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("cli"), true);
        assert!(
            b.exempt,
            "granted net_bind capability must exempt the uplink"
        );
        assert!(!b.bound_run_loop);
    }

    #[test]
    fn budget_uplink_capability_exempts_non_admin() {
        let p = profile_with(&["agent"], &[astrid_core::CAP_UPLINK], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("uplink"), true);
        assert!(b.exempt, "granted uplink capability must exempt the daemon");
        assert!(!b.bound_run_loop);
    }

    #[test]
    fn budget_manifest_declaration_without_grant_is_bounded() {
        // FIX 1, the closed hole: a capsule that merely DECLARES uplink /
        // net_bind in its OWN manifest, whose load principal does NOT hold the
        // granted capability, is BOUNDED. The manifest is not an input to the
        // exemption decision at all — `resolve_run_loop_budget` only sees the
        // owner profile + group config, never the manifest. A plain agent with
        // no net_bind/uplink/unbounded grant is bounded regardless of what its
        // capsule manifest claims.
        let p = profile_with(&["agent"], &[], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("self-declarer"), true);
        assert!(
            !b.exempt,
            "a capsule cannot self-exempt by declaring net_bind/uplink in its manifest"
        );
        assert!(b.bound_run_loop);
    }

    #[test]
    fn budget_revoke_overrides_admin_exemption() {
        // Admin (`*`) but with EVERY exemption capability revoked: revokes
        // win, so the run-loop is BOUNDED. Proves revoke precedence across all
        // three exemption strings.
        let p = profile_with(
            &["admin"],
            &[],
            &[
                astrid_core::CAP_RESOURCES_UNBOUNDED,
                astrid_core::CAP_NET_BIND,
                astrid_core::CAP_UPLINK,
            ],
        );
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert!(
            !b.exempt,
            "revoking all exemption capabilities must override the admin `*` grant"
        );
        assert!(b.bound_run_loop);
    }

    #[test]
    fn budget_missing_profile_is_fail_secure_bounded() {
        // Resolve failure (None profile) → bounded with the DEFAULT finite
        // window, never exempt.
        let g = builtin_groups();
        let b = resolve_run_loop_budget(None, Some(&g), &pid("ghost"), true);
        assert!(!b.exempt, "an unidentifiable principal must NOT be exempt");
        assert!(b.bound_run_loop);
        assert_eq!(b.window_ticks, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS));
        assert_eq!(b.mem_bytes, WASM_MAX_MEMORY_BYTES);
    }

    #[test]
    fn budget_missing_group_config_is_fail_secure_bounded() {
        // GroupConfig unthreaded (None) → cannot resolve the capability → not
        // exempt → bounded. Closes the "kernel didn't thread it" hole.
        let p = profile_with(&["admin"], &[], &[]);
        let b = resolve_run_loop_budget(Some(&p), None, &pid("alice"), true);
        assert!(!b.exempt, "missing GroupConfig must fail-secure to bounded");
        assert!(b.bound_run_loop);
    }

    #[test]
    fn budget_non_run_loop_capsule_is_not_bounded() {
        // No `run` export → pooled interceptor, not a run-loop. The run-loop
        // bound does not apply (interceptors are capped per-invocation).
        let p = profile_with(&["agent"], &[], &[]);
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), false);
        assert!(!b.bound_run_loop);
        assert_eq!(b.window_ticks, None);
        assert_eq!(b.mem_bytes, WASM_MAX_MEMORY_BYTES);
    }

    #[test]
    fn budget_uses_owner_memory_quota_for_bound_run_loop() {
        let mut p = profile_with(&["agent"], &[], &[]);
        p.quotas.max_memory_bytes = 32 * 1024 * 1024;
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert!(b.bound_run_loop);
        assert_eq!(b.mem_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn budget_tighter_timeout_shrinks_window() {
        // A short owner timeout pins a tighter epoch window (never longer than
        // the default). 2s = 20 ticks < 50-tick default.
        let mut p = profile_with(&["agent"], &[], &[]);
        p.quotas.max_timeout_secs = 2;
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert_eq!(b.window_ticks, Some(20));
    }

    #[test]
    fn budget_long_timeout_clamps_to_default_window() {
        // A long owner timeout does NOT widen the window past the default, so
        // the worst-case starvation grace stays bounded.
        let mut p = profile_with(&["agent"], &[], &[]);
        p.quotas.max_timeout_secs = 3600;
        let g = builtin_groups();
        let b = resolve_run_loop_budget(Some(&p), Some(&g), &pid("alice"), true);
        assert_eq!(b.window_ticks, Some(DEFAULT_RUN_LOOP_WINDOW_TICKS));
    }

    // ── resolve_exemption (the FIX 1 decision, directly) ─────────────────

    #[test]
    fn exemption_requires_both_profile_and_groups() {
        let p = profile_with(&["admin"], &[], &[]);
        let g = builtin_groups();
        assert!(resolve_exemption(Some(&p), Some(&g), &pid("a")));
        assert!(!resolve_exemption(None, Some(&g), &pid("a")));
        assert!(!resolve_exemption(Some(&p), None, &pid("a")));
        assert!(!resolve_exemption(None, None, &pid("a")));
    }

    #[test]
    fn exemption_is_false_for_plain_agent() {
        let p = profile_with(&["agent"], &[], &[]);
        let g = builtin_groups();
        assert!(!resolve_exemption(Some(&p), Some(&g), &pid("a")));
    }

    // ── resolve_audit_firehose (the audit-scope decision, directly) ──────
    //
    // Same discipline as the resolve_exemption tests: drive the PURE
    // function the production load path calls (no copies). The firehose is
    // resolved the PRIVILEGED way (profile + group config), NEVER from the
    // manifest — encoded structurally (the fn has no manifest input) and
    // pinned positively/negatively below.

    #[test]
    fn audit_firehose_cap_literal_pinned() {
        // The capsule-local literal must stay byte-equal to the gateway's
        // `events::AUDIT_FIREHOSE_CAP` and the core grammar's `audit:read_all`
        // so the three references can never drift.
        assert_eq!(AUDIT_FIREHOSE_CAP, "audit:read_all");
    }

    #[test]
    fn audit_firehose_holder_true() {
        // admin holds `audit:read_all` via `*` — the firehose case.
        let admin = profile_with(&["admin"], &[], &[]);
        let g = builtin_groups();
        assert!(resolve_audit_firehose(
            Some(&admin),
            Some(&g),
            &pid("default")
        ));

        // A non-admin explicitly granted the capability also gets the firehose.
        let granted = profile_with(&["agent"], &[AUDIT_FIREHOSE_CAP], &[]);
        assert!(resolve_audit_firehose(
            Some(&granted),
            Some(&g),
            &pid("alice")
        ));
    }

    #[test]
    fn audit_firehose_fail_secure_false() {
        let g = builtin_groups();
        let admin = profile_with(&["admin"], &[], &[]);
        // No owner profile → false (own-principal scoping).
        assert!(!resolve_audit_firehose(None, Some(&g), &pid("ghost")));
        // No group config, even for admin `*` → false (load-bearing config).
        assert!(!resolve_audit_firehose(Some(&admin), None, &pid("default")));
        // A profile WITHOUT the capability → false.
        let plain = profile_with(&["agent"], &[], &[]);
        assert!(!resolve_audit_firehose(
            Some(&plain),
            Some(&g),
            &pid("alice")
        ));
    }

    #[test]
    fn audit_firehose_revoke_overrides_admin() {
        // admin `*` but with the firehose capability revoked: revokes win →
        // scoped, not firehose. Proves revoke precedence on the audit path.
        let p = profile_with(&["admin"], &[], &[AUDIT_FIREHOSE_CAP]);
        let g = builtin_groups();
        assert!(
            !resolve_audit_firehose(Some(&p), Some(&g), &pid("alice")),
            "revoking audit:read_all must override the admin `*` grant"
        );
    }

    #[test]
    fn audit_firehose_ignores_manifest_by_construction() {
        // The decision is profile-only: a principal whose profile lacks
        // audit:read_all is `false` no matter what an ipc_subscribe array
        // in some Capsule.toml claims — the function has NO manifest input,
        // so a capsule can never self-grant the firehose. The positive case
        // requires the operator-owned grant.
        let g = builtin_groups();
        let no_cap = profile_with(&["agent"], &[], &[]);
        assert!(!resolve_audit_firehose(
            Some(&no_cap),
            Some(&g),
            &pid("self-declarer")
        ));
        let with_cap = profile_with(&["agent"], &[AUDIT_FIREHOSE_CAP], &[]);
        assert!(resolve_audit_firehose(
            Some(&with_cap),
            Some(&g),
            &pid("self-declarer")
        ));
    }

    // ── CPU-rate DENY gate (PR2, the security boundary) ──────────────────
    //
    // These drive `cpu_rate_deny` — the SAME function the production
    // `invoke_interceptor` calls (no copies). Inputs are injected, including a
    // synthetic `now: Instant`, so the gate is exercised with no wasmtime and
    // no real sleep. `cpu_rate_deny` returns `Some(reason)` to deny / `None` to
    // admit; the call site wraps `Some` in `Ok(InterceptResult::Deny)`.

    // A budget small enough that one recorded charge blows it.
    const RATE_BUDGET: u64 = 1_000;

    /// Drive a principal far over `RATE_BUDGET` in the limiter's current window.
    fn saturate(
        rl: &crate::FuelRateLimiter,
        p: &astrid_core::PrincipalId,
        now: std::time::Instant,
    ) {
        rl.record(p, RATE_BUDGET * 100, now);
    }

    /// A profile pinning the small test budget, in the given groups/grants.
    fn budgeted_profile(
        groups: &[&str],
        grants: &[&str],
    ) -> astrid_core::profile::PrincipalProfile {
        let mut p = profile_with(groups, grants, &[]);
        p.quotas.max_cpu_fuel_per_sec = RATE_BUDGET;
        p
    }

    #[test]
    fn rate_gate_bounded_principal_is_denied_when_over_budget() {
        // A plain agent over its budget IS denied — the core enforcement.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("alice");
        let prof = budgeted_profile(&["agent"], &[]);
        let g = builtin_groups();
        saturate(&rl, &p, now);
        let decision = cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, now);
        assert!(
            decision.is_some(),
            "a bounded principal over budget must be denied"
        );
        assert!(
            decision.unwrap().contains("alice"),
            "the deny reason must name the principal"
        );
    }

    #[test]
    fn rate_gate_self_heals_after_window_rolls() {
        // Anti-brick guarantee, pinned on the PRODUCTION entry point: a bounded
        // principal denied while over budget is ADMITTED again once its
        // 1-second window rolls. A budget throttles; it never permanently
        // bricks. Injected clock — no real sleep.
        let rl = crate::FuelRateLimiter::default();
        let t0 = std::time::Instant::now();
        let p = pid("alice");
        let prof = budgeted_profile(&["agent"], &[]);
        let g = builtin_groups();
        saturate(&rl, &p, t0);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, t0).is_some(),
            "over budget at t0 -> denied"
        );
        let t1 = t0 + std::time::Duration::from_millis(1_001);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, t1).is_none(),
            "after the 1s window rolls -> admitted again (no permanent brick)"
        );
    }

    #[test]
    fn rate_gate_exempt_principal_not_denied_even_over_budget() {
        // system:resources:unbounded holder: NEVER denied, even pinned way over
        // budget. Exemption short-circuits before the window is even consulted.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("uplink");
        let prof = budgeted_profile(&["agent"], &[astrid_core::CAP_RESOURCES_UNBOUNDED]);
        let g = builtin_groups();
        saturate(&rl, &p, now);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, now).is_none(),
            "an exempt (unbounded) principal must never be CPU-rate denied"
        );
    }

    #[test]
    fn rate_gate_admin_with_group_config_is_never_gated() {
        // Admin holds `*` => exempt via capability when group_config is present.
        // Even saturated, admin is admitted.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("default");
        let prof = budgeted_profile(&["admin"], &[]);
        let g = builtin_groups();
        saturate(&rl, &p, now);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, now).is_none(),
            "admin (`*`) with group_config must never be CPU-rate gated"
        );
    }

    #[test]
    fn rate_gate_missing_group_config_makes_admin_bounded() {
        // Regression proving group_config is LOAD-BEARING: the SAME admin
        // profile, but with group_config unthreaded (None), can no longer
        // resolve its `*` exemption, so it fails CLOSED to bounded and — over
        // budget — IS denied. If group_config were ignored this would wrongly
        // admit.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("default");
        let prof = budgeted_profile(&["admin"], &[]);
        saturate(&rl, &p, now);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), None, &p, now).is_some(),
            "missing group_config must fail-secure: admin becomes bounded and is denied over budget"
        );
    }

    #[test]
    fn rate_gate_reads_latest_group_config_snapshot() {
        let live_groups = Arc::new(ArcSwap::from_pointee(builtin_groups()));
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let principal = pid("operator-1");
        let prof = budgeted_profile(&["ops-team"], &[]);
        saturate(&rl, &principal, now);

        let before = live_groups.load_full();
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(before.as_ref()), &principal, now).is_some(),
            "before the group exists, an over-budget custom-group principal fails closed"
        );

        let mut updated = builtin_groups();
        updated.groups.insert(
            "ops-team".to_owned(),
            astrid_core::Group {
                capabilities: vec![astrid_core::CAP_RESOURCES_UNBOUNDED.to_owned()],
                description: Some("runtime-created ops group".to_owned()),
                unsafe_admin: false,
            },
        );
        live_groups.store(Arc::new(updated));

        let after = live_groups.load_full();
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(after.as_ref()), &principal, now).is_none(),
            "later invocations must observe runtime group config updates"
        );
    }

    #[test]
    fn rate_gate_zero_budget_is_unlimited() {
        // budget == 0 => unlimited; a bounded principal saturated way past any
        // finite budget is still admitted (must not become deny-all).
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("alice");
        let mut prof = profile_with(&["agent"], &[], &[]);
        prof.quotas.max_cpu_fuel_per_sec = 0;
        let g = builtin_groups();
        saturate(&rl, &p, now);
        assert!(
            cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, now).is_none(),
            "a zero (unlimited) budget must never deny, even when saturated"
        );
    }

    #[test]
    fn rate_gate_no_profile_uses_generous_default_budget() {
        // No profile (tests / single-tenant) => DEFAULT_MAX_CPU_FUEL_PER_SEC,
        // still enforced but generous: a principal under the default is
        // admitted, and one driven past the default is denied. Proves the
        // default is wired AND enforced.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("anon");
        let g = builtin_groups();
        // Under the (very large) default: admitted.
        rl.record(&p, 1_000, now);
        assert!(
            cpu_rate_deny(&rl, None, Some(&g), &p, now).is_none(),
            "a principal under the default budget is admitted"
        );
        // Past the default: denied.
        rl.record(&p, astrid_core::profile::DEFAULT_MAX_CPU_FUEL_PER_SEC, now);
        assert!(
            cpu_rate_deny(&rl, None, Some(&g), &p, now).is_some(),
            "with no profile the generous DEFAULT budget is still enforced"
        );
    }

    #[test]
    fn rate_gate_deny_is_ok_deny_not_err() {
        // The single most important regression: the gate's deny must surface as
        // `Ok(InterceptResult::Deny { .. })`, NEVER `Err`. The dispatcher HALTS
        // the chain on `Ok(Deny)` but CONTINUES on `Err` (see dispatcher.rs), so
        // an `Err`-based deny would be a SILENT enforcement bypass. We mirror
        // the call site's wrapping exactly and assert the result is the Deny
        // variant carrying the reason.
        let rl = crate::FuelRateLimiter::default();
        let now = std::time::Instant::now();
        let p = pid("alice");
        let prof = budgeted_profile(&["agent"], &[]);
        let g = builtin_groups();
        saturate(&rl, &p, now);

        let reason = cpu_rate_deny(&rl, Some(&prof), Some(&g), &p, now)
            .expect("a saturated bounded principal must be denied");
        // EXACTLY how invoke_interceptor wraps it.
        let result: CapsuleResult<crate::capsule::InterceptResult> =
            Ok(crate::capsule::InterceptResult::Deny { reason });

        match result {
            Ok(crate::capsule::InterceptResult::Deny { reason }) => {
                assert!(reason.contains("alice"), "deny reason names the principal");
            },
            Ok(other) => panic!("deny must be InterceptResult::Deny, got {other:?}"),
            Err(e) => panic!(
                "deny must be Ok(Deny), NEVER Err — an Err-deny is a silent \
                 enforcement bypass (dispatcher continues the chain on Err): {e}"
            ),
        }
    }

    // ── epoch_decision (the FIX 2 callback logic, directly) ──────────────

    #[test]
    fn epoch_recv_loop_never_traps_and_resets() {
        // recv_yielded=true → Yield, flag cleared, counter reset to 0 — no
        // matter how high the counter had climbed.
        let (action, recv, windows) = epoch_decision(true, 99, 50, MAX_NO_YIELD_WINDOWS);
        assert_eq!(action, EpochAction::Yield(50));
        assert!(!recv, "flag must be cleared after reading");
        assert_eq!(windows, 0, "a recv resets the no-yield counter");
    }

    #[test]
    fn epoch_no_recv_yields_during_grace_then_interrupts() {
        // A no-recv spinner: Yields (cooperatively, never starving) while the
        // counter is below max, then Interrupts exactly when it reaches max.
        let max = 3u32;
        // window 0 -> 1: yield
        let (a0, _, w0) = epoch_decision(false, 0, 50, max);
        assert_eq!(a0, EpochAction::Yield(50));
        assert_eq!(w0, 1);
        // window 1 -> 2: yield
        let (a1, _, w1) = epoch_decision(false, w0, 50, max);
        assert_eq!(a1, EpochAction::Yield(50));
        assert_eq!(w1, 2);
        // window 2 -> 3 == max: interrupt
        let (a2, _, w2) = epoch_decision(false, w1, 50, max);
        assert_eq!(a2, EpochAction::Interrupt);
        assert_eq!(w2, 3);
    }

    #[test]
    fn epoch_recv_every_window_never_interrupts_driven() {
        // The task's named guarantee, modelled as a DRIVEN feedback loop (not a
        // single shot): a legit recv/accept loop sets `recv_yielded` every
        // window, so feeding `epoch_decision`'s output back into its next call —
        // exactly as the production callback does via HostState — yields forever
        // and NEVER interrupts, even far past MAX_NO_YIELD_WINDOWS windows.
        let max = MAX_NO_YIELD_WINDOWS;
        let mut no_yield = 0u32;
        for window in 0..(max as u64 * 100 + 7) {
            // A recv occurred since the last window (the host fn set the flag).
            let recv_yielded = true;
            let (action, new_recv, new_windows) = epoch_decision(recv_yielded, no_yield, 50, max);
            assert_eq!(
                action,
                EpochAction::Yield(50),
                "a recv-yielding loop must Yield on window {window}, never Interrupt"
            );
            assert!(!new_recv, "the flag is always cleared after reading");
            assert_eq!(new_windows, 0, "every recv resets the no-yield counter");
            no_yield = new_windows;
        }
    }

    #[test]
    fn epoch_single_late_recv_restores_full_grace_driven() {
        // Adversarial boundary: a spinner accrues to max-1 (one window short of
        // the trap), then a SINGLE recv arrives. That recv must reset the
        // counter to 0 so the spinner gets the FULL grace again before any
        // trap — there must be no "primed" early interrupt carried across the
        // reset. Drive `epoch_decision`'s output back into itself.
        let max = MAX_NO_YIELD_WINDOWS;
        assert!(max >= 2, "test assumes a multi-window grace");
        let mut no_yield = 0u32;
        // Spin up to max-1 (still yielding, not yet trapped).
        for _ in 0..(max - 1) {
            let (action, _, w) = epoch_decision(false, no_yield, 50, max);
            assert_eq!(action, EpochAction::Yield(50));
            no_yield = w;
        }
        assert_eq!(no_yield, max - 1, "primed one window short of the trap");
        // A single recv resets the counter.
        let (action, _, w) = epoch_decision(true, no_yield, 50, max);
        assert_eq!(action, EpochAction::Yield(50));
        assert_eq!(w, 0, "one recv at the brink restores the full grace");
        no_yield = w;
        // Now the spinner must get the FULL grace again: max-1 yields, then trap
        // exactly on the max-th — not one window early.
        for window in 0..(max - 1) {
            let (action, _, w) = epoch_decision(false, no_yield, 50, max);
            assert_eq!(
                action,
                EpochAction::Yield(50),
                "post-reset grace window {window} must Yield, not trap early"
            );
            no_yield = w;
        }
        let (action, _, _) = epoch_decision(false, no_yield, 50, max);
        assert_eq!(
            action,
            EpochAction::Interrupt,
            "trap lands on the full max-th post-reset window, not earlier"
        );
    }

    #[test]
    fn epoch_interrupt_is_immediate_when_max_is_one() {
        // With max=1 the very first no-recv window traps.
        let (action, _, windows) = epoch_decision(false, 0, 10, 1);
        assert_eq!(action, EpochAction::Interrupt);
        assert_eq!(windows, 1);
    }

    #[test]
    fn epoch_counter_does_not_overflow() {
        // saturating_add guards a pathological counter near u32::MAX.
        let (action, _, windows) = epoch_decision(false, u32::MAX, 10, MAX_NO_YIELD_WINDOWS);
        assert_eq!(action, EpochAction::Interrupt);
        assert_eq!(windows, u32::MAX);
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
    /// `invoke_interceptor` future is dropped mid-call, the leased
    /// instance's `PoolCheckout::drop` MUST clear `caller_context`,
    /// `interceptor_active`, and every `invocation_*` field before the
    /// instance returns to the pool, so the next lease observes a
    /// clean HostState. The next test exercises the Drop clear path
    /// directly (without instantiating wasmtime, which would require
    /// a fixture WASM binary).
    #[tokio::test]
    async fn clear_on_drop_clears_invocation_state_on_unwind() {
        use crate::engine::wasm::host_state::HostState;
        use crate::engine::wasm::test_fixtures::minimal_host_state;

        // The clear lives in `PoolCheckout::drop` (engine/wasm/pool.rs);
        // we re-create the same logic here as a free function to keep
        // the test scoped to the contract (each invocation_* field
        // is cleared, interceptor_active flipped back to false) rather
        // than the inner type. This is the cancellation-safety guard
        // for async wasmtime: when the call_async future is dropped
        // mid-invocation, the Drop impl MUST run this clear path
        // synchronously before the leased instance returns to the pool.
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
            Topic::from_raw("x"),
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
            Topic::from_raw("baseline"),
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
            state.caller_context.as_ref().map(|m| m.topic.to_string()),
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
            options_from: None,
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
            options_from: None,
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
            options_from: None,
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
            options_from: None,
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
            options_from: None,
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
            options_from: None,
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
            options_from: None,
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

// ── Wasmtime epoch/memory/fuel integration tests ─────────────────────────
//
// These instantiate REAL guests (minimal core-wasm modules assembled from WAT
// via `Module::new`, which wasmtime accepts directly) on an engine built by
// the production [`build_wasmtime_engine`], and exercise the SAME mechanisms
// the load path applies to the dedicated run-loop Store:
//
//   * run-loop CPU bound — an epoch deadline + `epoch_deadline_callback` whose
//     body calls the PRODUCTION pure [`epoch_decision`] (Defect 3: no copies),
//     reading + writing the `recv_yielded` / `no_yield_windows` state exactly
//     as the load path does. A pure `loop {}` (no recv) is Interrupt-trapped
//     after `MAX_NO_YIELD_WINDOWS` and never starves the worker; a guest that
//     calls a recv-marking host import every iteration survives forever.
//   * memory cap          — `StoreLimitsBuilder::memory_size(cap)` BEFORE
//     `instantiate_async` (the MEMORY-ORDERING fix — `make_state`).
//   * fuel-delta meter     — `INTERCEPTOR_FUEL_BUDGET - get_fuel()` after a
//     call (the kept interceptor measurement).
//
// Core modules (not full WIT components) are deliberate: they exercise the
// SAME wasmtime epoch/`StoreLimits`/fuel primitives the engine relies on with
// zero external `.wasm` fixture and no wasi-sdk/QuickJS component build, so
// they carry none of the CI disk-SIGBUS risk (MEMORY.md
// project_ci_test_disk_sigbus) that gating a component build would. They reuse
// the production `build_wasmtime_engine` + `spawn_epoch_ticker` anchors. The
// pure `resolve_run_loop_budget` / `epoch_decision` tests above gate the
// *policy*; these gate the *enforcement primitive* wired to that policy.
#[cfg(test)]
mod epoch_integration_tests {
    use super::{
        EpochAction, INTERCEPTOR_FUEL_BUDGET, MAX_NO_YIELD_WINDOWS, build_wasmtime_engine,
        epoch_decision, spawn_epoch_ticker,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use wasmtime::{Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};

    /// Minimal run-loop Store state for the epoch callback — mirrors the two
    /// `HostState` fields the production callback touches. Using a tiny struct
    /// (not the full `HostState`) keeps the test free of the entire host
    /// service graph while exercising the IDENTICAL callback wiring.
    struct RunLoopTestState {
        recv_yielded: bool,
        no_yield_windows: u32,
    }

    /// Install the PRODUCTION bound-run-loop epoch callback on `store`.
    ///
    /// This is a byte-for-byte mirror of the load path's bound-run-loop branch:
    /// set the deadline to `window_ticks`, then a callback that reads the
    /// store's `(recv_yielded, no_yield_windows)`, runs the shared
    /// [`epoch_decision`], writes the new state back, and maps the action to
    /// `UpdateDeadline`. The DECISION is the same function production calls; the
    /// test does not reimplement it.
    fn apply_epoch_bound(store: &mut Store<RunLoopTestState>, window_ticks: u64) {
        store.set_fuel(u64::MAX).expect("fuel enabled");
        store.set_epoch_deadline(window_ticks);
        store.epoch_deadline_callback(move |mut cx| {
            let st = cx.data_mut();
            let (action, recv_yielded, no_yield_windows) = epoch_decision(
                st.recv_yielded,
                st.no_yield_windows,
                window_ticks,
                MAX_NO_YIELD_WINDOWS,
            );
            st.recv_yielded = recv_yielded;
            st.no_yield_windows = no_yield_windows;
            Ok(match action {
                EpochAction::Yield(ticks) => wasmtime::UpdateDeadline::Yield(ticks),
                EpochAction::Interrupt => wasmtime::UpdateDeadline::Interrupt,
            })
        });
    }

    /// Assert a guest-call error is the wasmtime epoch INTERRUPT trap.
    ///
    /// Couples to the [`Trap`] enum variant via
    /// [`root_cause`](wasmtime::Error::root_cause) (the documented idiom), NOT
    /// the trap's `Display` string — robust across wasmtime point releases and
    /// stronger than a substring match.
    fn assert_interrupt(err: &wasmtime::Error) {
        let trap = err.root_cause().downcast_ref::<Trap>();
        assert_eq!(
            trap,
            Some(&Trap::Interrupt),
            "expected the epoch-interrupt trap (the CPU bound), got: {err:?}"
        );
    }

    fn unit_module(engine: &Engine, wat: &str) -> Module {
        Module::new(engine, wat).expect("valid wat module")
    }

    /// FIX 2 / DEFECT 3, the core guarantee: a PURE `loop {}` with no recv —
    /// the worst-case spinner — is INTERRUPT-trapped via the PRODUCTION
    /// callback after `MAX_NO_YIELD_WINDOWS` windows, AND does not starve the
    /// worker (the `call_async` future resolves; it does not hang). The empty
    /// `loop $l (br $l)` burns zero fuel, so ONLY the epoch yield/interrupt can
    /// stop it — exactly what the run-loop CPU bound must do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pure_spin_guest_interrupt_trapped_via_production_callback() {
        let engine = build_wasmtime_engine().expect("engine");
        let module = unit_module(
            &engine,
            r#"(module (func (export "run") (loop $l (br $l))))"#,
        );
        let mut store = Store::new(
            &engine,
            RunLoopTestState {
                recv_yielded: false,
                no_yield_windows: 0,
            },
        );
        // Small window so the few grace windows elapse fast.
        apply_epoch_bound(&mut store, 1);
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .expect("instantiate");
        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .expect("run export");

        let ticker = spawn_epoch_ticker(&engine);
        // If the bound works the trap is near-instant; the timeout only fires
        // if the guest never traps (bug) or starves the worker so the future
        // cannot resolve.
        let res =
            tokio::time::timeout(Duration::from_secs(10), run.call_async(&mut store, ())).await;
        drop(ticker);

        let outcome = res.expect("pure-spin guest must not starve the worker / hang");
        let err = outcome.expect_err("pure-spin guest must TRAP, not run forever");
        assert_interrupt(&err);
    }

    /// FIX 2 / DEFECT 3, the no-hang coexistence guarantee: a no-recv `loop {}`
    /// spinner must (a) be `Interrupt`-trapped — its call future RESOLVES with
    /// the interrupt trap, it does not hang — and (b) NOT prevent a concurrent
    /// task from completing meanwhile. The original failure was "a `loop {}`
    /// never yields, starving a tokio worker so the whole runtime wedges"; here
    /// the spinner both terminates (interrupt) and coexists with a probe that
    /// runs to completion. We deliberately do NOT assert single-worker tokio
    /// FAIRNESS (how promptly a busy-yielding task lets timers advance is a
    /// tokio scheduler property, not a property of this fix); the production
    /// daemon is multi-worker and the bound's guarantee is "terminates +
    /// doesn't wedge the runtime", which this proves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_recv_spinner_terminates_and_coexists() {
        let engine = build_wasmtime_engine().expect("engine");
        let module = unit_module(
            &engine,
            r#"(module (func (export "run") (loop $l (br $l))))"#,
        );
        let mut store = Store::new(
            &engine,
            RunLoopTestState {
                recv_yielded: false,
                no_yield_windows: 0,
            },
        );
        // Short window: a few grace windows then interrupt (~300ms).
        apply_epoch_bound(&mut store, 1);
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .expect("instantiate");
        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .expect("run export");

        let ticker = spawn_epoch_ticker(&engine);

        // Concurrent probe that runs to completion alongside the spinner.
        let progress = Arc::new(AtomicU64::new(0));
        let p = progress.clone();
        let probe = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                p.fetch_add(1, Ordering::Relaxed);
            }
        });

        // The spinner's call future must RESOLVE (interrupt), not hang.
        let spin = tokio::time::timeout(Duration::from_secs(10), run.call_async(&mut store, ()));
        let outcome = spin
            .await
            .expect("no-recv spinner must not hang — its future must resolve");
        let err = outcome.expect_err("no-recv spinner must be Interrupt-trapped");
        assert_interrupt(&err);

        let _ = tokio::time::timeout(Duration::from_secs(2), probe).await;
        let ticks = progress.load(Ordering::Relaxed);
        drop(ticker);
        assert_eq!(
            ticks, 10,
            "the concurrent probe must complete — the spinner must not wedge the runtime (got {ticks}/10)"
        );
    }

    /// FIX 2: a guest that calls a recv-marking host import EVERY iteration is
    /// a legitimate recv/accept loop and must NEVER be trapped — the epoch
    /// callback sees `recv_yielded=true` each window, resets the counter, and
    /// `Yield`s forever. We wire an imported `recv` host fn that sets the flag
    /// exactly as the production ipc `recv` host fn does, and a guest that loops
    /// calling it. After many windows (well past MAX_NO_YIELD_WINDOWS) the call
    /// is still running, proving the bound never trips on a healthy loop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_yielding_guest_survives_many_windows() {
        let engine = build_wasmtime_engine().expect("engine");
        // Guest imports `host.recv` and calls it every iteration, with a cheap
        // body between calls. The import sets `recv_yielded`, mirroring the ipc
        // recv host fn.
        let module = unit_module(
            &engine,
            r#"(module
                (import "host" "recv" (func $recv))
                (func (export "run")
                  (loop $l
                    (call $recv)
                    (drop (i32.add (i32.const 1) (i32.const 2)))
                    (br $l))))"#,
        );
        let mut store = Store::new(
            &engine,
            RunLoopTestState {
                recv_yielded: false,
                no_yield_windows: 0,
            },
        );
        apply_epoch_bound(&mut store, 1);
        let mut linker: Linker<RunLoopTestState> = Linker::new(&engine);
        linker
            .func_wrap(
                "host",
                "recv",
                |mut caller: wasmtime::Caller<'_, RunLoopTestState>| {
                    // The production ipc recv host fn sets this on entry.
                    caller.data_mut().recv_yielded = true;
                },
            )
            .expect("wire recv import");
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .expect("instantiate");
        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .expect("run export");

        let ticker = spawn_epoch_ticker(&engine);
        // Run for several windows. A bug that trapped a recv loop would resolve
        // the future with an error inside this window; a healthy loop never
        // returns, so the timeout elapses with the call still pending — which
        // is the PASS signal here.
        let res =
            tokio::time::timeout(Duration::from_millis(1500), run.call_async(&mut store, ())).await;
        drop(ticker);
        assert!(
            res.is_err(),
            "a recv-yielding guest must NEVER trap — it should still be running \
             when the wall-clock budget elapses, but it returned: {res:?}"
        );
    }

    /// MEMORY-ORDERING fix: the run-loop linear-memory cap is baked into
    /// `StoreLimits` BEFORE `instantiate_async`, so a guest whose INITIAL
    /// declared memory exceeds the owner quota fails AT INSTANTIATION (not after
    /// it has already allocated). 3 initial pages (192 KiB) against a 1-page
    /// (64 KiB) cap must fail; a 1-page module must succeed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn memory_cap_enforced_at_instantiation() {
        struct MemState {
            limits: StoreLimits,
        }
        let engine = build_wasmtime_engine().expect("engine");
        let cap = 64 * 1024; // one wasm page

        let over = unit_module(&engine, r#"(module (memory (export "m") 3))"#);
        let mut store = Store::new(
            &engine,
            MemState {
                limits: StoreLimitsBuilder::new().memory_size(cap).build(),
            },
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(INTERCEPTOR_FUEL_BUDGET).expect("fuel");
        store.set_epoch_deadline(u64::MAX);
        let linker = Linker::new(&engine);
        let over_res = linker.instantiate_async(&mut store, &over).await;
        assert!(
            over_res.is_err(),
            "initial memory above the cap MUST fail at instantiation"
        );

        let ok = unit_module(&engine, r#"(module (memory (export "m") 1))"#);
        let mut store = Store::new(
            &engine,
            MemState {
                limits: StoreLimitsBuilder::new().memory_size(cap).build(),
            },
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(INTERCEPTOR_FUEL_BUDGET).expect("fuel");
        store.set_epoch_deadline(u64::MAX);
        linker
            .instantiate_async(&mut store, &ok)
            .await
            .expect("a within-cap initial memory MUST instantiate");
    }

    /// KEPT interceptor MEASUREMENT: the per-invocation fuel delta
    /// `INTERCEPTOR_FUEL_BUDGET - get_fuel()` is the exact deterministic
    /// instruction count, stable across repeated runs of the same deterministic
    /// guest (the property the per-principal ledger relies on). A counting loop
    /// of N iterations costs a fixed, reproducible amount of fuel; N and 2N show
    /// the delta scales with work and the same N yields the identical delta.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fuel_delta_is_exact_and_deterministic() {
        let engine = build_wasmtime_engine().expect("engine");
        let module = unit_module(
            &engine,
            r#"(module
                (func (export "count") (param i32) (result i32)
                  (local $i i32) (local $acc i32)
                  (block $done
                    (loop $l
                      (br_if $done (i32.ge_s (local.get $i) (local.get 0)))
                      (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
                      (local.set $i (i32.add (local.get $i) (i32.const 1)))
                      (br $l)))
                  (local.get $acc)))"#,
        );

        async fn run_n(engine: &Engine, module: &Module, n: i32) -> (i32, u64) {
            let mut store = Store::new(engine, ());
            store.set_fuel(INTERCEPTOR_FUEL_BUDGET).expect("fuel");
            store.set_epoch_deadline(u64::MAX);
            let linker = Linker::new(engine);
            let instance = linker
                .instantiate_async(&mut store, module)
                .await
                .expect("instantiate");
            let count = instance
                .get_typed_func::<i32, i32>(&mut store, "count")
                .expect("count export");
            let out = count.call_async(&mut store, n).await.expect("call");
            let after = store.get_fuel().expect("fuel enabled");
            (out, INTERCEPTOR_FUEL_BUDGET.saturating_sub(after))
        }

        let (out_a, used_a1) = run_n(&engine, &module, 1000).await;
        let (out_a2, used_a2) = run_n(&engine, &module, 1000).await;
        let (_out_b, used_b) = run_n(&engine, &module, 2000).await;

        assert_eq!(out_a, 1000, "guest must compute the loop result");
        assert_eq!(out_a2, 1000);
        assert_eq!(
            used_a1, used_a2,
            "fuel delta must be deterministic for identical guest work"
        );
        assert!(
            used_b > used_a1,
            "fuel delta must grow with work: used(2000)={used_b} \
             must exceed used(1000)={used_a1}"
        );
        assert!(
            used_a1 > 0 && used_a1 < INTERCEPTOR_FUEL_BUDGET,
            "fuel delta must be a real, bounded count: {used_a1}"
        );
    }

    /// EXEMPT run-loop end-to-end: the exempt branch sets the epoch deadline to
    /// `u64::MAX` with NO callback, so the CPU bound is gone. A finite-but-heavy
    /// terminating workload that would be epoch-trapped under a bound run-loop
    /// runs to completion when exempt. (A genuinely infinite `loop {}` would pin
    /// a worker forever with no yield — the admin trade-off in production — so a
    /// terminating loop is used to prove "unmetered" without hanging the test.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exempt_run_loop_is_unmetered() {
        let engine = build_wasmtime_engine().expect("engine");
        let module = unit_module(
            &engine,
            r#"(module
                (func (export "count") (param i32) (result i32)
                  (local $i i32) (local $acc i32)
                  (block $done
                    (loop $l
                      (br_if $done (i32.ge_s (local.get $i) (local.get 0)))
                      (local.set $acc (i32.add (local.get $acc) (i32.const 1)))
                      (local.set $i (i32.add (local.get $i) (i32.const 1)))
                      (br $l)))
                  (local.get $acc)))"#,
        );
        let heavy: i32 = 5_000_000;
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX).expect("fuel"); // exempt branch
        store.set_epoch_deadline(u64::MAX); // exempt branch — no callback
        let linker = Linker::new(&engine);
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .expect("instantiate");
        let count = instance
            .get_typed_func::<i32, i32>(&mut store, "count")
            .expect("count export");

        let ticker = spawn_epoch_ticker(&engine);
        let out = count
            .call_async(&mut store, heavy)
            .await
            .expect("an exempt (u64::MAX, no-callback) run-loop must NOT trap");
        drop(ticker);
        assert_eq!(out, heavy, "exempt guest must complete the full workload");
    }
}
