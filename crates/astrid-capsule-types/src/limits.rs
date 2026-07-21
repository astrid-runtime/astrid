//! Host-derived runtime concurrency limits for the WASM capsule engine.
//!
//! Phase 2 splits the single vestigial `host_semaphore` (a `cores - 2` cap that
//! gated *every* host call, blocking and async alike) into two independently
//! sized gates, because the two classes have opposite costs:
//!
//! * **blocking** host calls (`block_in_place` + `block_on`: KV, identity, sys,
//!   fs, the net/process security gates, DNS, sockets) PIN a tokio worker for
//!   the whole permit-held wait, so their ceiling must track CPU cores — let
//!   too many run and blocking host work starves the scheduler.
//! * **async-I/O** host calls (`.await` real I/O directly: HTTP, `ipc::recv`)
//!   FREE the worker while pending, so cores are not the bound — file
//!   descriptors are, since each in-flight call may hold a socket. This is the
//!   outbound-throughput gate the LLM path rides on (`astrid#816`).
//!
//! Each knob therefore keys off a *different* host resource. Values are read
//! ONCE at construction and become ceilings; an operator overrides any of them
//! through the `[capsule]` config section (which also maps to the
//! `ASTRID_CAPSULE_*` env vars and the daemon's CLI flags). Precedence is
//! resolved by the caller (CLI > config file > env > host-derived default); a
//! `None` override here means "use the host-derived default".

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread::available_parallelism;
use std::time::Duration;

/// Permits reserved for the tokio scheduler + event dispatch so blocking host
/// work can never consume every worker. Doubles as the floor for blocking
/// concurrency on small hosts.
const SCHED_RESERVE: usize = 2;

/// Async-I/O permits granted per CPU core before the fd clamp applies. Async
/// host calls do not pin a worker, so this scales generously with machine size
/// and is bounded by the descriptor limit rather than the core count.
const IO_PER_CORE: usize = 64;

/// Floor for async-I/O concurrency, so even a 1-core / low-fd host keeps a
/// usable amount of outbound parallelism.
const IO_MIN: usize = 64;

/// Pooled instances granted per CPU core (the dynamic pool's *max*, the
/// concurrency ceiling for a capsule's interceptor invocations).
const POOL_PER_CORE: usize = 2;

/// Floor for the instance-pool max, so even a small host keeps useful
/// per-capsule concurrency (and is not *below* the old fixed value on a typical
/// box: an 8-core host resolves to 16, matching the previous constant).
const POOL_MIN: usize = 8;

/// Ceiling for the host-derived instance-pool max. Each pooled instance is a
/// linear memory (capped per-invocation), so the default is bounded to avoid a
/// large worst-case footprint on big hosts; an operator who wants more sets
/// `instance_pool_size` explicitly. A RAM-budget-derived ceiling lands with the
/// per-principal memory ledger.
const POOL_MAX: usize = 64;

/// Instances kept warm (eagerly built, never evicted) so a burst does not pay
/// instantiate latency for the first few invocations. The pool grows lazily
/// above this toward the max and an idle timer reclaims back down to it.
const WARM_MIN_IDLE: usize = 4;

/// Maximum redirect hops the host follows by default, and the caller ceiling a
/// per-request `max-redirects` clamps DOWN to. The single source of truth for
/// the redirect ceiling: the request-path SSRF airlock references this value.
pub const MAX_HTTP_REDIRECTS: usize = 10;

/// CPU cores reported for this process, honouring the cgroup CPU quota on Linux
/// (`available_parallelism` reads `sched_getaffinity` / `cpu.max`). Falls back
/// to a conservative [`SCHED_RESERVE`] if the count cannot be determined.
fn cores() -> usize {
    available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(SCHED_RESERVE)
}

/// Host-derived default for the **blocking** host-call semaphore: `cores -
/// SCHED_RESERVE`, floored at [`SCHED_RESERVE`].
///
/// Deliberately tight — blocking host calls pin a tokio worker, so this must
/// not approach the worker-pool size or blocking host work starves the
/// scheduler and event dispatch.
#[must_use]
pub fn host_blocking_concurrency_default() -> usize {
    cores().saturating_sub(SCHED_RESERVE).max(SCHED_RESERVE)
}

/// Host-derived default for the **async-I/O** host-call semaphore: `cores *
/// IO_PER_CORE` floored at [`IO_MIN`], then clamped to half the process
/// file-descriptor soft limit (`RLIMIT_NOFILE`).
///
/// Async host calls free the worker while pending, so cores are not the bound;
/// each in-flight call may hold a socket, so the descriptor limit is. The
/// half-budget leaves descriptors for listeners, the KV store, log files, and
/// the uplink socket — the daemon is one process among many and must not claim
/// every fd. When the fd limit is unreadable or unbounded the clamp is skipped.
///
/// On an fd-scarce host the clamp wins and the result can fall **below**
/// [`IO_MIN`]: the clamp is floored at `1`, not `IO_MIN`, so the gate stays
/// strictly bounded by the available descriptors (preventing `EMFILE`) while
/// still guaranteeing at least one permit so it never wedges.
#[must_use]
pub fn host_io_concurrency_default() -> usize {
    let by_cores = cores().saturating_mul(IO_PER_CORE).max(IO_MIN);
    match fd_soft_limit() {
        // Floor the clamp at 1, NOT IO_MIN: flooring at IO_MIN would let the
        // result exceed `soft / 2` on a low-fd host (e.g. soft=50 → 25 < 64),
        // re-opening the EMFILE risk this clamp exists to close.
        Some(soft) => by_cores.min((soft / 2).max(1)),
        None => by_cores,
    }
}

/// Host-derived process-wide ceiling for persistent network streams.
///
/// A stream occupies a file descriptor for its whole lifetime. Taking half of
/// the already fd-clamped async-I/O budget reserves at most one quarter of
/// `RLIMIT_NOFILE` for persistent capsule streams and leaves the rest for
/// in-flight I/O, listeners, storage, logs, and unrelated descriptors.
#[must_use]
pub fn host_net_stream_limit_default() -> usize {
    (host_io_concurrency_default() / 2).max(1)
}

/// Process-wide admission budget shared by every capsule engine and Store.
/// Lowering the limit is non-destructive: existing streams remain valid and
/// new admissions pause until usage falls below the new ceiling.
#[derive(Debug)]
pub struct NetStreamBudget {
    limit: AtomicUsize,
    active: AtomicUsize,
    available: event_listener::Event,
}

impl NetStreamBudget {
    /// Construct a stream budget. Programmatic zero is clamped to one; config
    /// and CLI validation reject explicit zero earlier with a clearer error.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit.max(1)),
            active: AtomicUsize::new(0),
            available: event_listener::Event::new(),
        }
    }

    /// Atomically acquire one stream slot and return its RAII lease.
    #[must_use]
    pub fn try_acquire(self: &Arc<Self>) -> Option<NetStreamLease> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit.load(Ordering::Acquire)).then_some(active + 1)
            })
            .ok()?;
        Some(NetStreamLease {
            budget: Arc::clone(self),
        })
    }

    /// Change the admission ceiling without disrupting existing streams.
    pub fn set_limit(&self, limit: usize) {
        let limit = limit.max(1);
        let previous = self.limit.swap(limit, Ordering::AcqRel);
        if limit > previous {
            self.available.notify(usize::MAX);
        }
    }

    /// Current admission ceiling.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    /// Current number of admitted live streams.
    #[must_use]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Whether a new stream can be admitted at this instant.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.active() < self.limit()
    }

    /// Wait without polling until at least one stream slot may be available.
    /// Callers must still use [`try_acquire`](Self::try_acquire): another task
    /// may win the slot between this wake and admission.
    pub async fn wait_available(&self) {
        loop {
            let listener = self.available.listen();
            if self.has_capacity() {
                return;
            }
            listener.await;
        }
    }
}

impl Default for NetStreamBudget {
    fn default() -> Self {
        Self::new(host_net_stream_limit_default())
    }
}

/// RAII ownership of one slot in a [`NetStreamBudget`].
#[derive(Debug)]
pub struct NetStreamLease {
    budget: Arc<NetStreamBudget>,
}

impl Drop for NetStreamLease {
    fn drop(&mut self) {
        let previous = self.budget.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "net stream budget underflow");
        self.budget.available.notify(1);
    }
}

/// Host-derived default for the dynamic instance pool's **max** size — the
/// ceiling on a capsule's concurrent interceptor invocations.
///
/// `cores * POOL_PER_CORE`, clamped to `[POOL_MIN, POOL_MAX]`. Replaces the old
/// fixed `INSTANCE_POOL_SIZE = 16`: it scales with the machine (more
/// concurrency on big hosts, less eager memory on small ones) instead of one
/// magic number. The pool warm-starts well below this and grows lazily, so the
/// max bounds the peak, not the resting footprint.
#[must_use]
pub fn host_instance_pool_size_default() -> usize {
    cores()
        .saturating_mul(POOL_PER_CORE)
        .clamp(POOL_MIN, POOL_MAX)
}

/// Process file-descriptor soft limit (`RLIMIT_NOFILE`), if readable.
///
/// `None` on non-Unix, on read error, or when the limit is unbounded
/// (`RLIM_INFINITY`, which `usize::try_from` either widens past any real
/// `by_cores` value or rejects on 32-bit) — callers then skip the fd clamp.
#[cfg(unix)]
fn fd_soft_limit() -> Option<usize> {
    use nix::sys::resource::{Resource, getrlimit};

    let (soft, _hard) = getrlimit(Resource::RLIMIT_NOFILE).ok()?;
    let soft = usize::try_from(soft).ok()?;
    // A zero limit would pathologically clamp I/O to the floor; treat the
    // (impossible-in-practice) value as "unknown" and skip the clamp.
    (soft > 0).then_some(soft)
}

#[cfg(not(unix))]
fn fd_soft_limit() -> Option<usize> {
    None
}

/// Resolved per-host runtime limits for the WASM capsule engine, handed from
/// the daemon down to every `WasmEngine` (mirrors the
/// [`FuelLedger`](crate::FuelLedger) plumbing).
///
/// Each field is the operator override when set, else the host-derived default.
/// `Copy` so the kernel forwards it as a plain value through the loader rather
/// than threading a shared handle.
#[derive(Debug, Clone, Copy)]
pub struct CapsuleRuntimeLimits {
    /// Ceiling on concurrent **blocking** host calls (`block_in_place` +
    /// `block_on`); sizes the blocking host semaphore.
    pub blocking_concurrency: usize,
    /// Ceiling on concurrent **async-I/O** host calls (`.await` real I/O);
    /// sizes the I/O host semaphore.
    pub io_concurrency: usize,
    /// **Max** size of a capsule's dynamic instance pool — the ceiling on its
    /// concurrent interceptor invocations. The pool warm-starts below this and
    /// grows lazily toward it. (Run-loop and `host_process` capsules are pinned
    /// to a single Store regardless and ignore this.)
    pub instance_pool_size: usize,
}

impl CapsuleRuntimeLimits {
    /// Resolve from optional operator overrides, falling back to the
    /// host-derived default for any field left `None`. Every ceiling is clamped
    /// to at least 1 (fail-secure: a zero would wedge a host-call class or
    /// leave a capsule with no instance to lease, rather than merely throttle).
    #[must_use]
    pub fn resolve(
        blocking_concurrency: Option<usize>,
        io_concurrency: Option<usize>,
        instance_pool_size: Option<usize>,
    ) -> Self {
        Self {
            blocking_concurrency: blocking_concurrency
                .unwrap_or_else(host_blocking_concurrency_default)
                .max(1),
            io_concurrency: io_concurrency
                .unwrap_or_else(host_io_concurrency_default)
                .max(1),
            instance_pool_size: instance_pool_size
                .unwrap_or_else(host_instance_pool_size_default)
                .max(1),
        }
    }

    /// Warm-start size for an interceptor pool: [`WARM_MIN_IDLE`] instances,
    /// never exceeding the pool max. The idle-eviction timer reclaims back down
    /// to this. (Single-Store carve-outs pass `max == min_idle == 1`.)
    #[must_use]
    pub fn instance_pool_min_idle(self) -> usize {
        WARM_MIN_IDLE.min(self.instance_pool_size).max(1)
    }
}

impl Default for CapsuleRuntimeLimits {
    /// All-host-derived limits (no operator overrides).
    fn default() -> Self {
        Self::resolve(None, None, None)
    }
}

/// Resolved operator HTTP host policy for `astrid:http`, handed from the daemon
/// down to every `HostState` (mirrors the [`CapsuleRuntimeLimits`] plumbing).
/// Resolved once from the `[http]` config section; the kernel only stores and
/// forwards this `Copy` value.
///
/// These are **operator policy**, set by the trust root. The operator MAY raise
/// or lower the soft limits (timeouts, redirect/stream caps) — that is
/// legitimate. The fields fall into three roles for a per-request
/// `request-options` value:
/// - **Timeout DEFAULTS** (`default_total_timeout`, `stream_connect_timeout`,
///   `stream_read_timeout`, `header_deadline_floor`): applied only when the
///   caller sets no corresponding `*-ms`. An explicit caller value OVERRIDES the
///   default and MAY be LARGER (e.g. a longer `total-ms` for a big download) —
///   these are not ceilings.
/// - **Caller CEILINGS** (`max_redirects`, `max_concurrent_streams`): a caller
///   is clamped DOWN to these — may request fewer, never more.
/// - **`max_response_bytes`**: both a default and a caller ceiling, and itself
///   hard-clamped by the request path to the absolute `MAX_GUEST_PAYLOAD_LEN`
///   host payload limit — the one true hard cap that even the operator cannot
///   exceed.
///
/// Timeouts are pre-converted to [`Duration`] here so the request hot path reads
/// them directly (no per-request `from_secs`). The [`Default`] reproduces the
/// host's historical hardcoded constants exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    /// Default whole-request timeout for the buffered path, applied only when
    /// the caller sets no `total-ms`. An explicit caller `total-ms` overrides it
    /// and may be larger. Host const default: 30s.
    pub default_total_timeout: Duration,
    /// Connect timeout applied to the streaming path when the caller sets no
    /// `connect-ms` (a default, not a ceiling). Host const default: 30s.
    pub stream_connect_timeout: Duration,
    /// Per-chunk read timeout for streaming responses when the caller sets no
    /// `between-bytes-ms` (a default, not a ceiling). Host const default: 120s.
    pub stream_read_timeout: Duration,
    /// Time-to-first-byte (header) deadline floor for the streaming path when
    /// the caller set neither `first-byte-ms` nor a total timeout (a default,
    /// not a ceiling). Host const default: 120s.
    pub header_deadline_floor: Duration,
    /// Maximum redirect hops the host follows. A per-request `max-redirects`
    /// clamps DOWN to this (a caller ceiling). Host const default: 10.
    pub max_redirects: usize,
    /// Per-capsule ceiling on concurrent HTTP streaming responses, checked per
    /// principal and globally (a caller ceiling). Host const default: 4.
    pub max_concurrent_streams: usize,
    /// Default and hard ceiling on a buffered response body, in bytes. A
    /// per-request `max-response-bytes` clamps DOWN to this; the value itself is
    /// clamped by the request path to the absolute `MAX_GUEST_PAYLOAD_LEN` host
    /// limit (the one hard cap the operator cannot exceed). Host const default:
    /// 10 MiB.
    pub max_response_bytes: u64,
}

impl HttpLimits {
    /// Build resolved limits from the raw `[http]` config values (seconds and
    /// counts). The seconds → [`Duration`] conversion happens once here, off the
    /// request hot path. Shared by the daemon, the capsule-install lifecycle
    /// path, and the hook handler so the conversion lives in one place. Kept
    /// config-crate-free (takes primitives, not the config type) to preserve the
    /// `astrid-capsule` → no-`astrid-config` dependency boundary.
    #[must_use]
    pub fn from_config_values(
        default_timeout_secs: u64,
        stream_connect_timeout_secs: u64,
        stream_read_timeout_secs: u64,
        header_deadline_secs: u64,
        max_redirects: u32,
        max_concurrent_streams: u32,
        max_response_bytes: u64,
    ) -> Self {
        Self {
            default_total_timeout: Duration::from_secs(default_timeout_secs),
            stream_connect_timeout: Duration::from_secs(stream_connect_timeout_secs),
            stream_read_timeout: Duration::from_secs(stream_read_timeout_secs),
            header_deadline_floor: Duration::from_secs(header_deadline_secs),
            max_redirects: max_redirects as usize,
            max_concurrent_streams: max_concurrent_streams as usize,
            max_response_bytes,
        }
    }
}

impl Default for HttpLimits {
    /// The host's historical hardcoded constants — used in tests and whenever no
    /// operator `[http]` config is present.
    fn default() -> Self {
        Self {
            default_total_timeout: Duration::from_secs(30),
            stream_connect_timeout: Duration::from_secs(30),
            stream_read_timeout: Duration::from_secs(120),
            header_deadline_floor: Duration::from_secs(120),
            // Single source of truth for the redirect default (the request-path
            // airlock references this const).
            max_redirects: MAX_HTTP_REDIRECTS,
            max_concurrent_streams: 4,
            max_response_bytes: 10 * 1024 * 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_limits_default_matches_historical_constants() {
        let d = HttpLimits::default();
        assert_eq!(d.default_total_timeout, Duration::from_secs(30));
        assert_eq!(d.stream_connect_timeout, Duration::from_secs(30));
        assert_eq!(d.stream_read_timeout, Duration::from_secs(120));
        assert_eq!(d.header_deadline_floor, Duration::from_secs(120));
        assert_eq!(d.max_redirects, 10);
        assert_eq!(d.max_concurrent_streams, 4);
        assert_eq!(d.max_response_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn http_limits_from_config_values_converts_and_threads() {
        // The shared resolver used by the daemon, the install lifecycle path,
        // and the hook handler: seconds → Duration, counts widened, bytes as-is.
        // A NON-default config must produce non-default resolved limits (proves
        // operator `[http]` policy actually threads through, not the defaults).
        let l = HttpLimits::from_config_values(5, 7, 11, 13, 3, 2, 4096);
        assert_eq!(l.default_total_timeout, Duration::from_secs(5));
        assert_eq!(l.stream_connect_timeout, Duration::from_secs(7));
        assert_eq!(l.stream_read_timeout, Duration::from_secs(11));
        assert_eq!(l.header_deadline_floor, Duration::from_secs(13));
        assert_eq!(l.max_redirects, 3);
        assert_eq!(l.max_concurrent_streams, 2);
        assert_eq!(l.max_response_bytes, 4096);
        // And the default-valued args reproduce the historical constants exactly.
        assert_eq!(
            HttpLimits::from_config_values(30, 30, 120, 120, 10, 4, 10 * 1024 * 1024)
                .max_concurrent_streams,
            HttpLimits::default().max_concurrent_streams
        );
    }

    #[test]
    fn blocking_default_reserves_for_scheduler_and_floors() {
        let b = host_blocking_concurrency_default();
        // Never zero (would wedge blocking host calls) and never above the core
        // count (would over-subscribe the worker pool).
        assert!(b >= SCHED_RESERVE, "blocking floor is SCHED_RESERVE");
        assert!(b <= cores().max(SCHED_RESERVE));
    }

    #[test]
    fn io_default_is_large_and_floored() {
        let io = host_io_concurrency_default();

        // The cores-based value is floored at IO_MIN, but the fd clamp can pull
        // the result below IO_MIN on an fd-scarce host (the clamp is floored at
        // 1, not IO_MIN). So only assert the IO_MIN floor when fds are ample; on
        // a scarce host the result must equal the clamp `(soft / 2).max(1)`.
        match fd_soft_limit() {
            Some(soft) if soft / 2 < IO_MIN => assert_eq!(io, (soft / 2).max(1)),
            _ => assert!(io >= IO_MIN),
        }

        // The point of the split is that I/O concurrency dwarfs blocking — but
        // only when descriptors are not scarcer than cores. On a pathological
        // host (very high core count AND a low `RLIMIT_NOFILE`) the fd clamp can
        // legitimately pull io below blocking; that is the CORRECT fail-secure
        // behaviour (you cannot hold more concurrent sockets than the process
        // has descriptors). So assert `io >= blocking` only on hosts where the
        // fd budget is not the binding constraint — never unconditionally.
        let fd_not_scarce = fd_soft_limit().is_none_or(|soft| soft >= cores().saturating_mul(2));
        if fd_not_scarce {
            assert!(
                io >= host_blocking_concurrency_default(),
                "with ample fds the io ceiling must not be tighter than blocking"
            );
        }
    }

    #[test]
    fn net_stream_default_is_derived_from_fd_clamped_io_budget() {
        assert_eq!(
            host_net_stream_limit_default(),
            (host_io_concurrency_default() / 2).max(1)
        );
    }

    #[test]
    fn net_stream_budget_is_atomic_raii_and_live_tunable() {
        let budget = Arc::new(NetStreamBudget::new(2));
        let first = budget.try_acquire().expect("first stream");
        let second = budget.try_acquire().expect("second stream");
        assert!(budget.try_acquire().is_none());
        assert_eq!(budget.active(), 2);

        budget.set_limit(1);
        drop(first);
        assert!(budget.try_acquire().is_none());
        drop(second);
        assert_eq!(budget.active(), 0);
        assert!(budget.try_acquire().is_some());
    }

    #[test]
    fn resolve_prefers_overrides_and_clamps_zero() {
        let r = CapsuleRuntimeLimits::resolve(Some(7), Some(900), Some(40));
        assert_eq!(r.blocking_concurrency, 7);
        assert_eq!(r.io_concurrency, 900);
        assert_eq!(r.instance_pool_size, 40);

        // A zero override is clamped up to 1 rather than wedging a class.
        let z = CapsuleRuntimeLimits::resolve(Some(0), Some(0), Some(0));
        assert_eq!(z.blocking_concurrency, 1);
        assert_eq!(z.io_concurrency, 1);
        assert_eq!(z.instance_pool_size, 1);
    }

    #[test]
    fn resolve_none_uses_host_defaults() {
        let r = CapsuleRuntimeLimits::resolve(None, None, None);
        assert_eq!(r.blocking_concurrency, host_blocking_concurrency_default());
        assert_eq!(r.io_concurrency, host_io_concurrency_default());
        assert_eq!(r.instance_pool_size, host_instance_pool_size_default());
    }

    #[test]
    fn pool_default_is_bounded_and_beats_the_old_constant_on_a_typical_box() {
        let max = host_instance_pool_size_default();
        assert!((POOL_MIN..=POOL_MAX).contains(&max));
        // The old fixed value was 16; the floor guarantees we never resolve
        // below 8, and an 8-core host lands exactly on 16.
        assert!(max >= POOL_MIN);
    }

    #[test]
    fn min_idle_is_clamped_to_the_max() {
        // Large pool keeps WARM_MIN_IDLE warm.
        let big = CapsuleRuntimeLimits::resolve(None, None, Some(32));
        assert_eq!(big.instance_pool_min_idle(), WARM_MIN_IDLE);
        // A size-1 (carve-out) pool warm-starts its single instance.
        let one = CapsuleRuntimeLimits::resolve(None, None, Some(1));
        assert_eq!(one.instance_pool_min_idle(), 1);
    }
}
