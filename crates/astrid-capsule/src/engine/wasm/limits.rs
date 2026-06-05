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

use std::sync::Arc;
use std::thread::available_parallelism;

use tokio::sync::Semaphore;

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
/// the daemon down to every [`WasmEngine`](super::WasmEngine) (mirrors the
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
}

impl CapsuleRuntimeLimits {
    /// Resolve from optional operator overrides, falling back to the
    /// host-derived default for any field left `None`. Both ceilings are
    /// clamped to at least 1 permit (fail-secure: a zero-permit semaphore would
    /// wedge every host call rather than merely throttle).
    #[must_use]
    pub fn resolve(blocking_concurrency: Option<usize>, io_concurrency: Option<usize>) -> Self {
        Self {
            blocking_concurrency: blocking_concurrency
                .unwrap_or_else(host_blocking_concurrency_default)
                .max(1),
            io_concurrency: io_concurrency
                .unwrap_or_else(host_io_concurrency_default)
                .max(1),
        }
    }

    /// Build the blocking host-call semaphore sized to this limit.
    #[must_use]
    pub fn blocking_semaphore(self) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(self.blocking_concurrency))
    }

    /// Build the async-I/O host-call semaphore sized to this limit.
    #[must_use]
    pub fn io_semaphore(self) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(self.io_concurrency))
    }
}

impl Default for CapsuleRuntimeLimits {
    /// All-host-derived limits (no operator overrides).
    fn default() -> Self {
        Self::resolve(None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn resolve_prefers_overrides_and_clamps_zero() {
        let r = CapsuleRuntimeLimits::resolve(Some(7), Some(900));
        assert_eq!(r.blocking_concurrency, 7);
        assert_eq!(r.io_concurrency, 900);

        // A zero override is clamped up to 1 rather than wedging host calls.
        let z = CapsuleRuntimeLimits::resolve(Some(0), Some(0));
        assert_eq!(z.blocking_concurrency, 1);
        assert_eq!(z.io_concurrency, 1);
    }

    #[test]
    fn resolve_none_uses_host_defaults() {
        let r = CapsuleRuntimeLimits::resolve(None, None);
        assert_eq!(r.blocking_concurrency, host_blocking_concurrency_default());
        assert_eq!(r.io_concurrency, host_io_concurrency_default());
    }

    #[test]
    fn semaphores_match_resolved_counts() {
        let r = CapsuleRuntimeLimits::resolve(Some(3), Some(11));
        assert_eq!(r.blocking_semaphore().available_permits(), 3);
        assert_eq!(r.io_semaphore().available_permits(), 11);
    }
}
