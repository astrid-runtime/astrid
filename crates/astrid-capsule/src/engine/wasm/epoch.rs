//! Run-loop epoch deadline policy and Store callback wiring.
//!
//! CPU-starvation policy ([`epoch_decision`], [`exempt_epoch_action`]) stays
//! separate from unload liveness: [`run_epoch_action`] Interrupts when the
//! instance [`HostState::cancel_token`] is cancelled, before that policy, so
//! `call_async` can complete. A per-principal overlay
//! (`invocation_cancel_token` / [`HostState::effective_cancel_token`]) must
//! not trap the shared run worker; it remains a wait-site signal.
//! The shared engine epoch ticker is not advanced here.

use wasmtime::Store;

use super::RunLoopBudget;
use super::host_state::HostState;

/// Default length (epoch ticks) of a bound run-loop's epoch deadline window
/// when the owner profile does not pin a tighter timeout.
///
/// One tick is [`super::EPOCH_TICK_INTERVAL`] (100 ms), so the default ~5 s
/// window is `5000 / 100 = 50` ticks. Each window the bound run-loop's
/// `epoch_deadline_callback` fires: a recv/accept/sleep loop (which set
/// `recv_yielded` since the last window) is re-extended and cooperatively
/// yields the tokio worker; a no-recv spinner accrues `no_yield_windows` and
/// is interrupt-trapped once it reaches [`MAX_NO_YIELD_WINDOWS`]. The window
/// is derived per-capsule from the owner quota `max_timeout_secs` (clamped to
/// this default) in [`super::resolve_run_loop_budget`]; this const is the
/// fail-safe.
pub(crate) const DEFAULT_RUN_LOOP_WINDOW_TICKS: u64 = 50;

/// Number of consecutive windows a bound run-loop may burn CPU **without**
/// cooperating through recv/accept or a completed nonzero sleep (setting
/// `recv_yielded`) before its epoch callback returns
/// [`UpdateDeadline::Interrupt`](wasmtime::UpdateDeadline) and traps the guest.
///
/// A legitimate run loop waits through recv/accept or sleep, so it resets the
/// counter every window and is never trapped. A pure `loop {}` (or any
/// no-recv burner) never resets it and is interrupt-trapped after this many
/// windows. With the default window (~5 s) this is a ~15 s grace before a
/// runaway is killed — generous enough to never catch a healthy capsule, tight
/// enough to bound a genuine spinner.
pub(crate) const MAX_NO_YIELD_WINDOWS: u32 = 3;

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
/// * If the guest waited through recv/accept or completed a nonzero sleep
///   since the last window (`recv_yielded`): clear the flag, reset the no-yield
///   counter to 0, and **`Yield`** (cooperatively yield the worker + re-arm).
///   Such a loop is never trapped.
/// * Otherwise it burned the whole window without a cooperative wait: increment
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
        // Cooperative wait: reset and keep running.
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

/// Pure epoch-deadline decision for an EXEMPT run-loop **while the instance
/// remains live**.
///
/// An exempt run-loop's owner holds an [`EXEMPT_CAPABILITIES`](astrid_core)
/// capability (`CAP_RESOURCES_UNBOUNDED` / `CAP_NET_BIND` / `CAP_UPLINK`; admin
/// via `*`), so it is **unbounded CPU** and must NEVER be trapped
/// (`Interrupt`) or fuel-out for quota reasons. Cancellation is a teardown
/// trap in [`run_epoch_action`], not a CPU quota: a cancelled instance
/// Interrupts so unload can complete `call_async`. Live admin still always
/// Yields here.
///
/// "Unbounded" must not mean "never yields": before this it was pinned at
/// `epoch_deadline = u64::MAX` with no callback, so the guest fiber never
/// reached a yield point and enough concurrent exempt compute pinned every
/// tokio worker — starving the reactor (and the SIGTERM handler) into a
/// `SIGKILL`-only wedge.
///
/// This makes a live exempt run-loop **always `Yield`** every window and
/// re-arm — the exact cooperativeness guarantee a bound run-loop already has,
/// minus the trap. It can still burn a core, but it can no longer starve the
/// daemon: the worker is released to the reactor every window. An OS cgroup
/// remains the backstop for raw CPU burn. Pure so it is unit-testable without
/// wasmtime, mirroring [`epoch_decision`].
pub(crate) const fn exempt_epoch_action(window_ticks: u64) -> EpochAction {
    EpochAction::Yield(window_ticks)
}

/// Apply a run-loop Store's CPU bound: a wasmtime EPOCH deadline plus interrupt
/// callback driven by the shared epoch ticker. Factored out of `load` so every
/// worker Store (one for the single-worker default, N for `bind_workers > 1`)
/// is configured identically.
///
/// BOUND run-loop (`window_ticks = Some`): the callback runs the pure
/// [`epoch_decision`] each window — a recv/accept/sleep loop `Yield`s (never trapped),
/// a no-recv spinner accrues toward `Interrupt` after `MAX_NO_YIELD_WINDOWS` but
/// still `Yield`s during the grace windows, so it can never starve the daemon.
///
/// EXEMPT run-loop (`window_ticks = None`): unbounded CPU while the instance is
/// live — [`exempt_epoch_action`] always `Yield`s, never `Interrupt`s for quota
/// — but still cooperatively yields the tokio worker every window.
/// `UpdateDeadline::Yield` is async-legal because the run loop drives the guest
/// via `call_async`.
///
/// Instance cancellation ([`HostState::cancel_token`]) returns
/// [`EpochAction::Interrupt`] from [`run_epoch_action`] before that CPU policy,
/// including exempt admin run-loops, so unload can complete `call_async`.
/// Per-principal overlay tokens do not trap the shared run worker; they remain
/// wait-site signals, and `clear_stale_invocation_cancel_token` re-arms the
/// pump on the next recv. Live (not cancelled) admin still always Yields. This
/// does not increment the shared engine epoch.
pub(crate) fn configure_run_store(store: &mut Store<HostState>, run_budget: &RunLoopBudget) {
    let window = run_budget.window_ticks;
    store.set_epoch_deadline(window.unwrap_or(DEFAULT_RUN_LOOP_WINDOW_TICKS));
    store.epoch_deadline_callback(move |mut context| {
        Ok(match run_epoch_action(context.data_mut(), window) {
            EpochAction::Yield(ticks) => wasmtime::UpdateDeadline::Yield(ticks),
            EpochAction::Interrupt => wasmtime::UpdateDeadline::Interrupt,
        })
    });
}

/// One watchdog policy for both personal and user-accounted run loops.
///
/// A cancelled **instance** Interrupts before CPU-starvation policy so unload
/// can complete `call_async` even for exempt admin run-loops. Overlay /
/// `effective_cancel_token` cancellation must not trap a shared pump: retiring
/// one principal leaves Bob's SystemResident worker intact. Live admin still
/// always Yields via [`exempt_epoch_action`]. Cleanup trap of a cancelled
/// instance is not a change to the live CPU bound.
pub(crate) fn run_epoch_action(state: &mut HostState, window: Option<u64>) -> EpochAction {
    if state.cancel_token.is_cancelled() {
        return EpochAction::Interrupt;
    }
    if let Some(window) = window {
        let (action, recv_yielded, no_yield_windows) = epoch_decision(
            state.recv_yielded,
            state.no_yield_windows,
            window,
            MAX_NO_YIELD_WINDOWS,
        );
        state.recv_yielded = recv_yielded;
        state.no_yield_windows = no_yield_windows;
        action
    } else {
        exempt_epoch_action(DEFAULT_RUN_LOOP_WINDOW_TICKS)
    }
}

#[cfg(test)]
mod runtime_tests;
#[cfg(test)]
mod tests;
