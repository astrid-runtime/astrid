//! OS-thread signal watchdog — a starvation-proof shutdown path.
//!
//! The daemon's async `run()` used to handle SIGTERM/SIGINT/SIGHUP with a
//! `tokio::select!`, which can only fire when a tokio worker is free to poll
//! the reactor. Under enough concurrent guest compute every worker is pinned,
//! so a `SIGTERM` sat unhandled and only `SIGKILL` could stop the daemon —
//! which then left the audit `LOCK` held until process death and raced the next
//! boot. (Fix 5 stops exempt run-loops from pinning workers, but a starvation-
//! proof kill path is the defense-in-depth guarantee: the daemon must ALWAYS be
//! killable, whether the CPU load was a bug or legitimate heavy work.)
//!
//! This module owns those signals on a plain [`std::thread`] scheduled by the
//! OS — independent of the tokio runtime. On the first signal it (a) requests a
//! graceful shutdown via the kernel's `shutdown_tx` watch channel (the async
//! `run()` selects on it and runs the normal `kernel.shutdown().await`), and
//! (b) arms a hard deadline on a separate thread: after [`SHUTDOWN_GRACE`], if
//! the process is still alive (graceful shutdown wedged), it force-exits so the
//! OS releases every lock. A SECOND signal before the deadline force-exits
//! immediately (an impatient operator).

/// Grace period between the first shutdown signal and a forced exit.
///
/// Long enough for a healthy graceful shutdown (capsule drain + KV/audit close)
/// to complete and let the process exit on its own, but bounded so a starved
/// daemon can never hang indefinitely holding the audit lock.
#[cfg(unix)]
pub(crate) const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(8);

/// Force-exit code used when graceful shutdown exceeds the grace deadline.
#[cfg(unix)]
const EXIT_GRACE_TIMEOUT: i32 = 1;

/// Force-exit code used when a second signal arrives before the deadline.
#[cfg(unix)]
const EXIT_IMPATIENT: i32 = 130;

/// The action the watchdog takes for a received signal, given whether it is the
/// first one seen. Pure so the decision is unit-testable without real signals
/// or a real `process::exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalDecision {
    /// First signal: request graceful shutdown and arm the force-exit deadline.
    GracefulThenArm,
    /// A subsequent signal before the deadline fired: force an immediate exit.
    ForceExitNow,
}

/// Decide what to do for a signal: the first one starts graceful shutdown and
/// arms the deadline; any later one (the operator hitting Ctrl-C again) forces
/// an immediate exit.
#[must_use]
pub(crate) const fn signal_decision(is_first: bool) -> SignalDecision {
    if is_first {
        SignalDecision::GracefulThenArm
    } else {
        SignalDecision::ForceExitNow
    }
}

/// Spawn the OS-thread signal watchdog owning SIGTERM/SIGINT/SIGHUP.
///
/// `shutdown_tx` is the kernel's shutdown watch sender; on the first signal the
/// watchdog sets it to `true`, which the async `run()` awaits to run the normal
/// graceful shutdown. The watchdog thread runs for the process lifetime.
///
/// Fail-safe: if the signal handler cannot be installed the daemon falls back
/// to the default signal disposition (terminate on SIGTERM) — still killable,
/// just not graceful — which is logged. Killable-but-abrupt beats wedged.
#[cfg(unix)]
pub(crate) fn spawn_signal_watchdog(shutdown_tx: tokio::sync::watch::Sender<bool>) {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let spawn_result = std::thread::Builder::new()
        .name("astrid-signal-watchdog".into())
        .spawn(move || {
            let mut signals = match Signals::new([SIGTERM, SIGINT, SIGHUP]) {
                Ok(signals) => signals,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to install the signal watchdog; the daemon falls back to \
                         the default signal disposition (still killable, not graceful)"
                    );
                    return;
                },
            };

            let mut first = true;
            for signal in &mut signals {
                match signal_decision(first) {
                    SignalDecision::GracefulThenArm => {
                        first = false;
                        tracing::info!(
                            signal,
                            "termination signal received; starting graceful shutdown"
                        );
                        // Feed the async shutdown path. `send` fails only if
                        // every receiver dropped, which means `run()` already
                        // moved past its wait — the deadline below still guards
                        // the exit either way.
                        let _ = shutdown_tx.send(true);
                        arm_force_exit_deadline();
                    },
                    SignalDecision::ForceExitNow => {
                        tracing::warn!(
                            signal,
                            "second termination signal before graceful shutdown completed; \
                             forcing immediate exit"
                        );
                        std::process::exit(EXIT_IMPATIENT);
                    },
                }
            }
        });

    if let Err(e) = spawn_result {
        tracing::error!(
            error = %e,
            "failed to spawn the signal watchdog thread; the daemon falls back to the \
             default signal disposition (still killable, not graceful)"
        );
    }
}

/// Arm the hard force-exit deadline on its OWN thread, so the watchdog's signal
/// loop can keep running and still catch a second signal while this sleeps.
///
/// If graceful shutdown finishes first, `run()` returns and `main` exits the
/// process normally (exit 0) — this sleeping thread is torn down with it before
/// it fires. If graceful shutdown wedges (workers starved), this fires after
/// [`SHUTDOWN_GRACE`] and force-exits so the OS releases every lock (including
/// the audit `LOCK`).
#[cfg(unix)]
fn arm_force_exit_deadline() {
    let spawn_result = std::thread::Builder::new()
        .name("astrid-shutdown-deadline".into())
        .spawn(|| {
            std::thread::sleep(SHUTDOWN_GRACE);
            tracing::error!(
                grace_secs = SHUTDOWN_GRACE.as_secs(),
                "graceful shutdown timed out under load; forcing exit"
            );
            std::process::exit(EXIT_GRACE_TIMEOUT);
        });

    if let Err(e) = spawn_result {
        // Could not arm the deadline thread. Do not force-exit here: graceful
        // shutdown is already in flight and usually completes. Log so a wedged
        // shutdown without its backstop is diagnosable.
        tracing::error!(
            error = %e,
            "failed to arm the force-exit deadline thread; graceful shutdown has no \
             hard backstop this run"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{SignalDecision, signal_decision};

    #[test]
    fn first_signal_starts_graceful_and_arms_deadline() {
        assert_eq!(signal_decision(true), SignalDecision::GracefulThenArm);
    }

    #[test]
    fn subsequent_signal_forces_immediate_exit() {
        assert_eq!(signal_decision(false), SignalDecision::ForceExitNow);
    }

    #[test]
    fn two_signals_are_graceful_then_force_exit() {
        // Mirrors the watchdog loop's `first` state machine: the first signal
        // requests graceful shutdown + arms the deadline; the next forces exit.
        let mut first = true;

        let d1 = signal_decision(first);
        assert_eq!(d1, SignalDecision::GracefulThenArm);
        if matches!(d1, SignalDecision::GracefulThenArm) {
            first = false;
        }

        let d2 = signal_decision(first);
        assert_eq!(d2, SignalDecision::ForceExitNow);
    }
}
