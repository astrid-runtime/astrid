//! Generation-safe daemon runtime cleanup and stop confirmation.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{KernelRequest, KernelResponse};

use super::daemon_control;
use crate::{socket_client, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopConfirmation {
    ConfirmedGone,
    Unconfirmed,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ShutdownRequestOutcome {
    Acknowledged,
    Escalate(String),
    Rejected(String),
}

/// Stop the daemon and confirm that its process and runtime namespace are gone.
///
/// A shutdown response is only an acknowledgement. Runtime files are removed
/// after process-exit evidence is obtained while holding the singleton lock.
pub(crate) async fn handle_stop() -> Result<StopConfirmation> {
    let socket_path = socket_client::try_proxy_socket_path()?;
    let pid_path = socket_client::try_pid_path()?;

    // Capture identity before shutdown because a clean exit removes the PID
    // file, and the original identity is needed to confirm or force exit.
    let recorded = daemon_control::read_pid_file(&pid_path)?;
    let endpoint_reachable = daemon_endpoint_reachable(&socket_path).await;
    let recorded_alive = recorded
        .as_ref()
        .is_some_and(|identity| daemon_control::is_process_alive(identity.pid));
    if !endpoint_reachable && !recorded_alive {
        return Ok(report_confirmed_cleanup(
            "No Astrid daemon is running.",
            &pid_path,
            &socket_path,
        ));
    }

    // Stopping is the recovery path for a daemon from another workspace, so
    // intentionally bypass the selected-workspace check.
    let recovery_client = if endpoint_reachable {
        match tokio::time::timeout(
            Duration::from_secs(5),
            socket_client::connect_kernel_for_recovery(),
        )
        .await
        {
            Ok(Ok(client)) => Some(client),
            Ok(Err(error)) if is_handshake_rejection(&error) => {
                return Err(error)
                    .context("daemon rejected the authenticated lifecycle-recovery connection");
            },
            Ok(Err(error)) => {
                eprintln!(
                    "{}",
                    theme::Theme::warning(&format!(
                        "Daemon recovery connection failed ({error:#}); escalating through the \
                         recorded process identity."
                    ))
                );
                None
            },
            Err(_) => {
                eprintln!(
                    "{}",
                    theme::Theme::warning(
                        "Daemon recovery connection timed out; escalating through the recorded \
                         process identity."
                    )
                );
                None
            },
        }
    } else {
        None
    };

    if let Some(client) = recovery_client {
        let mut client = client.with_timeout(Duration::from_secs(10));
        match shutdown_request_outcome(
            client
                .request(KernelRequest::Shutdown {
                    reason: Some("astrid stop".to_string()),
                })
                .await,
        ) {
            ShutdownRequestOutcome::Acknowledged => {
                return Ok(confirm_graceful_stop(recorded, &pid_path, &socket_path).await);
            },
            ShutdownRequestOutcome::Escalate(reason) => {
                eprintln!(
                    "{}",
                    theme::Theme::warning(&format!(
                        "Authenticated daemon shutdown failed ({reason}); escalating through the \
                         recorded process identity."
                    ))
                );
            },
            ShutdownRequestOutcome::Rejected(reason) => anyhow::bail!("{reason}"),
        }
    }

    let outcome = match &recorded {
        Some(identity) => daemon_control::terminate_known(identity).await,
        None => daemon_control::KillOutcome::NotRunning,
    };
    // A lost shutdown response may still mean the daemon exited. Refresh the
    // endpoint observation before treating `NotRunning` as proof of absence.
    let endpoint_reachable = if matches!(outcome, daemon_control::KillOutcome::NotRunning) {
        daemon_endpoint_reachable(&socket_path).await
    } else {
        endpoint_reachable
    };
    Ok(report_orphan_stop(
        outcome,
        endpoint_reachable,
        &pid_path,
        &socket_path,
    ))
}

pub(super) fn is_handshake_rejection(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<astrid_uplink::socket_client::HandshakeRejected>()
        .is_some()
}

async fn daemon_endpoint_reachable(socket_path: &Path) -> bool {
    match astrid_core::local_transport::connect_outcome(socket_path).await {
        Ok(astrid_core::local_transport::ConnectOutcome::Connected(stream)) => {
            drop(stream);
            true
        },
        Ok(
            astrid_core::local_transport::ConnectOutcome::Absent
            | astrid_core::local_transport::ConnectOutcome::Stale,
        ) => false,
        Err(_) => true,
    }
}

pub(super) fn shutdown_request_outcome<E>(
    response: std::result::Result<KernelResponse, E>,
) -> ShutdownRequestOutcome
where
    E: std::fmt::Display,
{
    match response {
        Ok(KernelResponse::Success(_)) => ShutdownRequestOutcome::Acknowledged,
        Ok(KernelResponse::Error(reason)) => {
            ShutdownRequestOutcome::Rejected(format!("daemon rejected shutdown: {reason}"))
        },
        Ok(other) => ShutdownRequestOutcome::Rejected(format!(
            "daemon returned an unexpected shutdown response: {other:?}"
        )),
        Err(error) => ShutdownRequestOutcome::Escalate(format!("shutdown request failed: {error}")),
    }
}

async fn confirm_graceful_stop(
    recorded: Option<daemon_control::DaemonIdentity>,
    pid_path: &Path,
    socket_path: &Path,
) -> StopConfirmation {
    let Some(identity) = recorded else {
        eprintln!(
            "{}",
            theme::Theme::warning(
                "The daemon acknowledged shutdown, but its process identity was unavailable; \
                 exit could not be confirmed and runtime state was left intact."
            )
        );
        return StopConfirmation::Unconfirmed;
    };
    let pid = identity.pid;

    if daemon_control::wait_for_exit(pid, daemon_control::GRACE).await {
        return report_confirmed_cleanup("Astrid daemon stopped.", pid_path, socket_path);
    }

    eprintln!(
        "{}",
        theme::Theme::warning(
            "Daemon acknowledged shutdown but is still running; escalating with forced \
             termination so the state-db lock is released."
        )
    );
    let outcome = daemon_control::terminate_known(&identity).await;
    report_orphan_stop(outcome, true, pid_path, socket_path)
}

fn report_orphan_stop(
    outcome: daemon_control::KillOutcome,
    endpoint_reachable: bool,
    pid_path: &Path,
    socket_path: &Path,
) -> StopConfirmation {
    match &outcome {
        daemon_control::KillOutcome::NotRunning => {
            if endpoint_reachable {
                eprintln!(
                    "{}",
                    theme::Theme::warning(
                        "The daemon transport is reachable, but authenticated shutdown failed and \
                         no daemon process could be verified. Leaving runtime state intact."
                    )
                );
            }
        },
        daemon_control::KillOutcome::TermExited | daemon_control::KillOutcome::KilledExited => {},
        daemon_control::KillOutcome::StillAlive => {
            eprintln!(
                "{}",
                theme::Theme::error(
                    "An unresponsive Astrid daemon did not exit even after forced termination; the \
                     state-db lock may still be held. Inspect the process before retrying."
                )
            );
        },
        daemon_control::KillOutcome::Unverified(pid) => {
            eprintln!(
                "{}",
                theme::Theme::warning(&format!(
                    "A process may hold the recorded daemon PID {pid}, but I can't confirm either \
                     its absence or that it's the Astrid daemon — not killing it. If the daemon is \
                     genuinely stuck, inspect PID {pid} and stop it manually."
                ))
            );
        },
    }
    let confirmation = stop_confirmation(outcome, endpoint_reachable);
    if confirmation == StopConfirmation::ConfirmedGone {
        let message = if matches!(outcome, daemon_control::KillOutcome::NotRunning) {
            "No Astrid daemon is running."
        } else {
            "Stopped an unresponsive Astrid daemon."
        };
        return report_confirmed_cleanup(message, pid_path, socket_path);
    }
    confirmation
}

pub(super) fn report_confirmed_cleanup(
    success_message: &str,
    pid_path: &Path,
    socket_path: &Path,
) -> StopConfirmation {
    match remove_runtime_files_if_unowned(pid_path, socket_path) {
        Ok(true) => {
            println!("{}", theme::Theme::success(success_message));
            StopConfirmation::ConfirmedGone
        },
        Ok(false) => {
            eprintln!(
                "{}",
                theme::Theme::warning(
                    "The stopped daemon exited, but another daemon generation now owns the \
                     runtime namespace. Its files were left intact."
                )
            );
            StopConfirmation::Unconfirmed
        },
        Err(error) => {
            eprintln!(
                "{}",
                theme::Theme::warning(&format!(
                    "The stopped daemon exited, but runtime cleanup could not be verified: {error}. \
                     Runtime files were left for a later recovery."
                ))
            );
            StopConfirmation::Unconfirmed
        },
    }
}

/// Remove runtime artifacts only while holding the daemon namespace lock.
///
/// A newly booting generation acquires this same lock before publishing any
/// shared runtime state. `Ok(false)` therefore means another generation owns
/// the namespace and no path may be removed.
pub(super) fn remove_runtime_files_if_unowned(
    pid_path: &Path,
    socket_path: &Path,
) -> std::io::Result<bool> {
    let run_dir = pid_path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon PID path has no run directory",
        )
    })?;
    let root = run_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon run directory has no Astrid home",
        )
    })?;
    let home = astrid_core::dirs::AstridHome::from_path(root);
    if home.pid_path() != pid_path || home.socket_path() != socket_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon runtime paths do not belong to one Astrid home",
        ));
    }
    let Some(_singleton) = astrid_core::platform_fs::try_acquire_daemon_singleton(&home)? else {
        return Ok(false);
    };

    astrid_core::local_transport::remove_endpoint(socket_path)?;
    remove_file_if_present(&home.ready_path())?;
    remove_file_if_present(&home.token_path())?;
    remove_file_if_present(pid_path)?;
    Ok(true)
}

fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Whether a stop outcome confirms the daemon is gone.
const fn stop_confirmed_gone(outcome: daemon_control::KillOutcome) -> bool {
    matches!(
        outcome,
        daemon_control::KillOutcome::NotRunning
            | daemon_control::KillOutcome::TermExited
            | daemon_control::KillOutcome::KilledExited
    )
}

/// Combine process evidence with transport evidence.
///
/// `NotRunning` proves absence only when the transport is also unreachable. A
/// reachable endpoint whose authenticated recovery handshake failed could
/// still belong to the daemon, and without a verified PID there is no safe
/// destructive fallback.
pub(super) const fn stop_confirmation(
    outcome: daemon_control::KillOutcome,
    endpoint_reachable: bool,
) -> StopConfirmation {
    if endpoint_reachable && matches!(outcome, daemon_control::KillOutcome::NotRunning) {
        StopConfirmation::Unconfirmed
    } else if stop_confirmed_gone(outcome) {
        StopConfirmation::ConfirmedGone
    } else {
        StopConfirmation::Unconfirmed
    }
}
