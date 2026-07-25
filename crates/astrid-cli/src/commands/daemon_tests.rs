use super::*;

#[test]
fn daemon_ready_attempts_match_timeout_window() {
    assert_eq!(
        DAEMON_READY_ATTEMPTS,
        readiness_attempts(DAEMON_READY_TIMEOUT_SECS, DAEMON_READY_POLL_MILLIS)
    );
    assert_eq!(
        DAEMON_READY_ATTEMPTS
            .checked_mul(DAEMON_READY_POLL_MILLIS)
            .expect("readiness window fits"),
        60_000
    );
}

#[test]
fn daemon_workspace_metadata_rejects_unknown_or_different_selection() {
    let expected = "a".repeat(64);
    assert!(validate_daemon_workspace_metadata("", &expected).is_err());
    assert!(
        validate_daemon_workspace_metadata(&format!("v1:{}", "b".repeat(64)), &expected).is_err()
    );
    validate_daemon_workspace_metadata(&format!("v1:{expected}\n"), &expected).unwrap();
}

#[test]
fn explicit_workspace_selection_wins_over_current_directory() {
    let explicit = crate::test_support::private_tempdir();
    let current = crate::test_support::private_tempdir();
    assert_ne!(explicit.path(), current.path());

    assert_eq!(
        expected_workspace_fingerprint_from(Some(explicit.path()), current.path()).unwrap(),
        astrid_core::dirs::checked_workspace_selection_fingerprint(
            explicit.path(),
            crate::workspace_layout::current(),
        )
        .unwrap()
    );
    assert_eq!(
        expected_workspace_fingerprint_from(None, current.path()).unwrap(),
        astrid_core::dirs::checked_workspace_selection_fingerprint(
            current.path(),
            crate::workspace_layout::current(),
        )
        .unwrap()
    );
}

#[test]
fn ephemeral_boot_passes_the_selected_workspace_to_the_daemon() {
    use std::ffi::OsStr;

    let command = ephemeral_daemon_command(
        Path::new("/installed/astrid-daemon"),
        Path::new("/selected/project"),
    );
    let args = command.get_args().collect::<Vec<_>>();

    assert_eq!(
        args,
        vec![
            OsStr::new("--ephemeral"),
            OsStr::new("--workspace"),
            OsStr::new("/selected/project"),
        ]
    );
    assert_eq!(
        command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("ASTRID_WORKSPACE_STATE_DIR"))
            .and_then(|(_, value)| value),
        Some(OsStr::new(
            crate::workspace_layout::current().state_dir_name()
        ))
    );
}

#[test]
fn persistent_and_foreground_start_never_enable_ephemeral_shutdown() {
    use std::ffi::OsStr;

    let persistent = persistent_daemon_command(
        Path::new("/installed/astrid-daemon"),
        Path::new("/selected/project"),
    );
    let foreground = foreground_daemon_command(
        Path::new("/installed/astrid-daemon"),
        Path::new("/selected/project"),
    );

    let persistent_args = persistent.get_args().collect::<Vec<_>>();
    assert_eq!(
        persistent_args,
        vec![OsStr::new("--workspace"), OsStr::new("/selected/project")]
    );
    assert!(!persistent_args.contains(&OsStr::new("--ephemeral")));

    let foreground_args = foreground.get_args().collect::<Vec<_>>();
    assert_eq!(
        foreground_args,
        vec![OsStr::new("--workspace"), OsStr::new("/selected/project"),]
    );
    assert!(!foreground_args.contains(&OsStr::new("--ephemeral")));
    assert_eq!(
        foreground
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("ASTRID_DAEMON_FOREGROUND"))
            .and_then(|(_, value)| value),
        Some(OsStr::new("1"))
    );
}

#[test]
fn foreground_exit_code_is_propagated() {
    #[cfg(unix)]
    let status = std::process::Command::new("sh")
        .args(["-c", "exit 23"])
        .status()
        .unwrap();
    #[cfg(windows)]
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "exit 23"])
        .status()
        .unwrap();

    assert_eq!(
        exit_code_from_status(status),
        std::process::ExitCode::from(23)
    );
}

#[test]
fn stop_cleans_up_only_when_confirmed_gone() {
    use daemon_control::KillOutcome;
    assert!(stop_confirmed_gone(KillOutcome::NotRunning));
    assert!(stop_confirmed_gone(KillOutcome::TermExited));
    assert!(stop_confirmed_gone(KillOutcome::KilledExited));
    assert!(!stop_confirmed_gone(KillOutcome::StillAlive));
    assert!(!stop_confirmed_gone(KillOutcome::Unverified(4242)));
}

#[test]
fn reachable_endpoint_without_verified_process_keeps_stop_unconfirmed() {
    use daemon_control::KillOutcome;

    // Models a reachable endpoint whose authenticated recovery handshake
    // failed while the PID file was missing or unusable. Endpoint reachability
    // alone cannot prove daemon identity, but it also forbids declaring absence.
    assert_eq!(
        stop_confirmation(KillOutcome::NotRunning, true),
        StopConfirmation::Unconfirmed
    );
    assert_eq!(
        stop_confirmation(KillOutcome::NotRunning, false),
        StopConfirmation::ConfirmedGone
    );
}

#[test]
fn start_reachable_daemon_is_already_running() {
    assert_eq!(
        decide_start_action(true, false),
        StartAction::AlreadyRunning
    );
    assert_eq!(decide_start_action(true, true), StartAction::AlreadyRunning);
    assert!(!start_clears_sentinels(StartAction::AlreadyRunning));
}

#[test]
fn start_unreachable_with_dead_pid_heals_and_spawns() {
    let action = decide_start_action(false, false);
    assert_eq!(action, StartAction::HealAndSpawn);
    assert!(start_clears_sentinels(action));
}

#[test]
fn start_unreachable_with_live_pid_defers_and_leaves_sentinels() {
    let action = decide_start_action(false, true);
    assert_eq!(action, StartAction::RunningButUnreachable);
    assert!(!start_clears_sentinels(action));
}

#[test]
fn status_error_is_not_reported_as_a_successful_status() {
    let error = status_response(KernelResponse::Error("denied".into()))
        .expect_err("kernel status errors must fail the command");
    assert!(
        error
            .to_string()
            .contains("daemon rejected status request: denied")
    );
}

#[test]
fn shutdown_acknowledgement_uses_graceful_exit_confirmation() {
    assert_eq!(
        shutdown_request_outcome(Ok::<_, anyhow::Error>(KernelResponse::Success(
            "shutting down".into(),
        ))),
        ShutdownRequestOutcome::Acknowledged
    );
}

#[test]
fn shutdown_transport_failure_escalates_to_identity_gated_recovery() {
    assert!(matches!(
        shutdown_request_outcome(Err(anyhow::anyhow!("request timed out"))),
        ShutdownRequestOutcome::Escalate(_)
    ));
}

#[test]
fn shutdown_response_failures_never_bypass_daemon_authorization() {
    for outcome in [
        shutdown_request_outcome(Ok::<_, anyhow::Error>(KernelResponse::Error(
            "denied".into(),
        ))),
        shutdown_request_outcome(Ok::<_, anyhow::Error>(KernelResponse::Working)),
    ] {
        assert!(
            matches!(outcome, ShutdownRequestOutcome::Rejected(_)),
            "an authenticated daemon response must fail closed without process termination"
        );
    }
}

#[test]
fn handshake_rejection_never_enters_process_recovery() {
    let error = anyhow::Error::new(astrid_uplink::socket_client::HandshakeRejected::new(
        "principal denied",
    ))
    .context("failed to connect to daemon");
    assert!(is_handshake_rejection(&error));

    let transport = anyhow::anyhow!("connection reset");
    assert!(!is_handshake_rejection(&transport));
}
