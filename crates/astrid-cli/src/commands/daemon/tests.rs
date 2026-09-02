use super::*;

#[test]
fn fresh_home_boot_log_does_not_preinitialize_layout() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().join("astrid-home");
    let home = astrid_core::dirs::AstridHome::from_path(&root);

    assert!(boot_log_stderr_for_home(&home).is_none());
    assert!(
        !root.exists(),
        "boot-log capture must not create content before kernel admission"
    );
}

#[test]
fn fresh_home_start_fence_lives_outside_the_layout() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().join("astrid-home");
    let home = astrid_core::dirs::AstridHome::from_path(&root);
    let fence = daemon_start_fence_path(&home);

    assert!(fence.starts_with(std::env::temp_dir()));
    assert!(!fence.starts_with(home.root()));
    assert!(!root.exists());
}

#[tokio::test]
async fn already_stopped_fresh_home_does_not_create_layout() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().join("astrid-home");
    let home = astrid_core::dirs::AstridHome::from_path(&root);

    cleanup_daemon_runtime_for_home(&home, &home.socket_path(), &home.pid_path())
        .await
        .expect("an absent runtime is already stopped");
    assert!(!root.exists(), "stop must not initialize a fresh home");
}

#[tokio::test]
async fn marker_cleanup_failure_is_authoritative() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("astrid-home"));
    std::fs::create_dir_all(home.run_dir()).expect("runtime directory");
    std::fs::create_dir(home.ready_path()).expect("directory-shaped ready marker");

    let error = cleanup_daemon_runtime_for_home(&home, &home.socket_path(), &home.pid_path())
        .await
        .expect_err("an unremovable marker must fail stop");
    assert!(
        format!("{error:#}").contains("shutdown stage daemon.marker_cleanup"),
        "unexpected error: {error:#}"
    );
    assert!(
        home.ready_path().is_dir(),
        "failed marker remains diagnosable"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn confirmed_stop_removes_every_runtime_marker() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("astrid-home"));
    std::fs::create_dir_all(home.run_dir()).expect("runtime directory");
    for path in [home.ready_path(), home.pid_path(), home.token_path()] {
        std::fs::write(&path, b"stale").expect("stale marker");
    }
    let listener = astrid_core::local_transport::bind(&home.socket_path()).expect("listener");
    drop(listener);

    cleanup_daemon_runtime_for_home(&home, &home.socket_path(), &home.pid_path())
        .await
        .expect("confirmed stale runtime cleanup");

    for path in [
        home.socket_path(),
        home.ready_path(),
        home.pid_path(),
        home.token_path(),
    ] {
        assert!(
            !path.exists(),
            "marker survived cleanup: {}",
            path.display()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn live_listener_prevents_marker_removal() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("astrid-home"));
    std::fs::create_dir_all(home.run_dir()).expect("runtime directory");
    std::fs::write(home.ready_path(), b"live").expect("ready marker");
    let _listener = astrid_core::local_transport::bind(&home.socket_path()).expect("listener");

    let error = cleanup_daemon_runtime_for_home(&home, &home.socket_path(), &home.pid_path())
        .await
        .expect_err("a live listener must fail cleanup");
    assert!(format!("{error:#}").contains("daemon.listener_absence"));
    assert!(home.ready_path().exists(), "live marker must remain");
}

#[tokio::test]
async fn held_singleton_lock_prevents_marker_removal() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = astrid_core::dirs::AstridHome::from_path(temp.path().join("astrid-home"));
    std::fs::create_dir_all(home.run_dir()).expect("runtime directory");
    std::fs::write(home.ready_path(), b"live").expect("ready marker");
    let lock_path = home.run_dir().join("system.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("singleton lock");
    lock.try_lock().expect("hold singleton lock");

    let error = cleanup_daemon_runtime_for_home(&home, &home.socket_path(), &home.pid_path())
        .await
        .expect_err("a held singleton lock must fail cleanup");
    assert!(format!("{error:#}").contains("daemon.singleton_lock"));
    assert!(home.ready_path().exists(), "locked marker must remain");
}

#[test]
fn daemon_workspace_metadata_rejects_unknown_or_different_selection() {
    let expected = vec!["a".repeat(64)];
    assert!(validate_daemon_workspace_metadata("", &expected).is_err());
    assert!(
        validate_daemon_workspace_metadata(&format!("v1:{}", "b".repeat(64)), &expected).is_err()
    );
    validate_daemon_workspace_metadata(&format!("v1:{}\n", expected[0]), &expected).unwrap();
}

#[test]
fn explicit_workspace_selection_wins_over_current_directory() {
    let current = std::env::current_dir().expect("current directory");
    let explicit = tempfile::tempdir().expect("explicit workspace");
    assert_ne!(explicit.path(), current);

    let explicit_fingerprint = astrid_core::dirs::checked_workspace_selection_fingerprint(
        explicit.path(),
        crate::workspace_layout::current(),
    )
    .unwrap();
    assert!(
        expected_workspace_fingerprints(Some(explicit.path()))
            .unwrap()
            .contains(&explicit_fingerprint)
    );
    let current_fingerprint = astrid_core::dirs::checked_workspace_selection_fingerprint(
        &current,
        crate::workspace_layout::current(),
    )
    .unwrap();
    assert!(
        expected_workspace_fingerprints(None)
            .unwrap()
            .contains(&current_fingerprint)
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

/// REGRESSION (#1120): `astrid stop` must remove runtime markers only when the
/// daemon is confirmed gone. `StillAlive`/`Unverified` retain diagnostic state.
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
fn unconfirmed_termination_is_a_nonzero_outcome() {
    use daemon_control::KillOutcome;

    let still_alive = confirm_kill_outcome(KillOutcome::StillAlive)
        .expect_err("a live daemon cannot be successful");
    assert!(format!("{still_alive:#}").contains("daemon.process_reap"));

    let unverified = confirm_kill_outcome(KillOutcome::Unverified(4242))
        .expect_err("PID reuse cannot be successful");
    assert!(format!("{unverified:#}").contains("daemon.process_identity"));
}

#[tokio::test]
async fn acknowledged_shutdown_without_pid_is_unverified() {
    let error = confirm_graceful_stop(
        None,
        Path::new("/tmp/absent-astrid.sock"),
        Path::new("/tmp/absent-astrid.pid"),
    )
    .await
    .expect_err("an ACK without a process identity cannot prove process exit");
    assert!(format!("{error:#}").contains("daemon.process_reap"));
}

#[test]
fn first_shutdown_failure_remains_primary() {
    let error = combine_stop_results(
        Err(anyhow::anyhow!("gateway.final_ack")),
        Err(anyhow::anyhow!("daemon.process_reap")),
    )
    .expect_err("both failures must be returned");
    let message = format!("{error:#}");
    assert!(message.starts_with("gateway.final_ack"));
    assert!(message.contains("additional shutdown failure: daemon.process_reap"));
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
fn ensure_unlinked_or_stale_sock_with_live_pid_refuses_second_boot() {
    use astrid_core::local_transport::ConnectOutcome;
    assert_eq!(
        decide_ensure_action(&ConnectOutcome::Absent, true),
        EnsureAction::RefuseSecondBoot
    );
    assert_eq!(
        decide_ensure_action(&ConnectOutcome::Stale, true),
        EnsureAction::RefuseSecondBoot
    );
    assert_eq!(
        decide_ensure_action(&ConnectOutcome::Absent, false),
        EnsureAction::Spawn
    );
    assert_eq!(
        decide_ensure_action(&ConnectOutcome::Stale, false),
        EnsureAction::CleanStaleAndSpawn
    );
}

#[test]
fn status_unlinked_sock_with_live_pid_is_unreachable() {
    assert_eq!(
        decide_status_action(false, true),
        StatusAction::RunningButUnreachable
    );
    assert_eq!(decide_status_action(false, false), StatusAction::NotRunning);
    assert_eq!(
        decide_status_action(true, true),
        StatusAction::QueryLiveSocket
    );
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
fn absent_daemon_has_typed_stopped_status() {
    assert_eq!(
        status_document(None),
        serde_json::json!({ "state": "stopped" })
    );
}
