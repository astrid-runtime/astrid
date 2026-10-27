#![allow(clippy::unwrap_used)]

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

#[test]
fn production_shutdown_grace_remains_eight_seconds() {
    assert_eq!(super::SHUTDOWN_GRACE, std::time::Duration::from_secs(8));
}

#[test]
fn api_shutdown_arms_the_shared_deadline_without_a_signal() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "signal::tests::api_deadline_child",
            "--nocapture",
        ])
        .env("ASTRID_TEST_API_DEADLINE_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let began = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(super::EXIT_GRACE_TIMEOUT));
            assert!(began.elapsed() >= std::time::Duration::from_millis(150));
            return;
        }
        if began.elapsed() >= std::time::Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("API shutdown did not arm its independent deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn api_deadline_child() {
    if std::env::var_os("ASTRID_TEST_API_DEADLINE_CHILD").is_none() {
        return;
    }
    let deadline = super::ShutdownDeadline {
        grace: std::time::Duration::from_millis(150),
        ..Default::default()
    };
    let (sender, mut receiver) = tokio::sync::watch::channel(false);
    sender.send_replace(true);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(deadline.wait_for_shutdown(&mut receiver));
    // The API path already armed it; later signal/API observers must neither
    // create a second deadline nor reset the original start time.
    assert!(!deadline.try_arm());
    // No Tokio runtime is running here. Only the independent OS deadline can
    // terminate this owned test process; no OS termination signal is sent.
    loop {
        std::thread::park();
    }
}
