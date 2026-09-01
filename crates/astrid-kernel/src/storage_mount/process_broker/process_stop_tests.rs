use super::{ProcessStopPolicy, stop_process_provider};
use astrid_core::local_transport;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Notify;

fn spawn_exited_child() -> tokio::process::Child {
    #[cfg(unix)]
    {
        tokio::process::Command::new("true")
            .spawn()
            .expect("spawn exited child")
    }
    #[cfg(windows)]
    {
        tokio::process::Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn exited child")
    }
}

#[test]
fn default_stop_policy_preserves_the_protocol_and_reap_hard_guard() {
    let policy = ProcessStopPolicy::default();
    assert_eq!(policy.stop_acknowledgement, Duration::from_secs(10));
    assert_eq!(policy.reap_grace, Duration::from_secs(10));
    assert_eq!(policy.killed_reap, Duration::from_secs(10));
}

#[test]
fn timeout_config_derives_each_stop_and_reap_budget() {
    let timeouts = astrid_config::TimeoutsSection {
        process_stop_ack_secs: 7,
        process_reap_grace_secs: 11,
        process_killed_reap_secs: 13,
        ..astrid_config::TimeoutsSection::default()
    };
    let policy = ProcessStopPolicy::from(&timeouts);
    assert_eq!(policy.stop_acknowledgement, Duration::from_secs(7));
    assert_eq!(policy.reap_grace, Duration::from_secs(11));
    assert_eq!(policy.killed_reap, Duration::from_secs(13));
}

#[tokio::test]
async fn absent_control_endpoint_is_stopped_after_child_reap() {
    let mut child = spawn_exited_child();
    let directory = tempfile::tempdir().expect("temporary control dir");
    let path = directory.path().join("missing.sock");
    assert!(
        stop_process_provider(
            &mut child,
            path,
            "unused-token".to_owned(),
            ProcessStopPolicy::default()
        )
        .await,
        "reaped child with no control endpoint must not wedge the projection key"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stale_control_endpoint_is_stopped_after_child_reap() {
    let mut child = spawn_exited_child();
    let directory = tempfile::tempdir().expect("temporary control dir");
    let path = directory.path().join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&path).expect("stale listener"));
    assert!(
        stop_process_provider(
            &mut child,
            path,
            "unused-token".to_owned(),
            ProcessStopPolicy::default(),
        )
        .await,
        "reaped child with a stale control endpoint must not wedge the projection key"
    );
}

#[cfg(any(unix, windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_stop_with_live_endpoint_is_retained_after_child_reap() {
    let mut child = spawn_exited_child();
    let directory = tempfile::tempdir().expect("temporary control dir");
    let path = directory.path().join("still-live.sock");
    let listener = local_transport::bind(&path).expect("bind live control endpoint");
    let release = Arc::new(Notify::new());
    let responder = tokio::spawn({
        let release = Arc::clone(&release);
        async move {
            let mut stream = local_transport::accept(&listener)
                .await
                .expect("accept authenticated stop request");
            stream
                .write_all(b"{\"status\":\"stopped\"}\n")
                .await
                .expect("write canonical stop acknowledgement");
            let _ = stream.read_u8().await;
            release.notified().await;
        }
    });

    assert!(
        !stop_process_provider(
            &mut child,
            path,
            "unused-token".to_owned(),
            ProcessStopPolicy::default(),
        )
        .await,
        "a canonical STOP followed by reap must not release a live endpoint"
    );
    release.notify_waiters();
    responder.await.expect("live endpoint responder");
}
