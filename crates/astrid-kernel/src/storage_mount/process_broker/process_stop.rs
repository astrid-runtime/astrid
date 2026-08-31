//! Bounded STOP/reap for a native process storage provider.

use std::{path::PathBuf, time::Duration};

use astrid_core::local_transport::{self, ConnectOutcome};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
enum ProcessProviderStopResponse {
    Stopped,
    Ready,
    Failure { code: String, message: String },
}

/// Typed operator policy for bounded native provider STOP and reaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessStopPolicy {
    stop_acknowledgement: std::time::Duration,
    reap_grace: std::time::Duration,
    killed_reap: std::time::Duration,
}

impl Default for ProcessStopPolicy {
    fn default() -> Self {
        // Ten seconds bounds a wedged protocol reply without making normal
        // unmount latency depend on provider I/O or child startup.
        let timeout = std::time::Duration::from_secs(10);
        Self {
            stop_acknowledgement: timeout,
            reap_grace: timeout,
            killed_reap: timeout,
        }
    }
}

impl From<&astrid_config::TimeoutsSection> for ProcessStopPolicy {
    fn from(timeouts: &astrid_config::TimeoutsSection) -> Self {
        Self {
            stop_acknowledgement: Duration::from_secs(timeouts.process_stop_ack_secs),
            reap_grace: Duration::from_secs(timeouts.process_reap_grace_secs),
            killed_reap: Duration::from_secs(timeouts.process_killed_reap_secs),
        }
    }
}

pub(super) async fn stop_process_provider(
    child: &mut tokio::process::Child,
    control_path: PathBuf,
    token: String,
    policy: ProcessStopPolicy,
) -> bool {
    let protocol_ok = match local_transport::connect_outcome(&control_path).await {
        Ok(ConnectOutcome::Connected(stream)) => {
            send_stop_request(stream, &token, policy).await.is_ok()
        },
        Ok(ConnectOutcome::Absent | ConnectOutcome::Stale) | Err(_) => false,
    };
    if !protocol_ok {
        let _ = child.start_kill();
    }
    if !reap_child(child, policy).await {
        return false;
    }
    // Reaping is not ownership release. A provider can acknowledge STOP,
    // exit, and still leave a replacement or inherited listener at the
    // control endpoint. Probe after every STOP/reap outcome so only a dead
    // endpoint can clear the projection key.
    match local_transport::connect_outcome(&control_path).await {
        Ok(ConnectOutcome::Absent | ConnectOutcome::Stale) => true,
        Ok(ConnectOutcome::Connected(stream)) => {
            drop(stream);
            false
        },
        Err(_) => false,
    }
}

async fn send_stop_request(
    mut stream: local_transport::LocalStream,
    token: &str,
    policy: ProcessStopPolicy,
) -> Result<(), String> {
    let request = serde_json::json!({"operation": "stop", "token": token});
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("encode provider stop request: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("write provider stop request: {error}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|error| format!("write provider stop frame: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush provider stop request: {error}"))?;
    let mut line = String::new();
    let reader = tokio::io::BufReader::new(stream);
    let read = tokio::time::timeout(
        policy.stop_acknowledgement,
        reader.take((64 * 1024 + 1) as u64).read_line(&mut line),
    )
    .await
    .map_err(|_| "timed out waiting for provider stop acknowledgement".to_owned())?
    .map_err(|error| format!("read provider stop acknowledgement: {error}"))?;
    if read == 0 || read > 64 * 1024 || !line.ends_with('\n') {
        return Err("provider stop acknowledgement frame is malformed or oversized".to_owned());
    }
    match serde_json::from_str(&line)
        .map_err(|error| format!("decode provider stop acknowledgement: {error}"))?
    {
        ProcessProviderStopResponse::Stopped => Ok(()),
        ProcessProviderStopResponse::Ready => {
            Err("provider remained mounted after stop request".to_owned())
        },
        ProcessProviderStopResponse::Failure { code, message } => {
            Err(format!("provider refused stop ({code}): {message}"))
        },
    }
}

async fn reap_child(child: &mut tokio::process::Child, policy: ProcessStopPolicy) -> bool {
    if let Ok(Ok(_)) = tokio::time::timeout(policy.reap_grace, child.wait()).await {
        return true;
    }
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(policy.killed_reap, child.wait()).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
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
}
