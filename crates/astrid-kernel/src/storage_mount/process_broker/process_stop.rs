//! Bounded STOP/reap for a native process storage provider.

use std::path::PathBuf;

use astrid_core::local_transport::{self, ConnectOutcome};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status", deny_unknown_fields)]
enum ProcessProviderStopResponse {
    Stopped,
    Ready,
    Failure { code: String, message: String },
}

pub(super) async fn stop_process_provider(
    child: &mut tokio::process::Child,
    control_path: PathBuf,
    token: String,
) -> bool {
    let protocol_ok = match local_transport::connect_outcome(&control_path).await {
        Ok(ConnectOutcome::Connected(stream)) => send_stop_request(stream, &token).await.is_ok(),
        Ok(ConnectOutcome::Absent | ConnectOutcome::Stale) | Err(_) => false,
    };
    if !protocol_ok {
        let _ = child.start_kill();
    }
    if !reap_child(child).await {
        return false;
    }
    if protocol_ok {
        return true;
    }
    // A crashed child can leave a stale or absent control endpoint. Treat
    // that as stopped only after the process has been reaped and the
    // endpoint is confirmed dead; a live endpoint still owning the key
    // remains wedged.
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
        std::time::Duration::from_secs(10),
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

async fn reap_child(child: &mut tokio::process::Child) -> bool {
    if let Ok(Ok(_)) = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await
    {
        return true;
    }
    let _ = child.start_kill();
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::stop_process_provider;

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

    #[tokio::test]
    async fn absent_control_endpoint_is_stopped_after_child_reap() {
        let mut child = spawn_exited_child();
        let directory = tempfile::tempdir().expect("temporary control dir");
        let path = directory.path().join("missing.sock");
        assert!(
            stop_process_provider(&mut child, path, "unused-token".to_owned()).await,
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
            stop_process_provider(&mut child, path, "unused-token".to_owned()).await,
            "reaped child with a stale control endpoint must not wedge the projection key"
        );
    }
}
