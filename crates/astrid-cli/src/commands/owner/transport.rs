//! No-autostart native controls and explicit co-installed administrative mode.

use anyhow::{Context, Result};
use astrid_core::identity::hosted_owner::HostedOwnerConfiguration;
use astrid_core::{
    SessionId,
    kernel_api::hosted_owner::{HostedOwnerRequest, HostedOwnerResponse},
};
use astrid_types::{
    Topic,
    ipc::{IpcMessage, IpcPayload},
};
use astrid_uplink::{
    native::hosted_owner::{REQUEST_TOPIC, RESPONSE_TOPIC},
    socket_client::SocketClient,
};

pub(super) async fn request(request: HostedOwnerRequest) -> Result<HostedOwnerResponse> {
    let seconds = astrid_config::client::production_admin_timeout()?;
    tokio::time::timeout(std::time::Duration::from_secs(seconds),async {
        let mut client=SocketClient::connect(SessionId::SYSTEM,crate::principal::current()).await
            .context("owner controls require an already-running daemon; no automatic startup was attempted")?;
        anyhow::ensure!(client.is_authenticated(),"registered native device authentication required");
        client.send_message(IpcMessage::new(Topic::from_raw(REQUEST_TOPIC),
            IpcPayload::RawJson(serde_json::to_value(request)?),uuid::Uuid::new_v4())).await?;
        // Native RawJson results deliberately use guest-wire payload encoding;
        // the typed IpcMessage reader skips those untagged JSON frames.
        let frame = client.read_until_topic(RESPONSE_TOPIC,std::time::Duration::from_secs(seconds)).await?;
        let body = frame.get("payload").context("missing native owner payload")?;
        if let Some(error) = body.get("error").and_then(serde_json::Value::as_str) {
            anyhow::bail!("owner operation refused: {error}");
        }
        serde_json::from_value(body.get("result").cloned().context("missing owner response")?).context("invalid owner response")
    }).await.context("native owner operation timed out; inspect durable status before retrying")?
}

pub(super) async fn configure(
    policy: HostedOwnerConfiguration,
    target_default: bool,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    policy.validate_selection(
        target_default,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |time| time.as_secs()),
    )?;
    let deadline =
        std::time::Duration::from_secs(astrid_config::client::production_admin_timeout()?);
    let binary = crate::bootstrap::find_companion_binary("astrid-daemon")?;
    let mut child = tokio::process::Command::new(binary)
        .arg("--configure-hosted-owner")
        .args(target_default.then_some("--owner-target-default"))
        .stdin(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let result = tokio::time::timeout(deadline, async {
        let mut input = child.stdin.take().context("missing policy input pipe")?;
        input.write_all(&serde_json::to_vec(&policy)?).await?;
        input.shutdown().await?;
        drop(input);
        child
            .wait()
            .await
            .context("wait for native policy configuration")
    })
    .await;
    let status = if let Ok(status) = result {
        status?
    } else {
        child
            .kill()
            .await
            .context("terminate timed-out native configuration")?;
        child
            .wait()
            .await
            .context("reap timed-out native configuration")?;
        anyhow::bail!("configuration timed out; inspect before retrying");
    };
    anyhow::ensure!(
        status.success(),
        "native controlling-account configuration failed"
    );
    Ok(())
}
