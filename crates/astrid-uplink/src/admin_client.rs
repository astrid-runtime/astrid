//! Layer 6 admin IPC client.
//!
//! Wraps [`SocketClient`] with the request/response correlation
//! pattern introduced by issue #672. Each call generates a UUID v4
//! `request_id`, sends an [`AdminKernelRequest`] on
//! `astrid.v1.admin.<suffix>`, and reads messages from the daemon
//! until one arrives on `astrid.v1.admin.response.<suffix>` whose
//! echoed `request_id` matches.
//!
//! Messages on other topics or with a non-matching `request_id` are
//! dropped — the admin client does not consume the chat event stream,
//! so unrelated broadcasts (capsule-loaded notices, agent responses)
//! are safe to discard while we wait.
//!
//! Trust shape: the caller passes `PrincipalId` explicitly. The CLI
//! resolves it from its `context::active_agent()` file; the HTTP
//! gateway resolves it from a verified bearer token. Both stamp the
//! outbound `IpcMessage.principal` so the kernel's `resolve_caller`
//! reads the right principal for Layer 5/6 capability checks.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    AdminKernelRequest, AdminKernelResponse, AdminRequestKind, AdminResponseBody,
};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use serde_json::Value;
use uuid::Uuid;

use crate::socket_client::SocketClient;

/// Default timeout for the response read loop. Generous because admin
/// writes can block on the kernel write lock.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Stable wire-name suffix for an [`AdminRequestKind`].
///
/// Mirrors `admin_request_method` on the kernel side — the suffix is
/// the part after `astrid.v1.admin.`. This is the exact string the
/// kernel router uses to derive the response topic, so the suffix MUST
/// match between sides.
#[must_use]
pub const fn topic_suffix(req: &AdminRequestKind) -> &'static str {
    match req {
        AdminRequestKind::AgentCreate { .. } => "agent.create",
        AdminRequestKind::AgentDelete { .. } => "agent.delete",
        AdminRequestKind::AgentEnable { .. } => "agent.enable",
        AdminRequestKind::AgentDisable { .. } => "agent.disable",
        AdminRequestKind::AgentModify { .. } => "agent.modify",
        AdminRequestKind::AgentList => "agent.list",
        AdminRequestKind::QuotaSet { .. } => "quota.set",
        AdminRequestKind::QuotaGet { .. } => "quota.get",
        AdminRequestKind::UsageGet { .. } => "usage.get",
        AdminRequestKind::GroupCreate { .. } => "group.create",
        AdminRequestKind::GroupDelete { .. } => "group.delete",
        AdminRequestKind::GroupModify { .. } => "group.modify",
        AdminRequestKind::GroupList => "group.list",
        AdminRequestKind::CapsGrant { .. } => "caps.grant",
        AdminRequestKind::CapsRevoke { .. } => "caps.revoke",
        AdminRequestKind::CapsTokenMint { .. } => "caps.token.mint",
        AdminRequestKind::CapsTokenRevoke { .. } => "caps.token.revoke",
        AdminRequestKind::CapsTokenList { .. } => "caps.token.list",
        AdminRequestKind::InviteIssue { .. } => "invite.issue",
        AdminRequestKind::InviteRedeem { .. } => "invite.redeem",
        AdminRequestKind::InviteList => "invite.list",
        AdminRequestKind::InviteRevoke { .. } => "invite.revoke",
        AdminRequestKind::PairDeviceIssue { .. } => "auth.pair.issue",
        AdminRequestKind::PairDeviceRedeem { .. } => "auth.pair.redeem",
        AdminRequestKind::PairDeviceList { .. } => "auth.pair.list",
        AdminRequestKind::PairDeviceRevoke { .. } => "auth.pair.revoke",
    }
}

/// Build the request topic for an [`AdminRequestKind`].
#[must_use]
pub fn request_topic(req: &AdminRequestKind) -> Topic {
    Topic::admin_request(topic_suffix(req))
}

/// Build the response topic for an [`AdminRequestKind`].
#[must_use]
pub fn response_topic(req: &AdminRequestKind) -> Topic {
    Topic::admin_response(topic_suffix(req))
}

/// A connected admin client. Sends [`AdminRequestKind`] requests and
/// awaits the matching [`AdminResponseBody`].
pub struct AdminClient {
    inner: SocketClient,
    caller: PrincipalId,
    timeout: Duration,
}

impl AdminClient {
    /// Connect to the running daemon, authenticate via the existing
    /// handshake, and bind the client to `caller`. Every outbound
    /// request stamps `IpcMessage.principal = caller` so the kernel's
    /// `resolve_caller` reads it for Layer 5/6 capability checks.
    ///
    /// # Errors
    /// Returns an error if the socket file is missing (no daemon),
    /// connection fails, or the handshake is rejected.
    pub async fn connect(caller: PrincipalId) -> Result<Self> {
        let session_id = astrid_core::SessionId::from_uuid(Uuid::new_v4());
        let inner = SocketClient::connect(session_id, caller.clone())
            .await
            .context("Failed to connect to Astrid daemon. Run `astrid start` to launch it.")?;
        Ok(Self {
            inner,
            caller,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Override the response read timeout. Used by tests.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Borrow the principal this client stamps on outbound messages.
    #[must_use]
    pub const fn caller(&self) -> &PrincipalId {
        &self.caller
    }

    /// Send an admin request and await the matching response.
    ///
    /// The `request_id` is generated as a fresh UUID v4 and echoed
    /// back on the response. Messages with a different topic or a
    /// non-matching `request_id` are dropped while we wait.
    ///
    /// # Errors
    /// Returns an error if the request fails to serialize, the send
    /// fails, the response is not received within the timeout, or
    /// the connection drops before a matching response arrives.
    pub async fn request(&mut self, kind: AdminRequestKind) -> Result<AdminResponseBody> {
        let request_id = Uuid::new_v4().to_string();
        let topic = request_topic(&kind);
        let want_response = response_topic(&kind);

        let req = AdminKernelRequest::with_request_id(request_id.clone(), kind);
        let payload =
            serde_json::to_value(&req).context("Failed to serialize AdminKernelRequest")?;
        let msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), Uuid::nil())
            .with_principal(self.caller.to_string());
        self.inner.send_message(msg).await?;

        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!(
                    "Admin request timed out after {:?} waiting for {want_response}",
                    self.timeout
                );
            }
            let read = tokio::time::timeout(remaining, self.inner.read_raw_frame()).await;
            let frame = match read {
                Ok(Ok(Some(bytes))) => bytes,
                Ok(Ok(None)) => {
                    anyhow::bail!("Daemon closed the connection before responding");
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    anyhow::bail!(
                        "Admin request timed out after {:?} waiting for {want_response}",
                        self.timeout
                    );
                },
            };

            // The host serializes IPC envelopes through `to_guest_bytes`
            // which strips the `type` tag for `IpcPayload::RawJson`, so
            // the bytes the uplink sees from the proxy embed the
            // response directly under `payload` (no `IpcPayload`
            // wrapper). Match by topic, then deserialize
            // `AdminKernelResponse` straight out of the `payload` field.
            let raw: Value = match serde_json::from_slice(&frame) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "frame is not JSON, skipping");
                    continue;
                },
            };
            let topic = raw
                .get("topic")
                .and_then(|t| t.as_str())
                .unwrap_or_default();
            if topic != want_response {
                tracing::debug!(topic = %topic, "ignoring non-matching message");
                continue;
            }
            let Some(payload) = raw.get("payload").cloned() else {
                tracing::warn!(topic = %topic, "matched response missing payload");
                continue;
            };
            // `payload` may be either the bare AdminKernelResponse JSON
            // (after `to_guest_bytes` stripped the type tag) or a
            // wrapped `{"type": "raw_json", "value": ...}`. Try the
            // bare form first; fall back to extracting `value`.
            let response_value = if payload
                .as_object()
                .is_some_and(|m| m.contains_key("type") && m.contains_key("value"))
            {
                payload.get("value").cloned().unwrap_or(payload)
            } else {
                payload
            };
            match serde_json::from_value::<AdminKernelResponse>(response_value) {
                Ok(resp) => {
                    if resp.request_id.as_deref() == Some(&request_id) {
                        return Ok(resp.body);
                    }
                    tracing::debug!(
                        echoed = ?resp.request_id,
                        expected = %request_id,
                        "ignoring response with non-matching request_id"
                    );
                },
                Err(e) => {
                    tracing::warn!(error = %e, "failed to deserialize admin response");
                },
            }
        }
    }
}

/// Convert an [`AdminResponseBody`] into a `Result`, lifting `Error`
/// variants into `Err` so the caller can use `?` for cross-tenant
/// permission denials and validation failures.
///
/// # Errors
/// Returns an error wrapping the kernel's error message when the
/// response body is [`AdminResponseBody::Error`].
pub fn into_result(body: AdminResponseBody) -> Result<AdminResponseBody> {
    match body {
        AdminResponseBody::Error(msg) => Err(anyhow!("kernel rejected request: {msg}")),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::PrincipalId;

    #[test]
    fn topic_suffixes_match_kernel_constants() {
        assert_eq!(
            topic_suffix(&AdminRequestKind::AgentCreate {
                name: "x".into(),
                groups: vec![],
                grants: vec![],
                inherit_from: None,
                clone_from: None,
                allow_admin_clone: false,
            }),
            "agent.create"
        );
        assert_eq!(topic_suffix(&AdminRequestKind::AgentList), "agent.list");
        assert_eq!(topic_suffix(&AdminRequestKind::GroupList), "group.list");
        let p = PrincipalId::default();
        assert_eq!(
            topic_suffix(&AdminRequestKind::QuotaGet { principal: p }),
            "quota.get"
        );
    }

    #[test]
    fn request_topic_uses_admin_prefix() {
        let req = AdminRequestKind::AgentList;
        assert_eq!(request_topic(&req), "astrid.v1.admin.agent.list");
        assert_eq!(response_topic(&req), "astrid.v1.admin.response.agent.list");
    }

    #[test]
    fn invite_topic_suffixes() {
        assert_eq!(
            topic_suffix(&AdminRequestKind::InviteIssue {
                group: "agent".into(),
                expires_secs: Some(3600),
                max_uses: 1,
                metadata: None,
            }),
            "invite.issue"
        );
        assert_eq!(
            topic_suffix(&AdminRequestKind::InviteRedeem {
                token: "x".into(),
                public_key: String::new(),
                display_name: None,
            }),
            "invite.redeem"
        );
        assert_eq!(topic_suffix(&AdminRequestKind::InviteList), "invite.list");
    }

    #[test]
    fn into_result_lifts_error_variant() {
        let err = AdminResponseBody::Error("permission denied".into());
        let res = into_result(err);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("permission denied"), "got: {msg}");
    }

    #[test]
    fn into_result_passes_through_success() {
        let ok = AdminResponseBody::AgentList(vec![]);
        let res = into_result(ok);
        assert!(matches!(res, Ok(AdminResponseBody::AgentList(_))));
    }
}
