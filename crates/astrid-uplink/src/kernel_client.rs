//! Kernel-API IPC client.
//!
//! Mirrors [`AdminClient`](crate::admin_client::AdminClient) but for
//! the `KernelRequest` family that flows over the
//! `astrid.v1.request.*` / `astrid.v1.response.*` topic prefixes
//! instead of the `astrid.v1.admin.*` admin surface. Used by the
//! HTTP gateway's capsule + system routes (`GET /api/capsules`,
//! `GET /api/sys/status`, etc.).
//!
//! ## Why a separate client
//!
//! [`KernelRequest`](astrid_core::kernel_api::KernelRequest) and
//! [`AdminRequestKind`](astrid_core::kernel_api::AdminRequestKind)
//! are two distinct typed wire formats with two distinct topic
//! prefixes; the kernel dispatchers are sibling-but-separate. Splitting
//! the client mirror keeps the type-level boundaries clean — a route
//! handler for `/api/capsules` literally cannot accidentally publish
//! an `AdminRequestKind` and vice-versa.
//!
//! ## Concurrency safety
//!
//! Unlike `AdminClient`, the `KernelRequest` payload has no
//! `request_id` field for correlation. To make concurrent HTTP
//! requests safe on a shared bus, every outbound message gets a
//! per-request UUID embedded in the topic suffix
//! (`astrid.v1.request.<wire-name>.<uuid>`). The kernel router echoes
//! the full suffix on its response (`response_topic` does
//! `topic.strip_prefix("astrid.v1.request.")` then prepends the
//! response prefix), so the client can match a unique
//! `astrid.v1.response.<wire-name>.<uuid>` and never confuse two
//! in-flight `GetStatus` calls for each other.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use uuid::Uuid;

use crate::socket_client::SocketClient;

/// Default response timeout. Generous because some kernel ops
/// (capsule reload, status under load) can take a few seconds.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Stable wire-name component of the topic suffix for a
/// [`KernelRequest`] variant.
///
/// These names are hand-curated rather than auto-derived — they
/// match the CLI's existing conventions
/// (`crates/astrid-cli/src/commands/{who,daemon,ps,doctor}.rs`) so
/// the gateway and CLI publish on the same topics and the kernel
/// can't accidentally see two different name conventions for the
/// same payload.
#[must_use]
pub const fn topic_suffix(req: &KernelRequest) -> &'static str {
    match req {
        KernelRequest::InstallCapsule { .. } => "install_capsule",
        KernelRequest::ApproveCapability { .. } => "approve_capability",
        KernelRequest::ListCapsules => "list_capsules",
        KernelRequest::ReloadCapsules => "reload_capsules",
        KernelRequest::ReloadCapsule { .. } => "reload_capsule",
        KernelRequest::UnloadCapsule { .. } => "unload_capsule",
        KernelRequest::GetCommands => "get_commands",
        KernelRequest::GetCapsuleMetadata => "metadata",
        KernelRequest::GetAgentReadiness => "agent_readiness",
        KernelRequest::Shutdown { .. } => "shutdown",
        KernelRequest::GetStatus => "status",
    }
}

/// A connected kernel-management client. One short-lived
/// `KernelClient` per HTTP request; the per-request connection (plus
/// the per-call UUID embedded in the topic) avoids cross-talk
/// between concurrent dashboard calls.
pub struct KernelClient {
    inner: SocketClient,
    caller: PrincipalId,
    timeout: Duration,
    /// The authenticating device's `key_id`, when the caller's bearer/handshake
    /// was device-scoped. Stamped on every outbound request so the kernel
    /// cap-gate applies the per-device capability scope (#999); `None` for a
    /// full-authority caller (no attenuation).
    device_key_id: Option<String>,
}

/// Build the request message and its private response topic for `req` on behalf
/// of `caller`, carrying `device_key_id` when the caller was device-scoped.
///
/// Free function (no `self`) so the principal + device-scope stamping is
/// unit-testable without a live socket. The kernel strips the
/// `astrid.v1.request.` prefix and reprefixes `astrid.v1.response.`, so the
/// per-call correlation UUID gives a response channel concurrent calls can't
/// collide on.
fn build_request_message(
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    req: &KernelRequest,
) -> Result<(IpcMessage, Topic)> {
    let correlation = Uuid::new_v4().simple().to_string();
    let suffix = format!("{}.{correlation}", topic_suffix(req));
    let request_topic = Topic::kernel_request(&suffix);
    let want_response = Topic::kernel_response(&suffix);

    let payload = serde_json::to_value(req).context("serialise KernelRequest")?;
    let mut msg = IpcMessage::new(request_topic, IpcPayload::RawJson(payload), Uuid::nil())
        .with_principal(caller.to_string());
    if let Some(kid) = device_key_id {
        msg = msg.with_device_key_id(kid);
    }
    Ok((msg, want_response))
}

impl KernelClient {
    /// Connect to the running daemon, authenticate via the existing
    /// handshake, and bind the client to `caller`. Every outbound
    /// request stamps `IpcMessage.principal = caller` so the kernel's
    /// `resolve_caller` reads it for Layer 5 capability checks.
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
            device_key_id: None,
        })
    }

    /// Override the response read timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Carry the authenticating device's `key_id` so the kernel cap-gate
    /// applies the per-device capability scope (#999). Callers behind the
    /// gateway auth middleware pass the bearer's `CallerContext.device_key_id`;
    /// a full-authority bearer passes `None` (unattenuated, the prior behaviour).
    #[must_use]
    pub fn with_device_key_id(mut self, device_key_id: Option<String>) -> Self {
        self.device_key_id = device_key_id;
        self
    }

    /// Send a [`KernelRequest`] and await the matching
    /// [`KernelResponse`].
    ///
    /// # Errors
    /// Returns an error on serialization failure, send failure, or
    /// timeout / connection drop before a matching response arrives.
    pub async fn request(&mut self, req: KernelRequest) -> Result<KernelResponse> {
        let (msg, want_response) =
            build_request_message(&self.caller, self.device_key_id.as_deref(), &req)?;
        self.inner.send_message(msg).await?;

        let raw = self
            .inner
            .read_until_topic(want_response.as_str(), self.timeout)
            .await
            .with_context(|| format!("waiting on {want_response}"))?;

        SocketClient::extract_kernel_response(&raw).ok_or_else(|| {
            anyhow!("kernel response on {want_response} did not deserialize as KernelResponse")
        })
    }

    /// Borrow the principal this client stamps on outbound messages.
    #[must_use]
    pub const fn caller(&self) -> &PrincipalId {
        &self.caller
    }
}

/// Convenience: lift a [`KernelResponse::Error`] into `Err`.
///
/// # Errors
/// Returns an error wrapping the kernel's error message when the
/// response is `KernelResponse::Error`.
pub fn into_result(resp: KernelResponse) -> Result<KernelResponse> {
    match resp {
        KernelResponse::Error(msg) => Err(anyhow!("kernel rejected request: {msg}")),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_suffixes_match_cli_conventions() {
        // Pin these to the strings the CLI's existing kernel-request
        // code already uses (who.rs, daemon.rs, ps.rs, doctor.rs).
        // Drift here means the gateway and CLI publish to different
        // topics for the same payload — silent breakage.
        assert_eq!(topic_suffix(&KernelRequest::GetStatus), "status");
        assert_eq!(topic_suffix(&KernelRequest::ListCapsules), "list_capsules");
        assert_eq!(topic_suffix(&KernelRequest::GetCommands), "get_commands");
        assert_eq!(topic_suffix(&KernelRequest::GetCapsuleMetadata), "metadata");
        assert_eq!(
            topic_suffix(&KernelRequest::GetAgentReadiness),
            "agent_readiness"
        );
        assert_eq!(
            topic_suffix(&KernelRequest::ReloadCapsules),
            "reload_capsules"
        );
        assert_eq!(
            topic_suffix(&KernelRequest::Shutdown { reason: None }),
            "shutdown"
        );
    }

    #[test]
    fn request_message_stamps_principal_and_device_key_id() {
        // A device-scoped caller's key_id MUST ride the outbound request so the
        // kernel cap-gate applies the per-device scope (#999). Regression guard:
        // without the stamp, every HTTP gateway admin call (status, readiness,
        // reload, capsule list/install) bypasses device-scope attenuation.
        let caller = PrincipalId::new("alice").unwrap();
        let (msg, want) = build_request_message(
            &caller,
            Some("abcdef0123456789"),
            &KernelRequest::GetAgentReadiness,
        )
        .expect("build message");
        assert_eq!(msg.principal.as_deref(), Some("alice"));
        assert_eq!(
            msg.device_key_id.as_deref(),
            Some("abcdef0123456789"),
            "device key id must reach the kernel cap-gate"
        );
        // Response topic carries the request suffix so the reply is correlated.
        assert!(want.starts_with("astrid.v1.response."));
        assert!(want.contains("agent_readiness"));
    }

    #[test]
    fn request_message_omits_device_key_id_for_full_authority_caller() {
        // A full-authority bearer carries no device scope — the message must
        // leave device_key_id unset so the kernel treats it as unattenuated,
        // preserving the prior single-tenant behaviour.
        let caller = PrincipalId::new("alice").unwrap();
        let (msg, _) =
            build_request_message(&caller, None, &KernelRequest::GetStatus).expect("build message");
        assert!(msg.device_key_id.is_none());
    }

    #[test]
    fn into_result_lifts_error_variant() {
        let err = KernelResponse::Error("not allowed".into());
        let res = into_result(err);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not allowed"));
    }
}
