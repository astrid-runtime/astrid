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
use astrid_types::ipc::{IpcMessage, IpcPayload};
use uuid::Uuid;

use crate::socket_client::SocketClient;

/// Topic prefix for kernel-management requests.
const REQUEST_PREFIX: &str = "astrid.v1.request.";
/// Topic prefix for kernel-management responses.
const RESPONSE_PREFIX: &str = "astrid.v1.response.";

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
        KernelRequest::GetCommands => "get_commands",
        KernelRequest::GetCapsuleMetadata => "metadata",
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
        let inner = SocketClient::connect(session_id)
            .await
            .context("Failed to connect to Astrid daemon. Run `astrid start` to launch it.")?;
        Ok(Self {
            inner,
            caller,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Override the response read timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a [`KernelRequest`] and await the matching
    /// [`KernelResponse`].
    ///
    /// # Errors
    /// Returns an error on serialization failure, send failure, or
    /// timeout / connection drop before a matching response arrives.
    pub async fn request(&mut self, req: KernelRequest) -> Result<KernelResponse> {
        // Per-call UUID suffix. The kernel's `handle_request` strips
        // the `astrid.v1.request.` prefix and reprefixes with
        // `astrid.v1.response.`, so embedding a UUID here gives us a
        // private response channel that other concurrent in-flight
        // calls can't collide on.
        let correlation = Uuid::new_v4().simple().to_string();
        let suffix = format!("{}.{correlation}", topic_suffix(&req));
        let request_topic = format!("{REQUEST_PREFIX}{suffix}");
        let want_response = format!("{RESPONSE_PREFIX}{suffix}");

        let payload = serde_json::to_value(&req).context("serialise KernelRequest")?;
        let msg = IpcMessage::new(request_topic, IpcPayload::RawJson(payload), Uuid::nil())
            .with_principal(self.caller.to_string());
        self.inner.send_message(msg).await?;

        let raw = self
            .inner
            .read_until_topic(&want_response, self.timeout)
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
            topic_suffix(&KernelRequest::ReloadCapsules),
            "reload_capsules"
        );
        assert_eq!(
            topic_suffix(&KernelRequest::Shutdown { reason: None }),
            "shutdown"
        );
    }

    #[test]
    fn into_result_lifts_error_variant() {
        let err = KernelResponse::Error("not allowed".into());
        let res = into_result(err);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not allowed"));
    }
}
