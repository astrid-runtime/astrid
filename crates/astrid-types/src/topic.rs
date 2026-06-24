//! Typed IPC topic construction.
//!
//! Every cross-boundary message carries a `topic` — a dotted, versioned
//! string (`astrid.v1.elicit.response.<uuid>`, `agent.v1.response`, …) that
//! the event bus routes on. Historically these were built ad-hoc with
//! `format!` and scattered `const *_TOPIC` literals, so a one-character drift
//! in any producer silently broke IPC routing with no compile-time signal.
//!
//! [`Topic`] is a transparent newtype over `String` with a typed constructor
//! per topic family. The constructors are the single source of truth for the
//! exact wire string of each family; a unit test pins every constructor's
//! output so the byte-identical-on-the-wire invariant is enforced at build
//! time.
//!
//! ## Wire compatibility
//!
//! `#[serde(transparent)]` means a `Topic` serializes and deserializes as a
//! bare JSON string, identical to the `String` it replaced. No WIT change, no
//! wire-format change: the guest ABI for a topic stays `string`, and the
//! bindgen boundary converts in/out with [`Topic::from_raw`] / [`Topic::as_str`].
//!
//! ## Raw construction is explicit
//!
//! There is no blanket `From<&str>`/`From<String>` — the only way to build a
//! `Topic` from an arbitrary string is [`Topic::from_raw`], the deliberate
//! escape hatch for the bindgen boundary (a guest-supplied `string` topic) and
//! genuinely dynamic topics that have no typed family. Read operations
//! (`starts_with`, `strip_prefix`, slicing, `==`) keep working via [`Deref`]
//! and the `PartialEq<str>` impls.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A cross-boundary IPC topic.
///
/// Transparent newtype over `String`: serializes as a bare JSON string,
/// byte-identical to the `String` it replaced. Build one with a typed
/// constructor (e.g. [`Topic::elicit_response`]) for a known family, or
/// [`Topic::from_raw`] for the bindgen boundary / genuinely dynamic topics.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Topic(String);

impl Topic {
    /// Borrow the underlying topic string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build a `Topic` from an arbitrary string.
    ///
    /// The **explicit escape hatch** for boundary conversions — chiefly the
    /// WIT bindgen boundary, where a guest supplies a topic as `string` — and
    /// for genuinely dynamic topics that have no typed family. This is the
    /// only way to construct a `Topic` from an arbitrary string; prefer a
    /// typed constructor whenever the family is known so the wire string stays
    /// single-sourced.
    #[must_use]
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    // --- elicit family ---------------------------------------------------

    /// The elicit request base topic: `astrid.v1.elicit`.
    #[must_use]
    pub fn elicit_request() -> Self {
        Self("astrid.v1.elicit".to_string())
    }

    /// The elicit response topic for `request_id`:
    /// `astrid.v1.elicit.response.<request_id>`.
    #[must_use]
    pub fn elicit_response(request_id: Uuid) -> Self {
        Self(format!("astrid.v1.elicit.response.{request_id}"))
    }

    // --- approval family -------------------------------------------------

    /// The approval request base topic: `astrid.v1.approval`.
    #[must_use]
    pub fn approval_request() -> Self {
        Self("astrid.v1.approval".to_string())
    }

    /// The approval response topic for `request_id`:
    /// `astrid.v1.approval.response.<request_id>`.
    ///
    /// Accepts any `Display` because call sites pass both `String` (opaque
    /// correlation ids) and `Uuid`.
    #[must_use]
    pub fn approval_response(request_id: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.approval.response.{request_id}"))
    }

    // --- audit family ----------------------------------------------------

    /// The cross-principal audit feed topic: `astrid.v1.audit.entry`.
    #[must_use]
    pub fn audit_entry() -> Self {
        Self("astrid.v1.audit.entry".to_string())
    }

    // --- user / agent / client families ----------------------------------

    /// The user prompt topic: `user.v1.prompt`.
    #[must_use]
    pub fn user_prompt() -> Self {
        Self("user.v1.prompt".to_string())
    }

    /// The agent response topic: `agent.v1.response`.
    #[must_use]
    pub fn agent_response() -> Self {
        Self("agent.v1.response".to_string())
    }

    /// The agent stream delta topic: `agent.v1.stream.delta`.
    #[must_use]
    pub fn agent_stream_delta() -> Self {
        Self("agent.v1.stream.delta".to_string())
    }

    /// The agent session-changed topic: `agent.v1.session_changed`.
    #[must_use]
    pub fn agent_session_changed() -> Self {
        Self("agent.v1.session_changed".to_string())
    }

    /// The client connect topic: `client.v1.connect`.
    #[must_use]
    pub fn client_connect() -> Self {
        Self("client.v1.connect".to_string())
    }

    /// The client disconnect topic: `client.v1.disconnect`.
    #[must_use]
    pub fn client_disconnect() -> Self {
        Self("client.v1.disconnect".to_string())
    }

    // --- cli command family ----------------------------------------------

    /// The CLI command execute topic: `cli.v1.command.execute`.
    #[must_use]
    pub fn cli_command_execute() -> Self {
        Self("cli.v1.command.execute".to_string())
    }

    /// The CLI command run topic for `provider`:
    /// `cli.v1.command.run.<provider>`.
    #[must_use]
    pub fn cli_command_run(provider: impl std::fmt::Display) -> Self {
        Self(format!("cli.v1.command.run.{provider}"))
    }

    /// The CLI command result topic for `req_id`:
    /// `cli.v1.command.result.<req_id>`.
    #[must_use]
    pub fn cli_command_result(req_id: impl std::fmt::Display) -> Self {
        Self(format!("cli.v1.command.result.{req_id}"))
    }

    // --- kernel request / response family --------------------------------

    /// A kernel-management request topic: `astrid.v1.request.<suffix>`.
    ///
    /// `suffix` may itself be a multi-segment, correlation-bearing string
    /// (e.g. `status.<uuid>`); the prefix is the invariant part.
    #[must_use]
    pub fn kernel_request(suffix: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.request.{suffix}"))
    }

    /// A kernel-management response topic: `astrid.v1.response.<suffix>`.
    #[must_use]
    pub fn kernel_response(suffix: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.response.{suffix}"))
    }

    /// A reload-capsule request topic:
    /// `astrid.v1.request.reload_capsule.<correlation>`.
    #[must_use]
    pub fn reload_capsule_request(correlation: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.request.reload_capsule.{correlation}"))
    }

    /// A reload-capsule response topic:
    /// `astrid.v1.response.reload_capsule.<correlation>`.
    #[must_use]
    pub fn reload_capsule_response(correlation: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.response.reload_capsule.{correlation}"))
    }

    // --- admin family ----------------------------------------------------

    /// An admin request topic: `astrid.v1.admin.<suffix>`.
    #[must_use]
    pub fn admin_request(suffix: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.admin.{suffix}"))
    }

    /// An admin response topic: `astrid.v1.admin.response.<suffix>`.
    #[must_use]
    pub fn admin_response(suffix: impl std::fmt::Display) -> Self {
        Self(format!("astrid.v1.admin.response.{suffix}"))
    }

    // --- session family --------------------------------------------------

    /// A session response topic for an operation + correlation:
    /// `session.v1.response.<op>.<correlation>`.
    #[must_use]
    pub fn session_response(
        op: impl std::fmt::Display,
        correlation: impl std::fmt::Display,
    ) -> Self {
        Self(format!("session.v1.response.{op}.{correlation}"))
    }
}

impl std::ops::Deref for Topic {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Topic {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Topic> for String {
    fn from(topic: Topic) -> Self {
        topic.0
    }
}

impl PartialEq<str> for Topic {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Topic {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Topic> for str {
    fn eq(&self, other: &Topic) -> bool {
        self == other.0
    }
}

impl PartialEq<Topic> for &str {
    fn eq(&self, other: &Topic) -> bool {
        *self == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elicit_request_string() {
        assert_eq!(Topic::elicit_request().as_str(), "astrid.v1.elicit");
    }

    #[test]
    fn elicit_response_string() {
        let id = Uuid::nil();
        assert_eq!(
            Topic::elicit_response(id).as_str(),
            format!("astrid.v1.elicit.response.{id}")
        );
    }

    #[test]
    fn approval_request_string() {
        assert_eq!(Topic::approval_request().as_str(), "astrid.v1.approval");
    }

    #[test]
    fn approval_response_string_accepts_string_and_uuid() {
        let id = Uuid::nil();
        assert_eq!(
            Topic::approval_response(id).as_str(),
            format!("astrid.v1.approval.response.{id}")
        );
        let rid = "req-1".to_string();
        assert_eq!(
            Topic::approval_response(&rid).as_str(),
            "astrid.v1.approval.response.req-1"
        );
    }

    #[test]
    fn audit_entry_string() {
        assert_eq!(Topic::audit_entry().as_str(), "astrid.v1.audit.entry");
    }

    #[test]
    fn user_agent_client_strings() {
        assert_eq!(Topic::user_prompt().as_str(), "user.v1.prompt");
        assert_eq!(Topic::agent_response().as_str(), "agent.v1.response");
        assert_eq!(
            Topic::agent_stream_delta().as_str(),
            "agent.v1.stream.delta"
        );
        assert_eq!(
            Topic::agent_session_changed().as_str(),
            "agent.v1.session_changed"
        );
        assert_eq!(Topic::client_connect().as_str(), "client.v1.connect");
        assert_eq!(Topic::client_disconnect().as_str(), "client.v1.disconnect");
    }

    #[test]
    fn cli_command_strings() {
        assert_eq!(
            Topic::cli_command_execute().as_str(),
            "cli.v1.command.execute"
        );
        assert_eq!(
            Topic::cli_command_run("openai").as_str(),
            "cli.v1.command.run.openai"
        );
        assert_eq!(
            Topic::cli_command_result("abc").as_str(),
            "cli.v1.command.result.abc"
        );
    }

    #[test]
    fn kernel_request_response_strings() {
        assert_eq!(
            Topic::kernel_request("status.abc").as_str(),
            "astrid.v1.request.status.abc"
        );
        assert_eq!(
            Topic::kernel_response("status.abc").as_str(),
            "astrid.v1.response.status.abc"
        );
    }

    #[test]
    fn reload_capsule_strings() {
        assert_eq!(
            Topic::reload_capsule_request("corr").as_str(),
            "astrid.v1.request.reload_capsule.corr"
        );
        assert_eq!(
            Topic::reload_capsule_response("corr").as_str(),
            "astrid.v1.response.reload_capsule.corr"
        );
    }

    #[test]
    fn admin_strings() {
        assert_eq!(
            Topic::admin_request("agent.list").as_str(),
            "astrid.v1.admin.agent.list"
        );
        assert_eq!(
            Topic::admin_response("agent.list").as_str(),
            "astrid.v1.admin.response.agent.list"
        );
    }

    #[test]
    fn session_response_string() {
        assert_eq!(
            Topic::session_response("get_messages", "corr").as_str(),
            "session.v1.response.get_messages.corr"
        );
    }

    #[test]
    fn from_raw_preserves_arbitrary_string() {
        assert_eq!(
            Topic::from_raw("tool.v1.execute.do_thing").as_str(),
            "tool.v1.execute.do_thing"
        );
    }

    // --- serde transparency: byte-identical to the old String ------------

    #[test]
    fn serializes_as_bare_json_string() {
        let topic = Topic::agent_response();
        let json = serde_json::to_string(&topic).unwrap();
        assert_eq!(json, r#""agent.v1.response""#);
        // Identical to serializing the underlying String directly.
        let plain = serde_json::to_string("agent.v1.response").unwrap();
        assert_eq!(json, plain);
    }

    #[test]
    fn deserializes_from_bare_json_string() {
        let topic: Topic = serde_json::from_str(r#""astrid.v1.elicit""#).unwrap();
        assert_eq!(topic, Topic::elicit_request());
    }

    #[test]
    fn serde_roundtrip_with_correlation_suffix() {
        let id = Uuid::nil();
        let topic = Topic::elicit_response(id);
        let json = serde_json::to_string(&topic).unwrap();
        let parsed: Topic = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, topic);
        assert_eq!(json, format!(r#""astrid.v1.elicit.response.{id}""#));
    }

    // --- Deref / PartialEq ergonomics ------------------------------------

    #[test]
    fn deref_read_ops_work() {
        let topic = Topic::elicit_response(Uuid::nil());
        assert!(topic.starts_with("astrid.v1.elicit.response."));
        let nil = Uuid::nil().to_string();
        assert_eq!(
            topic.strip_prefix("astrid.v1.elicit.response."),
            Some(nil.as_str())
        );
    }

    #[test]
    fn partial_eq_against_str() {
        let topic = Topic::elicit_request();
        assert!(topic == "astrid.v1.elicit");
        assert!("astrid.v1.elicit" == topic);
        assert!(topic != "astrid.v1.approval");
    }
}
