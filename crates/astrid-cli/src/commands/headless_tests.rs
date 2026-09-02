use std::collections::VecDeque;
use std::future::pending;

use astrid_core::SessionId;
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use uuid::Uuid;

use super::*;

enum ReadStep {
    Message(Box<IpcMessage>),
    Timeout,
}

struct DeterministicSource {
    steps: VecDeque<ReadStep>,
    sent: Vec<IpcMessage>,
}

impl DeterministicSource {
    fn new(steps: impl IntoIterator<Item = ReadStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            sent: Vec::new(),
        }
    }
}

impl ResponseSource for DeterministicSource {
    async fn read_message_before(&mut self, _remaining: Duration) -> ReadOutcome {
        match self.steps.pop_front() {
            Some(ReadStep::Message(message)) => ReadOutcome::Message(message),
            Some(ReadStep::Timeout) => ReadOutcome::Timeout,
            None => ReadOutcome::Closed,
        }
    }

    async fn send_message(&mut self, message: IpcMessage) -> Result<()> {
        self.sent.push(message);
        Ok(())
    }
}

fn response_on_topic(
    topic: Topic,
    text: &str,
    is_final: bool,
    session_id: &SessionId,
) -> IpcMessage {
    IpcMessage::new(
        topic,
        IpcPayload::AgentResponse {
            text: text.to_owned(),
            is_final,
            session_id: session_id.0.to_string(),
        },
        session_id.0,
    )
}

fn response(text: &str, is_final: bool, session_id: &SessionId) -> IpcMessage {
    response_on_topic(Topic::agent_response(), text, is_final, session_id)
}

fn raw_json_on_topic(topic: Topic, value: serde_json::Value, session_id: &SessionId) -> IpcMessage {
    IpcMessage::new(topic, IpcPayload::RawJson(value), session_id.0)
}

fn raw_json_response(text: &str, is_final: bool, session_id: &SessionId) -> IpcMessage {
    raw_json_on_topic(
        Topic::agent_response(),
        serde_json::json!({
            "session_id": session_id.0.to_string(),
            "text": text,
            "is_final": is_final,
        }),
        session_id,
    )
}

fn spoofed_response(text: &str, is_final: bool, session_id: &SessionId) -> IpcMessage {
    response_on_topic(
        Topic::from_raw("astrid.v1.response.spoof"),
        text,
        is_final,
        session_id,
    )
}

fn spoofed_raw_json_response(session_id: &SessionId) -> IpcMessage {
    raw_json_on_topic(
        Topic::from_raw("astrid.v1.response.spoof"),
        serde_json::json!({
            "session_id": session_id.0.to_string(),
            "text": "injected",
            "is_final": true,
        }),
        session_id,
    )
}

fn stream_delta(session_id: &SessionId, text: &str) -> IpcMessage {
    IpcMessage::new(
        Topic::agent_stream_delta(),
        IpcPayload::RawJson(serde_json::json!({
            "session_id": session_id.0.to_string(),
            "delta": text,
        })),
        session_id.0,
    )
}

fn foreign_message(session_id: &SessionId) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw("registry.v1.active_model_changed"),
        IpcPayload::RawJson(serde_json::json!({"model": "other"})),
        session_id.0,
    )
}

fn approval_message(session_id: &SessionId, principal: &str) -> IpcMessage {
    IpcMessage::new(
        Topic::approval_request(),
        IpcPayload::ApprovalRequired {
            request_id: "test-request".to_owned(),
            action: "run command".to_owned(),
            resource: "/tmp/example".to_owned(),
            reason: "test".to_owned(),
        },
        session_id.0,
    )
    .with_principal(principal)
}

fn disconnect_message(session_id: &SessionId) -> IpcMessage {
    IpcMessage::new(
        Topic::client_disconnect(),
        IpcPayload::Disconnect {
            reason: Some("test".to_owned()),
        },
        session_id.0,
    )
}

#[test]
fn idle_timeout_preserves_default_and_fails_closed() {
    assert!(matches!(idle_timeout(120), Ok(timeout) if timeout == Duration::from_mins(2)));
    assert!(idle_timeout(0).is_err());
    assert!(idle_timeout(u64::MAX).is_err());
    assert!(idle_timeout(86_401).is_err());
}

#[tokio::test]
async fn active_run_messages_refresh_the_idle_boundary() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(response("first", false, &session_id))),
        ReadStep::Message(Box::new(response("done", true, &session_id))),
    ]);
    let (text, _) = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap();

    assert_eq!(text, "firstdone");
}

#[tokio::test]
async fn session_raw_json_stream_delta_is_active_run_traffic() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(stream_delta(&session_id, "partial"))),
        ReadStep::Message(Box::new(response("done", true, &session_id))),
    ]);
    let (text, _) = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap();

    assert_eq!(text, "done");
}

#[tokio::test]
async fn raw_json_terminal_response_surfaces_text_and_finalizes() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(raw_json_response("hello", true, &session_id))),
        ReadStep::Timeout,
    ]);
    let (text, _) = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap();

    assert_eq!(text, "hello");
}

#[tokio::test]
async fn spoofed_typed_response_is_not_active_run_traffic() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(spoofed_response("injected", true, &session_id))),
        ReadStep::Timeout,
    ]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    assert!(source.sent.is_empty());
}

#[tokio::test]
async fn spoofed_raw_json_response_is_not_active_run_traffic() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(spoofed_raw_json_response(&session_id))),
        ReadStep::Timeout,
    ]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    assert!(source.sent.is_empty());
}

#[tokio::test]
async fn missing_active_run_message_returns_timeout_without_process_exit() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([ReadStep::Timeout]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
}

#[tokio::test]
async fn foreign_frame_then_injected_timeout_returns_idle_timeout() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(foreign_message(&session_id))),
        ReadStep::Timeout,
    ]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
}

#[tokio::test]
async fn foreign_same_principal_approval_is_ignored() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let foreign_session = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(approval_message(
            &foreign_session,
            "same-principal-alice",
        ))),
        ReadStep::Timeout,
    ]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    assert!(source.sent.is_empty());
}

#[tokio::test]
async fn session_source_approval_is_also_ignored() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([
        ReadStep::Message(Box::new(approval_message(
            &session_id,
            "same-principal-alice",
        ))),
        ReadStep::Timeout,
    ]);
    let error = collect_response(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    assert!(source.sent.is_empty());
}

#[tokio::test]
async fn timeout_cleanup_sends_disconnect_within_injected_budget() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = DeterministicSource::new([ReadStep::Timeout]);
    let error = collect_response_with_cleanup_budget(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
    assert_eq!(source.sent.len(), 1);
    assert!(matches!(
        source.sent[0].payload,
        IpcPayload::Disconnect { .. }
    ));
}

#[tokio::test]
async fn wedged_cleanup_send_returns_the_injected_idle_timeout() {
    struct WedgedSource;

    impl ResponseSource for WedgedSource {
        async fn read_message_before(&mut self, _remaining: Duration) -> ReadOutcome {
            ReadOutcome::Timeout
        }

        async fn send_message(&mut self, _message: IpcMessage) -> Result<()> {
            pending().await
        }
    }

    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = WedgedSource;
    let error = collect_response_with_cleanup_budget(
        &mut source,
        &session_id,
        formatter::OutputFormat::Json,
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, HeadlessError::IdleTimeout { .. }));
}

#[tokio::test]
async fn wedged_success_disconnect_is_bounded() {
    struct WedgedSource;

    impl ResponseSource for WedgedSource {
        async fn read_message_before(&mut self, _remaining: Duration) -> ReadOutcome {
            ReadOutcome::Closed
        }

        async fn send_message(&mut self, _message: IpcMessage) -> Result<()> {
            pending().await
        }
    }

    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let mut source = WedgedSource;
    send_message_bounded(&mut source, disconnect_message(&session_id), Duration::ZERO).await;
}

#[test]
fn cleanup_budget_is_finite_and_shared() {
    assert_eq!(MESSAGE_SEND_BUDGET, Duration::from_secs(5));
}

#[test]
fn only_session_correlated_payloads_can_reset_the_timer() {
    let session_id = SessionId::from_uuid(Uuid::new_v4());
    let foreign_session = SessionId::from_uuid(Uuid::new_v4());

    assert!(is_active_run_message(
        &response("active", false, &session_id),
        &session_id
    ));
    assert!(!is_active_run_message(
        &spoofed_response("injected", false, &session_id),
        &session_id
    ));
    assert!(is_active_run_message(
        &stream_delta(&session_id, "partial"),
        &session_id
    ));
    assert!(is_active_run_message(
        &raw_json_response("done", true, &session_id),
        &session_id
    ));
    assert!(!is_active_run_message(
        &raw_json_response("not terminal", false, &session_id),
        &session_id
    ));
    assert!(!is_active_run_message(
        &spoofed_raw_json_response(&session_id),
        &session_id
    ));
    assert!(!is_active_run_message(
        &stream_delta(&foreign_session, "foreign"),
        &session_id
    ));
    assert!(!is_active_run_message(
        &approval_message(&session_id, "same-principal-alice"),
        &session_id
    ));
    assert!(!is_active_run_message(
        &approval_message(&foreign_session, "same-principal-alice"),
        &session_id
    ));
}
