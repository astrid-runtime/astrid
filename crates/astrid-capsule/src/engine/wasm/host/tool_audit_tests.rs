//! Tests for tool-call audit: the published result is captured through the
//! IPC publish host fn and one `ToolCall` record carries hashes of the
//! arguments and the result.

use std::sync::{Arc, Mutex};

use astrid_core::PrincipalId;
use astrid_crypto::ContentHash;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use serde_json::json;

use super::ToolCallAudit;
use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use crate::engine::wasm::bindings::astrid::ipc::host::Host as _;
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::minimal_host_state;

#[derive(Debug, Clone, PartialEq)]
struct Recorded {
    capsule_id: String,
    tool: String,
    call_id: Option<String>,
    args_hash: ContentHash,
    result_hash: Option<ContentHash>,
    failure: Option<String>,
}

#[derive(Default)]
struct ToolSink(Mutex<Vec<Recorded>>);

impl HostAuditSink for ToolSink {
    fn record(
        &self,
        _principal: &PrincipalId,
        event: HostAuditEvent<'_>,
        outcome: HostAuditOutcome<'_>,
    ) {
        if let HostAuditEvent::ToolCall {
            capsule_id,
            tool,
            call_id,
            args_hash,
            result_hash,
        } = event
        {
            self.0.lock().unwrap().push(Recorded {
                capsule_id: capsule_id.to_owned(),
                tool: tool.to_owned(),
                call_id: call_id.map(str::to_owned),
                args_hash,
                result_hash,
                failure: match outcome {
                    HostAuditOutcome::Allowed => None,
                    HostAuditOutcome::Failed(e) | HostAuditOutcome::Denied(e) => Some(e.to_owned()),
                },
            });
        }
    }
}

fn arguments() -> serde_json::Value {
    json!({"query": "cats", "limit": 3})
}

fn tool_request(topic: &str) -> IpcMessage {
    IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::ToolExecuteRequest {
            call_id: "call-1".to_owned(),
            tool_name: "search".to_owned(),
            arguments: arguments(),
        },
        uuid::Uuid::nil(),
    )
    .with_principal("default")
}

fn tool_state() -> (HostState, Arc<ToolSink>, IpcMessage) {
    let sink = Arc::new(ToolSink::default());
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.audit_sink = Some(Arc::clone(&sink) as Arc<dyn HostAuditSink>);
    state.ipc_publish_patterns = vec!["tool.v1.execute.*".to_owned()];
    let request = tool_request("tool.v1.execute.search");
    state.caller_context = Some(request.clone());
    (state, sink, request)
}

fn publish_result(state: &mut HostState, topic: &str, call_id: &str, is_error: bool) {
    let payload = json!({
        "type": "tool_execute_result",
        "call_id": call_id,
        "result": {"call_id": call_id, "content": "3 results", "is_error": is_error},
    });
    state
        .publish(topic.to_owned(), payload.to_string())
        .expect("publish succeeds");
}

fn args_hash() -> ContentHash {
    ContentHash::hash(&serde_json::to_vec(&arguments()).unwrap())
}

#[tokio::test]
async fn published_result_is_recorded_with_hashes() {
    let (mut state, sink, request) = tool_state();
    let audit = ToolCallAudit::arm(&state, Some(&request), &PrincipalId::default()).expect("armed");
    publish_result(&mut state, "tool.v1.execute.search.result", "call-1", false);
    audit.finish(state.tool_result.take(), None);

    assert_eq!(
        sink.0.lock().unwrap().clone(),
        vec![Recorded {
            capsule_id: state.capsule_id.as_str().to_owned(),
            tool: "search".to_owned(),
            call_id: Some("call-1".to_owned()),
            args_hash: args_hash(),
            result_hash: Some(ContentHash::hash(b"3 results")),
            failure: None,
        }]
    );
}

#[tokio::test]
async fn tool_error_and_missing_result_are_failures() {
    // The tool reported an error.
    let (mut state, sink, request) = tool_state();
    let audit = ToolCallAudit::arm(&state, Some(&request), &PrincipalId::default()).expect("armed");
    publish_result(&mut state, "tool.v1.execute.result", "call-1", true);
    audit.finish(state.tool_result.take(), None);

    // A result for another call does not count as this call's result.
    let audit = ToolCallAudit::arm(&state, Some(&request), &PrincipalId::default()).expect("armed");
    publish_result(&mut state, "tool.v1.execute.search.result", "call-2", false);
    audit.finish(state.tool_result.take(), None);

    // The guest call failed.
    let audit = ToolCallAudit::arm(&state, Some(&request), &PrincipalId::default()).expect("armed");
    audit.finish(None, Some("wasm trap"));

    // The invocation was cancelled before it finished.
    drop(ToolCallAudit::arm(&state, Some(&request), &PrincipalId::default()).expect("armed"));

    let records = sink.0.lock().unwrap().clone();
    let outcomes: Vec<_> = records
        .iter()
        .map(|r| (r.result_hash.is_some(), r.failure.clone()))
        .collect();
    assert_eq!(
        outcomes,
        vec![
            (true, Some("tool reported an error".to_owned())),
            (false, Some("no result published".to_owned())),
            (false, Some("wasm trap".to_owned())),
            (false, Some("invocation cancelled".to_owned())),
        ]
    );
    assert!(records.iter().all(|r| r.args_hash == args_hash()));
}

#[tokio::test]
async fn non_tool_invocations_are_not_armed() {
    let (state, _sink, _) = tool_state();
    for topic in ["llm.v1.request.generate.x", "tool.v1.execute.search.result"] {
        let message = tool_request(topic);
        assert!(ToolCallAudit::arm(&state, Some(&message), &PrincipalId::default()).is_none());
    }
    assert!(ToolCallAudit::arm(&state, None, &PrincipalId::default()).is_none());
}
