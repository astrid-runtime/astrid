//! Audit of tool invocations delivered to tool capsules.
//!
//! Agents call tools by publishing a `ToolExecuteRequest` on
//! `tool.v1.execute.<tool>`; the tool capsule receives it as an interceptor
//! invocation and publishes a `ToolExecuteResult` on the request topic plus
//! `.result` (or on `tool.v1.execute.result`) before it returns. The engine
//! arms a [`ToolCallAudit`] for each such invocation, the IPC publish host fn
//! captures the matching result ([`capture_tool_result`]), and the engine
//! records one `ToolCall` entry when the invocation ends: the tool, the call
//! id, and BLAKE3 hashes of the arguments and of the published result. The
//! outcome is a failure when the tool reported an error, published no
//! result, or the invocation failed or was cancelled.

use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_crypto::ContentHash;
use astrid_events::ipc::{IpcMessage, IpcPayload};

use crate::audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
use crate::engine::wasm::host_state::HostState;

/// Topic prefix of tool invocation requests.
const TOOL_EXECUTE_PREFIX: &str = "tool.v1.execute.";
/// Suffix of a tool result topic.
const RESULT_SUFFIX: &str = ".result";
/// Shared tool result topic.
const SHARED_RESULT_TOPIC: &str = "tool.v1.execute.result";

/// A tool result the guest published during the current invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolResultCapture {
    result_hash: ContentHash,
    is_error: bool,
}

/// The tool name of a tool invocation request topic.
fn tool_name(topic: &str) -> Option<&str> {
    topic
        .strip_prefix(TOOL_EXECUTE_PREFIX)
        .filter(|name| !name.is_empty() && *name != "result" && !name.ends_with(RESULT_SUFFIX))
}

/// The `(tool, call_id, arguments)` of a tool invocation request message.
fn tool_request(message: &IpcMessage) -> Option<(&str, &str, &serde_json::Value)> {
    let tool = tool_name(message.topic.as_str())?;
    match &message.payload {
        IpcPayload::ToolExecuteRequest {
            call_id, arguments, ..
        } => Some((tool, call_id.as_str(), arguments)),
        _ => None,
    }
}

/// Capture `payload` as the result of the tool invocation in flight, if it is
/// one: the caller is a tool request, `topic` is its result topic, and the
/// call ids match. The first matching result wins.
pub(crate) fn capture_tool_result(state: &mut HostState, topic: &str, payload: &IpcPayload) {
    if state.tool_result.is_some() {
        return;
    }
    let Some(caller) = state.caller_context.as_ref() else {
        return;
    };
    let Some((_, request_call_id, _)) = tool_request(caller) else {
        return;
    };
    let result_topic_matches = topic == SHARED_RESULT_TOPIC
        || topic
            .strip_suffix(RESULT_SUFFIX)
            .is_some_and(|base| base == caller.topic.as_str());
    let IpcPayload::ToolExecuteResult { call_id, result } = payload else {
        return;
    };
    if result_topic_matches && call_id == request_call_id {
        state.tool_result = Some(ToolResultCapture {
            result_hash: ContentHash::hash(result.content.as_bytes()),
            is_error: result.is_error,
        });
    }
}

/// One tool invocation's pending audit record. Dropping it unfinished (the
/// invocation future was cancelled) records a failed call.
pub(crate) struct ToolCallAudit {
    sink: Arc<dyn HostAuditSink>,
    principal: PrincipalId,
    capsule_id: String,
    tool: String,
    call_id: String,
    args_hash: ContentHash,
    finished: bool,
}

impl ToolCallAudit {
    /// Arm the audit for an invocation whose caller is a tool request.
    /// `None` for other invocations or when no audit sink is installed.
    pub(crate) fn arm(
        state: &HostState,
        caller: Option<&IpcMessage>,
        principal: &PrincipalId,
    ) -> Option<Self> {
        let sink = state.audit_sink.clone()?;
        let (tool, call_id, arguments) = tool_request(caller?)?;
        let args = serde_json::to_vec(arguments).unwrap_or_default();
        Some(Self {
            sink,
            principal: principal.clone(),
            capsule_id: state.capsule_id.as_str().to_owned(),
            tool: tool.to_owned(),
            call_id: call_id.to_owned(),
            args_hash: ContentHash::hash(&args),
            finished: false,
        })
    }

    /// Record the call. `invocation_error` is set when the guest call failed.
    pub(crate) fn finish(
        mut self,
        result: Option<ToolResultCapture>,
        invocation_error: Option<&str>,
    ) {
        let outcome = match (invocation_error, result) {
            (Some(error), _) => HostAuditOutcome::Failed(error),
            (None, Some(result)) if result.is_error => {
                HostAuditOutcome::Failed("tool reported an error")
            },
            (None, Some(_)) => HostAuditOutcome::Allowed,
            (None, None) => HostAuditOutcome::Failed("no result published"),
        };
        self.emit(result.map(|r| r.result_hash), outcome);
    }

    fn emit(&mut self, result_hash: Option<ContentHash>, outcome: HostAuditOutcome<'_>) {
        self.finished = true;
        self.sink.record(
            &self.principal,
            HostAuditEvent::ToolCall {
                capsule_id: &self.capsule_id,
                tool: &self.tool,
                call_id: Some(&self.call_id),
                args_hash: self.args_hash,
                result_hash,
            },
            outcome,
        );
    }
}

impl Drop for ToolCallAudit {
    fn drop(&mut self) {
        if !self.finished {
            self.emit(None, HostAuditOutcome::Failed("invocation cancelled"));
        }
    }
}

#[cfg(test)]
#[path = "tool_audit_tests.rs"]
mod tests;
