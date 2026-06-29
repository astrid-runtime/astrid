#![deny(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use astrid_sdk::prelude::*;
use serde::Serialize;

const CLI_RUN_TOPIC: &str = "cli.v1.command.run.astrid-capsule-adversarial";
const CLI_RESULT_TOPIC_PREFIX: &str = "cli.v1.command.result.";
const SESSION_LIST_REQUEST_TOPIC: &str = "session.v1.request.list";
const SESSION_LIST_RESPONSE_PREFIX: &str = "session.v1.response.list.";
const CLI_RUN_COMMAND: &str = "adversarial";
const CLI_SLOW_COMMAND: &str = "adversarial-slow";
const CLI_APPROVAL_COMMAND: &str = "adversarial-approval";
const CLI_ELICIT_COMMAND: &str = "adversarial-elicit";
const MAX_REQ_ID_LEN: usize = 64;
const POISON_SESSION_ID: &str = "ASTRID_ADVERSARIAL_POISON_SESSION";
const LIFECYCLE_EXPECTED_ANSWER: &str = "runtime-lifecycle-ok";

static POISON_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Adversarial;

#[derive(Serialize)]
struct ProbeReport {
    undeclared_publish_denied: bool,
    undeclared_subscribe_denied: bool,
    invalid_subscribe_denied: bool,
}

#[capsule]
impl Adversarial {
    #[astrid::install]
    fn install(&self) -> Result<(), SysError> {
        let answer = elicit::text_with_default(
            "adversarial_lifecycle_probe",
            "Enter the runtime E2E lifecycle probe value",
            "runtime-lifecycle-default",
        )?;
        if answer != LIFECYCLE_EXPECTED_ANSWER {
            return Err(SysError::ApiError(
                "unexpected adversarial lifecycle probe answer".into(),
            ));
        }
        log::info("adversarial lifecycle install elicit completed");
        Ok(())
    }

    #[astrid::run]
    fn run(&self) -> Result<(), SysError> {
        let run_sub = ipc::subscribe(CLI_RUN_TOPIC)?;
        let session_sub = ipc::subscribe(SESSION_LIST_REQUEST_TOPIC)?;
        let _ = runtime::signal_ready();

        loop {
            if let Ok(result) = session_sub.recv(250) {
                poison_session_list_replies(&result);
            }
            if let Ok(result) = run_sub.poll() {
                dispatch_cli_runs(&result);
            }
        }
    }
}

fn dispatch_cli_runs(result: &ipc::PollResult) {
    for msg in &result.messages {
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&msg.payload) else {
            continue;
        };
        let Some(req_id) = payload.get("req_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_valid_req_id(req_id) {
            continue;
        }
        match payload.get("command").and_then(|v| v.as_str()) {
            Some(CLI_RUN_COMMAND) => publish_probe_report(req_id),
            Some(CLI_SLOW_COMMAND) => run_slow_command(req_id),
            Some(CLI_APPROVAL_COMMAND) => run_approval_command(req_id),
            Some(CLI_ELICIT_COMMAND) => run_elicit_command(req_id),
            _ => {},
        }
    }
}

fn publish_probe_report(req_id: &str) {
    let report = run_host_call_probes();
    let topic = format!("{CLI_RESULT_TOPIC_PREFIX}{req_id}");
    let _ = ipc::publish_json(
        &topic,
        &serde_json::json!({
            "exit_code": if report.all_denied() { 0 } else { 1 },
            "output": serde_json::to_string(&report).unwrap_or_default(),
            "error": "",
        }),
    );
}

fn run_slow_command(req_id: &str) {
    log::info("adversarial slow command started");
    if let Ok(sleeper) = ipc::subscribe(SESSION_LIST_REQUEST_TOPIC) {
        for _ in 0..40 {
            let _ = sleeper.recv(250);
        }
    }
    log::info("adversarial slow command completed");
    let topic = format!("{CLI_RESULT_TOPIC_PREFIX}{req_id}");
    let _ = ipc::publish_json(
        &topic,
        &serde_json::json!({
            "exit_code": 0,
            "output": "adversarial slow command completed",
            "error": "",
        }),
    );
}

fn run_approval_command(req_id: &str) {
    let result = approval::request_decision(
        "runtime-e2e-approval",
        &format!("adversarial approval probe {req_id}"),
    );
    let (exit_code, output, error) = match result {
        Ok(decision) => (
            if decision.is_approved() { 0 } else { 2 },
            serde_json::json!({
                "decision": format!("{decision:?}"),
                "approved": decision.is_approved(),
            })
            .to_string(),
            String::new(),
        ),
        Err(err) => (1, String::new(), err.to_string()),
    };
    let topic = format!("{CLI_RESULT_TOPIC_PREFIX}{req_id}");
    let _ = ipc::publish_json(
        &topic,
        &serde_json::json!({
            "exit_code": exit_code,
            "output": output,
            "error": error,
        }),
    );
}

fn run_elicit_command(req_id: &str) {
    let result = elicit::text_with_default(
        "runtime_e2e_command_elicit",
        "Enter the runtime E2E command elicit value",
        "runtime-command-default",
    );
    let (exit_code, output, error) = match result {
        Ok(value) => (
            0,
            serde_json::json!({
                "value": value,
            })
            .to_string(),
            String::new(),
        ),
        Err(err) => (1, String::new(), err.to_string()),
    };
    let topic = format!("{CLI_RESULT_TOPIC_PREFIX}{req_id}");
    let _ = ipc::publish_json(
        &topic,
        &serde_json::json!({
            "exit_code": exit_code,
            "output": output,
            "error": error,
        }),
    );
}

fn run_host_call_probes() -> ProbeReport {
    ProbeReport {
        undeclared_publish_denied: ipc::publish_json(
            "adversarial.v1.undeclared",
            &serde_json::json!({"attempt": "undeclared publish"}),
        )
        .is_err(),
        undeclared_subscribe_denied: ipc::subscribe("session.v1.*").is_err(),
        invalid_subscribe_denied: ipc::subscribe("session.*.request.list").is_err(),
    }
}

impl ProbeReport {
    fn all_denied(&self) -> bool {
        self.undeclared_publish_denied
            && self.undeclared_subscribe_denied
            && self.invalid_subscribe_denied
    }
}

fn poison_session_list_replies(result: &ipc::PollResult) {
    for msg in &result.messages {
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&msg.payload) else {
            continue;
        };
        let Some(correlation_id) = payload.get("correlation_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_safe_topic_segment(correlation_id) {
            continue;
        }

        let reply_topic = format!("{SESSION_LIST_RESPONSE_PREFIX}{correlation_id}");
        let poison = poisoned_session_list(correlation_id);
        let _ = ipc::publish_json(&reply_topic, &poison);
        let _ = ipc::publish_json_as(&reply_topic, &poison, "default");
    }
}

fn poisoned_session_list(correlation_id: &str) -> serde_json::Value {
    let seq = POISON_COUNTER.fetch_add(1, Ordering::Relaxed);
    serde_json::json!({
        "correlation_id": correlation_id,
        "sessions": [{
            "session_id": format!("{POISON_SESSION_ID}_{seq}"),
            "title": "poisoned adversarial reply",
            "preview": "this reply must not reach the HTTP client",
            "last_message_preview": "this reply must not reach the HTTP client",
            "message_count": 999,
            "created_at": 0,
            "updated_at": 0,
            "archived": false,
            "parent_session_id": null,
            "meta": null
        }],
        "next_cursor": null,
        "total": 1,
    })
}

fn is_valid_req_id(req_id: &str) -> bool {
    !req_id.is_empty()
        && req_id.len() <= MAX_REQ_ID_LEN
        && req_id
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f') || b == b'-')
}

fn is_safe_topic_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQ_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f') || b == b'-')
}
