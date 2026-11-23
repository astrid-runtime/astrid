//! Real-daemon regression. Requires the AOS chat capsules and fake-echo provider
//! installed in a disposable home; never run against an operator's live home.
//! Point `ASTRID_E2E_PROVIDER_LOG` at fake-openai-compat.py's `--log` JSONL file
//! for the watchdog case. Preparation and provider response have separate bounds.

use std::{
    fmt::Write as _,
    future::Future,
    io::{BufRead, BufReader},
    time::Duration,
};

use astrid_core::kernel_api::KernelRequest;
use astrid_core::{PrincipalId, SessionId};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use astrid_uplink::{kernel_client::KernelClient, socket_client::SocketClient};

async fn select_model(client: &mut SocketClient, model: &str) {
    client
        .send_message(IpcMessage::new(
            Topic::from_raw("registry.v1.selection.callback"),
            IpcPayload::RawJson(serde_json::json!({"selected_id": model})),
            client.session_id.0,
        ))
        .await
        .expect("model selection");
    let selected = client
        .read_until_topic("registry.v1.active_model_changed", Duration::from_secs(10))
        .await
        .expect("model selection acknowledgment");
    assert_eq!(selected["payload"]["id"], model);
}

async fn terminal(client: &mut SocketClient) -> (serde_json::Value, String) {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut text = String::new();
        loop {
            let frame = client
                .read_raw_frame()
                .await
                .expect("read frame")
                .expect("connected");
            let value: serde_json::Value = serde_json::from_slice(&frame).expect("JSON frame");
            if matches!(
                value["topic"].as_str(),
                Some("agent.v1.stream.delta" | "agent.v1.response")
            ) {
                text.push_str(value["payload"]["text"].as_str().expect("chat text"));
            }
            if value["topic"] == "agent.v1.response" && value["payload"]["is_final"] == true {
                return (value, text);
            }
        }
    })
    .await
    .expect("terminal within fixture deadline")
}

// The fake provider already records streaming POSTs before writing its first
// chunk. Observe that entry, not a client delta: buffering can legitimately
// keep the first text hidden until after the watchdog terminal.
fn held_provider_request_seen(log: &mut impl BufRead, pending: &mut Vec<u8>, marker: &str) -> bool {
    loop {
        if log.read_until(b'\n', pending).expect("read provider log") == 0
            || !pending.ends_with(b"\n")
        {
            return false;
        }
        let record: serde_json::Value =
            serde_json::from_slice(pending).expect("complete provider JSONL record");
        pending.clear();
        let user_content = record["messages"].as_array().and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message["role"] == "user")
        });
        if record["method"] == "POST"
            && record["path"] == "/v1/chat/completions"
            && record["stream"] == true
            && user_content.is_some_and(|message| message["content"].to_string().contains(marker))
        {
            return true;
        }
    }
}

async fn watchdog_response<T>(
    terminal: impl Future<Output = T>,
    mut provider_log: impl BufRead,
    marker: &str,
) -> T {
    // Pin one continuous reader: losing a select! branch must not cancel a
    // partially read native frame or discard a pre-delta terminal.
    tokio::pin!(terminal);
    let started = tokio::time::Instant::now();
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    let mut pending = Vec::new();
    let mut response_deadline = started
        .checked_add(Duration::from_secs(30))
        .expect("fixture deadline fits monotonic clock");
    let early_terminal = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                message = &mut terminal => return Some(message),
                _ = poll.tick() => {
                    let probe_started = tokio::time::Instant::now();
                    if held_provider_request_seen(&mut provider_log, &mut pending, marker) {
                        return None;
                    }
                    // The provider had not recorded entry at this probe. Anchor
                    // conservatively here so polling delay cannot extend its budget.
                    if pending.is_empty() {
                        response_deadline = probe_started
                            .checked_add(Duration::from_secs(30))
                            .expect("fixture deadline fits monotonic clock");
                    }
                }
            }
        }
    })
    .await
    .expect("provider entry or watchdog terminal within preparation deadline");
    if let Some(message) = early_terminal {
        return message;
    }
    eprintln!("watchdog provider entry after {:?}", started.elapsed());
    let streaming_wait = tokio::time::Instant::now();
    let message = tokio::time::timeout_at(response_deadline, &mut terminal)
        .await
        .expect("typed watchdog terminal within fixture deadline");
    eprintln!(
        "watchdog terminal after provider entry: {:?}",
        streaming_wait.elapsed()
    );
    message
}

#[tokio::test]
#[ignore = "requires disposable daemon, fake-echo JSONL at ASTRID_E2E_PROVIDER_LOG, aos-react streaming_timeout_secs=20 and HTTP stream_read_timeout_secs >30"]
async fn autonomous_watchdog_timeout_then_success_on_same_connection() {
    let mut client = disposable_client().await;
    select_model(&mut client, "openai-compat:fake-echo").await;
    let log_path = std::env::var_os("ASTRID_E2E_PROVIDER_LOG")
        .expect("explicit owned fake-provider JSONL log");
    // Consume the append-only file once; the unique marker excludes old records.
    let log = std::fs::File::open(log_path).expect("open fake-provider log");
    let provider_log = BufReader::new(log);
    let marker = format!("ASTRID_E2E_INFLIGHT_CRASH_watchdog_{}", client.session_id.0);
    client
        .send_input(marker.clone())
        .await
        .expect("held prompt");
    let timeout_response = async {
        loop {
            let message = client
                .read_message()
                .await
                .expect("typed frame")
                .expect("connected");
            if let IpcPayload::AgentResponse { is_final: true, .. } = message.payload {
                return message;
            }
        }
    };
    let timed_out = watchdog_response(timeout_response, provider_log, &marker).await;
    // A short watchdog deadline can beat the provider's first buffered delta.
    // The named Streaming phase proves generation was entered; waiting for a
    // delta would discard the pre-delta timeout this test must recover.
    let IpcPayload::AgentResponse { text, .. } = &timed_out.payload else {
        panic!("typed terminal response");
    };
    assert!(
        text.contains("Request timed out (Streaming phase exceeded 20s limit)"),
        "{text}"
    );
    let timeout_owner = timed_out.request_owner.expect("validated timeout owner");
    // No explicit cancellation, capsule reload or client reconnection repairs
    // this turn: the autonomous terminal must release native admission itself.
    client
        .send_input("after-watchdog-timeout-marker".to_owned())
        .await
        .expect("next prompt");
    let (completed, text) = terminal(&mut client).await;
    assert_eq!(text.trim(), "fake echo: after-watchdog-timeout-marker");
    assert_ne!(
        completed["request_owner"],
        serde_json::to_value(timeout_owner).unwrap()
    );
}

#[tokio::test]
#[ignore = "requires disposable daemon with current AOS chat capsules and fake-echo provider"]
async fn reload_cancel_then_success_on_same_connection() {
    let home = std::env::var("ASTRID_HOME").expect("explicit disposable home");
    assert!(
        home.starts_with("/private/tmp/astrid-fast-stream-qa."),
        "refuse live home"
    );
    let principal = PrincipalId::new("default").expect("principal");
    let session = SessionId::new();
    let mut client = SocketClient::connect(session.clone(), principal.clone())
        .await
        .expect("connect");
    assert!(client.is_authenticated());
    select_model(&mut client, "openai-compat:fake-echo").await;
    client
        .send_input("ASTRID_E2E_INFLIGHT_CRASH_reload".to_owned())
        .await
        .expect("first prompt");
    client
        .read_until_topic("agent.v1.stream.delta", Duration::from_secs(30))
        .await
        .expect("held response must start before capsule reload");
    let mut admin = KernelClient::connect(principal)
        .await
        .expect("management connection");
    let response = admin
        .request(KernelRequest::ReloadCapsule {
            id: "aos-react".to_owned(),
        })
        .await
        .expect("reload response");
    astrid_uplink::kernel_client::into_result(response).expect("reload succeeds");
    client
        .send_message(IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: String::new(),
                session_id: session.0.to_string(),
                context: Some(serde_json::json!({"action": "cancel_turn"})),
            },
            session.0,
        ))
        .await
        .expect("cancel after reload");
    let (cancelled, _) = terminal(&mut client).await;
    assert_eq!(cancelled["payload"]["text"], "Request cancelled.");
    client
        .send_input("after-reload-success-marker".to_owned())
        .await
        .expect("subsequent prompt");
    let (completed, text) = terminal(&mut client).await;
    assert_ne!(completed["request_owner"], cancelled["request_owner"]);
    // Read raw frames rather than only typed responses: the real guest payload
    // is emitted without the internal enum discriminator on this transport.
    assert_eq!(text.trim(), "fake echo: after-reload-success-marker");
}

#[tokio::test]
#[ignore = "requires disposable daemon with AOS chat capsules and fake-burst provider selected"]
async fn burst_preserves_complete_reply_and_terminal() {
    stream_then_next_turn("openai-compat:fake-burst").await;
}

#[tokio::test]
#[ignore = "requires disposable daemon with AOS chat capsules and fake-fast provider"]
async fn paced_fast_stream_preserves_complete_reply_and_next_turn() {
    stream_then_next_turn("openai-compat:fake-fast").await;
}

#[tokio::test]
#[ignore = "requires disposable daemon with AOS chat capsules and fake-error provider"]
async fn provider_error_then_success_on_same_connection() {
    let mut client = disposable_client().await;
    select_model(&mut client, "openai-compat:fake-error").await;
    client
        .send_input("provider error".to_owned())
        .await
        .expect("prompt");
    let (failed, text) = terminal(&mut client).await;
    assert!(
        text.contains("502"),
        "provider failure must be visible: {text}"
    );
    select_model(&mut client, "openai-compat:fake-echo").await;
    client
        .send_input("after-provider-error-marker".to_owned())
        .await
        .expect("next prompt");
    let (completed, text) = terminal(&mut client).await;
    assert_eq!(text.trim(), "fake echo: after-provider-error-marker");
    assert_ne!(failed["request_owner"], completed["request_owner"]);
}

#[tokio::test]
#[ignore = "requires disposable daemon with AOS chat capsules and fake-burst provider"]
async fn cancel_burst_then_success_on_same_connection() {
    cancel_then_next_turn(true).await;
}

#[tokio::test]
#[ignore = "requires disposable daemon with AOS chat capsules and fake-burst provider"]
async fn cancel_before_generation_then_success_on_same_connection() {
    cancel_then_next_turn(false).await;
}

async fn cancel_then_next_turn(wait_for_delta: bool) {
    let mut client = disposable_client().await;
    select_model(&mut client, "openai-compat:fake-burst").await;
    client
        .send_input("cancel this burst".to_owned())
        .await
        .expect("prompt");
    if wait_for_delta {
        client
            .read_until_topic("agent.v1.stream.delta", Duration::from_secs(30))
            .await
            .expect("stream must start before cancellation");
    } else {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client
        .send_message(IpcMessage::new(
            Topic::user_prompt(),
            IpcPayload::UserInput {
                text: String::new(),
                session_id: client.session_id.0.to_string(),
                context: Some(serde_json::json!({"action":"cancel_turn"})),
            },
            client.session_id.0,
        ))
        .await
        .expect("cancel");
    let (cancelled, _) = terminal(&mut client).await;
    assert_eq!(cancelled["payload"]["text"], "Request cancelled.");
    eprintln!("burst cancellation terminal received");
    select_model(&mut client, "openai-compat:fake-echo").await;
    client
        .send_input("after-burst-cancel-marker".to_owned())
        .await
        .expect("next prompt");
    let (completed, text) = terminal(&mut client).await;
    assert_eq!(text.trim(), "fake echo: after-burst-cancel-marker");
    assert_ne!(completed["request_owner"], cancelled["request_owner"]);
}

async fn disposable_client() -> SocketClient {
    let home = std::env::var("ASTRID_HOME").expect("explicit disposable home");
    assert!(
        home.starts_with("/private/tmp/astrid-fast-stream-qa."),
        "refuse live home"
    );
    let client = SocketClient::connect(
        SessionId::new(),
        PrincipalId::new("default").expect("principal"),
    )
    .await
    .expect("connect");
    assert!(client.is_authenticated());
    client
}

#[tokio::test]
#[ignore = "requires disposable daemon and publicly provisioned stream-peer with AOS chat capsules"]
async fn concurrent_principals_keep_replies_and_model_selection_isolated() {
    let mut burst = disposable_client().await;
    let mut peer =
        SocketClient::connect(SessionId::new(), PrincipalId::new("stream-peer").unwrap())
            .await
            .expect("provisioned peer connection");
    assert!(peer.is_authenticated());
    select_model(&mut burst, "openai-compat:fake-burst").await;
    select_model(&mut peer, "openai-compat:fake-echo").await;
    burst
        .send_input("principal burst".into())
        .await
        .expect("burst prompt");
    peer.send_input("isolated-peer-marker".into())
        .await
        .expect("peer prompt");
    let ((burst_frame, burst_text), (peer_frame, peer_text)) =
        tokio::join!(terminal(&mut burst), terminal(&mut peer));
    let expected = expected_stream_text();
    assert_eq!(burst_text, expected);
    assert_eq!(peer_text.trim(), "fake echo: isolated-peer-marker");
    assert_eq!(burst_frame["principal"], "default");
    assert_eq!(peer_frame["principal"], "stream-peer");
    assert_ne!(burst_frame["request_owner"], peer_frame["request_owner"]);
}

async fn stream_then_next_turn(model: &str) {
    let home = std::env::var("ASTRID_HOME").expect("explicit disposable home");
    assert!(
        home.starts_with("/private/tmp/astrid-fast-stream-qa."),
        "refuse live home"
    );
    let mut client = SocketClient::connect(
        SessionId::new(),
        PrincipalId::new("default").expect("principal"),
    )
    .await
    .expect("connect");
    assert!(client.is_authenticated());
    select_model(&mut client, model).await;
    let started = std::time::Instant::now();
    client
        .send_input("deterministic burst".to_owned())
        .await
        .expect("prompt");
    let (completed, text) = terminal(&mut client).await;
    eprintln!("{model}: {} bytes in {:?}", text.len(), started.elapsed());
    let expected = expected_stream_text();
    assert!(
        text == expected,
        "indexed reply mismatch: received {} bytes, expected {}",
        text.len(),
        expected.len()
    );
    select_model(&mut client, "openai-compat:fake-echo").await;
    client
        .send_input("after-fast-stream-marker".to_owned())
        .await
        .expect("next turn");
    let (next, text) = terminal(&mut client).await;
    assert_eq!(text.trim(), "fake echo: after-fast-stream-marker");
    assert_ne!(next["request_owner"], completed["request_owner"]);
}

fn expected_stream_text() -> String {
    let mut expected = String::new();
    for index in 0..4096 {
        write!(expected, "unit-{index:05} ").expect("write expected reply");
    }
    expected
}

mod watchdog_fixture_tests {
    use super::*;
    use std::io::Write as _;

    fn provider_record(marker: &str) -> String {
        serde_json::json!({
            "method": "POST", "path": "/v1/chat/completions", "stream": true,
            "messages": [{"role": "user", "content": marker}]
        })
        .to_string()
    }

    #[tokio::test(start_paused = true)]
    async fn preparation_is_not_charged_to_streaming_response_wait() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async move {
            tokio::time::sleep(Duration::from_secs(8)).await;
            writeln!(file, "{}", provider_record("current")).unwrap();
            file.flush().unwrap();
            tokio::time::sleep(Duration::from_secs(24)).await;
            7
        };
        assert_eq!(watchdog_response(terminal, log, "current").await, 7);
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "typed watchdog terminal within fixture deadline")]
    async fn streaming_response_still_expires_after_thirty_seconds() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async move {
            tokio::time::sleep(Duration::from_secs(8)).await;
            writeln!(file, "{}", provider_record("current")).unwrap();
            file.flush().unwrap();
            tokio::time::sleep(Duration::from_secs(31)).await;
        };
        watchdog_response(terminal, log, "current").await;
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "typed watchdog terminal within fixture deadline")]
    async fn delayed_log_observation_does_not_extend_response_budget() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async move {
            tokio::time::sleep(Duration::from_secs(8)).await;
            writeln!(file, "{}", provider_record("current")).unwrap();
            file.flush().unwrap();
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::time::sleep(Duration::from_secs(29)).await;
        };
        watchdog_response(terminal, log, "current").await;
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "typed watchdog terminal within fixture deadline")]
    async fn partial_entry_does_not_extend_response_budget() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async move {
            tokio::time::sleep(Duration::from_secs(8)).await;
            let record = provider_record("current");
            let split = record.len() / 2;
            write!(file, "{}", &record[..split]).unwrap();
            file.flush().unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            writeln!(file, "{}", &record[split..]).unwrap();
            file.flush().unwrap();
            tokio::time::sleep(Duration::from_secs(29)).await;
        };
        watchdog_response(terminal, log, "current").await;
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_before_provider_entry_needs_no_delta_or_marker() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async {
            tokio::time::sleep(Duration::from_secs(25)).await;
            7
        };
        assert_eq!(watchdog_response(terminal, log, "current").await, 7);
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "provider entry or watchdog terminal within preparation deadline")]
    async fn preparation_still_expires_after_thirty_seconds() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let log = BufReader::new(file.reopen().unwrap());
        let terminal = async {
            tokio::time::sleep(Duration::from_secs(31)).await;
        };
        watchdog_response(terminal, log, "current").await;
    }

    #[test]
    fn provider_log_retains_partial_records_and_ignores_old_history() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "method":"POST", "path":"/v1/chat/completions", "stream":false,
                "messages":[{"role":"user", "content":"current"}]
            })
        )
        .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "method":"POST", "path":"/v1/chat/completions", "stream":true,
                "messages":[{"role":"user", "content":"current"},
                            {"role":"user", "content":"other"}]
            })
        )
        .unwrap();
        let record = provider_record("current");
        let split = record.len() / 2;
        write!(file, "{}", &record[..split]).unwrap();
        file.flush().unwrap();
        let mut log = BufReader::new(file.reopen().unwrap());
        let mut pending = Vec::new();
        assert!(!held_provider_request_seen(
            &mut log,
            &mut pending,
            "current"
        ));
        assert!(!pending.is_empty());
        writeln!(file, "{}", &record[split..]).unwrap();
        file.flush().unwrap();
        assert!(held_provider_request_seen(
            &mut log,
            &mut pending,
            "current"
        ));
    }
}
