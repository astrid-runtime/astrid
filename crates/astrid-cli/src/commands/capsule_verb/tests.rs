use super::*;

fn cmd(name: &str, provider: &str, kind: CommandKind) -> CommandInfo {
    CommandInfo {
        name: name.to_string(),
        description: format!("{name} desc"),
        provider_capsule: provider.to_string(),
        kind,
        caller_max_timeout_secs: None,
    }
}

#[test]
fn match_verb_none_when_no_cli_provider() {
    let cmds = vec![
        cmd("deploy", "ops", CommandKind::Slash),
        cmd("status", "ops", CommandKind::Cli),
    ];
    // `deploy` exists only as a slash command → no CLI match.
    assert_eq!(match_verb("deploy", &cmds), VerbMatch::None);
    // Entirely unknown verb.
    assert_eq!(match_verb("nope", &cmds), VerbMatch::None);
}

#[test]
fn match_verb_one_when_single_cli_provider() {
    let cmds = vec![
        cmd("status", "ops", CommandKind::Cli),
        cmd("other", "misc", CommandKind::Cli),
    ];
    assert_eq!(
        match_verb("status", &cmds),
        VerbMatch::One {
            provider: "ops".to_string(),
            description: "status desc".to_string(),
            caller_max_timeout_secs: None,
        }
    );
}

#[test]
fn match_verb_ambiguous_when_multiple_cli_providers() {
    let cmds = vec![
        cmd("deploy", "ops", CommandKind::Cli),
        cmd("deploy", "infra", CommandKind::Cli),
        // A slash command of the same name must not count.
        cmd("deploy", "ui", CommandKind::Slash),
    ];
    assert_eq!(
        match_verb("deploy", &cmds),
        VerbMatch::Ambiguous {
            providers: vec!["ops".to_string(), "infra".to_string()],
        }
    );
}

#[test]
fn render_result_handles_valid_and_out_of_range_exit_codes() {
    // `ExitCode` exposes no inner-value accessor, so these assert the
    // valid and out-of-range paths execute without panicking (rendering
    // output to stdout/stderr) and return a process exit code. Out-of-
    // range codes (negative or > 255) map to failure (1), never to 0 —
    // a capsule sending garbage must not look like success.
    let frame = serde_json::json!({
        "payload": { "req_id": "x", "exit_code": 5, "output": "" }
    });
    let _ = render_result("p", &frame);

    let over = serde_json::json!({
        "payload": { "req_id": "x", "exit_code": 99999, "output": "hi" }
    });
    let _ = render_result("p", &over);

    let negative = serde_json::json!({
        "payload": { "req_id": "x", "exit_code": -1, "output": "" }
    });
    let _ = render_result("p", &negative);
}

#[test]
fn render_result_handles_malformed_payloads() {
    // Missing exit_code and missing payload both take the error-exit
    // path; ensure neither panics.
    let no_code = serde_json::json!({ "payload": { "output": "hi" } });
    let _ = render_result("p", &no_code);

    let no_payload = serde_json::json!({ "topic": "x" });
    let _ = render_result("p", &no_payload);
}

#[test]
fn capsules_loaded_missing_provider_detects_unload() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "payload": {
            "status": "ready",
            "capsules": [
                { "name": "astrid-capsule-session", "meta": null }
            ]
        }
    });
    assert!(capsules_loaded_missing_provider(
        &raw,
        "astrid-capsule-adversarial",
        "alice"
    ));
    assert!(!capsules_loaded_missing_provider(
        &raw,
        "astrid-capsule-session",
        "alice"
    ));
}

#[test]
fn capsules_loaded_missing_provider_accepts_wrapped_raw_json() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "payload": {
            "type": "raw_json",
            "value": {
                "status": "ready",
                "capsules": []
            }
        }
    });
    assert!(capsules_loaded_missing_provider(&raw, "provider", "alice"));
}

#[test]
fn capsules_loaded_missing_provider_ignores_unparseable_payload() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "payload": { "status": "ready" }
    });
    assert!(!capsules_loaded_missing_provider(&raw, "provider", "alice"));
}

#[test]
fn capsules_loaded_missing_provider_filters_by_principal() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "payload": {
            "status": "ready",
            "capsules": [
                {
                    "principal": "bob",
                    "name": "astrid-capsule-adversarial",
                    "meta": null
                }
            ]
        }
    });

    assert!(
        capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "alice"),
        "alice's provider should be missing when only bob still has it loaded"
    );
    assert!(
        !capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "bob"),
        "bob's provider should remain available while bob still has it loaded"
    );
}

#[test]
fn capsules_loaded_missing_provider_ignores_other_frame_principal() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "principal": "bob",
        "payload": {
            "status": "ready",
            "capsules": []
        }
    });

    assert!(
        !capsules_loaded_missing_provider(&raw, "astrid-capsule-adversarial", "alice"),
        "alice must not cancel on another principal's capsules_loaded frame"
    );
}

#[test]
fn capsules_loaded_missing_provider_detects_current_principal_entry() {
    let raw = serde_json::json!({
        "topic": "astrid.v1.capsules_loaded",
        "principal": "alice",
        "payload": {
            "status": "ready",
            "capsules": [
                {
                    "principal": "alice",
                    "name": "astrid-capsule-adversarial",
                    "meta": null
                },
                {
                    "principal": "bob",
                    "name": "astrid-capsule-session",
                    "meta": null
                }
            ]
        }
    });

    assert!(!capsules_loaded_missing_provider(
        &raw,
        "astrid-capsule-adversarial",
        "alice"
    ));
}
#[test]
fn result_wait_uses_caller_policy_and_legacy_default() {
    assert_eq!(
        command_result_timeout(None).unwrap(),
        Duration::from_secs(310)
    );
    assert_eq!(
        command_result_timeout(Some(600)).unwrap(),
        Duration::from_secs(610)
    );
    assert_eq!(
        command_result_timeout(Some(1)).unwrap(),
        Duration::from_secs(11)
    );
    assert!(command_result_timeout(Some(0)).is_err());
    assert!(command_result_timeout(Some(astrid_core::TIMEOUT_SECS_UPPER_BOUND + 1)).is_err());
    assert!(command_result_timeout(Some(u64::MAX)).is_err());
    let mut command = cmd("slow", "realm", CommandKind::Cli);
    command.caller_max_timeout_secs = Some(600);
    assert!(matches!(
        match_verb("slow", &[command]),
        VerbMatch::One {
            caller_max_timeout_secs: Some(600),
            ..
        }
    ));
}

#[cfg(unix)]
fn wait_client_pair() -> (SocketClient, tokio::net::UnixStream) {
    let (client, peer) = tokio::net::UnixStream::pair().unwrap();
    (
        SocketClient::from_stream_for_test(
            client,
            astrid_core::SessionId::new(),
            astrid_core::PrincipalId::new("alice").unwrap(),
        ),
        peer,
    )
}

#[cfg(unix)]
async fn send_wait_frame(peer: &mut tokio::net::UnixStream, value: serde_json::Value) {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(&value).unwrap();
    peer.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    peer.write_all(&bytes).await.unwrap();
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn result_after_old_seventy_second_limit_is_delivered() {
    let (mut client, mut peer) = wait_client_pair();
    let waiting = tokio::spawn(async move {
        wait_for_command_result(
            &mut client,
            "result.ours",
            "realm",
            "alice",
            tokio::time::Instant::now()
                .checked_add(command_result_timeout(Some(300)).unwrap())
                .unwrap(),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(71)).await;
    tokio::task::yield_now().await;
    assert!(
        !waiting.is_finished(),
        "must not discard a still-authorized slow command"
    );
    send_wait_frame(&mut peer, serde_json::json!({"topic":"result.other"})).await;
    send_wait_frame(
        &mut peer,
        serde_json::json!({
            "topic":"result.ours", "payload":{"exit_code":0,"output":"retained"}
        }),
    )
    .await;
    let CommandWait::Result(raw) = waiting.await.unwrap().unwrap() else {
        panic!("expected the command's result");
    };
    assert_eq!(raw["payload"]["output"], "retained");
    // The observation path sends no cancellation or retry to the server.
    let mut outbound = [0; 1];
    assert_eq!(peer.try_read(&mut outbound).unwrap(), 0);
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn unrelated_frames_do_not_extend_command_result_deadline() {
    let (mut client, mut peer) = wait_client_pair();
    let waiting = tokio::spawn(async move {
        wait_for_command_result(
            &mut client,
            "result.ours",
            "realm",
            "alice",
            tokio::time::Instant::now()
                .checked_add(command_result_timeout(Some(1)).unwrap())
                .unwrap(),
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    send_wait_frame(&mut peer, serde_json::json!({"topic":"result.other"})).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = waiting
        .await
        .unwrap()
        .err()
        .expect("observation must time out");
    assert!(error.to_string().contains("timed out"));
    let mut outbound = [0; 1];
    assert_eq!(peer.try_read(&mut outbound).unwrap(), 0);
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn repeated_waits_share_one_absolute_deadline() {
    let (mut client, mut peer) = wait_client_pair();
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(11))
        .unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    send_wait_frame(&mut peer, serde_json::json!({"topic":"result.first"})).await;
    assert!(matches!(
        wait_for_command_result(&mut client, "result.first", "realm", "alice", deadline)
            .await
            .unwrap(),
        CommandWait::Result(_)
    ));
    // Repeated observation uses the same deadline, without a fresh wait.
    let waiting = tokio::spawn(async move {
        wait_for_command_result(&mut client, "result.second", "realm", "alice", deadline).await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(waiting.await.unwrap().is_err());
}
