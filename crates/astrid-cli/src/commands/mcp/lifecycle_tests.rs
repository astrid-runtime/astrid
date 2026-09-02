use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::*;

#[test]
fn gateway_lifecycle_admits_only_one_generation() {
    let first = try_acquire_gateway_lifecycle()
        .expect("lifecycle probe")
        .expect("first generation owns the lifecycle");
    assert!(
        try_acquire_gateway_lifecycle()
            .expect("lifecycle probe")
            .is_none(),
        "a successor must not bind while a generation lifecycle is held"
    );
    drop(first);
    assert!(
        try_acquire_gateway_lifecycle()
            .expect("lifecycle probe")
            .is_some(),
        "releasing the lifecycle must permit the next generation"
    );
}

#[test]
fn process_parser_preserves_command_after_pid_fields() {
    let row = parse_process_row(" 123  1 /usr/local/bin/aos mcp serve --request-timeout 1d5m")
        .expect("process row");
    assert_eq!(row.pid, 123);
    assert_eq!(row.ppid, 1);
    assert!(is_long_mcp_serve(&row.command));
}

#[test]
fn gc_match_is_exact_about_timeout_and_verb() {
    assert!(is_long_mcp_serve("aos mcp serve --request-timeout 1d5m"));
    assert!(is_long_mcp_serve("aos mcp serve --request-timeout=1d5m"));
    assert!(!is_long_mcp_serve("aos mcp serve --request-timeout 30s"));
    assert!(!is_long_mcp_serve("aos mcp gateway --request-timeout 1d5m"));
}

#[test]
fn gc_reaps_orphaned_attach_but_never_python_frames() {
    assert!(is_mcp_attach(
        "/Users/me/.aos/runtime/bin/astrid --principal codex-code mcp attach --workspace /tmp/proj"
    ));
    assert!(is_mcp_attach("aos --principal codex-code mcp attach"));
    assert!(!is_mcp_attach(
        "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python -u /cache/unicity-aos/bin/aos-mcp-frame /runtime/bin/astrid --principal codex-code mcp attach --workspace /plugin"
    ));
    assert!(is_python_frame(
        "Python -u /cache/bin/aos-mcp-frame astrid --principal codex-code mcp attach --workspace /plugin"
    ));
    assert!(!is_mcp_attach(
        "node worker.js mcp attach --workspace /tmp/astrid"
    ));
    assert!(!is_mcp_attach("node /tmp/astrid worker.js mcp attach"));
    assert!(is_mcp_attach(
        "env ASTRID_SESSION_ID=thread-1 /opt/aos mcp attach --workspace /tmp/proj"
    ));
    assert!(!is_mcp_attach("astrid --principal codex-code mcp gateway"));
    assert!(!is_mcp_attach("aos mcp serve --request-timeout 1d5m"));
}

#[test]
fn ready_record_is_stable_json_contract() {
    let record = GatewayReady {
        version: 1,
        principal: "codex-code".into(),
        pid: 42,
        hook_token: "test-hook-token".into(),
    };
    let body = serde_json::to_string(&record).expect("record json");
    assert_eq!(serde_json::from_str::<GatewayReady>(&body).unwrap(), record);
    assert_eq!(ReadyFormat::parse("hook").unwrap(), ReadyFormat::Hook);
}

#[test]
fn ready_cleanup_cannot_remove_a_successor_record() {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().join(GATEWAY_READY_NAME);
    let old = GatewayReady {
        version: 1,
        principal: "codex-code".into(),
        pid: 41,
        hook_token: "old-token".into(),
    };
    let successor = GatewayReady {
        version: 1,
        principal: "codex-code".into(),
        pid: 42,
        hook_token: "successor-token".into(),
    };
    std::fs::write(&path, serde_json::to_vec(&successor).unwrap()).unwrap();

    let error = remove_gateway_ready_at(&path, &old)
        .expect_err("old cleanup must not remove a successor marker");
    assert!(error.to_string().contains("readiness changed"));
    assert_eq!(
        read_gateway_ready_at(&path).unwrap(),
        Some(successor.clone())
    );

    remove_gateway_ready_at(&path, &successor).expect("successor removes its own marker");
    assert!(!path.exists());
}

#[tokio::test]
async fn control_ack_is_bound_to_operation_pid_and_success() {
    for ack in [
        GatewayControlAck::success(GatewayControlOperation::Stop, 42),
        GatewayControlAck::success(GatewayControlOperation::Health, 43),
        GatewayControlAck::failure(GatewayControlOperation::Health, 42, "uplink unavailable"),
    ] {
        let (client, server) = UnixStream::pair().expect("stream pair");
        let serving = tokio::spawn(async move {
            let (read_half, mut write_half) = server.into_split();
            let mut reader = BufReader::new(read_half);
            let request = read_bounded_line(&mut reader).await.expect("request");
            serde_json::from_slice::<GatewayControlRequest>(&request).expect("valid request");
            write_half
                .write_all(&serde_json::to_vec(&ack).unwrap())
                .await
                .unwrap();
            write_half.write_all(b"\n").await.unwrap();
        });
        let record = GatewayReady {
            version: 1,
            principal: "codex-code".into(),
            pid: 42,
            hook_token: "gateway-token".into(),
        };
        request_gateway_control(client, &record, GatewayControlOperation::Health)
            .await
            .expect_err("an unbound or unsuccessful ACK must fail");
        serving.await.expect("fake server");
    }
}
