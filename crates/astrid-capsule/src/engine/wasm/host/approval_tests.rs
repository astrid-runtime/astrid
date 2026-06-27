use super::*;

#[test]
fn check_allowance_matches_command_pattern() {
    let store = AllowanceStore::new();
    let keypair = KeyPair::generate();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: PrincipalId::default(),
        action_pattern: AllowancePattern::CommandPattern {
            command: "git push *".into(),
        },
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: keypair.sign(b"test"),
    };
    store.add_allowance(allowance).unwrap();

    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git status",
        None
    ));
}

#[test]
fn check_allowance_returns_false_on_empty_store() {
    let store = AllowanceStore::new();
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
}

#[test]
fn create_allowance_approve_session() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
}

#[test]
fn create_allowance_approve_always() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "docker run",
        "approve_always",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "docker run my-image",
        None
    ));
}

#[test]
fn create_allowance_simple_approve_does_nothing() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "approve",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
}

#[test]
fn create_allowance_deny_does_nothing() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "deny",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
}

#[test]
fn create_allowance_garbage_decision_does_nothing() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "garbage",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
}

#[test]
fn check_allowance_with_special_characters() {
    let store = AllowanceStore::new();
    let keypair = KeyPair::generate();
    let allowance = Allowance {
        id: AllowanceId::new(),
        principal: PrincipalId::default(),
        action_pattern: AllowancePattern::CommandPattern {
            command: "git push *".into(),
        },
        created_at: Timestamp::now(),
        expires_at: None,
        max_uses: None,
        uses_remaining: None,
        session_only: true,
        workspace_root: None,
        signature: keypair.sign(b"test"),
    };
    store.add_allowance(allowance).unwrap();

    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git status; rm -rf /",
        None
    ));
    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "git push --force origin main",
        None
    ));
}

#[test]
fn escape_glob_metacharacters_preserves_normal_chars() {
    assert_eq!(escape_glob_metacharacters("git push"), "git push");
    assert_eq!(
        escape_glob_metacharacters("npm install @types/react"),
        "npm install @types/react"
    );
    assert_eq!(escape_glob_metacharacters("my-tool_v2.0"), "my-tool_v2.0");
}

#[test]
fn escape_glob_metacharacters_escapes_wildcards() {
    assert_eq!(escape_glob_metacharacters("*"), "\\*");
    assert_eq!(escape_glob_metacharacters("git *"), "git \\*");
    assert_eq!(escape_glob_metacharacters("git[status]"), "git\\[status\\]");
    assert_eq!(escape_glob_metacharacters("cmd?"), "cmd\\?");
}

#[test]
fn create_allowance_with_wildcard_in_action_is_not_overly_broad() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "*",
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
}

#[test]
fn create_allowance_empty_action() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "",
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push",
        None
    ));
}

#[test]
fn approve_once_does_not_create_allowance() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git push",
        "approve",
        None,
        "test",
    );
    assert_eq!(store.count(), 0);
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
}

fn approval_response_event(
    request_id: &str,
    principal: Option<&str>,
    decision: &str,
) -> AstridEvent {
    let topic = Topic::approval_response(request_id);
    let mut message = IpcMessage::new(
        topic,
        IpcPayload::ApprovalResponse {
            request_id: request_id.to_string(),
            decision: decision.to_string(),
            reason: None,
        },
        Uuid::nil(),
    );
    if let Some(principal) = principal {
        message = message.with_principal(principal);
    }
    AstridEvent::Ipc {
        message,
        metadata: astrid_events::EventMetadata::default(),
    }
}

#[test]
fn approval_response_principal_match_is_exact() {
    let request_id = "approval-principal-match";
    let same = approval_response_event(request_id, Some("agent-alice"), "approve");
    let other = approval_response_event(request_id, Some("agent-bob"), "approve");
    let none = approval_response_event(request_id, None, "approve");

    assert!(response_principal_matches("agent-alice", &same));
    assert!(!response_principal_matches("agent-alice", &other));
    assert!(!response_principal_matches("agent-alice", &none));
}

fn publish_approval_reply(
    bus: &astrid_events::EventBus,
    request_id: &str,
    principal: Option<&str>,
    decision: &str,
) {
    bus.publish(approval_response_event(request_id, principal, decision));
}

#[tokio::test]
async fn approval_wait_times_out_after_wrong_principal_reply() {
    let bus = astrid_events::EventBus::with_capacity(64);
    let request_id = "approval-wrong-principal-timeout";
    let mut rx = bus.subscribe_topic(Topic::approval_response(request_id).as_str());
    publish_approval_reply(&bus, request_id, Some("agent-bob"), "approve");

    let result = await_matching_approval_response(
        &mut rx,
        "agent-alice",
        "test",
        request_id,
        std::time::Duration::from_millis(100),
    )
    .await;

    assert!(
        result.is_none(),
        "wrong-principal reply must not satisfy approval wait"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_wait_mismatch_flood_does_not_extend_deadline() {
    let bus = astrid_events::EventBus::with_capacity(128);
    let request_id = "approval-mismatch-flood";
    let mut rx = bus.subscribe_topic(Topic::approval_response(request_id).as_str());

    let pub_bus = bus.clone();
    let publisher = tokio::spawn(async move {
        for _ in 0..50 {
            publish_approval_reply(&pub_bus, request_id, Some("agent-bob"), "approve");
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
    });

    let budget = std::time::Duration::from_millis(150);
    let start = std::time::Instant::now();
    let result =
        await_matching_approval_response(&mut rx, "agent-alice", "test", request_id, budget).await;
    let elapsed = start.elapsed();

    publisher.abort();

    assert!(
        result.is_none(),
        "wrong-principal approval flood must not satisfy the waiter"
    );
    assert!(
        elapsed < budget * 5,
        "wrong-principal approval flood must not extend the deadline; took {elapsed:?}"
    );
}

#[tokio::test]
async fn approval_wait_ignores_wrong_principal_then_accepts_matching_reply() {
    let bus = astrid_events::EventBus::with_capacity(64);
    let request_id = "approval-wrong-then-right";
    let mut rx = bus.subscribe_topic(Topic::approval_response(request_id).as_str());
    publish_approval_reply(&bus, request_id, Some("agent-bob"), "approve");
    publish_approval_reply(&bus, request_id, Some("agent-alice"), "approve");

    let event = await_matching_approval_response(
        &mut rx,
        "agent-alice",
        "test",
        request_id,
        std::time::Duration::from_secs(1),
    )
    .await
    .expect("matching approval reply should be accepted");

    assert!(response_principal_matches("agent-alice", &event));
}

#[tokio::test]
async fn concurrent_approval_waiters_keep_correlation_and_principal_scopes() {
    let bus = astrid_events::EventBus::with_capacity(128);
    let mut rx_alice = bus.subscribe_topic(Topic::approval_response("approval-alice").as_str());
    let mut rx_bob = bus.subscribe_topic(Topic::approval_response("approval-bob").as_str());

    let alice = await_matching_approval_response(
        &mut rx_alice,
        "agent-alice",
        "test",
        "approval-alice",
        std::time::Duration::from_secs(1),
    );
    let bob = await_matching_approval_response(
        &mut rx_bob,
        "agent-bob",
        "test",
        "approval-bob",
        std::time::Duration::from_secs(1),
    );

    publish_approval_reply(&bus, "approval-alice", Some("agent-bob"), "approve");
    publish_approval_reply(&bus, "approval-bob", Some("agent-alice"), "approve");
    publish_approval_reply(&bus, "approval-alice", Some("agent-alice"), "approve");
    publish_approval_reply(&bus, "approval-bob", Some("agent-bob"), "deny");

    let (alice, bob) = tokio::join!(alice, bob);
    let alice = alice.expect("alice approval should resolve");
    let bob = bob.expect("bob approval should resolve");

    assert!(response_principal_matches("agent-alice", &alice));
    assert!(response_principal_matches("agent-bob", &bob));
}

fn approval_request(action: &str, resource: &str) -> ApprovalRequest {
    ApprovalRequest {
        action: action.to_string(),
        target_resource: resource.to_string(),
    }
}

async fn await_approval_request(mut rx: astrid_events::EventReceiver) -> (String, Option<String>) {
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("approval request observed")
        .expect("bus open");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected IPC approval request");
    };
    let IpcPayload::ApprovalRequired { request_id, .. } = &message.payload else {
        panic!("expected ApprovalRequired payload");
    };
    (request_id.clone(), message.principal.clone())
}

#[tokio::test]
async fn request_approval_stamps_principal_and_ignores_wrong_responder() {
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let bus = state.event_bus.clone();
    let request_rx = bus.subscribe_topic(Topic::approval_request().as_str());

    let approval_handle = tokio::task::spawn_blocking(move || {
        let result = <HostState as approval::Host>::request_approval(
            &mut state,
            approval_request("run", "run payment"),
        );
        (result, state)
    });

    let (request_id, request_principal) = await_approval_request(request_rx).await;
    assert_eq!(
        request_principal.as_deref(),
        Some("default"),
        "approval request must be stamped with the originating principal"
    );

    publish_approval_reply(&bus, &request_id, Some("agent-bob"), "approve");
    publish_approval_reply(&bus, &request_id, Some("default"), "approve");

    let (result, _state) = approval_handle.await.expect("approval thread joined");
    let response = result.expect("matching approval response should be accepted");
    assert_eq!(response.decision, ApprovalDecision::Approved);
}

#[tokio::test]
async fn request_approval_accepts_same_principal_deny() {
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let bus = state.event_bus.clone();
    let request_rx = bus.subscribe_topic(Topic::approval_request().as_str());

    let approval_handle = tokio::task::spawn_blocking(move || {
        let result = <HostState as approval::Host>::request_approval(
            &mut state,
            approval_request("delete", "delete workspace"),
        );
        (result, state)
    });

    let (request_id, request_principal) = await_approval_request(request_rx).await;
    publish_approval_reply(&bus, &request_id, request_principal.as_deref(), "deny");

    let (result, _state) = approval_handle.await.expect("approval thread joined");
    let response = result.expect("matching deny response should be accepted");
    assert_eq!(response.decision, ApprovalDecision::Denied);
}

#[tokio::test]
async fn request_approval_cancel_token_unblocks_wait() {
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let cancel = state.cancel_token.clone();
    let request_rx = state
        .event_bus
        .subscribe_topic(Topic::approval_request().as_str());

    let approval_handle = tokio::task::spawn_blocking(move || {
        let result = <HostState as approval::Host>::request_approval(
            &mut state,
            approval_request("delete", "delete workspace"),
        );
        (result, state)
    });

    let (_request_id, request_principal) = await_approval_request(request_rx).await;
    assert_eq!(request_principal.as_deref(), Some("default"));

    let start = std::time::Instant::now();
    cancel.cancel();
    let (result, _state) = approval_handle.await.expect("approval thread joined");

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "expected timeout after cancellation, got {result:?}"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "cancellation should unblock approval promptly"
    );
}

// --- sanitize_action_for_pattern tests ---

#[test]
fn sanitize_action_preserves_shell_fragments() {
    assert_eq!(
        sanitize_action_for_pattern("python -c 'print(\"hello\")'", "test"),
        "python -c 'print(\"hello\")'"
    );
    assert_eq!(
        sanitize_action_for_pattern("awk '{print $1}' file.txt", "test"),
        "awk '{print $1}' file.txt"
    );
    assert_eq!(
        sanitize_action_for_pattern("bash -c 'echo $HOME'", "test"),
        "bash -c 'echo $HOME'"
    );
    assert_eq!(
        sanitize_action_for_pattern("g++ main.cpp", "test"),
        "g++ main.cpp"
    );
    assert_eq!(
        sanitize_action_for_pattern("npm install @types/react", "test"),
        "npm install @types/react"
    );
    assert_eq!(
        sanitize_action_for_pattern("docker run ubuntu:latest", "test"),
        "docker run ubuntu:latest"
    );
}

#[test]
fn sanitize_action_preserves_glob_chars_for_escaping() {
    assert_eq!(sanitize_action_for_pattern("*", "test"), "*");
    assert_eq!(sanitize_action_for_pattern("git *", "test"), "git *");
    assert_eq!(sanitize_action_for_pattern("cmd?", "test"), "cmd?");
    assert_eq!(
        sanitize_action_for_pattern("git[status]", "test"),
        "git[status]"
    );
}

#[test]
fn sanitize_action_strips_control_characters() {
    assert_eq!(sanitize_action_for_pattern("git\0push", "test"), "gitpush");
    assert_eq!(sanitize_action_for_pattern("git\rpush", "test"), "gitpush");
    assert_eq!(
        sanitize_action_for_pattern("git\x1b[31mpush", "test"),
        "git[31mpush"
    );
    assert_eq!(sanitize_action_for_pattern("git\tpush", "test"), "gitpush");
    assert_eq!(sanitize_action_for_pattern("git\npush", "test"), "gitpush");
}

#[test]
fn sanitize_action_truncates_long_strings() {
    let long_action = "a".repeat(500);
    let sanitized = sanitize_action_for_pattern(&long_action, "test");
    assert_eq!(sanitized.chars().count(), MAX_ACTION_LEN);
}

#[test]
fn sanitize_action_exact_limit_no_change() {
    let action = "a".repeat(MAX_ACTION_LEN);
    let sanitized = sanitize_action_for_pattern(&action, "test");
    assert_eq!(sanitized, action);
    assert_eq!(sanitized.chars().count(), MAX_ACTION_LEN);
}

#[test]
fn sanitize_action_truncates_multibyte_chars() {
    let action = "a".repeat(200) + &"\u{0100}".repeat(100);
    assert_eq!(action.chars().count(), 300);
    let sanitized = sanitize_action_for_pattern(&action, "test");
    assert_eq!(sanitized.chars().count(), MAX_ACTION_LEN);
    assert!(sanitized.starts_with(&"a".repeat(200)));
}

#[test]
fn sanitize_action_trims_whitespace() {
    assert_eq!(
        sanitize_action_for_pattern("  git push  ", "test"),
        "git push"
    );
}

#[test]
fn create_allowance_whitespace_padded_action() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "  git push  ",
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git status",
        None
    ));
}

#[test]
fn create_allowance_combined_attack() {
    let store = AllowanceStore::new();
    let attack = "git\0 *\x1b[31m";
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        attack,
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git status",
        None
    ));
}

#[test]
fn create_allowance_null_byte_attack() {
    let store = AllowanceStore::new();
    create_allowance_from_decision(
        &store,
        &PrincipalId::default(),
        "git\0push",
        "approve_session",
        None,
        "test",
    );
    assert_eq!(store.count(), 1);
    assert!(!check_allowance(
        &store,
        &PrincipalId::default(),
        "git push origin main",
        None
    ));
    assert!(check_allowance(
        &store,
        &PrincipalId::default(),
        "gitpush something",
        None
    ));
}

// --- sanitize_guest_field tests ---

#[test]
fn sanitize_guest_field_strips_control_chars() {
    let mut s = "git push\x1b[31m origin".to_string();
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s, "git push[31m origin");
}

#[test]
fn sanitize_guest_field_truncates_resource() {
    let mut s = "a".repeat(2000);
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s.chars().count(), MAX_RESOURCE_LEN);
}

#[test]
fn sanitize_guest_field_resource_exact_limit() {
    let original = "a".repeat(MAX_RESOURCE_LEN);
    let mut s = original.clone();
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s, original);
}

#[test]
fn sanitize_guest_field_truncates_multibyte() {
    let mut s = "a".repeat(500) + &"\u{0100}".repeat(600);
    assert_eq!(s.chars().count(), 1100);
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s.chars().count(), MAX_RESOURCE_LEN);
    assert!(s.starts_with(&"a".repeat(500)));
}

#[test]
fn sanitize_guest_field_trims_whitespace() {
    let mut s = "  git push origin  ".to_string();
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s, "git push origin");
}

#[test]
fn sanitize_guest_field_combined_attack() {
    let mut s = format!("{}\x1b[31m{}", "A".repeat(1000), "B".repeat(1000));
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert_eq!(s.chars().count(), MAX_RESOURCE_LEN);
    assert!(s.chars().all(|c| !c.is_control()));
}

#[test]
fn sanitize_guest_field_empty_string() {
    let mut s = String::new();
    sanitize_guest_field(&mut s, MAX_RESOURCE_LEN, "resource", "test");
    assert!(s.is_empty());
}
