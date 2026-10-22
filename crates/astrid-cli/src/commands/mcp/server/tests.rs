use super::*;

#[test]
fn inbound_protocol_prefers_modern_and_retains_legacy_fallback() {
    assert_eq!(
        ASTRID_MCP_PROTOCOL_VERSIONS,
        &[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25,]
    );
    assert_eq!(ASTRID_MCP_PROTOCOL_VERSION, ProtocolVersion::V_2026_07_28);
}

#[test]
fn failed_reconnect_remains_armed_until_a_checked_replacement_succeeds() {
    let needs_reconnect = AtomicBool::new(false);
    record_reconnect_outcome(&needs_reconnect, &Err::<(), _>("mismatch"));
    assert!(needs_reconnect.load(Ordering::Relaxed));

    record_reconnect_outcome(&needs_reconnect, &Ok::<_, &str>(()));
    assert!(!needs_reconnect.load(Ordering::Relaxed));
}

/// The read-only tool-enumeration front door (MCP `tools/list`) is the only
/// round trip safe to transparently re-issue after a mid-wait connection
/// loss: it never mutates state.
#[test]
fn tools_list_is_retriable() {
    assert!(is_request_retriable(TOOLS_LIST_TOPIC));
}

/// Running a tool (MCP `tools/call`) may have ALREADY executed on the
/// broker before the connection died — never auto-retry it, or a mutating
/// tool could run twice.
#[test]
fn tool_call_is_not_retriable() {
    assert!(!is_request_retriable(TOOL_CALL_TOPIC));
}

/// Recording a capability-approval, ingress-consent, or grant-on-use
/// decision is a state mutation on the broker (grant additionally persists
/// a capsule on the principal); re-issuing could double-apply, so these are
/// not retriable either.
#[test]
fn respond_front_doors_are_not_retriable() {
    assert!(!is_request_retriable(elicit::APPROVAL_RESPOND_TOPIC));
    assert!(!is_request_retriable(ingress::INGRESS_RESPOND_TOPIC));
    assert!(!is_request_retriable(grant::GRANT_RESPOND_TOPIC));
}

/// Default-deny: an unrecognized topic must never be treated as retriable.
#[test]
fn unknown_topic_is_not_retriable() {
    assert!(!is_request_retriable("astrid.v1.request.mcp.something.new"));
    assert!(!is_request_retriable(""));
}

// ── Bounded grant-on-use loop (#1117) ───────────────────────────

/// A well-formed, still-present `grant_required` signal.
fn grant_reply(capsule: &str) -> Value {
    json!({
        "kind": "tool.call",
        "content": [],
        "isError": false,
        "grant_required": {
            "request_id": format!("grant-{capsule}"),
            "capsule_id": capsule,
            "principal": "claude-code",
            "tool_name": "some.tool",
            "call_id": "call-1"
        }
    })
}

/// A grant-free reply — the terminal / already-granted shape.
fn terminal_reply() -> Value {
    json!({ "kind": "tool.call", "content": [], "isError": false })
}

/// No grant signal → `Terminal`: proceed to the approval/terminal path.
#[test]
fn grant_step_terminal_when_no_signal() {
    assert!(matches!(
        next_grant_step(&terminal_reply(), 0),
        GrantStep::Terminal
    ));
}

/// A well-formed grant under the bound → `Resolve` (elicit + re-send).
#[test]
fn grant_step_resolves_present_signal_under_bound() {
    assert!(matches!(
        next_grant_step(&grant_reply("shell"), 0),
        GrantStep::Resolve(_)
    ));
    // Still resolvable right up to the last permitted resolution.
    assert!(matches!(
        next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS - 1),
        GrantStep::Resolve(_)
    ));
}

/// At or above the bound, a still-present grant signal must `Fail` with the
/// bound-exceeded message — never resolve again, never go `Terminal`.
#[test]
fn grant_step_fails_when_bound_exceeded() {
    let GrantStep::Fail(message) = next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS)
    else {
        panic!("a present grant signal at the bound must Fail, not Resolve/Terminal");
    };
    assert_eq!(message, GRANT_BOUND_EXCEEDED_MESSAGE);
    // Well above the bound too.
    assert!(matches!(
        next_grant_step(&grant_reply("shell"), MAX_GRANT_RESOLUTIONS + 5),
        GrantStep::Fail(_)
    ));
}

/// A present-but-unanswerable (malformed) signal fails with the malformed
/// message — it is never returned as an empty success.
#[test]
fn grant_step_fails_on_malformed_signal() {
    let malformed = json!({ "grant_required": { "request_id": "" } });
    let GrantStep::Fail(message) = next_grant_step(&malformed, 0) else {
        panic!("a malformed grant signal must Fail");
    };
    assert_eq!(message, MALFORMED_GRANT_MESSAGE);
}

/// The core #1117 invariant: as long as a grant signal is present, NO
/// resolved-count ever yields `Terminal`. If it did, the loop would hand a
/// `grant_required` reply to `call_tool_result_from_reply`, which would
/// reshape it into an empty `isError:false` success — the phantom result
/// the bug produced.
#[test]
fn grant_step_never_terminal_while_grant_present() {
    let reply = grant_reply("shell");
    for resolved in 0..=(MAX_GRANT_RESOLUTIONS + 2) {
        assert!(
            !matches!(next_grant_step(&reply, resolved), GrantStep::Terminal),
            "a present grant signal must never classify as Terminal (resolved={resolved})"
        );
    }
}
