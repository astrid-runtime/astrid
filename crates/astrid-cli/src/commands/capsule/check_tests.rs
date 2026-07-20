//! Tests for [`super`] — the `astrid capsule check` ruleset and source scan.

use super::*;

fn names(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn intercept(event: &str, action: &str) -> InterceptorDef {
    InterceptorDef {
        event: event.into(),
        action: action.into(),
        priority: 100,
    }
}

/// The two mandatory `[publish]` patterns, so tests not exercising rule 2 stay
/// green on it.
fn mandatory_publishes() -> Vec<String> {
    MANDATORY_PUBLISH
        .iter()
        .map(|(pattern, _, _)| (*pattern).to_string())
        .collect()
}

fn rules(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().map(|f| f.rule).collect()
}

// ── source scan ────────────────────────────────────────────────────────

#[test]
fn source_scan_extracts_literal_names() {
    assert_eq!(
        tool_names_in_source(
            r#"
            #[astrid::tool("reverse_text")]
            fn reverse_text() {}

            #[astrid::tool("upcase", mutable)]
            fn upcase() {}
            "#,
        ),
        names(&["reverse_text", "upcase"]),
    );
}

#[test]
fn source_scan_ignores_comments_calls_and_embedded_templates() {
    let source = r##"
        // #[astrid::tool("line_comment")]
        /* #[astrid::tool("block_comment")] */
        const ORDINARY: &str = "#[astrid::tool(\"ordinary_string\")]";
        const TEMPLATE: &str = r#"
            #[astrid::tool("raw_string")]
            fn example() {}
        "#;

        fn unrelated() {
            astrid::tool_helper("helper_call");
            astrid::tool_describe();
        }

        #[astrid::tool("real_tool")]
        fn real_tool() {}
    "##;

    assert_eq!(tool_names_in_source(source), names(&["real_tool"]));
}

// ── ruleset ────────────────────────────────────────────────────────────

#[test]
fn clean_capsule_has_no_findings() {
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[intercept(
            "tool.v1.execute.reverse_text",
            "tool_execute_reverse_text",
        )],
        &mandatory_publishes(),
    );
    assert!(findings.is_empty(), "expected clean, got {findings:?}");
}

#[test]
fn flags_advertised_but_unrouted_tool() {
    // Tool declared, no subscription routes its execute topic.
    let findings = check_capsule(&names(&["reverse_text"]), &[], &mandatory_publishes());
    assert_eq!(rules(&findings), vec!["unrouted-tool"]);
    assert!(findings[0].message.contains("tool.v1.execute.reverse_text"));
    // The suggested fix carries the REQUIRED wit field (a bare handler = ...
    // line would fail manifest parsing).
    assert!(
        findings[0]
            .message
            .contains("wit = \"@unicity-astrid/wit/types/tool-call\"")
    );
}

#[test]
fn flags_missing_mandatory_publish_boilerplate() {
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[intercept(
            "tool.v1.execute.reverse_text",
            "tool_execute_reverse_text",
        )],
        &[], // no publishes at all
    );
    // Both mandatory publish patterns are reported.
    assert_eq!(rules(&findings), vec!["missing-publish", "missing-publish"]);
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("tool.v1.execute.*.result"))
    );
    assert!(
        findings
            .iter()
            .any(|f| f.message.contains("tool.v1.response.describe.*"))
    );
}

#[test]
fn missing_publish_not_flagged_for_toolless_capsule() {
    // A capsule with no tools needs no tool-bus publish boilerplate.
    let findings = check_capsule(&[], &[], &[]);
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn flags_dangling_tool_subscription() {
    // A subscription whose tool name (typo) matches no #[astrid::tool].
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[
            intercept("tool.v1.execute.reverse_text", "tool_execute_reverse_text"),
            intercept("tool.v1.execute.reverze_text", "tool_execute_reverze_text"),
        ],
        &mandatory_publishes(),
    );
    assert_eq!(rules(&findings), vec!["dangling-subscription"]);
    assert!(findings[0].message.contains("reverze_text"));
}

#[test]
fn flags_handler_name_mismatch() {
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[intercept("tool.v1.execute.reverse_text", "do_reverse")],
        &mandatory_publishes(),
    );
    assert_eq!(rules(&findings), vec!["handler-mismatch"]);
    assert!(findings[0].message.contains("tool_execute_reverse_text"));
    assert!(findings[0].message.contains("do_reverse"));
}

#[test]
fn wildcard_subscription_routes_all_tools_no_false_positives() {
    // A single catch-all `tool.v1.execute.*` routes every tool and must not be
    // flagged as unrouted (rule 1) or dangling/mismatched (rules 3/4 skip it).
    let findings = check_capsule(
        &names(&["alpha", "beta"]),
        &[intercept("tool.v1.execute.*", "tool_execute_dispatch")],
        &mandatory_publishes(),
    );
    assert!(
        findings.is_empty(),
        "wildcard should route all, got {findings:?}"
    );
}

#[test]
fn reserved_result_topic_is_not_flagged_dangling() {
    // A react-style capsule subscribing to the bare result-delivery topic
    // `tool.v1.execute.result` is not naming a tool — don't flag it dangling.
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[
            intercept("tool.v1.execute.reverse_text", "tool_execute_reverse_text"),
            intercept("tool.v1.execute.result", "handle_result"),
        ],
        &mandatory_publishes(),
    );
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn per_tool_result_topic_is_not_treated_as_a_tool() {
    // A `<name>.result` subscription is multi-segment — not a tool invocation.
    let findings = check_capsule(
        &names(&["reverse_text"]),
        &[
            intercept("tool.v1.execute.reverse_text", "tool_execute_reverse_text"),
            intercept("tool.v1.execute.reverse_text.result", "handle_result"),
        ],
        &mandatory_publishes(),
    );
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn findings_are_sorted_deterministically_by_rule() {
    // A capsule tripping several rules at once: `alpha` is unrouted, both
    // mandatory publishes are missing, and `ghost` is a dangling subscription.
    // Regardless of the order the rules fire (HashMap-backed manifest tables +
    // filesystem scan order), the output must be stable — sorted by rule so a
    // CI gate never emits a flaky ordering.
    let findings = check_capsule(
        &names(&["alpha"]),
        &[intercept("tool.v1.execute.ghost", "tool_execute_ghost")],
        &[],
    );
    assert_eq!(
        rules(&findings),
        vec![
            "dangling-subscription",
            "missing-publish",
            "missing-publish",
            "unrouted-tool",
        ]
    );
}
