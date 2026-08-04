//! Tool-descriptor capture from a loaded capsule.
//!
//! [`describe_loaded_capsule`] invokes a live, already-loaded capsule's
//! `tool_describe` interceptor and parses the static tool surface the
//! `#[astrid::tool]` macro generated. The kernel calls this at load time on
//! every loaded capsule so a consumer (e.g. the sage-mcp broker) gets a
//! deterministic tool surface without a runtime describe fan-out and without
//! the capsule having been rebuilt.

use serde::{Deserialize, Serialize};

use crate::capsule::{Capsule, InterceptResult};

/// A single tool's descriptor, as emitted by the `#[astrid::tool]`-generated
/// `tool_describe` interceptor.
///
/// Field shape matches the JSON the macro builds
/// (`{ name, description, input_schema }`) and what the MCP bridge /
/// prompt-builder consume, so a captured descriptor round-trips without
/// translation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolDescriptor {
    /// Tool name (the `#[astrid::tool("name")]` argument).
    pub name: String,
    /// Human-readable description (the tool method's doc comment).
    pub description: String,
    /// JSON Schema for the tool's input arguments.
    #[serde(rename = "input_schema")]
    pub input_schema: serde_json::Value,
}

/// Invoke an already-loaded capsule's `tool_describe` interceptor and parse the
/// tool descriptors it returns.
///
/// The `tool_describe` interceptor returns the descriptor JSON in its
/// `CapsuleResult { action: "continue", data: Some(...) }`, surfaced as
/// `InterceptResult::Continue(bytes)`. A capsule with no `#[astrid::tool]` has no
/// `tool_describe` arm, and the engine signals that two ways depending on whether
/// the capsule has *any* interceptors: a capsule with none yields a
/// `NotSupported` error, while a capsule with other interceptors (e.g. the
/// sage-mcp broker) has its generated dispatch *deny* the unknown action with
/// "unknown hook action: tool_describe". Both mean "no tools", not a failure.
///
/// # Errors
///
/// Returns an error if the interceptor errors for any reason other than "not
/// implemented", genuinely denies (a reason other than the unknown-action one),
/// or returns a payload that is present but not the expected JSON shape.
///
/// Preserves the original signature: a pool-less run-loop capsule's *unknown*
/// surface collapses to an empty vec here. Callers that must distinguish
/// "unknown" from "empty" — to drive the describe fan-out (#1198) — use
/// [`describe_loaded_capsule_status`] instead.
pub async fn describe_loaded_capsule(capsule: &dyn Capsule) -> anyhow::Result<Vec<ToolDescriptor>> {
    Ok(describe_loaded_capsule_status(capsule)
        .await?
        .unwrap_or_default())
}

/// Like [`describe_loaded_capsule`], but preserves the "surface unknown" signal
/// the load-time capture needs.
///
/// Returns:
/// - `Ok(Some(tools))` — the describe ran and returned a (possibly empty) tool
///   surface; the caller injects it into the `capsules_loaded` meta.
/// - `Ok(None)` — the describe COULD NOT run because this is a pool-less
///   run-loop capsule (`invoke_interceptor` reports `NotSupported`). The caller
///   must then leave `tools` ABSENT (not `[]`), so the consumer's describe
///   fan-out fires and the capsule's own `tool.v1.request.describe` responder
///   supplies the surface. Injecting `[]` here reads as "0 tools" and suppresses
///   the fan-out — the bug in #1198.
///
/// # Errors
///
/// Same as [`describe_loaded_capsule`].
pub async fn describe_loaded_capsule_status(
    capsule: &dyn Capsule,
) -> anyhow::Result<Option<Vec<ToolDescriptor>>> {
    interpret_describe_result(capsule.invoke_interceptor("tool_describe", &[], None).await)
}

/// Pure mapping of a `tool_describe` interceptor outcome to a captured tool
/// surface. Split out from [`describe_loaded_capsule`] so the capture semantics
/// — especially the pool-less `NotSupported => None` case that fixes #1198 — are
/// unit-testable without a live capsule.
fn interpret_describe_result(
    outcome: Result<InterceptResult, crate::error::CapsuleError>,
) -> anyhow::Result<Option<Vec<ToolDescriptor>>> {
    let result = match outcome {
        Ok(r) => r,
        // Pool-less run-loop capsule: the interceptor path isn't available, so
        // the tool surface is UNKNOWN — not empty. Signal absent (`None`) so the
        // caller lets the describe fan-out supply it (#1198), rather than
        // injecting `[]` and suppressing the fan-out.
        Err(e) if is_unsupported(&e) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("tool_describe interceptor failed: {e}")),
    };

    let payload = match result {
        InterceptResult::Continue(bytes) | InterceptResult::Final(bytes) => bytes,
        // A capsule that CAN run interceptors but has no `#[astrid::tool]` arm
        // (e.g. the broker) genuinely has zero static tools: captured-empty
        // (`Some([])`), NOT absent — there is nothing for a fan-out to supply.
        InterceptResult::Deny { reason } if is_unknown_action(&reason) => {
            return Ok(Some(Vec::new()));
        },
        // Any other deny is a genuine refusal — surface it.
        InterceptResult::Deny { reason } => {
            anyhow::bail!("tool_describe interceptor denied: {reason}");
        },
    };

    if payload.is_empty() {
        return Ok(Some(Vec::new()));
    }

    parse_tool_descriptors(&payload).map(Some)
}

/// Parse the `tools` array out of a `tool_describe` descriptor payload
/// (`{ "tools": [ {name, description, input_schema}, ... ], "description": "..." }`).
///
/// Deserializes straight into a typed wrapper rather than walking a generic
/// `serde_json::Value` — no intermediate allocation or clone. A missing
/// `tools` key defaults to empty (a non-tool payload), while a present-but-
/// malformed `tools` array is a hard error.
fn parse_tool_descriptors(payload: &[u8]) -> anyhow::Result<Vec<ToolDescriptor>> {
    #[derive(Deserialize)]
    struct ToolDescribePayload {
        #[serde(default)]
        tools: Vec<ToolDescriptor>,
    }
    let parsed: ToolDescribePayload = serde_json::from_slice(payload).map_err(|e| {
        anyhow::anyhow!("tool_describe payload is not valid JSON or has an unexpected shape: {e}")
    })?;
    Ok(parsed.tools)
}

/// Names of advertised tools that no interceptor route will ever deliver an
/// execute call to.
///
/// A tool is advertised straight from its `#[astrid::tool]` annotation (the
/// describe path bypasses the subscribe ACL), but the dispatcher routes execute
/// calls *solely* from the manifest's `[subscribe]` handlers. So a tool whose
/// `Capsule.toml` is missing (or has a mistyped) `tool.v1.execute.<name>`
/// subscription appears in `tools/list` yet silently never runs — no dispatch,
/// no log, no error. This returns those tool names so the caller can warn.
///
/// Matching uses the SAME [`crate::topic::topic_matches`] the dispatcher uses,
/// so a wildcard subscription (e.g. `tool.v1.execute.*`) correctly counts as a
/// route and is NOT reported. Pure over its inputs.
#[must_use]
pub fn tools_missing_execute_route<'a>(
    tools: &'a [ToolDescriptor],
    interceptors: &[crate::manifest::InterceptorDef],
) -> Vec<&'a str> {
    // No interceptors at all → no tool can be routed; every advertised tool is
    // missing its route. Short-circuit before per-tool topic formatting.
    if interceptors.is_empty() {
        return tools.iter().map(|tool| tool.name.as_str()).collect();
    }
    tools
        .iter()
        .filter(|tool| {
            let topic = format!("{}{}", crate::topic::TOOL_EXECUTE_PREFIX, tool.name);
            !interceptors
                .iter()
                .any(|def| crate::topic::topic_matches(&topic, &def.event))
        })
        .map(|tool| tool.name.as_str())
        .collect()
}

/// Whether a capsule error signals "this interceptor action is not
/// implemented" (a capsule with no tools), as opposed to a real
/// failure. The WASM engine returns `NotSupported` for an unknown
/// action and the trait default does the same.
fn is_unsupported(err: &crate::error::CapsuleError) -> bool {
    matches!(err, crate::error::CapsuleError::NotSupported(_))
}

/// Whether a `tool_describe` deny reason means the capsule simply has no
/// `tool_describe` arm (a capsule with other interceptors but no
/// `#[astrid::tool]`), as opposed to a genuine refusal. The SDK's generated
/// interceptor dispatch denies an unhandled action with the exact reason
/// "unknown hook action: <action>" — match it precisely (this is only ever
/// called for the `tool_describe` action) rather than by substring, so a
/// genuine deny whose message happens to contain the phrase is never silently
/// swallowed as "no tools".
fn is_unknown_action(reason: &str) -> bool {
    reason == "unknown hook action: tool_describe"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1198: a pool-less run-loop capsule's `NotSupported` describe maps to
    /// `None` (surface UNKNOWN → leave absent so the describe fan-out fires), NOT
    /// to a captured-empty `Some([])` which reads as "0 tools" and suppresses it.
    #[test]
    fn pool_less_notsupported_maps_to_none_for_fan_out() {
        let out = interpret_describe_result(Err(crate::error::CapsuleError::NotSupported(
            "no interceptors".into(),
        )));
        assert!(matches!(out, Ok(None)));
    }

    /// A capsule that CAN run interceptors but has no `#[astrid::tool]` (the
    /// broker) is captured-empty (`Some([])`), not absent — nothing to fan out.
    #[test]
    fn unknown_action_deny_is_captured_empty_not_absent() {
        let out = interpret_describe_result(Ok(InterceptResult::Deny {
            reason: "unknown hook action: tool_describe".into(),
        }));
        assert!(matches!(out, Ok(Some(ref v)) if v.is_empty()));
    }

    #[test]
    fn described_tools_are_captured_as_some() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "tools": [{ "name": "t", "description": "d", "input_schema": { "type": "object" } }]
        }))
        .unwrap();
        let tools = interpret_describe_result(Ok(InterceptResult::Continue(payload)))
            .expect("ok")
            .expect("some");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "t");
    }

    #[test]
    fn empty_describe_payload_is_captured_empty() {
        let out = interpret_describe_result(Ok(InterceptResult::Continue(Vec::new())));
        assert!(matches!(out, Ok(Some(ref v)) if v.is_empty()));
    }

    #[test]
    fn genuine_deny_surfaces_as_error() {
        let out = interpret_describe_result(Ok(InterceptResult::Deny {
            reason: "capability denied: caps:token:mint".into(),
        }));
        assert!(out.is_err());
    }

    #[test]
    fn unknown_action_deny_matches_only_tool_describe() {
        // A capsule with interceptors but no `#[astrid::tool]` (e.g. the broker)
        // denies the unknown `tool_describe` action — that is "no tools".
        assert!(is_unknown_action("unknown hook action: tool_describe"));
        // An unknown action for a DIFFERENT endpoint is not our signal — don't
        // swallow it (this fn is only ever called for `tool_describe`, but the
        // exact match keeps it honest).
        assert!(!is_unknown_action("unknown hook action: other_action"));
        // A genuine refusal must NOT be swallowed as "no tools", even if its
        // message happens to contain the phrase.
        assert!(!is_unknown_action("capability denied: caps:token:mint"));
        assert!(!is_unknown_action(
            "policy blocked: unknown hook action is not allowed here"
        ));
    }

    #[test]
    fn parses_tool_describe_payload() {
        // The exact shape the `#[astrid::tool]` macro emits.
        let payload = serde_json::json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file",
                    "input_schema": { "type": "object", "properties": {} }
                },
                {
                    "name": "write_file",
                    "description": "Write a file",
                    "input_schema": { "type": "object" }
                }
            ],
            "description": "fs capsule"
        });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        let tools = parse_tool_descriptors(&bytes).expect("parse");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "read_file");
        assert_eq!(tools[0].description, "Read a file");
        assert_eq!(tools[0].input_schema["type"], "object");
        assert_eq!(tools[1].name, "write_file");
    }

    #[test]
    fn empty_tools_array_yields_empty_vec() {
        let payload = serde_json::json!({ "tools": [], "description": "" });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).expect("parse").is_empty());
    }

    #[test]
    fn missing_tools_key_yields_empty_vec() {
        let payload = serde_json::json!({ "description": "no tools key" });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).expect("parse").is_empty());
    }

    #[test]
    fn malformed_tools_array_errors() {
        let payload = serde_json::json!({ "tools": [ { "name": 42 } ] });
        let bytes = serde_json::to_vec(&payload).expect("serialize");
        assert!(parse_tool_descriptors(&bytes).is_err());
    }

    fn tool(name: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.into(),
            description: String::new(),
            input_schema: serde_json::json!({ "type": "object" }),
        }
    }

    fn intercept(event: &str) -> crate::manifest::InterceptorDef {
        crate::manifest::InterceptorDef {
            event: event.into(),
            action: "tool_execute_x".into(),
            priority: 100,
        }
    }

    #[test]
    fn missing_execute_route_flags_only_the_unrouted_tool() {
        // `upcase` is subscribed; `reverse_text` is advertised but has no
        // `tool.v1.execute.reverse_text` route — it will never execute.
        let tools = [tool("reverse_text"), tool("upcase")];
        let subs = [intercept("tool.v1.execute.upcase")];
        assert_eq!(
            tools_missing_execute_route(&tools, &subs),
            vec!["reverse_text"]
        );
    }

    #[test]
    fn missing_execute_route_exact_subscription_is_routed() {
        let tools = [tool("reverse_text")];
        let subs = [intercept("tool.v1.execute.reverse_text")];
        assert!(tools_missing_execute_route(&tools, &subs).is_empty());
    }

    #[test]
    fn missing_execute_route_wildcard_subscription_routes_all() {
        // A single-segment wildcard covers every tool — must NOT be flagged
        // (mirrors the dispatcher's own matcher).
        let tools = [tool("reverse_text"), tool("upcase")];
        let subs = [intercept("tool.v1.execute.*")];
        assert!(tools_missing_execute_route(&tools, &subs).is_empty());
    }

    #[test]
    fn missing_execute_route_no_subscriptions_flags_every_tool() {
        let tools = [tool("a"), tool("b")];
        assert_eq!(tools_missing_execute_route(&tools, &[]), vec!["a", "b"]);
    }

    #[test]
    fn missing_execute_route_ignores_unrelated_subscriptions() {
        // A subscription to a different topic family doesn't route the tool.
        let tools = [tool("reverse_text")];
        let subs = [
            intercept("session.v1.event.*"),
            intercept("tool.v1.execute.other_tool"),
        ];
        assert_eq!(
            tools_missing_execute_route(&tools, &subs),
            vec!["reverse_text"]
        );
    }

    #[test]
    fn tool_descriptor_round_trips_with_input_schema_rename() {
        let d = ToolDescriptor {
            name: "do_thing".into(),
            description: "does it".into(),
            input_schema: serde_json::json!({ "type": "object" }),
        };
        let json = serde_json::to_value(&d).expect("serialize");
        // Field is `input_schema` on the wire, matching the macro output.
        assert!(json.get("input_schema").is_some());
        let back: ToolDescriptor = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, d);
    }
}
