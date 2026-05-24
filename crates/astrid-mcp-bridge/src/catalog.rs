//! Build the MCP tool catalog by calling capsule-system's
//! introspection tools (`list_capsules`, `inspect_capsule`) and
//! translating the responses into rmcp's [`Tool`] shape.
//!
//! # Observed response shapes (2026-05-24)
//!
//! - `list_capsules` returns a JSON-pretty array of `CapsuleSummary`
//!   objects: `[{ "name": "astrid-capsule-shell", "version": "0.1.0",
//!   "exports": [...], "imports": [...] }, ...]`.
//! - `inspect_capsule` returns a plain-text blob, **not** JSON:
//!   `"=== Capsule.toml ===\n<toml>\n\n=== meta.json ===\n<json>"`.
//!   The tool list lives in the TOML's `[subscribe]` table (modern
//!   manifests) or `[[interceptor]]` array (legacy manifests), keyed
//!   by topics like `tool.v1.execute.<tool_name>`.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::Tool;
use serde_json::Value;

use crate::daemon::DaemonConnection;
use crate::error::BridgeError;

const CATALOG_TIMEOUT: Duration = Duration::from_secs(10);

/// Capsule-name prefix stripped when building short capsule names.
/// `astrid-capsule-shell` -> `shell`.
const CAPSULE_NAME_PREFIX: &str = "astrid-capsule-";

/// Topic prefix that marks a subscribe/interceptor entry as a tool
/// invocation. We strip this to get the bare tool name.
const TOOL_EXECUTE_PREFIX: &str = "tool.v1.execute.";

/// Topic suffix that marks an entry as a *result* publisher rather
/// than a tool invocation. Must be excluded.
const TOOL_RESULT_SUFFIX: &str = ".result";

/// Build the catalog by introspecting every installed capsule.
///
/// # Errors
/// Propagates any [`BridgeError`] from the underlying
/// `call_tool_round_trip` calls (timeout, daemon disconnect, etc.).
pub async fn build_catalog(daemon: &mut DaemonConnection) -> Result<Vec<Tool>, BridgeError> {
    let list = daemon
        .call_tool_round_trip("list_capsules", serde_json::json!({}), CATALOG_TIMEOUT)
        .await?;
    let capsule_names = parse_capsule_names(&list.content);

    let mut tools = Vec::new();
    for name in capsule_names {
        let inspect = daemon
            .call_tool_round_trip(
                "inspect_capsule",
                serde_json::json!({ "name": &name }),
                CATALOG_TIMEOUT,
            )
            .await?;
        tools.extend(parse_tools_from_inspect(&name, &inspect.content));
    }
    Ok(tools)
}

/// Extract capsule names from the JSON array returned by
/// `list_capsules`.
///
/// `ToolCallResult.content` is itself a string; capsules return their
/// payload via `serde_json::to_string_pretty`, then the IPC layer
/// wraps it again. We strip up to two JSON-string layers before
/// expecting an array.
fn parse_capsule_names(content: &str) -> Vec<String> {
    let parsed = match unwrap_json_string_layers(content) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let arr = parsed
        .as_array()
        .or_else(|| parsed.get("capsules").and_then(Value::as_array))
        .cloned()
        .unwrap_or_default();
    arr.into_iter()
        .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Parse `content` as JSON. If the result is a JSON string (i.e. the
/// payload was wrapped one extra time by the IPC layer), parse the
/// inner string and return that. Returns `None` on parse failure.
fn unwrap_json_string_layers(content: &str) -> Option<Value> {
    let mut value: Value = serde_json::from_str(content).ok()?;
    // Unwrap up to two extra layers of string-encoding.
    for _ in 0..2 {
        match value {
            Value::String(inner) => {
                value = serde_json::from_str(&inner).ok()?;
            }
            other => return Some(other),
        }
    }
    Some(value)
}

/// Translate one `inspect_capsule` response into MCP [`Tool`] defs.
///
/// The response is `=== Capsule.toml ===\n<toml>\n\n=== meta.json ===\n<json>`.
/// We isolate the TOML chunk and harvest tool names from the
/// `[subscribe]` table or `[[interceptor]]` array.
fn parse_tools_from_inspect(capsule_name: &str, content: &str) -> Vec<Tool> {
    // inspect_capsule returns a plain-text blob, but the IPC layer
    // wraps it as a JSON-encoded string. Unwrap one layer if needed.
    let text = unwrap_string_layer(content);
    let Some(toml_src) = extract_toml_section(&text) else {
        return Vec::new();
    };
    let parsed: toml::Value = match toml::from_str(&toml_src) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let short = capsule_name
        .strip_prefix(CAPSULE_NAME_PREFIX)
        .unwrap_or(capsule_name);

    let mut tool_names: Vec<String> = Vec::new();

    // Modern manifests: [subscribe] table keyed by topic.
    if let Some(subscribe) = parsed.get("subscribe").and_then(toml::Value::as_table) {
        for topic in subscribe.keys() {
            if let Some(name) = tool_name_from_topic(topic) {
                tool_names.push(name);
            }
        }
    }

    // Legacy manifests: [[interceptor]] array of tables, each with
    // an `event` string.
    if let Some(interceptors) = parsed.get("interceptor").and_then(toml::Value::as_array) {
        for entry in interceptors {
            if let Some(event) = entry.get("event").and_then(toml::Value::as_str) {
                if let Some(name) = tool_name_from_topic(event) {
                    tool_names.push(name);
                }
            }
        }
    }

    tool_names
        .into_iter()
        .map(|raw| make_tool(short, &raw))
        .collect()
}

/// If `content` parses as a JSON string, return the inner string;
/// otherwise return `content` unchanged. This undoes one layer of
/// IPC wrapping where a plain-text capsule response gets
/// JSON-encoded before transit.
fn unwrap_string_layer(content: &str) -> String {
    match serde_json::from_str::<Value>(content) {
        Ok(Value::String(s)) => s,
        _ => content.to_owned(),
    }
}

/// Pull the `<toml>` substring from the inspect_capsule text blob.
/// Returns `None` if the markers aren't present.
fn extract_toml_section(content: &str) -> Option<String> {
    let after_header = content.split_once("=== Capsule.toml ===")?.1;
    let toml_part = match after_header.split_once("=== meta.json ===") {
        Some((before, _)) => before,
        None => after_header,
    };
    Some(toml_part.trim().to_owned())
}

/// Map a subscribe/interceptor topic like `tool.v1.execute.run_shell_command`
/// to its bare tool name (`run_shell_command`). Returns `None` for
/// non-tool topics (e.g. `.result` publishers, `tool.v1.request.describe`).
fn tool_name_from_topic(topic: &str) -> Option<String> {
    let rest = topic.strip_prefix(TOOL_EXECUTE_PREFIX)?;
    // Reject empty, wildcards, or anything that's a result publisher.
    // `react` subscribes to `tool.v1.execute.result` (the bare word
    // "result" — the framework's result topic), so we filter that too,
    // not just `<name>.result` suffixes.
    if rest.is_empty() || rest.contains('*') || rest == "result" || rest.ends_with(TOOL_RESULT_SUFFIX) {
        return None;
    }
    Some(rest.to_owned())
}

/// Construct an `rmcp::Tool` with namespaced name `<short>.<tool>`.
/// Input schema is left as a permissive `{"type": "object"}` until we
/// have a way to fetch real schemas (Task 7+).
fn make_tool(short_capsule: &str, raw_name: &str) -> Tool {
    let mut schema = serde_json::Map::new();
    schema.insert("type".into(), Value::String("object".into()));
    Tool {
        name: Cow::Owned(format!("{short_capsule}.{raw_name}")),
        title: None,
        description: None,
        input_schema: Arc::new(schema),
        output_schema: None,
        annotations: None,
        execution: None,
        icons: None,
        meta: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capsule_names_extracts_from_array() {
        let json = r#"[{"name": "astrid-capsule-shell", "version": "0.1.0"},
                       {"name": "astrid-capsule-system", "version": "0.1.0"}]"#;
        let names = parse_capsule_names(json);
        assert_eq!(names, vec!["astrid-capsule-shell", "astrid-capsule-system"]);
    }

    #[test]
    fn extract_toml_section_handles_full_blob() {
        let blob = "=== Capsule.toml ===\n[package]\nname = \"foo\"\n\n=== meta.json ===\n{}";
        let toml = extract_toml_section(blob).unwrap();
        assert!(toml.contains("[package]"));
        assert!(!toml.contains("meta.json"));
    }

    #[test]
    fn tool_name_from_topic_filters_results_and_wildcards() {
        assert_eq!(
            tool_name_from_topic("tool.v1.execute.run_shell_command"),
            Some("run_shell_command".into())
        );
        assert_eq!(tool_name_from_topic("tool.v1.execute.*.result"), None);
        assert_eq!(tool_name_from_topic("tool.v1.execute.foo.result"), None);
        assert_eq!(tool_name_from_topic("tool.v1.request.describe"), None);
        // capsule-react subscribes to the bare `result` topic — it's the
        // framework's tool-result fanout, not a tool of its own.
        assert_eq!(tool_name_from_topic("tool.v1.execute.result"), None);
    }

    #[test]
    fn unwrap_json_string_layers_handles_double_encoded() {
        // The IPC layer wraps capsule string responses one extra time:
        // capsule returns `"[{...}]"`, transit gives us `"\"[{...}]\""`.
        let double = "\"[{\\\"name\\\": \\\"x\\\"}]\"";
        let v = unwrap_json_string_layers(double).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[test]
    fn unwrap_string_layer_passes_through_plain_text() {
        // `inspect_capsule` returns plain text; if it ever stops being
        // JSON-string-wrapped, we still want it to flow through.
        assert_eq!(unwrap_string_layer("hello"), "hello");
        assert_eq!(unwrap_string_layer("\"hello\""), "hello");
    }

    #[test]
    fn parse_tools_modern_subscribe_table() {
        let blob = r#"=== Capsule.toml ===
[package]
name = "astrid-capsule-shell"

[subscribe]
"tool.v1.execute.run_shell_command" = { handler = "x" }
"tool.v1.execute.kill_process" = { handler = "y" }
"tool.v1.request.describe" = { handler = "z" }

=== meta.json ===
{}"#;
        let tools = parse_tools_from_inspect("astrid-capsule-shell", blob);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.contains(&"shell.run_shell_command"));
        assert!(names.contains(&"shell.kill_process"));
        assert!(!names.iter().any(|n| n.contains("describe")));
    }

    #[test]
    fn parse_tools_legacy_interceptor_array() {
        let blob = r#"=== Capsule.toml ===
[package]
name = "astrid-capsule-system"

[[interceptor]]
event = "tool.v1.execute.list_capsules"
action = "tool_execute_list_capsules"

[[interceptor]]
event = "tool.v1.execute.inspect_capsule"
action = "tool_execute_inspect_capsule"

[[interceptor]]
event = "tool.v1.request.describe"
action = "tool_describe"

=== meta.json ===
{}"#;
        let tools = parse_tools_from_inspect("astrid-capsule-system", blob);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.contains(&"system.list_capsules"));
        assert!(names.contains(&"system.inspect_capsule"));
        assert!(!names.iter().any(|n| n.contains("describe")));
    }
}
