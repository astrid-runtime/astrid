//! Environment variable fallback and `${VAR}` reference resolution.
//!
//! Per D15 semantics: env vars are **fallback**, not override. They are only
//! applied to fields that no config file set.

use std::collections::HashMap;
use std::fmt::Write as _;

use tracing::debug;

use crate::merge::{ConfigLayer, FieldSources};

/// Mapping from environment variable name to config field path.
struct EnvMapping {
    var_name: &'static str,
    field_path: &'static str,
}

/// All supported `ASTRID_*` and legacy `ANTHROPIC_*` env var mappings.
const ENV_MAPPINGS: &[EnvMapping] = &[
    EnvMapping {
        var_name: "ASTRID_MODEL_PROVIDER",
        field_path: "model.provider",
    },
    EnvMapping {
        var_name: "ASTRID_MODEL_API_KEY",
        field_path: "model.api_key",
    },
    EnvMapping {
        var_name: "ASTRID_MODEL_API_URL",
        field_path: "model.api_url",
    },
    EnvMapping {
        var_name: "ASTRID_MODEL",
        field_path: "model.model",
    },
    EnvMapping {
        var_name: "ASTRID_LOG_LEVEL",
        field_path: "logging.level",
    },
    EnvMapping {
        var_name: "ASTRID_BUDGET_SESSION_MAX_USD",
        field_path: "budget.session_max_usd",
    },
    EnvMapping {
        var_name: "ASTRID_BUDGET_PER_ACTION_MAX_USD",
        field_path: "budget.per_action_max_usd",
    },
    EnvMapping {
        var_name: "ASTRID_WORKSPACE_MODE",
        field_path: "workspace.mode",
    },
    // Sub-agent settings.
    EnvMapping {
        var_name: "ASTRID_SUBAGENT_MAX_CONCURRENT",
        field_path: "subagents.max_concurrent",
    },
    EnvMapping {
        var_name: "ASTRID_SUBAGENT_MAX_DEPTH",
        field_path: "subagents.max_depth",
    },
    EnvMapping {
        var_name: "ASTRID_SUBAGENT_TIMEOUT_SECS",
        field_path: "subagents.timeout_secs",
    },
    // Capsule runtime concurrency ceilings.
    EnvMapping {
        var_name: "ASTRID_CAPSULE_HOST_BLOCKING_CONCURRENCY",
        field_path: "capsule.host_blocking_concurrency",
    },
    EnvMapping {
        var_name: "ASTRID_CAPSULE_HOST_IO_CONCURRENCY",
        field_path: "capsule.host_io_concurrency",
    },
    EnvMapping {
        var_name: "ASTRID_CAPSULE_INSTANCE_POOL_SIZE",
        field_path: "capsule.instance_pool_size",
    },
    // Retry settings.
    EnvMapping {
        var_name: "ASTRID_RETRY_LLM_MAX_ATTEMPTS",
        field_path: "retry.llm_max_attempts",
    },
    EnvMapping {
        var_name: "ASTRID_RETRY_MCP_MAX_ATTEMPTS",
        field_path: "retry.mcp_max_attempts",
    },
    // Standard Anthropic SDK env vars.
    EnvMapping {
        var_name: "ANTHROPIC_API_KEY",
        field_path: "model.api_key",
    },
    EnvMapping {
        var_name: "ANTHROPIC_MODEL",
        field_path: "model.model",
    },
    // Z.AI env var.
    EnvMapping {
        var_name: "ZAI_API_KEY",
        field_path: "model.api_key",
    },
    // OpenAI env var.
    EnvMapping {
        var_name: "OPENAI_API_KEY",
        field_path: "model.api_key",
    },
];

/// Apply environment variable fallbacks to fields that were **not** set by
/// any config file layer.
///
/// Returns the number of env vars applied.
pub fn apply_env_fallbacks<S: ::std::hash::BuildHasher>(
    merged: &mut toml::Value,
    sources: &mut FieldSources,
    env_vars: &HashMap<String, String, S>,
) -> usize {
    let mut count: usize = 0;

    for mapping in ENV_MAPPINGS {
        // Only apply if no config file set this field.
        if sources.contains_key(mapping.field_path) {
            continue;
        }

        if let Some(val) = env_vars.get(mapping.var_name) {
            debug!(
                var = mapping.var_name,
                field = mapping.field_path,
                "applying env var fallback"
            );

            set_field_from_string(merged, mapping.field_path, val);
            sources.insert(mapping.field_path.to_owned(), ConfigLayer::Environment);
            count = count.saturating_add(1);
        }
    }

    count
}

/// Resolve `${VAR}` references in the workspace layer, restricted to only
/// `ASTRID_*` and `ANTHROPIC_*` prefixed environment variables.
///
/// This prevents a malicious workspace config from exfiltrating sensitive
/// env vars like `${AWS_SECRET_ACCESS_KEY}` into fields sent to the LLM.
pub fn resolve_env_references_restricted<S: ::std::hash::BuildHasher>(
    val: &mut toml::Value,
    env_vars: &HashMap<String, String, S>,
) {
    let restricted: HashMap<String, String> = env_vars
        .iter()
        .filter(|(k, _)| k.starts_with("ASTRID_") || k.starts_with("ANTHROPIC_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    resolve_env_references(val, &restricted);
}

/// Resolve `${VAR}` references within string values in the config tree.
///
/// Only string values are processed. References that don't resolve are left
/// as-is (with a warning logged).
pub fn resolve_env_references<S: ::std::hash::BuildHasher>(
    val: &mut toml::Value,
    env_vars: &HashMap<String, String, S>,
) {
    match val {
        toml::Value::String(s) => {
            *s = resolve_string_refs(s, env_vars);
        },
        toml::Value::Table(table) => {
            let keys: Vec<String> = table.keys().cloned().collect();
            for key in keys {
                if let Some(child) = table.get_mut(&key) {
                    resolve_env_references(child, env_vars);
                }
            }
        },
        toml::Value::Array(arr) => {
            for child in arr.iter_mut() {
                resolve_env_references(child, env_vars);
            }
        },
        _ => {},
    }
}

/// Replace `${VAR}` references in a string with their env var values.
fn resolve_string_refs<S: ::std::hash::BuildHasher>(
    input: &str,
    env_vars: &HashMap<String, String, S>,
) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut closed = false;

            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                var_name.push(ch);
            }

            if closed && !var_name.is_empty() {
                if let Some(val) = env_vars.get(&var_name) {
                    result.push_str(val);
                } else {
                    debug!(var = var_name, "unresolved env var reference in config");
                    // Leave the reference as-is.
                    let _ = write!(result, "${{{var_name}}}");
                }
            } else {
                // Malformed reference, leave as-is.
                result.push('$');
                result.push('{');
                result.push_str(&var_name);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Set a field in the TOML tree from a string value. Handles type coercion
/// for known numeric and boolean fields.
fn set_field_from_string(root: &mut toml::Value, path: &str, val: &str) {
    let segments: Vec<&str> = path.split('.').collect();

    // Determine the toml::Value to insert based on the field type.
    let toml_val = coerce_to_toml_value(path, val);

    // Navigate to the parent and insert.
    let mut current = root;
    // Safety: segments is non-empty (path contains at least one segment)
    #[expect(clippy::arithmetic_side_effects)]
    let parent_segments = &segments[..segments.len() - 1];
    for segment in parent_segments {
        if !current.as_table().is_some_and(|t| t.contains_key(*segment)) {
            // Create intermediate table.
            if let Some(table) = current.as_table_mut() {
                table.insert(
                    (*segment).to_owned(),
                    toml::Value::Table(toml::map::Map::new()),
                );
            }
        }
        current = current
            .as_table_mut()
            .and_then(|t| t.get_mut(*segment))
            .expect("just created intermediate table");
    }

    if let Some(table) = current.as_table_mut() {
        // Safety: segments is non-empty (path contains at least one segment)
        #[expect(clippy::arithmetic_side_effects)]
        let leaf = segments[segments.len() - 1];
        table.insert(leaf.to_owned(), toml_val);
    }
}

/// Attempt to coerce a string env var value to the appropriate TOML type
/// based on the field path.
fn coerce_to_toml_value(path: &str, val: &str) -> toml::Value {
    // Known float fields.
    if matches!(
        path,
        "budget.session_max_usd"
            | "budget.per_action_max_usd"
            | "model.pricing.input_per_million"
            | "model.pricing.output_per_million"
            | "model.temperature"
    ) && let Ok(f) = val.parse::<f64>()
    {
        return toml::Value::Float(f);
    }

    // Known integer fields.
    if matches!(
        path,
        "model.max_tokens"
            | "security.approval_timeout_secs"
            | "security.policy.max_argument_size"
            | "budget.warn_at_percent"
            | "rate_limits.elicitation_per_server_per_min"
            | "rate_limits.max_pending_requests"
            | "subagents.max_concurrent"
            | "subagents.max_depth"
            | "subagents.timeout_secs"
            | "capsule.host_blocking_concurrency"
            | "capsule.host_io_concurrency"
            | "capsule.instance_pool_size"
            | "retry.llm_max_attempts"
            | "retry.mcp_max_attempts"
    ) && let Ok(i) = val.parse::<i64>()
    {
        return toml::Value::Integer(i);
    }

    // Known boolean fields.
    if matches!(
        path,
        "security.require_signatures"
            | "security.policy.require_approval_for_delete"
            | "security.policy.require_approval_for_network"
    ) && let Ok(b) = val.parse::<bool>()
    {
        return toml::Value::Boolean(b);
    }

    // Default: string.
    toml::Value::String(val.to_owned())
}

/// Collect all current environment variables into a map.
#[must_use]
pub fn collect_env_vars() -> HashMap<String, String> {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn test_apply_env_fallbacks() {
        let mut merged: toml::Value = toml::from_str("[model]\nprovider = \"claude\"").unwrap();
        let mut sources = FieldSources::new();
        let env = make_env(&[("ASTRID_LOG_LEVEL", "debug")]);

        let count = apply_env_fallbacks(&mut merged, &mut sources, &env);

        assert_eq!(count, 1);
        assert_eq!(merged["logging"]["level"].as_str().unwrap(), "debug");
        assert_eq!(
            sources.get("logging.level"),
            Some(&ConfigLayer::Environment)
        );
    }

    #[test]
    fn test_env_fallback_skips_already_set() {
        let mut merged: toml::Value = toml::from_str("[logging]\nlevel = \"warn\"").unwrap();
        let mut sources = FieldSources::new();
        sources.insert("logging.level".to_owned(), ConfigLayer::User);

        let env = make_env(&[("ASTRID_LOG_LEVEL", "debug")]);
        let count = apply_env_fallbacks(&mut merged, &mut sources, &env);

        assert_eq!(count, 0);
        // Value unchanged.
        assert_eq!(merged["logging"]["level"].as_str().unwrap(), "warn");
    }

    #[test]
    fn test_resolve_env_references() {
        let mut val: toml::Value =
            toml::from_str(r#"[model]\napi_key = "${MY_API_KEY}""#.replace(r"\n", "\n").as_str())
                .unwrap();
        let env = make_env(&[("MY_API_KEY", "sk-secret-123")]);
        resolve_env_references(&mut val, &env);

        assert_eq!(val["model"]["api_key"].as_str().unwrap(), "sk-secret-123");
    }

    #[test]
    fn test_resolve_env_references_unresolved() {
        let mut val: toml::Value =
            toml::from_str(r#"[model]\napi_key = "${MISSING_VAR}""#.replace(r"\n", "\n").as_str())
                .unwrap();
        let env = HashMap::new();
        resolve_env_references(&mut val, &env);

        // Unresolved references left as-is.
        assert_eq!(val["model"]["api_key"].as_str().unwrap(), "${MISSING_VAR}");
    }

    #[test]
    fn test_coerce_float() {
        let v = coerce_to_toml_value("budget.session_max_usd", "50.0");
        assert!((v.as_float().unwrap() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coerce_integer() {
        let v = coerce_to_toml_value("model.max_tokens", "8192");
        assert_eq!(v.as_integer().unwrap(), 8192);
    }

    #[test]
    fn test_coerce_bool() {
        let v = coerce_to_toml_value("security.require_signatures", "true");
        assert!(v.as_bool().unwrap());
    }

    #[test]
    fn test_coerce_string_default() {
        let v = coerce_to_toml_value("model.provider", "openai");
        assert_eq!(v.as_str().unwrap(), "openai");
    }

    #[test]
    fn test_legacy_anthropic_api_key() {
        let mut merged: toml::Value = toml::from_str("[model]").unwrap();
        let mut sources = FieldSources::new();
        let env = make_env(&[("ANTHROPIC_API_KEY", "sk-ant-test")]);

        apply_env_fallbacks(&mut merged, &mut sources, &env);

        assert_eq!(merged["model"]["api_key"].as_str().unwrap(), "sk-ant-test");
    }

    // ---- Restricted ${VAR} resolution tests ----

    #[test]
    fn test_workspace_cannot_access_arbitrary_env_var() {
        let mut val: toml::Value = toml::from_str(
            r#"[model]
description = "${HOME}""#,
        )
        .unwrap();
        let env = make_env(&[("HOME", "/home/user")]);
        resolve_env_references_restricted(&mut val, &env);

        // Should NOT resolve — ${HOME} stays literal.
        assert_eq!(val["model"]["description"].as_str().unwrap(), "${HOME}");
    }

    #[test]
    fn test_workspace_can_access_astrid_var() {
        let mut val: toml::Value = toml::from_str(
            r#"[model]
model = "${ASTRID_MODEL}""#,
        )
        .unwrap();
        let env = make_env(&[("ASTRID_MODEL", "claude-opus-4-6")]);
        resolve_env_references_restricted(&mut val, &env);

        assert_eq!(val["model"]["model"].as_str().unwrap(), "claude-opus-4-6");
    }

    #[test]
    fn test_workspace_can_access_anthropic_var() {
        let mut val: toml::Value = toml::from_str(
            r#"[model]
api_key = "${ANTHROPIC_API_KEY}""#,
        )
        .unwrap();
        let env = make_env(&[("ANTHROPIC_API_KEY", "sk-ant-test")]);
        resolve_env_references_restricted(&mut val, &env);

        assert_eq!(val["model"]["api_key"].as_str().unwrap(), "sk-ant-test");
    }
}
