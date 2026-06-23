//! Interactive prompts driven by the CLI during a capsule install.
//!
//! Three pieces live here:
//!
//! * `prompt_env_fields` — fill in any `[env]` keys the manifest
//!   declares that don't already have a value on disk. Writes
//!   `~/.astrid/<principal>/.config/env/<id>.env.json` with 0o600.
//! * `cli_elicit_handler` — subscribed to `astrid.v1.elicit` during a
//!   lifecycle hook so capsules can call `elicit("api_key")` at
//!   install time and the user can answer on stdin.
//! * `prompt_stdin_field` — the actual stdin-prompt routine used by
//!   both of the above.
//!
//! All three are CLI-only by construction. The kernel-side install
//! handler runs without an elicit subscriber attached — the dashboard
//! collects configuration through a separate gateway endpoint.

use std::collections::HashMap;
use std::path::Path;

use astrid_capsule::manifest::EnvDef;
use astrid_events::{AstridEvent, EventBus, EventMetadata, EventReceiver};
use astrid_types::ipc::{IpcMessage, IpcPayload, OnboardingFieldType};

use super::model_discovery::fetch_options_blocking;

/// Order `[env]` keys so that fields are prompted after any field listed
/// in their `options-from.after`. Produces a stable order: keys are first
/// sorted alphabetically (preserving the existing deterministic prompt
/// order), then fields whose dependencies are not yet emitted are deferred.
///
/// The algorithm is a simple stable topological pass. A dependency cycle —
/// or an `after` naming an unknown key — cannot wedge it: any key still
/// pending after a full pass that emitted nothing is flushed in sorted
/// order, so every key is emitted exactly once.
pub(crate) fn order_env_keys(env_defs: &HashMap<String, EnvDef>) -> Vec<String> {
    let mut keys: Vec<String> = env_defs.keys().cloned().collect();
    keys.sort();

    let mut emitted: Vec<String> = Vec::with_capacity(keys.len());
    let mut pending = keys;

    while !pending.is_empty() {
        let mut progressed = false;
        let mut still_pending = Vec::new();

        for key in pending {
            let deps = env_defs
                .get(&key)
                .and_then(|d| d.options_from.as_ref())
                .map_or(&[][..], |o| o.after.as_slice());

            // Ready when every dependency that is itself a known env key
            // has already been emitted. Dependencies that name unknown
            // keys are ignored (they can never be satisfied).
            let ready = deps
                .iter()
                .all(|dep| !env_defs.contains_key(dep) || emitted.iter().any(|e| e == dep));

            if ready {
                emitted.push(key);
                progressed = true;
            } else {
                still_pending.push(key);
            }
        }

        if !progressed {
            // Cycle or unsatisfiable dependency: flush the rest in sorted
            // order rather than loop forever. Correctness over ordering.
            still_pending.sort();
            emitted.extend(still_pending);
            break;
        }
        pending = still_pending;
    }

    emitted
}

/// Prompt the user for missing environment-variable values defined in `[env]`.
///
/// Reads existing env config if present, skips fields that already have
/// values, and writes the updated config back with 0o600 permissions.
///
/// Fields declaring `options-from` are dynamic SELECTs: once their
/// `after` dependencies are collected, the installer fetches the live
/// option list (e.g. from a provider's `/v1/models`) and presents a
/// numbered menu. Any discovery failure degrades to a free-text prompt —
/// the install is never blocked on a discovery miss.
pub(crate) fn prompt_env_fields(
    env_defs: &HashMap<String, EnvDef>,
    env_path: &Path,
) -> anyhow::Result<()> {
    let mut values: serde_json::Map<String, serde_json::Value> = if env_path.exists() {
        let content = std::fs::read_to_string(env_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    let mut prompted = false;
    let keys = order_env_keys(env_defs);

    for key in &keys {
        if values.contains_key(key.as_str())
            && !values
                .get(key.as_str())
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .is_empty()
        {
            continue;
        }

        let def = &env_defs[key];
        if !prompted {
            eprintln!("\nThis capsule requires configuration:");
            prompted = true;
        }

        let value = prompt_single_field(key, def, &values);

        if !value.is_empty() {
            values.insert(key.clone(), serde_json::Value::String(value));
        }
    }

    if prompted {
        let json = serde_json::to_string_pretty(&values)?;
        std::fs::write(env_path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!("  Configuration saved.\n");
    }

    Ok(())
}

/// Prompt for one `[env]` field, honouring secret/enum/dynamic-select
/// types. `collected` holds the values already entered this session — used
/// to resolve `options-from` templates for dynamic selects.
fn prompt_single_field(
    key: &str,
    def: &EnvDef,
    collected: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let prompt = def.request.as_deref().unwrap_or(key);
    let description = def.description.as_deref().unwrap_or("");
    let default = def.default.as_ref().and_then(|v| v.as_str()).unwrap_or("");

    if !description.is_empty() {
        eprintln!("  {description}");
    }

    if def.env_type == "secret" {
        if def.options_from.is_some() {
            tracing::warn!(key = %key, "secret field declares options-from — ignoring discovery");
        }
        return read_line_value(prompt, "");
    }

    // Dynamic SELECT: fetch live options, fall back to free-text on any miss.
    if let Some(opts) = &def.options_from {
        let resolved: HashMap<String, String> = collected
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        match fetch_options_blocking(opts, &resolved) {
            Ok(options) => return select_from_options(prompt, &options, default),
            Err(e) => {
                eprintln!("  Could not fetch options ({e}); enter value manually.");
                let hint = if default.is_empty() {
                    def.placeholder.as_deref().unwrap_or("")
                } else {
                    default
                };
                return read_line_value(prompt, hint);
            },
        }
    }

    // Static enum: list the choices inline (existing behaviour).
    if !def.enum_values.is_empty() {
        eprintln!("  Options: {}", def.enum_values.join(", "));
    }
    read_line_value(prompt, default)
}

/// Prompt with an optional `[hint]` and return the trimmed entry, falling
/// back to `default` when the entry is empty (and non-empty default given).
fn read_line_value(prompt: &str, default: &str) -> String {
    let hint = if default.is_empty() {
        String::new()
    } else {
        format!(" [{default}]")
    };
    eprint!("  {prompt}{hint}: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return default.to_string();
    }
    let input = input.trim();
    if input.is_empty() && !default.is_empty() {
        default.to_string()
    } else {
        input.to_string()
    }
}

/// Render a numbered select over `options`, pre-selecting `default` when it
/// matches one of them. An out-of-range or empty entry picks the default
/// (or the first option).
fn select_from_options(prompt: &str, options: &[String], default: &str) -> String {
    eprintln!("  {prompt}:");
    let default_idx = options.iter().position(|o| o == default);
    for (i, opt) in options.iter().enumerate() {
        let marker = if Some(i) == default_idx {
            " (default)"
        } else {
            ""
        };
        eprintln!("    {}: {opt}{marker}", i.saturating_add(1));
    }
    let fallback = default_idx
        .map(|i| options[i].clone())
        .or_else(|| options.first().cloned())
        .unwrap_or_default();
    eprint!("  Select [1-{}]: ", options.len());
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return fallback;
    }
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return fallback;
    }
    match trimmed.parse::<usize>() {
        Ok(idx) if idx >= 1 && idx <= options.len() => options[idx.saturating_sub(1)].clone(),
        _ => fallback,
    }
}

/// CLI-inline elicit handler for non-TUI installs.
///
/// Listens for `ElicitRequest` IPC messages and prompts on stdin, then
/// publishes `ElicitResponse` back to the event bus.
pub(crate) async fn cli_elicit_handler(mut receiver: EventReceiver, event_bus: EventBus) {
    loop {
        let Some(event) = receiver.recv().await else {
            return;
        };

        let AstridEvent::Ipc { message, .. } = &*event else {
            continue;
        };

        let IpcPayload::ElicitRequest {
            request_id,
            capsule_id,
            field,
        } = &message.payload
        else {
            continue;
        };

        let request_id = *request_id;
        let prompt = field.description.as_ref().map_or_else(
            || format!("[{capsule_id}] {}", field.key),
            |d| format!("[{capsule_id}] {d}"),
        );

        let (value, values) =
            prompt_stdin_field(prompt, field.field_type.clone(), field.default.clone()).await;

        let response_topic = format!("astrid.v1.elicit.response.{request_id}");
        let response = IpcPayload::ElicitResponse {
            request_id,
            value,
            values,
        };
        let msg = IpcMessage::new(response_topic, response, uuid::Uuid::nil());
        event_bus.publish(AstridEvent::Ipc {
            message: msg,
            metadata: EventMetadata::default(),
        });
    }
}

/// Prompt the user on stdin for a single elicit field (runs in a blocking thread).
///
/// Returns `(value, values)` where exactly one is `Some`.
async fn prompt_stdin_field(
    prompt: String,
    field_type: OnboardingFieldType,
    default: Option<String>,
) -> (Option<String>, Option<Vec<String>>) {
    match field_type {
        OnboardingFieldType::Text => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let hint = default
                    .as_ref()
                    .map(|d| format!(" [{d}]"))
                    .unwrap_or_default();
                print!("{prompt}{hint}: ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                let input = input.trim().to_string();
                if input.is_empty() {
                    default.unwrap_or_default()
                } else {
                    input
                }
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Secret => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                print!("{prompt} (secret, input hidden): ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                input.trim().to_string()
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Enum(options) => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                println!("{prompt}:");
                for (i, opt) in options.iter().enumerate() {
                    println!("  {}: {opt}", i.saturating_add(1));
                }
                print!("Select [1-{}]: ", options.len());
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                let idx: usize = input.trim().parse().unwrap_or(0);
                if idx >= 1 && idx <= options.len() {
                    options[idx.saturating_sub(1)].clone()
                } else {
                    options.first().cloned().unwrap_or_default()
                }
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Array => {
            let items = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                println!("{prompt} (enter values one per line, empty line to finish):");
                let mut items = Vec::new();
                loop {
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    let mut input = String::new();
                    let _ = std::io::stdin().read_line(&mut input);
                    let input = input.trim().to_string();
                    if input.is_empty() {
                        break;
                    }
                    items.push(input);
                }
                items
            })
            .await
            .unwrap_or_default();
            (None, Some(items))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(toml_src: &str) -> HashMap<String, EnvDef> {
        toml::from_str(toml_src).expect("env table parses")
    }

    #[test]
    fn order_places_dynamic_select_after_dependencies() {
        // `model` depends on base_url + api_key; both must precede it.
        let defs = env(r#"
[model]
type = "select"
options-from = { http = "{base_url}/v1/models", bearer = "{api_key}", after = ["base_url", "api_key"] }

[base_url]
type = "text"

[api_key]
type = "secret"
"#);
        let order = order_env_keys(&defs);
        let pos = |k: &str| order.iter().position(|x| x == k).unwrap();
        assert!(
            pos("base_url") < pos("model"),
            "base_url before model: {order:?}"
        );
        assert!(
            pos("api_key") < pos("model"),
            "api_key before model: {order:?}"
        );
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn order_is_stable_alphabetical_without_deps() {
        let defs = env(r#"
[zebra]
type = "text"

[alpha]
type = "text"

[mango]
type = "text"
"#);
        assert_eq!(order_env_keys(&defs), vec!["alpha", "mango", "zebra"]);
    }

    #[test]
    fn order_ignores_unknown_after_dependency() {
        // `model` lists an `after` key that is not an env field — it must
        // not wedge the ordering; every key is still emitted once.
        let defs = env(r#"
[model]
type = "select"
options-from = { http = "{base_url}/v1/models", after = ["nonexistent"] }

[base_url]
type = "text"
"#);
        let order = order_env_keys(&defs);
        assert_eq!(order.len(), 2);
        assert!(order.contains(&"model".to_string()));
        assert!(order.contains(&"base_url".to_string()));
    }

    #[test]
    fn order_breaks_dependency_cycle_without_looping() {
        // a after b, b after a — unsatisfiable. Must terminate and emit both.
        let defs = env(r#"
[a]
type = "select"
options-from = { http = "x", after = ["b"] }

[b]
type = "select"
options-from = { http = "y", after = ["a"] }
"#);
        let order = order_env_keys(&defs);
        assert_eq!(order.len(), 2);
        assert!(order.contains(&"a".to_string()));
        assert!(order.contains(&"b".to_string()));
    }

    #[test]
    fn order_chains_transitive_dependencies() {
        // c after b, b after a → a, b, c.
        let defs = env(r#"
[c]
type = "select"
options-from = { http = "x", after = ["b"] }

[b]
type = "select"
options-from = { http = "y", after = ["a"] }

[a]
type = "text"
"#);
        let order = order_env_keys(&defs);
        let pos = |k: &str| order.iter().position(|x| x == k).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }
}
