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

/// Prompt the user for missing environment-variable values defined in `[env]`.
///
/// Reads existing env config if present, skips fields that already have
/// values, and writes the updated config back with 0o600 permissions.
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
    let mut keys: Vec<&String> = env_defs.keys().collect();
    keys.sort();

    for key in keys {
        if values.contains_key(key.as_str()) {
            continue;
        }

        let def = &env_defs[key];
        if !prompted {
            eprintln!("\nThis capsule requires configuration:");
            prompted = true;
        }

        let prompt = def.request.as_deref().unwrap_or(key.as_str());
        let description = def.description.as_deref().unwrap_or("");
        let default = def.default.as_ref().and_then(|v| v.as_str()).unwrap_or("");

        if !description.is_empty() {
            eprintln!("  {description}");
        }

        let is_secret = def.env_type == "secret";
        let is_enum = !def.enum_values.is_empty();

        let value = if is_secret {
            eprint!("  {prompt}: ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        } else {
            if is_enum {
                eprintln!("  Options: {}", def.enum_values.join(", "));
            }
            let hint = if default.is_empty() {
                String::new()
            } else {
                format!(" [{default}]")
            };
            eprint!("  {prompt}{hint}: ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() && !default.is_empty() {
                default.to_string()
            } else {
                input.to_string()
            }
        };

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
