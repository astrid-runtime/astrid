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
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_events::{AstridEvent, EventBus, EventMetadata, EventReceiver};
use astrid_storage::{FileSecretStore, SecretStore};
use astrid_types::Topic;
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
    capsule_id: &str,
    config_path: &Path,
    home: &AstridHome,
    principal: &PrincipalId,
) -> anyhow::Result<()> {
    let mut values: serde_json::Map<String, serde_json::Value> = if env_path.exists() {
        let content = std::fs::read_to_string(env_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    let secret_store =
        FileSecretStore::new(home.secrets_dir().join(principal.as_str()).join(capsule_id));
    let mut prompted = false;
    let mut changed = false;
    let keys = order_env_keys(env_defs);

    for key in &keys {
        let def = &env_defs[key];
        if def.env_type == "secret" {
            if secret_store.exists(key)? {
                if values.get(key).and_then(serde_json::Value::as_str) != Some("") {
                    values.insert(key.clone(), serde_json::Value::String(String::new()));
                    changed = true;
                }
                continue;
            }
            if let Some(legacy) = values
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
            {
                secret_store.set(key, &legacy)?;
                values.insert(key.clone(), serde_json::Value::String(String::new()));
                changed = true;
                continue;
            }
        }
        if !should_prompt_for_key(&values, key) {
            continue;
        }

        if !prompted {
            eprintln!("\nThis capsule requires configuration:");
            prompted = true;
        }

        let value = prompt_single_field(key, def, &values);

        if def.env_type == "secret" {
            if !value.is_empty() {
                secret_store.set(key, &value)?;
            }
            values.insert(key.clone(), serde_json::Value::String(String::new()));
            changed = true;
        } else if !value.is_empty() {
            // Guided pre-bless: if the operator just entered a provider endpoint
            // pointing at a local/private address (e.g. an LM Studio / Ollama
            // base_url), offer to add the SSRF-airlock exemption so the capsule
            // can actually reach it. The operator is unambiguously local here
            // (this runs in the CLI process), so a plain stdin prompt is safe —
            // this is NOT the daemon's runtime elicitation. A non-local /
            // free-text value is a silent no-op.
            super::local_egress::maybe_prompt_local_egress(capsule_id, &value, config_path);
            values.insert(key.clone(), serde_json::Value::String(value));
            changed = true;
        }
    }

    if changed {
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&values)?;
        std::fs::write(env_path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600))?;
        }
        if prompted {
            eprintln!("  Configuration saved.\n");
        }
    }

    Ok(())
}

/// Persist manifest configuration supplied to `capsule install --yes` without
/// reading stdin. Existing values are preserved unless the operator explicitly
/// supplies a replacement. Secret values go directly to the principal-scoped
/// secret store; the env JSON records only an empty configured marker.
pub(crate) fn write_headless_env_fields(
    env_defs: &HashMap<String, EnvDef>,
    env_path: &Path,
    capsule_id: &str,
    home: &AstridHome,
    principal: &PrincipalId,
    vars: &HashMap<String, String>,
) -> anyhow::Result<()> {
    for key in vars.keys() {
        if !env_defs.contains_key(key) {
            anyhow::bail!("--var names no [env] field in {capsule_id}: {key}");
        }
    }

    let mut values: serde_json::Map<String, serde_json::Value> = if env_path.exists() {
        let content = std::fs::read_to_string(env_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    let secret_store =
        FileSecretStore::new(home.secrets_dir().join(principal.as_str()).join(capsule_id));

    for key in order_env_keys(env_defs) {
        let def = &env_defs[&key];
        let env_key = headless_env_key(&key);
        let supplied = vars
            .get(&key)
            .cloned()
            .or_else(|| std::env::var(&env_key).ok());
        let existing = if def.env_type == "secret" {
            secret_store.exists(&key)?
        } else {
            values.contains_key(&key)
        };
        if supplied.is_none() && existing {
            continue;
        }
        let resolved = supplied
            .or_else(|| def.default.as_ref().map(json_value_string))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "required value is missing for {capsule_id}.{key} \
                     (use --var {key}=… or set {env_key})"
                )
            })?;

        if !def.enum_values.is_empty() && !def.enum_values.iter().any(|item| item == &resolved) {
            anyhow::bail!(
                "invalid value for {capsule_id}.{key}: expected one of {}, got {resolved:?}",
                def.enum_values.join(", ")
            );
        }

        if def.env_type == "secret" {
            if resolved.is_empty() {
                let _ = secret_store.delete(&key)?;
            } else {
                secret_store.set(&key, &resolved)?;
            }
            values.insert(key, serde_json::Value::String(String::new()));
        } else {
            values.insert(key, serde_json::Value::String(resolved));
        }
    }

    if !env_defs.is_empty() {
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&values)?;
        std::fs::write(env_path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn headless_env_key(key: &str) -> String {
    format!(
        "ASTRID_VAR_{}",
        key.chars()
            .map(|ch| if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    )
}

fn json_value_string(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

/// Decide whether to prompt the user for `key`, given the env values already
/// on disk.
///
/// We prompt **only** when the key is absent (UNSET). A key that is already
/// present is skipped even when its value is the empty string:
/// `write_env_files` deliberately writes an empty string to mean "use the
/// capsule's built-in default" for fields the distro pre-configured, so
/// re-prompting for a present-but-empty field would nag the user for a
/// blank-as-default value they never had to supply. Distinguishing UNSET
/// (absent → prompt) from EXPLICITLY-EMPTY (present `""` → skip) preserves
/// that contract.
fn should_prompt_for_key(values: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    !values.contains_key(key)
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
        // The host waiter authorizes the reply against the principal it stamped
        // on the request — echo it back so the same-principal check accepts our
        // answer (a missing principal would be rejected as a cross-principal
        // reply and the install would hang out the elicit timeout).
        let request_principal = message.principal.clone();
        let prompt = field.description.as_ref().map_or_else(
            || format!("[{capsule_id}] {}", field.key),
            |d| format!("[{capsule_id}] {d}"),
        );

        let (value, values) =
            prompt_stdin_field(prompt, field.field_type.clone(), field.default.clone()).await;

        let msg =
            build_elicit_response_msg(request_id, request_principal.as_deref(), value, values);
        event_bus.publish(AstridEvent::Ipc {
            message: msg,
            metadata: EventMetadata::default(),
        });
    }
}

/// Non-interactive install responder used by `capsule install --yes`.
///
/// Values resolve in the same order as distro initialization: an explicit
/// `--var KEY=VALUE`, `ASTRID_VAR_<KEY>`, then the manifest default. A field
/// with no source is recorded as an error instead of silently accepting the
/// first enum choice or an empty secret. The response is still published so a
/// lifecycle hook cannot remain blocked; the install command reports the
/// accumulated errors before it can claim success.
pub(crate) async fn headless_elicit_handler(
    mut receiver: EventReceiver,
    event_bus: EventBus,
    vars: HashMap<String, String>,
    errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
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

        let resolved = resolve_headless_field(
            &field.key,
            &field.field_type,
            field.default.as_deref(),
            &vars,
        );
        let (value, values) = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                if let Ok(mut guard) = errors.lock() {
                    guard.push(format!("{capsule_id}.{}: {error}", field.key));
                }
                (None, None)
            },
        };

        let response =
            build_elicit_response_msg(*request_id, message.principal.as_deref(), value, values);
        event_bus.publish(AstridEvent::Ipc {
            message: response,
            metadata: EventMetadata::default(),
        });
    }
}

fn resolve_headless_field(
    key: &str,
    field_type: &OnboardingFieldType,
    default: Option<&str>,
    vars: &HashMap<String, String>,
) -> Result<(Option<String>, Option<Vec<String>>), String> {
    let env_key = format!(
        "ASTRID_VAR_{}",
        key.chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() {
                    ch.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
    );
    let resolved = vars
        .get(key)
        .cloned()
        .or_else(|| std::env::var(&env_key).ok())
        .or_else(|| default.map(str::to_string))
        .ok_or_else(|| format!("required value is missing (use --var {key}=… or set {env_key})"))?;

    match field_type {
        OnboardingFieldType::Enum(options) => {
            if !options.iter().any(|option| option == &resolved) {
                return Err(format!(
                    "value is not one of the declared options: {}",
                    options.join(", ")
                ));
            }
            Ok((Some(resolved), None))
        },
        OnboardingFieldType::Array => Ok((
            None,
            Some(
                resolved
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect(),
            ),
        )),
        OnboardingFieldType::Text | OnboardingFieldType::Secret => Ok((Some(resolved), None)),
    }
}

/// Build the `ElicitResponse` IPC message for the in-process install answerer,
/// echoing the originating `request_principal` so the host waiter's
/// same-principal check accepts it.
///
/// Extracted as a pure function so the principal-echo invariant is testable
/// without driving the stdin-blocking [`cli_elicit_handler`] loop. A `None`
/// principal yields an unstamped message — which the host now rejects — so the
/// echo here is load-bearing for the in-process lifecycle-install flow.
fn build_elicit_response_msg(
    request_id: uuid::Uuid,
    request_principal: Option<&str>,
    value: Option<String>,
    values: Option<Vec<String>>,
) -> IpcMessage {
    let response = IpcPayload::ElicitResponse {
        request_id,
        value,
        values,
    };
    let mut msg = IpcMessage::new(
        Topic::elicit_response(request_id),
        response,
        uuid::Uuid::nil(),
    );
    if let Some(p) = request_principal {
        msg = msg.with_principal(p);
    }
    msg
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
    fn headless_value_prefers_explicit_input_and_validates_enums() {
        let mut vars = HashMap::new();
        vars.insert("auth_mode".to_string(), "subscription".to_string());
        let options =
            OnboardingFieldType::Enum(vec!["api_key".to_string(), "subscription".to_string()]);
        assert_eq!(
            resolve_headless_field("auth_mode", &options, Some("api_key"), &vars),
            Ok((Some("subscription".to_string()), None))
        );

        vars.insert("auth_mode".to_string(), "invalid".to_string());
        assert!(resolve_headless_field("auth_mode", &options, Some("api_key"), &vars).is_err());
    }

    #[test]
    fn headless_value_uses_manifest_default_without_guessing() {
        let vars = HashMap::new();
        assert_eq!(
            resolve_headless_field(
                "interaction_mode",
                &OnboardingFieldType::Text,
                Some("headless"),
                &vars,
            ),
            Ok((Some("headless".to_string()), None))
        );
        assert!(
            resolve_headless_field(
                "release_required_value_8c3f",
                &OnboardingFieldType::Secret,
                None,
                &vars,
            )
            .is_err()
        );
    }

    #[test]
    fn headless_array_uses_comma_separated_values() {
        let mut vars = HashMap::new();
        vars.insert("tags".to_string(), "one, two,,three".to_string());
        assert_eq!(
            resolve_headless_field("tags", &OnboardingFieldType::Array, None, &vars),
            Ok((
                None,
                Some(vec![
                    "one".to_string(),
                    "two".to_string(),
                    "three".to_string()
                ])
            ))
        );
    }

    #[test]
    fn explicitly_empty_value_is_not_reprompted() {
        // Regression for the blank-as-default nag: `write_env_files` writes an
        // empty string to mean "use the capsule default". A present-but-empty
        // field must be SKIPPED (not re-prompted), while a genuinely absent
        // field still prompts.
        let mut values = serde_json::Map::new();
        values.insert(
            "model".to_string(),
            serde_json::Value::String(String::new()),
        );
        values.insert(
            "base_url".to_string(),
            serde_json::Value::String("https://h".to_string()),
        );

        // Present-but-empty → skip.
        assert!(!should_prompt_for_key(&values, "model"));
        // Present-and-non-empty → skip.
        assert!(!should_prompt_for_key(&values, "base_url"));
        // Absent (UNSET) → prompt.
        assert!(should_prompt_for_key(&values, "api_key"));
    }

    #[test]
    fn fully_preconfigured_env_file_is_left_untouched() {
        // End-to-end: an env file whose keys are all present (one of them
        // explicitly empty) must not trigger any prompt — so `prompt_env_fields`
        // returns Ok without reading stdin and without rewriting the file.
        let defs = env(r#"
[model]
type = "text"

[base_url]
type = "text"
"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let env_path = dir.path().join("cap.env.json");
        // `model` explicitly empty (blank-as-default), `base_url` populated.
        std::fs::write(&env_path, r#"{"model":"","base_url":"https://h"}"#).expect("write");

        let config_path = dir.path().join("config.toml");
        let home = AstridHome::from_path(dir.path());
        prompt_env_fields(
            &defs,
            &env_path,
            "cap",
            &config_path,
            &home,
            &PrincipalId::default(),
        )
        .expect("no prompt → Ok");

        // Untouched: still exactly what we wrote (the function only rewrites
        // when it actually prompted).
        let after = std::fs::read_to_string(&env_path).expect("read");
        assert_eq!(after, r#"{"model":"","base_url":"https://h"}"#);
    }

    #[test]
    fn headless_env_persists_modes_and_keeps_secret_out_of_json() {
        let defs = env(r#"
[interaction_mode]
type = "select"
enum_values = ["headless", "repl"]
default = "headless"

[auth_mode]
type = "select"
enum_values = ["api_key", "subscription"]
default = "api_key"

[api_key]
type = "secret"
"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::new("claude-code").expect("principal");
        let env_path = home
            .principal_home(&principal)
            .env_dir()
            .join("claude-runner.env.json");
        let vars = HashMap::from([
            ("auth_mode".to_string(), "api_key".to_string()),
            ("api_key".to_string(), "top-secret".to_string()),
        ]);

        write_headless_env_fields(&defs, &env_path, "claude-runner", &home, &principal, &vars)
            .expect("headless config");

        let raw = std::fs::read_to_string(&env_path).expect("env json");
        assert!(!raw.contains("top-secret"));
        let values: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(values["interaction_mode"], "headless");
        assert_eq!(values["auth_mode"], "api_key");
        assert_eq!(values["api_key"], "");
        let secrets = FileSecretStore::new(
            home.secrets_dir()
                .join(principal.as_str())
                .join("claude-runner"),
        );
        assert_eq!(
            secrets.get("api_key").expect("secret read").as_deref(),
            Some("top-secret")
        );
    }

    #[test]
    fn headless_env_requires_missing_secret_and_rejects_unknown_var() {
        let defs = env(r#"
[api_key]
type = "secret"
"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::default();
        let env_path = dir.path().join("cap.env.json");

        let missing =
            write_headless_env_fields(&defs, &env_path, "cap", &home, &principal, &HashMap::new())
                .expect_err("missing secret must fail");
        assert!(missing.to_string().contains("required value is missing"));

        let unknown = write_headless_env_fields(
            &defs,
            &env_path,
            "cap",
            &home,
            &principal,
            &HashMap::from([("typo".to_string(), "value".to_string())]),
        )
        .expect_err("unknown --var must fail");
        assert!(unknown.to_string().contains("names no [env] field"));
    }

    #[test]
    fn headless_env_does_not_treat_an_empty_json_marker_as_a_stored_secret() {
        let defs = env(r#"
[api_key]
type = "secret"
"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::default();
        let env_path = dir.path().join("cap.env.json");
        std::fs::write(&env_path, r#"{"api_key":""}"#).expect("secret marker");

        let error =
            write_headless_env_fields(&defs, &env_path, "cap", &home, &principal, &HashMap::new())
                .expect_err("marker without secret material must fail");

        assert!(error.to_string().contains("required value is missing"));
    }

    #[test]
    fn interactive_env_migrates_legacy_plaintext_secret() {
        let defs = env(r#"
[api_key]
type = "secret"
"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::new("agent").expect("principal");
        let env_path = dir.path().join("cap.env.json");
        std::fs::write(&env_path, r#"{"api_key":"legacy-secret"}"#).expect("legacy env");

        prompt_env_fields(
            &defs,
            &env_path,
            "cap",
            &dir.path().join("config.toml"),
            &home,
            &principal,
        )
        .expect("migrate secret");

        assert_eq!(
            std::fs::read_to_string(&env_path).expect("env marker"),
            "{\n  \"api_key\": \"\"\n}"
        );
        let secrets = FileSecretStore::new(home.secrets_dir().join(principal.as_str()).join("cap"));
        assert_eq!(
            secrets.get("api_key").expect("secret read").as_deref(),
            Some("legacy-secret")
        );
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

    /// REGRESSION: the in-process install answerer must echo the request's
    /// principal onto its reply. The host elicit waiter now rejects any reply
    /// whose principal differs from the one it stamped on the request, so a
    /// dropped principal would hang `astrid capsule install` for the full
    /// elicit timeout. Fails if `build_elicit_response_msg` stops stamping.
    #[test]
    fn elicit_reply_echoes_request_principal() {
        let request_id = uuid::Uuid::new_v4();
        let msg = build_elicit_response_msg(
            request_id,
            Some("default"),
            Some("answer".to_string()),
            None,
        );
        assert_eq!(
            msg.principal.as_deref(),
            Some("default"),
            "reply must carry the originating principal for the host's same-principal check"
        );
        assert_eq!(msg.topic, Topic::elicit_response(request_id));
        match msg.payload {
            IpcPayload::ElicitResponse {
                request_id: got,
                value,
                values,
            } => {
                assert_eq!(got, request_id);
                assert_eq!(value.as_deref(), Some("answer"));
                assert!(values.is_none());
            },
            other => panic!("expected ElicitResponse, got {other:?}"),
        }
    }

    /// A request with no principal (system-originated) yields an unstamped
    /// reply — the helper must not fabricate one.
    #[test]
    fn elicit_reply_unstamped_when_request_has_no_principal() {
        let msg = build_elicit_response_msg(uuid::Uuid::new_v4(), None, None, None);
        assert!(msg.principal.is_none());
    }
}
