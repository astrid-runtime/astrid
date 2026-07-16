//! Non-interactive configuration for `capsule install --yes`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use astrid_capsule::manifest::EnvDef;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_events::{AstridEvent, EventBus, EventMetadata, EventReceiver};
use astrid_storage::{FileSecretStore, SecretStore};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload, OnboardingFieldType};

use super::install_prompts::order_env_keys;

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

/// Non-interactive install responder used by `capsule install --yes`.
pub(crate) async fn headless_elicit_handler(
    mut receiver: EventReceiver,
    event_bus: EventBus,
    vars: HashMap<String, String>,
    errors: Arc<Mutex<Vec<String>>>,
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
    let env_key = headless_env_key(key);
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
    if let Some(principal) = request_principal {
        msg = msg.with_principal(principal);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(toml_src: &str) -> HashMap<String, EnvDef> {
        toml::from_str(toml_src).expect("env table parses")
    }

    #[test]
    fn value_prefers_explicit_input_and_validates_enums() {
        let mut vars = HashMap::from([("auth_mode".to_string(), "subscription".to_string())]);
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
    fn value_uses_manifest_default_without_guessing() {
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
    fn array_uses_comma_separated_values() {
        let vars = HashMap::from([("tags".to_string(), "one, two,,three".to_string())]);
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
    fn env_persists_modes_and_keeps_secret_out_of_json() {
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
    fn env_requires_missing_secret_and_rejects_unknown_var() {
        let defs = env("[api_key]\ntype = \"secret\"\n");
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
    fn empty_json_marker_is_not_a_stored_secret() {
        let defs = env("[api_key]\ntype = \"secret\"\n");
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
    fn elicit_reply_echoes_request_principal() {
        let request_id = uuid::Uuid::new_v4();
        let msg = build_elicit_response_msg(
            request_id,
            Some("default"),
            Some("answer".to_string()),
            None,
        );
        assert_eq!(msg.principal.as_deref(), Some("default"));
        assert_eq!(msg.topic, Topic::elicit_response(request_id));
        assert!(matches!(
            msg.payload,
            IpcPayload::ElicitResponse { request_id: got, .. } if got == request_id
        ));
    }

    #[test]
    fn elicit_reply_unstamped_when_request_has_no_principal() {
        let msg = build_elicit_response_msg(uuid::Uuid::new_v4(), None, None, None);
        assert!(msg.principal.is_none());
    }
}
