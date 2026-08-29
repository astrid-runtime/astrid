//! Non-interactive configuration for `capsule install --yes`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use astrid_capsule::manifest::EnvDef;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, EnvStorageScope, EnvValueKind};
use astrid_events::{AstridEvent, EventBus, EventMetadata, EventReceiver};
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload, OnboardingFieldType};

use super::install_prompts::order_env_keys;

/// Persist manifest configuration supplied to `capsule install --yes` without
/// reading stdin. Existing values are preserved unless the operator explicitly
/// supplies a replacement. Secret and text values use typed daemon control
/// namespaces.
pub(crate) fn write_headless_env_fields(
    env_defs: &HashMap<String, EnvDef>,
    capsule_id: &str,
    principal: &PrincipalId,
    vars: &HashMap<String, String>,
) -> anyhow::Result<()> {
    // A config-free capsule has nothing to project into the daemon. Keeping
    // this path local also lets offline/manual installs remain daemon-free.
    if env_defs.is_empty() && vars.is_empty() {
        return Ok(());
    }
    for key in vars.keys() {
        if !env_defs.contains_key(key) {
            anyhow::bail!("--var names no [env] field in {capsule_id}: {key}");
        }
    }

    let existing = list_env_entries(principal, capsule_id)?;
    let existing_keys: std::collections::HashSet<String> =
        existing.into_iter().map(|entry| entry.key).collect();

    for key in order_env_keys(env_defs) {
        let def = &env_defs[&key];
        let env_key = headless_env_key(&key);
        let supplied = vars
            .get(&key)
            .cloned()
            .or_else(|| std::env::var(&env_key).ok());
        if supplied.is_none() && existing_keys.contains(&key) {
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
                delete_env_entry(principal, capsule_id, &key, EnvValueKind::Secret)?;
            } else {
                set_env_entry(
                    principal,
                    capsule_id,
                    &key,
                    &resolved,
                    EnvValueKind::Secret,
                    EnvStorageScope::Agent,
                )?;
            }
        } else {
            set_env_entry(
                principal,
                capsule_id,
                &key,
                &resolved,
                EnvValueKind::Text,
                EnvStorageScope::Agent,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn admin_block_on<F, T>(future: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(future)
    }
}

pub(crate) fn list_env_entries(
    principal: &PrincipalId,
    capsule: &str,
) -> anyhow::Result<Vec<astrid_core::kernel_api::EnvEntry>> {
    admin_block_on(async {
        let mut client = crate::admin_client::connect_as_active_agent().await?;
        let response = client
            .request(AdminRequestKind::EnvList {
                principal: principal.clone(),
                capsule: Some(capsule.to_owned()),
            })
            .await?;
        let response = crate::admin_client::into_result(response)?;
        let AdminResponseBody::EnvList(entries) = response else {
            anyhow::bail!("unexpected env list response: {response:?}");
        };
        Ok(entries)
    })
}

pub(crate) fn set_env_entry(
    principal: &PrincipalId,
    capsule: &str,
    key: &str,
    value: &str,
    kind: EnvValueKind,
    scope: EnvStorageScope,
) -> anyhow::Result<()> {
    admin_block_on(async {
        let mut client = crate::admin_client::connect_as_active_agent().await?;
        let response = client
            .request(AdminRequestKind::EnvSet {
                principal: principal.clone(),
                capsule: capsule.to_owned(),
                key: key.to_owned(),
                value: value.to_owned(),
                kind,
                scope,
                append: false,
            })
            .await?;
        crate::admin_client::into_result(response)?;
        Ok(())
    })
}

pub(crate) fn delete_env_entry(
    principal: &PrincipalId,
    capsule: &str,
    key: &str,
    kind: EnvValueKind,
) -> anyhow::Result<()> {
    admin_block_on(async {
        let mut client = crate::admin_client::connect_as_active_agent().await?;
        let response = client
            .request(AdminRequestKind::EnvDelete {
                principal: principal.clone(),
                capsule: capsule.to_owned(),
                key: key.to_owned(),
                kind,
                scope: EnvStorageScope::Agent,
            })
            .await?;
        crate::admin_client::into_result(response)?;
        Ok(())
    })
}

pub(super) fn headless_env_key(key: &str) -> String {
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

pub(super) fn json_value_string(value: &serde_json::Value) -> String {
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
