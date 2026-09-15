//! Post-install onboarding driven by the daemon's durable capsule registry.

use std::collections::HashMap;

use astrid_capsule::manifest::{EnvDef, EnvScope, OptionsFrom};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{CapsuleEnvMetadata, KernelRequest, KernelResponse};

use super::super::distro::manifest::DistroCapsule;
use crate::theme::Theme;

fn env_def(field: CapsuleEnvMetadata) -> EnvDef {
    EnvDef {
        env_type: field.env_type,
        request: field.request,
        description: field.description,
        default: field.default,
        enum_values: field.enum_values,
        placeholder: field.placeholder,
        options_from: field.options_from.map(|source| OptionsFrom {
            http: source.http,
            bearer: source.bearer,
            select: source.select,
            after: source.after,
        }),
        scope: EnvScope::Agent,
    }
}

async fn installed_env_schemas() -> anyhow::Result<HashMap<String, HashMap<String, EnvDef>>> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let response = client.request(KernelRequest::GetCapsuleMetadata).await?;
    let entries = match response {
        KernelResponse::CapsuleMetadata(entries) => entries,
        KernelResponse::Error(error) => anyhow::bail!("daemon metadata lookup failed: {error}"),
        other => anyhow::bail!("unexpected daemon metadata response: {other:?}"),
    };
    Ok(entries
        .into_iter()
        .map(|entry| {
            let env = entry
                .env
                .into_iter()
                .map(|(name, field)| (name, env_def(field)))
                .collect();
            (entry.name, env)
        })
        .collect())
}

/// Configure selected LLM providers from authenticated registry metadata.
///
/// Native principal-home capsule mirrors were retired by the volume layout;
/// the verified daemon registry is the authority for installed manifests.
pub(super) async fn onboard_llm_providers(
    home: &AstridHome,
    principal: &PrincipalId,
    selected: &[DistroCapsule],
) {
    let schemas = match installed_env_schemas().await {
        Ok(schemas) => schemas,
        Err(error) => {
            eprintln!("  Skipping provider onboarding: {error}");
            return;
        },
    };

    for capsule in selected
        .iter()
        .filter(|capsule| capsule.group.as_deref() == Some("llm"))
    {
        let Some(env) = schemas.get(&capsule.name) else {
            eprintln!(
                "  Skipping {} onboarding: capsule is absent from the daemon registry",
                capsule.name
            );
            continue;
        };
        if env.is_empty() {
            continue;
        }

        eprintln!();
        eprintln!("{}", Theme::header(&format!("Configure {}", capsule.name)));
        if let Err(error) = super::super::capsule::install_prompts::prompt_env_fields(
            env,
            &capsule.name,
            &home.config_path(),
            principal,
        ) {
            eprintln!("  Configuration for {} failed: {error}", capsule.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::kernel_api::CapsuleEnvOptionsFromMetadata;

    #[test]
    fn registry_metadata_preserves_dynamic_provider_discovery() {
        let converted = env_def(CapsuleEnvMetadata {
            env_type: "select".to_string(),
            request: Some("Model".to_string()),
            description: None,
            default: None,
            enum_values: Vec::new(),
            placeholder: None,
            options_from: Some(CapsuleEnvOptionsFromMetadata {
                http: "{base_url}/v1/models".to_string(),
                bearer: Some("{api_key}".to_string()),
                select: Some("data[].id".to_string()),
                after: vec!["base_url".to_string(), "api_key".to_string()],
            }),
        });

        let source = converted.options_from.expect("dynamic source");
        assert_eq!(source.http, "{base_url}/v1/models");
        assert_eq!(source.bearer.as_deref(), Some("{api_key}"));
        assert_eq!(source.after, ["base_url", "api_key"]);
    }
}
