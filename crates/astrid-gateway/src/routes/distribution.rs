//! `GET /api/distribution`, `GET /api/distribution/onboarding`.
//!
//! Reflects the deployment's cached `Distro.toml` so dashboards can
//! render branding and decide whether to surface a registration UI
//! (i.e. whether `[invites]` is configured).
//!
//! Both routes are unauthenticated: the response is identical for
//! every caller, and the data is what a freshly-onboarded dashboard
//! needs *before* it has a bearer token.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use serde_json::Value;

use crate::error::{GatewayError, GatewayResult};
use crate::state::GatewayState;

/// Distribution discovery response.
#[derive(Debug, Clone, Serialize)]
pub struct DistributionInfo {
    /// `distro.id` from the manifest. `"single-tenant"` when no
    /// distro is configured.
    pub id: String,
    /// `distro.name` (human-readable).
    pub name: String,
    /// `distro.pretty-name` (display name with version / codename).
    pub pretty_name: Option<String>,
    /// `distro.description`.
    pub description: Option<String>,
    /// `distro.homepage`.
    pub homepage: Option<String>,
    /// Whether `[invites]` has at least one issuer configured. The
    /// dashboard uses this to decide whether to render the
    /// registration flow.
    pub invites_enabled: bool,
    /// `[branding]` section, surfaced verbatim. `null` when absent.
    pub branding: Option<Value>,
}

pub async fn get_distribution(
    State(state): State<Arc<GatewayState>>,
) -> GatewayResult<Json<DistributionInfo>> {
    let info = match &state.distro_toml {
        None => DistributionInfo {
            id: "single-tenant".to_string(),
            name: "Astrid".to_string(),
            pretty_name: None,
            description: None,
            homepage: None,
            invites_enabled: false,
            branding: None,
        },
        Some(text) => parse_distribution(text)?,
    };
    Ok(Json(info))
}

/// `GET /api/distribution/onboarding` — distro-level cross-capsule
/// onboarding fields drawn from `[variables]`. The TUI uses the same
/// data via `astrid init`; the dashboard mirrors it here so a
/// freshly-redeemed principal can immediately fill in their copy
/// without a CLI roundtrip.
pub async fn get_onboarding(
    State(state): State<Arc<GatewayState>>,
) -> GatewayResult<Json<OnboardingFields>> {
    let Some(text) = &state.distro_toml else {
        return Ok(Json(OnboardingFields::default()));
    };
    Ok(Json(parse_onboarding(text)?))
}

/// Subset of `[variables]` surfaced to the dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct OnboardingFields {
    /// One entry per `[variables.<name>]` block.
    pub fields: Vec<OnboardingField>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnboardingField {
    /// Variable name (matches `[variables.<name>]`).
    pub key: String,
    /// Whether the value is sensitive (mask on input).
    pub secret: bool,
    /// Operator-facing description.
    pub description: Option<String>,
    /// Default value.
    pub default: Option<String>,
}

// ── parsing helpers ────────────────────────────────────────────────

fn parse_distribution(text: &str) -> GatewayResult<DistributionInfo> {
    let parsed: toml::Value = toml::from_str(text)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("distro manifest parse: {e}")))?;
    let distro_tbl = parsed
        .get("distro")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            GatewayError::Internal(anyhow::anyhow!("distro manifest missing [distro] table"))
        })?;

    let id = distro_tbl
        .get("id")
        .and_then(toml::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let name = distro_tbl
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or("Astrid")
        .to_string();
    let pretty_name = distro_tbl
        .get("pretty-name")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let description = distro_tbl
        .get("description")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let homepage = distro_tbl
        .get("homepage")
        .and_then(toml::Value::as_str)
        .map(str::to_string);

    let invites_enabled = parsed
        .get("invites")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("issuers"))
        .and_then(toml::Value::as_array)
        .is_some_and(|a| !a.is_empty());

    let branding = parsed
        .get("branding")
        .map(|v| serde_json::to_value(v).unwrap_or(Value::Null));

    Ok(DistributionInfo {
        id,
        name,
        pretty_name,
        description,
        homepage,
        invites_enabled,
        branding,
    })
}

fn parse_onboarding(text: &str) -> GatewayResult<OnboardingFields> {
    let parsed: toml::Value = toml::from_str(text)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("distro manifest parse: {e}")))?;
    let Some(vars) = parsed.get("variables").and_then(toml::Value::as_table) else {
        return Ok(OnboardingFields::default());
    };
    let mut fields = Vec::with_capacity(vars.len());
    for (key, val) in vars {
        let tbl = val.as_table();
        fields.push(OnboardingField {
            key: key.clone(),
            secret: tbl
                .and_then(|t| t.get("secret"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
            description: tbl
                .and_then(|t| t.get("description"))
                .and_then(toml::Value::as_str)
                .map(str::to_string),
            default: tbl
                .and_then(|t| t.get("default"))
                .and_then(toml::Value::as_str)
                .map(str::to_string),
        });
    }
    Ok(OnboardingFields { fields })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r##"
schema-version = 1

[distro]
id = "sphere"
name = "Sphere"
pretty-name = "Sphere 0.1.0"
description = "Spherical demo distro"
homepage = "https://example.invalid"

[invites]
issuers = ["admin"]
default-group = "agent"

[branding]
primary-color = "#0099ff"

[variables.api_key]
secret = true
description = "OpenAI key"
"##;

    #[test]
    fn parses_distribution_metadata() {
        let info = parse_distribution(SAMPLE).expect("parse");
        assert_eq!(info.id, "sphere");
        assert_eq!(info.name, "Sphere");
        assert_eq!(info.pretty_name.as_deref(), Some("Sphere 0.1.0"));
        assert!(info.invites_enabled);
        assert!(info.branding.is_some());
    }

    #[test]
    fn parses_onboarding_fields() {
        let fields = parse_onboarding(SAMPLE).expect("parse");
        assert_eq!(fields.fields.len(), 1);
        let f = &fields.fields[0];
        assert_eq!(f.key, "api_key");
        assert!(f.secret);
        assert_eq!(f.description.as_deref(), Some("OpenAI key"));
    }

    #[test]
    fn no_invites_section_disables_registration() {
        let text = r#"
schema-version = 1

[distro]
id = "alone"
name = "Alone"
"#;
        let info = parse_distribution(text).expect("parse");
        assert!(!info.invites_enabled);
    }
}
