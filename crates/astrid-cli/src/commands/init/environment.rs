//! Persist distro configuration without inventing empty credentials.

use std::collections::HashMap;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{EnvStorageScope, EnvValueKind};

use super::super::distro::manifest::{DistroCapsule, VariableDef};
use super::{extract_var_refs, resolve_template};

/// Persist distro variable templates through the daemon's typed env API.
///
/// Init may run before a capsule has been installed, so this deliberately
/// does not require a capsule manifest to classify fields. Variable metadata
/// from `Distro.toml` carries the secret bit; unresolved literal fields are
/// ordinary text. The daemon remains the only writer for durable env state.
pub(crate) fn write_env_files(
    _home: &AstridHome,
    principal: &PrincipalId,
    selected: &[DistroCapsule],
    variables: &HashMap<String, VariableDef>,
    vars: &HashMap<String, String>,
) -> anyhow::Result<()> {
    for cap in selected {
        for (key, template) in &cap.env {
            let value = resolve_template(template, vars);
            let secret = extract_var_refs(template)
                .iter()
                .filter_map(|name| variables.get(*name))
                .any(|definition| definition.secret);
            // An unset optional credential is absence, not an empty secret.
            // Reinitialization must not erase a previously configured key.
            if secret && value.is_empty() {
                continue;
            }
            let kind = if secret {
                EnvValueKind::Secret
            } else {
                EnvValueKind::Text
            };
            super::super::capsule::install_headless::set_env_entry(
                principal,
                &cap.name,
                key,
                &value,
                kind,
                EnvStorageScope::Agent,
            )?;
        }
    }
    Ok(())
}
