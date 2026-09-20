//! Persist distro configuration without inventing empty credentials.

use std::collections::{HashMap, HashSet};

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{EnvStorageScope, EnvValueKind};

use super::super::distro::manifest::{DistroCapsule, VariableDef};
use super::{extract_var_refs, resolve_template};

/// Keep operator intent separate from values filled from distribution defaults.
#[derive(Default)]
pub(crate) struct ResolvedVariables {
    pub(super) values: HashMap<String, String>,
    pub(super) explicit: HashSet<String>,
}

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
    vars: &ResolvedVariables,
) -> anyhow::Result<()> {
    write_env_with(
        selected,
        variables,
        vars,
        |capsule| {
            super::super::capsule::install_headless::list_env_entries(principal, capsule)
                .map(|entries| entries.into_iter().map(|entry| entry.key).collect())
        },
        |capsule, key, value, kind| {
            super::super::capsule::install_headless::set_env_entry(
                principal,
                capsule,
                key,
                value,
                kind,
                EnvStorageScope::Agent,
            )
        },
    )
}

fn write_env_with(
    selected: &[DistroCapsule],
    variables: &HashMap<String, VariableDef>,
    vars: &ResolvedVariables,
    mut existing_keys: impl FnMut(&str) -> anyhow::Result<HashSet<String>>,
    mut write: impl FnMut(&str, &str, &str, EnvValueKind) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    for cap in selected {
        let mut existing = None;
        for (key, template) in &cap.env {
            let references = extract_var_refs(template);
            // Test the input, not the rendered text: `Bearer {{ key }}` is
            // nonempty even when the optional key is absent. Interactive
            // collection omits empty values while headless collection retains
            // them. Neither form should overwrite an existing credential.
            let unset_optional_secret = references.iter().any(|name| {
                variables.get(*name).is_some_and(|definition| {
                    definition.secret && definition.default.as_deref() == Some("")
                }) && vars.values.get(*name).is_none_or(String::is_empty)
            });
            if unset_optional_secret {
                continue;
            }
            // A distro default is a first-install fallback, not permission to
            // reset operator configuration on upgrade or resume. Literal
            // templates also fill missing keys only. Explicit input still wins.
            if !references.iter().any(|name| vars.explicit.contains(*name)) {
                if existing.is_none() {
                    existing = Some(existing_keys(&cap.name)?);
                }
                if existing.as_ref().is_some_and(|keys| keys.contains(key)) {
                    continue;
                }
            }
            let value = resolve_template(template, &vars.values);
            let secret = references
                .iter()
                .filter_map(|name| variables.get(*name))
                .any(|definition| definition.secret);
            let kind = if secret {
                EnvValueKind::Secret
            } else {
                EnvValueKind::Text
            };
            write(&cap.name, key, &value, kind)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
