//! Named `--capsule` selection for signed Distro Apply refresh.

use std::collections::{HashMap, HashSet};

use anyhow::bail;
use astrid_core::kernel_api::{
    InstalledCapsuleGeneration, InstalledCapsuleIdentity, KernelRequest, KernelResponse,
};

use super::super::distro::manifest::DistroCapsule;

/// True when Distro Apply asked to refresh named members instead of the
/// unfiltered signed set.
pub(crate) fn filtered_refresh_requested(names: &[String]) -> bool {
    !names.is_empty()
}

/// Refuse `.shuttle` sources for named Distro Apply refresh.
pub(crate) fn reject_filtered_shuttle(
    source: &str,
    selected_capsules: &[String],
) -> anyhow::Result<()> {
    if filtered_refresh_requested(selected_capsules) && source.ends_with(".shuttle") {
        bail!("distro apply --capsule is not supported for .shuttle sources");
    }
    Ok(())
}

/// Resolve repeated `--capsule NAME` against the verified signed manifest.
///
/// Unknown, empty, and duplicate names fail closed. This does not fall back
/// to headless full-distro selection.
pub(crate) fn select_named_manifest_capsules(
    capsules: &[DistroCapsule],
    names: &[String],
) -> anyhow::Result<Vec<DistroCapsule>> {
    if names.is_empty() {
        bail!("distro apply --capsule requires at least one capsule name");
    }

    let mut selected = Vec::with_capacity(names.len());
    let mut seen = HashSet::new();
    for name in names {
        if name.is_empty() {
            bail!("distro apply --capsule requires a non-empty capsule name");
        }
        if !seen.insert(name.as_str()) {
            bail!("distro apply --capsule '{name}' was specified more than once");
        }
        let Some(capsule) = capsules.iter().find(|capsule| capsule.name == *name) else {
            bail!("distro apply --capsule '{name}' is not a member of the signed Distro manifest");
        };
        selected.push(capsule.clone());
    }
    Ok(selected)
}

/// Fail closed when any named member is absent from the caller's catalog.
pub(crate) fn require_named_members_present(
    selected: &[DistroCapsule],
    present: impl Fn(&str) -> bool,
) -> anyhow::Result<()> {
    for capsule in selected {
        if !present(&capsule.name) {
            bail!(
                "distro apply --capsule '{}' is not already installed; filtered apply refreshes existing members only",
                capsule.name
            );
        }
    }
    Ok(())
}

fn installed_generation_from_identity(
    name: &str,
    identity: Option<InstalledCapsuleIdentity>,
) -> anyhow::Result<InstalledCapsuleGeneration> {
    identity
        .map(|identity| identity.generation)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "distro apply --capsule '{name}' is not already installed; filtered apply refreshes existing members only"
            )
        })
}

/// Look up one observed generation. A present map is fail-closed for missing
/// names; an unconstrained (`None`) map leaves ordinary installs unbound.
pub(crate) fn require_named_generation(
    name: &str,
    observed: Option<&HashMap<String, InstalledCapsuleGeneration>>,
) -> anyhow::Result<Option<InstalledCapsuleGeneration>> {
    match observed {
        Some(map) => {
            let generation = map.get(name).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "distro apply --capsule '{name}' is missing an observed installed generation"
                )
            })?;
            Ok(Some(generation))
        },
        None => Ok(None),
    }
}

/// Query the authenticated caller's durable catalog before any install mutation.
pub(super) async fn require_installed_named_members(
    selected: &[DistroCapsule],
) -> anyhow::Result<HashMap<String, InstalledCapsuleGeneration>> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let mut observed = HashMap::with_capacity(selected.len());
    for capsule in selected {
        match client
            .request(KernelRequest::GetInstalledCapsuleIdentity {
                id: capsule.name.clone(),
            })
            .await?
        {
            KernelResponse::InstalledCapsuleIdentity(identity) => {
                observed.insert(
                    capsule.name.clone(),
                    installed_generation_from_identity(&capsule.name, identity)?,
                );
            },
            other => bail!(
                "unexpected daemon response while confirming installed capsule '{}': {other:?}",
                capsule.name
            ),
        }
    }
    Ok(observed)
}

/// Filtered refresh succeeds only when every named member completed.
pub(crate) fn reject_filtered_partial_refresh(
    total: usize,
    succeeded: usize,
) -> anyhow::Result<()> {
    if total == 0 || succeeded != total {
        bail!("filtered distro apply incomplete: {succeeded}/{total} capsule(s) refreshed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(seed: u8) -> InstalledCapsuleGeneration {
        InstalledCapsuleGeneration {
            archive: format!("{seed:02x}").repeat(32),
            metadata: format!("{:02x}", seed.wrapping_add(1)).repeat(32),
            authority: format!("{:02x}", seed.wrapping_add(2)).repeat(32),
        }
    }

    #[test]
    fn unconstrained_map_leaves_ordinary_installs_unbound() {
        assert_eq!(require_named_generation("demo", None).unwrap(), None);
    }

    #[test]
    fn present_map_returns_the_named_generation() {
        let expected = generation(1);
        let observed = HashMap::from([("demo".to_owned(), expected.clone())]);
        assert_eq!(
            require_named_generation("demo", Some(&observed)).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn present_map_fail_closes_on_missing_name() {
        let observed = HashMap::from([("demo".to_owned(), generation(1))]);
        let error = require_named_generation("other", Some(&observed)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing an observed installed generation"),
            "{error}"
        );
    }

    #[test]
    fn absent_identity_fail_closes() {
        let error = installed_generation_from_identity("demo", None).unwrap_err();
        assert!(
            error.to_string().contains("is not already installed"),
            "{error}"
        );
    }
}
