//! Named `--capsule` selection for signed Distro Apply refresh.

use std::collections::HashSet;

use anyhow::bail;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};

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
    capsules: Vec<DistroCapsule>,
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

/// Query the authenticated caller's durable catalog before any install mutation.
pub(super) async fn require_installed_named_members(
    selected: &[DistroCapsule],
) -> anyhow::Result<()> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    for capsule in selected {
        match client
            .request(KernelRequest::GetInstalledCapsuleIdentity {
                id: capsule.name.clone(),
            })
            .await?
        {
            KernelResponse::InstalledCapsuleIdentity(Some(_)) => {},
            KernelResponse::InstalledCapsuleIdentity(None) => {
                bail!(
                    "distro apply --capsule '{}' is not already installed; filtered apply refreshes existing members only",
                    capsule.name
                );
            },
            other => bail!(
                "unexpected daemon response while confirming installed capsule '{}': {other:?}",
                capsule.name
            ),
        }
    }
    Ok(())
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
