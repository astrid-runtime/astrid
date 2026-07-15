//! Distro-batch capsule installation contract.

use std::sync::atomic::Ordering;

/// Concrete git selector for a distro capsule install.
#[derive(Debug, Clone, Default)]
pub(crate) struct RefSpec {
    pub(crate) version: Option<String>,
    pub(crate) tag: Option<String>,
}

impl RefSpec {
    pub(crate) fn from_capsule(cap: &super::super::distro::manifest::DistroCapsule) -> Self {
        Self {
            version: (!cap.version.is_empty()).then(|| cap.version.clone()),
            tag: cap.tag.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct BatchInstallOutcome {
    pub(crate) installed_ids: Vec<String>,
    pub(crate) resolved_ref: Option<String>,
}

/// Install without prompting, returning the identities that actually landed.
pub(crate) async fn install_capsule_batch(
    source: &str,
    name_hint: Option<&str>,
    workspace: bool,
    refspec: &RefSpec,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<BatchInstallOutcome> {
    super::install::BATCH_MODE.store(true, Ordering::Relaxed);
    let result =
        super::install::install_capsule_inner(source, name_hint, workspace, refspec, principal)
            .await;
    super::install::BATCH_MODE.store(false, Ordering::Relaxed);
    result.map(|(installed_ids, resolved_ref)| BatchInstallOutcome {
        installed_ids,
        resolved_ref,
    })
}
