//! Distro-batch capsule installation contract.

use std::sync::atomic::Ordering;

use astrid_capsule::capsule::CapsuleId;

/// Concrete git selector for a distro capsule install.
#[derive(Debug, Clone, Default)]
pub(crate) struct RefSpec {
    pub(crate) version: Option<String>,
    pub(crate) tag: Option<String>,
}

impl RefSpec {
    pub(crate) fn from_capsule(cap: &super::super::distro::manifest::DistroCapsule) -> Self {
        Self {
            version: (!cap.version.trim().is_empty()).then(|| cap.version.trim().to_string()),
            tag: cap
                .tag
                .as_deref()
                .map(str::trim)
                .filter(|tag| !tag.is_empty())
                .map(str::to_string),
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstalledCapsuleOutcome {
    pub(crate) id: CapsuleId,
    pub(crate) version: String,
    pub(crate) wasm_hash: Option<String>,
}

#[derive(Debug)]
pub(crate) struct BatchInstallOutcome {
    pub(crate) installed: Vec<InstalledCapsuleOutcome>,
    pub(crate) resolved_ref: Option<String>,
}

/// Install without prompting, returning the identities that actually landed.
pub(crate) async fn install_capsule_batch(
    source: &str,
    expected: &CapsuleId,
    workspace: bool,
    refspec: &RefSpec,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<BatchInstallOutcome> {
    anyhow::ensure!(
        refspec.version.is_some() || refspec.tag.is_some(),
        "distro capsule '{}' has no concrete released version or tag",
        expected
    );
    super::install::BATCH_MODE.store(true, Ordering::Relaxed);
    let result = super::install::install_capsule_inner(
        source,
        Some(expected.as_str()),
        workspace,
        refspec,
        principal,
        Some(expected),
    )
    .await;
    super::install::BATCH_MODE.store(false, Ordering::Relaxed);
    result.map(|(installed, resolved_ref)| BatchInstallOutcome {
        installed,
        resolved_ref,
    })
}
