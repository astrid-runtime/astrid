//! Distro-batch capsule installation contract.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;

use astrid_capsule::capsule::CapsuleId;
use astrid_core::kernel_api::{
    CapsuleInstallBatchId, CapsuleInstallBatchMember, InstalledCapsuleGeneration, KernelRequest,
    KernelResponse,
};

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
    /// Whether the durable package already matched and no install request was
    /// sent. This lets init avoid treating a resume as a newly landed grant.
    pub(crate) skipped: bool,
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
    batch_id: Option<CapsuleInstallBatchId>,
    expected_generation: Option<InstalledCapsuleGeneration>,
) -> anyhow::Result<BatchInstallOutcome> {
    anyhow::ensure!(
        refspec.version.is_some() || refspec.tag.is_some(),
        "distro capsule '{expected}' has no concrete released version or tag"
    );
    super::install::BATCH_MODE.store(true, Ordering::Relaxed);
    let prompt = super::install::ManualInstallOptions::default();
    let result = super::install::install_capsule_inner(
        source,
        Some(expected.as_str()),
        workspace,
        refspec,
        principal,
        &prompt,
        Some(super::install::ExpectedInstall {
            id: expected,
            batch_id,
            expected_generation: expected_generation.as_ref(),
        }),
    )
    .await;
    super::install::BATCH_MODE.store(false, Ordering::Relaxed);
    result.map(|(installed, resolved_ref)| BatchInstallOutcome {
        installed,
        resolved_ref,
    })
}

/// Open a bounded kernel lease when every selected distro member is already a
/// local `.capsule` archive. Remote and source-directory installs retain the
/// ordinary per-minute path because they do not yet have fixed archive bytes.
pub(crate) async fn begin_verified_local_batch(
    selected: &[super::super::distro::manifest::DistroCapsule],
    principal: &astrid_core::PrincipalId,
    observed: Option<&HashMap<String, InstalledCapsuleGeneration>>,
) -> anyhow::Result<Option<CapsuleInstallBatchId>> {
    if selected.is_empty() {
        return Ok(None);
    }
    if !selected.iter().all(|capsule| {
        let source = Path::new(&capsule.source);
        source.is_file() && source.extension().and_then(|value| value.to_str()) == Some("capsule")
    }) {
        return Ok(None);
    }

    crate::commands::daemon::ensure_persistent_daemon("distro capsule batch").await?;
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let KernelResponse::Status(status) = client.request(KernelRequest::GetStatus).await? else {
        return Ok(None);
    };
    let Some(members) = batch_members_for_status(&status, selected, observed)? else {
        return Ok(None);
    };
    match client
        .request(KernelRequest::BeginCapsuleInstallBatch {
            target_principal: Some(principal.clone()),
            members,
        })
        .await?
    {
        KernelResponse::CapsuleInstallBatchStarted { batch_id, .. } => Ok(Some(batch_id)),
        KernelResponse::Error(error) => {
            anyhow::bail!("daemon rejected capsule install batch: {error}")
        },
        response => anyhow::bail!("unexpected capsule install batch response: {response:?}"),
    }
}

fn batch_members_for_status(
    status: &astrid_core::kernel_api::DaemonStatus,
    selected: &[super::super::distro::manifest::DistroCapsule],
    observed: Option<&HashMap<String, InstalledCapsuleGeneration>>,
) -> anyhow::Result<Option<Vec<CapsuleInstallBatchMember>>> {
    if !supports_install_batch(status) {
        return Ok(None);
    }
    let mut members = Vec::with_capacity(selected.len());
    for capsule in selected {
        let expected_generation = match observed {
            Some(map) => Some(map.get(&capsule.name).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "distro apply --capsule '{}' is missing an observed installed generation",
                    capsule.name
                )
            })?),
            None => None,
        };
        let source = Path::new(&capsule.source);
        let source_bytes = source.metadata()?.len();
        let manifest = astrid_capsule_install::read_archive_manifest(source)?;
        anyhow::ensure!(
            manifest.package.name == capsule.name && manifest.package.version == capsule.version,
            "distro batch member '{}' does not match archive identity {} {}",
            capsule.name,
            manifest.package.name,
            manifest.package.version
        );
        members.push(CapsuleInstallBatchMember {
            id: capsule.name.clone(),
            version: capsule.version.clone(),
            source_digest: format!(
                "blake3:{}",
                astrid_capsule_install::source_digest_for_archive(source)?
            ),
            archive_digest: format!(
                "blake3:{}",
                astrid_capsule_install::archive_digest_for_source(source)?
            ),
            source_bytes,
            expected_generation,
        });
    }
    Ok(Some(members))
}

fn supports_install_batch(status: &astrid_core::kernel_api::DaemonStatus) -> bool {
    status
        .capsule_install_batch_protocol
        .is_some_and(|revision| {
            revision >= astrid_core::kernel_api::CAPSULE_INSTALL_BATCH_PROTOCOL_V1
        })
}

pub(crate) async fn finish_verified_local_batch(
    batch_id: Option<CapsuleInstallBatchId>,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<()> {
    let Some(batch_id) = batch_id else {
        return Ok(());
    };
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    match client
        .request(KernelRequest::FinishCapsuleInstallBatch {
            batch_id,
            target_principal: Some(principal.clone()),
        })
        .await?
    {
        KernelResponse::Success(_) => Ok(()),
        KernelResponse::Error(error) => {
            anyhow::bail!("daemon rejected completed install batch: {error}")
        },
        response => anyhow::bail!("unexpected install batch completion response: {response:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(version: &str) -> astrid_core::kernel_api::DaemonStatus {
        astrid_core::kernel_api::DaemonStatus {
            pid: 1,
            uptime_secs: 1,
            version: version.to_owned(),
            ephemeral: false,
            connected_clients: 0,
            connections_by_principal: Vec::new(),
            loaded_capsules: Vec::new(),
            capsule_install_batch_protocol: None,
        }
    }

    #[test]
    fn feature_negotiation_falls_back_when_the_daemon_omits_the_protocol() {
        assert!(!supports_install_batch(&status("0.0.0")));
    }

    #[test]
    fn feature_negotiation_accepts_the_advertised_protocol_across_versions() {
        let mut status = status("older-or-newer-version");
        status.capsule_install_batch_protocol =
            Some(astrid_core::kernel_api::CAPSULE_INSTALL_BATCH_PROTOCOL_V1);
        assert!(supports_install_batch(&status));
    }

    #[test]
    fn unsupported_daemon_falls_back_before_parsing_local_archives() {
        let source = tempfile::Builder::new()
            .suffix(".capsule")
            .tempfile()
            .expect("malformed archive");
        std::fs::write(source.path(), b"not a capsule archive").expect("fixture bytes");
        let selected = [super::super::super::distro::manifest::DistroCapsule {
            name: "malformed".to_owned(),
            source: source.path().to_string_lossy().into_owned(),
            version: "1.0.0".to_owned(),
            tag: None,
            branch: None,
            rev: None,
            default: false,
            group: None,
            role: None,
            env: std::collections::HashMap::new(),
        }];

        assert!(
            batch_members_for_status(&status("legacy"), &selected, None)
                .expect("unsupported daemon fallback")
                .is_none()
        );
    }

    #[test]
    fn filtered_batch_fail_closes_on_missing_observed_generation() {
        let mut status = status("with-protocol");
        status.capsule_install_batch_protocol =
            Some(astrid_core::kernel_api::CAPSULE_INSTALL_BATCH_PROTOCOL_V1);
        let selected = [super::super::super::distro::manifest::DistroCapsule {
            name: "missing".to_owned(),
            source: "unused.capsule".to_owned(),
            version: "1.0.0".to_owned(),
            tag: None,
            branch: None,
            rev: None,
            default: false,
            group: None,
            role: None,
            env: std::collections::HashMap::new(),
        }];
        let observed = HashMap::from([(
            "other".to_owned(),
            InstalledCapsuleGeneration {
                archive: "aa".repeat(32),
                metadata: "bb".repeat(32),
                authority: "cc".repeat(32),
            },
        )]);
        let error = batch_members_for_status(&status, &selected, Some(&observed))
            .expect_err("missing generation");
        assert!(
            error
                .to_string()
                .contains("missing an observed installed generation"),
            "{error}"
        );
    }
}
