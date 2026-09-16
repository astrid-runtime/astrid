//! Immutable archive handling for bounded capsule-install batches.

use std::sync::Arc;

use astrid_capsule_install::{AuthorityDecision, InstallOptions, InstallOutput};
use astrid_core::kernel_api::{CapsuleInstallAuthority, CapsuleInstallBatchMember};

pub(super) struct BatchArchive {
    pub(super) bytes: Vec<u8>,
    pub(super) manifest: astrid_capsule::manifest::CapsuleManifest,
}

pub(super) fn prepare_batch_archive(
    source: &std::path::Path,
    member: Option<&CapsuleInstallBatchMember>,
) -> Result<Option<BatchArchive>, String> {
    let Some(member) = member else {
        return Ok(None);
    };
    let bytes = snapshot_batch_archive(source, member)?;
    let manifest = astrid_capsule_install::read_archive_manifest_bytes(&bytes)
        .map_err(|error| format!("validate batch capsule manifest: {error:#}"))?;
    if manifest.package.name != member.id || manifest.package.version != member.version {
        return Err(format!(
            "batch member identity mismatch: expected {} {}, got {} {}",
            member.id, member.version, manifest.package.name, manifest.package.version
        ));
    }
    Ok(Some(BatchArchive { bytes, manifest }))
}

pub(super) fn snapshot_batch_archive(
    source: &std::path::Path,
    expected: &CapsuleInstallBatchMember,
) -> Result<Vec<u8>, String> {
    let source_file = super::install_batch::open_batch_archive_source(source, expected)?;
    let capacity = usize::try_from(expected.source_bytes).map_err(|_| {
        format!(
            "capsule '{}' source is too large for this host",
            expected.id
        )
    })?;
    let mut snapshot = Vec::with_capacity(capacity);
    let mut bounded = std::io::Read::take(source_file, expected.source_bytes.saturating_add(1));
    let copied = std::io::copy(&mut bounded, &mut snapshot).map_err(|error| {
        format!(
            "snapshot batch capsule source {}: {error}",
            source.display()
        )
    })?;
    if copied != expected.source_bytes {
        return Err(format!(
            "capsule '{}' batch source changed while it was being snapshotted",
            expected.id
        ));
    }
    Ok(snapshot)
}

pub(super) async fn run_authorized_archive_install(
    kernel: &Arc<crate::Kernel>,
    principal: &astrid_core::principal::PrincipalId,
    archive: Vec<u8>,
    home: astrid_core::dirs::AstridHome,
    options: InstallOptions,
    authority: CapsuleInstallAuthority,
) -> Result<InstallOutput, String> {
    let workspace_layout = kernel.workspace_layout.clone();
    let workspace_root = kernel.workspace_root.clone();
    let principal = principal.clone();
    let authority = if authority == CapsuleInstallAuthority::Automatic {
        AuthorityDecision::Automatic
    } else {
        let inspection = astrid_capsule_install::inspect_archive_bytes_for_principal_in_workspace(
            &archive,
            &home,
            &principal,
            false,
            Some(&workspace_root),
            &workspace_layout,
        )
        .map_err(|error| format!("inspect capsule install authority: {error:#}"))?;
        match authority {
            CapsuleInstallAuthority::Automatic => AuthorityDecision::Automatic,
            CapsuleInstallAuthority::ExplicitApproval => AuthorityDecision::ExplicitApproval {
                content_digest: inspection.content_digest,
            },
            CapsuleInstallAuthority::OperatorDistribution => {
                AuthorityDecision::OperatorDistribution {
                    content_digest: inspection.content_digest,
                }
            },
        }
    };
    tokio::task::spawn_blocking(move || {
        astrid_capsule_install::unpack_and_install_authorized_bytes_for_principal_in_workspace(
            &archive,
            &home,
            options,
            &principal,
            Some(&workspace_root),
            &authority,
            &workspace_layout,
        )
    })
    .await
    .map_err(|error| format!("install task panicked: {error}"))?
    .map_err(|error| format!("install failed: {error:#}"))
}
