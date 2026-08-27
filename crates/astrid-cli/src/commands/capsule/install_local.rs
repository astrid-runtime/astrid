//! Local, offline, and archive-backed capsule install helpers.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule_install::{
    InstallOptions, inspect_archive_for_principal_with_layout,
    inspect_directory_for_principal_with_layout, resolve_target_dir_for_with_layout,
};
use astrid_core::dirs::AstridHome;

use super::super::install_batch::InstalledCapsuleOutcome;
use super::super::install_finish::{finish_install, run_with_elicit};
use super::authority::{authority_decision, daemon_install_authority};
use super::{BATCH_MODE, ExpectedCapsule, ManualInstallOptions, OfflineCapsuleProvenance};
use crate::commands::capsule::{install_daemon, meta};

/// One fully-resolved local route invocation. Bundled so the wide install
/// surface stays reviewable without growing an argument list.
pub(super) struct LocalInstallCall<'ctx, 'src> {
    pub(crate) source: &'src str,
    pub(crate) workspace: bool,
    pub(crate) home: &'ctx AstridHome,
    pub(crate) original_source: Option<&'src str>,
    pub(crate) principal: &'ctx astrid_core::PrincipalId,
    pub(crate) expected: Option<ExpectedCapsule<'src>>,
    pub(crate) prompt: &'ctx ManualInstallOptions,
    pub(crate) station_binding: Option<&'src astrid_core::kernel_api::StationInstallBinding>,
}

pub(super) async fn install_from_local(
    call: LocalInstallCall<'_, '_>,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    let LocalInstallCall {
        source,
        workspace,
        home,
        original_source,
        principal,
        expected,
        prompt,
        station_binding,
    } = call;
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("Source path does not exist: {source}");
    }

    // Unpack `.capsule` archive when source is a file.
    if source_path.is_file() && source.ends_with(".capsule") {
        if !workspace {
            #[cfg(test)]
            if let Some(result) = super::station_install::test_daemon_install_outcome(source) {
                return result;
            }
            let installed = daemon_route(source, prompt, principal, station_binding).await?;
            return Ok(vec![installed]);
        }
        return unpack_via_lib(
            source_path,
            workspace,
            home,
            original_source,
            principal,
            expected,
            prompt,
        )
        .map(|installed| vec![installed]);
    }

    // Auto-build Rust capsules when source is a directory with a Cargo.toml.
    if source_path.is_dir() && source_path.join("Cargo.toml").exists() {
        let tmp_dir = tempfile::tempdir().context("failed to create temp dir for building")?;
        let output_dir = tmp_dir.path().join("dist");

        let build_bin = crate::bootstrap::find_companion_binary("astrid-build")?;
        let status = std::process::Command::new(build_bin)
            .arg(source)
            .arg("--output")
            .arg(output_dir.to_str().context("Invalid output dir path")?)
            .arg("--type")
            .arg("rust")
            .status()
            .context("Failed to run astrid-build")?;
        if !status.success() {
            bail!(
                "astrid-build failed with exit code {}",
                status.code().unwrap_or(1)
            );
        }

        for entry in std::fs::read_dir(&output_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
                if !workspace {
                    let archive = entry.path();
                    let archive = archive
                        .to_str()
                        .context("built capsule archive path is not UTF-8")?;
                    // Auto-built archives never carry a caller Station lock;
                    // the builder output is not the locked artifact.
                    let installed = install_daemon::install_local_via_daemon_outcome(
                        archive,
                        prompt,
                        daemon_install_authority(archive, principal, prompt)?,
                        None,
                    )
                    .await?;
                    return Ok(vec![installed]);
                }
                return unpack_via_lib(
                    &entry.path(),
                    workspace,
                    home,
                    original_source,
                    principal,
                    expected,
                    prompt,
                )
                .map(|installed| vec![installed]);
            }
        }
        bail!("Failed to auto-build capsule from Cargo project.");
    }

    if !workspace {
        let installed = daemon_route(source, prompt, principal, station_binding).await?;
        return Ok(vec![installed]);
    }

    install_from_local_path_for_principal(
        source_path,
        workspace,
        home,
        original_source,
        principal,
        expected,
        prompt,
    )
    .map(|installed| vec![installed])
}

/// Send one fully-resolved local artifact to the sole durable writer.
/// The kernel owns caller-byte verification and any optional Station binding.
async fn daemon_route(
    source: &str,
    prompt: &ManualInstallOptions,
    principal: &astrid_core::PrincipalId,
    station_binding: Option<&astrid_core::kernel_api::StationInstallBinding>,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let authority = daemon_install_authority(source, principal, prompt)?;
    install_daemon::install_local_via_daemon_outcome(
        source,
        prompt,
        authority,
        station_binding.cloned(),
    )
    .await
}

pub(crate) fn install_from_local_path(
    source_dir: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    approve_untrusted: bool,
) -> anyhow::Result<String> {
    let principal = crate::principal::current();
    let prompt = ManualInstallOptions {
        approve_untrusted,
        ..Default::default()
    };
    install_from_local_path_for_principal(
        source_dir,
        workspace,
        home,
        original_source,
        &principal,
        None,
        &prompt,
    )
    .map(|installed| installed.id.as_str().to_string())
}

fn install_from_local_path_for_principal(
    source_dir: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    principal: &astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'_>>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let inspection = inspect_directory_for_principal_with_layout(
        source_dir,
        home,
        principal,
        workspace,
        crate::workspace_layout::current(),
    )?;
    let authority = authority_decision(&inspection, prompt)?;
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(std::sync::atomic::Ordering::Relaxed),
        lifecycle_bus: None,
        storage: None,
        provenance_distro: None,
        provenance_source_digest: None,
    };
    let output = run_with_elicit(opts, prompt, |opts, bus| {
        let opts = InstallOptions {
            lifecycle_bus: Some(bus),
            ..opts
        };
        match expected {
            Some(expected) => astrid_capsule_install::install_from_local_path_checked_authorized_for_principal_with_layout(
                source_dir,
                home,
                opts,
                principal,
                expected.id,
                expected.version,
                &authority,
                crate::workspace_layout::current(),
            ),
            None => astrid_capsule_install::install_from_local_path_authorized_for_principal_with_layout(
                source_dir,
                home,
                opts,
                principal,
                &authority,
                crate::workspace_layout::current(),
            ),
        }
    })?;
    finish_install(&output, home, principal, prompt)
}

pub(crate) fn install_offline_capsule(
    archive: &Path,
    home: &AstridHome,
    expected: &CapsuleId,
    expected_version: Option<&str>,
    provenance: OfflineCapsuleProvenance<'_>,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    BATCH_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
    let prompt = ManualInstallOptions::default();
    let result = (|| {
        let installed = unpack_via_lib(
            archive,
            false,
            home,
            Some(provenance.original_source),
            principal,
            Some(ExpectedCapsule {
                id: expected,
                version: expected_version,
            }),
            &prompt,
        )?;
        let target_dir = resolve_target_dir_for_with_layout(
            home,
            principal,
            expected.as_str(),
            false,
            crate::workspace_layout::current(),
        )?;
        if let Some(mut metadata) = meta::read_meta(&target_dir) {
            metadata.resolved_ref = provenance.resolved_ref.map(String::from);
            metadata.signer = provenance.signer.map(String::from);
            metadata.signature = provenance.signature.map(String::from);
            meta::write_meta(&target_dir, &metadata)?;
        }
        Ok(installed)
    })();
    BATCH_MODE.store(false, std::sync::atomic::Ordering::Relaxed);
    result
}

pub(super) fn unpack_via_lib(
    archive: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    principal: &astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'_>>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let inspection = inspect_archive_for_principal_with_layout(
        archive,
        home,
        principal,
        workspace,
        crate::workspace_layout::current(),
    )?;
    let authority = authority_decision(&inspection, prompt)?;
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(std::sync::atomic::Ordering::Relaxed),
        lifecycle_bus: None,
        storage: None,
        provenance_distro: None,
        provenance_source_digest: None,
    };
    let output = run_with_elicit(opts, prompt, |opts, bus| {
        let opts = InstallOptions {
            lifecycle_bus: Some(bus),
            ..opts
        };
        match expected {
            Some(expected) => astrid_capsule_install::unpack_and_install_checked_authorized_for_principal_with_layout(
                archive,
                home,
                opts,
                principal,
                expected.id,
                expected.version,
                &authority,
                crate::workspace_layout::current(),
            ),
            None => astrid_capsule_install::unpack_and_install_authorized_for_principal_with_layout(
                archive,
                home,
                opts,
                principal,
                &authority,
                crate::workspace_layout::current(),
            ),
        }
    })?;
    finish_install(&output, home, principal, prompt)
}
