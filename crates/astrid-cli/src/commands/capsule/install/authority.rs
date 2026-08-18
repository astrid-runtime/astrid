//! Install-authority inspection and operator approval.

use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::bail;
use astrid_capsule_install::{
    ArtifactProvenance, AuthorityDecision, InstallInspection,
    inspect_archive_for_principal_with_layout, inspect_directory_for_principal_with_layout,
};
use astrid_capsule_types::capability_presentation::semantic_expansion;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::CapsuleInstallAuthority;

use super::{BATCH_MODE, ManualInstallOptions};

pub(super) fn authority_decision(
    inspection: &InstallInspection,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<AuthorityDecision> {
    if matches!(
        inspection.provenance,
        ArtifactProvenance::LocalRuntime { .. }
    ) {
        return Ok(AuthorityDecision::Automatic);
    }
    if BATCH_MODE.load(Ordering::Relaxed) {
        return Ok(AuthorityDecision::OperatorDistribution {
            content_digest: inspection.content_digest.clone(),
        });
    }
    if prompt.approve_untrusted {
        return Ok(AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        });
    }
    if prompt.yes {
        bail!(
            "capsule '{}' is {}; --yes configures values but does not approve install authority. Re-run with --approve-untrusted after reviewing the artifact",
            inspection.capsule_id,
            inspection.provenance.label()
        );
    }

    eprintln!();
    eprintln!(
        "Capsule {} {} is {}.",
        inspection.capsule_id,
        inspection.version,
        inspection.provenance.label()
    );
    if let Some(signer) = inspection.provenance.signer() {
        eprintln!("  Signer: {signer}");
    }
    eprintln!("  Content: {}", inspection.content_digest);
    if inspection.capability_expansions.is_empty() {
        eprintln!("  New authority beyond the current install: none");
    } else {
        eprintln!("  NEW AUTHORITY REQUESTED");
        for expansion in &inspection.capability_expansions {
            let semantic = semantic_expansion(expansion);
            eprintln!("    - {}", semantic.action);
            if !semantic.scope.is_empty() {
                eprintln!("      Scope: {}", semantic.scope.join("; "));
            }
            eprintln!("      Impact: {}", semantic.impact);
        }
    }
    eprint!("Approve this exact install once? [y/N] ");
    std::io::Write::flush(&mut std::io::stderr())?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        })
    } else {
        bail!("capsule install authority was not approved")
    }
}

pub(super) fn daemon_install_authority(
    source: &str,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<CapsuleInstallAuthority> {
    let home = AstridHome::resolve()?;
    let path = Path::new(source.strip_prefix("file://").unwrap_or(source));
    let inspection = if path.is_file() {
        inspect_archive_for_principal_with_layout(
            path,
            &home,
            principal,
            false,
            crate::workspace_layout::current(),
        )?
    } else {
        inspect_directory_for_principal_with_layout(
            path,
            &home,
            principal,
            false,
            crate::workspace_layout::current(),
        )?
    };
    Ok(match authority_decision(&inspection, prompt)? {
        AuthorityDecision::Automatic => CapsuleInstallAuthority::Automatic,
        AuthorityDecision::ExplicitApproval { .. } => CapsuleInstallAuthority::ExplicitApproval,
        AuthorityDecision::OperatorDistribution { .. } => {
            CapsuleInstallAuthority::OperatorDistribution
        },
    })
}
