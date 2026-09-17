//! Unfiltered Distro install after named selection returns.

use std::collections::HashMap;

use anyhow::bail;
use astrid_core::dirs::AstridHome;

use super::super::distro::manifest::{DistroCapsule, VariableDef};
use super::signed_source::SignedDistroBundle;
use super::{
    InitOpts, ProvisioningLease, collect_variables, create_lock_from_parts,
    install_capsules_with_resume, persist_lock_if_earned_daemon, reject_total_install_failure,
    should_write_lock, write_env_files,
};
use crate::theme::Theme;

/// Inputs for the unfiltered Distro install after named selection returns.
pub(super) struct UnfilteredDistroInstall<'a> {
    pub(super) home: &'a AstridHome,
    pub(super) operator: astrid_core::PrincipalId,
    pub(super) target: astrid_core::PrincipalId,
    pub(super) opts: &'a InitOpts,
    pub(super) variables: HashMap<String, VariableDef>,
    pub(super) selected: Vec<DistroCapsule>,
    pub(super) signed_bundle: Option<SignedDistroBundle>,
    pub(super) schema_version: u32,
    pub(super) distro_id: String,
    pub(super) distro_version: String,
    pub(super) expected_manifest_hash: String,
}

/// Collect variables, persist env/lock/grants, and onboard the unfiltered set.
pub(super) async fn finalize_unfiltered_distro_install(
    install: UnfilteredDistroInstall<'_>,
    daemon_lease: ProvisioningLease,
) -> anyhow::Result<ProvisioningLease> {
    let UnfilteredDistroInstall {
        home,
        operator,
        target,
        opts,
        variables,
        selected,
        signed_bundle,
        schema_version,
        distro_id,
        distro_version,
        expected_manifest_hash,
    } = install;

    // Collect variables needed by selected capsules.
    let vars = collect_variables(&variables, &selected, opts.yes, &opts.vars)?;

    // Write per-capsule env files BEFORE installing capsules so that
    // install_capsule's onboarding check finds existing values and
    // doesn't re-prompt for fields the distro already configured.
    write_env_files(home, &target, &selected, &variables, &vars)?;

    // Install each capsule with progress. The helper returns one
    // `LockedCapsule` per member that either installed or matched a complete
    // durable package; failures are reported and dropped.
    let total = selected.len();
    let install_result = install_capsules_with_resume(
        &selected,
        opts.offline,
        &target,
        signed_bundle.as_ref().map(|bundle| &bundle.pinned_refs),
    )
    .await?;
    let locked = install_result.locked;
    let newly_installed_names = install_result.newly_installed_names;
    let succeeded = locked.len();

    // Provisioning honesty: a run where every selected install FAILED must
    // not claim success, must not persist a Distro.lock, and must exit
    // non-zero. Writing a lock here would wedge recovery — the next `init`
    // would otherwise see a version-matched lock and short-circuit. An empty
    // selection (nothing to install) is not a
    // failure.
    reject_total_install_failure(total, succeeded)?;

    // Per-provider onboarding runs only on a FULL success — a partial run
    // isn't finalized, and its re-run will onboard once it converges. For
    // each selected llm-group capsule this runs its own `[env]` schema
    // prompt so capsule-specific fields (api_key, base_url) and the dynamic
    // `model` select resolve from the installed manifest — not just the
    // shared free-text `[variables]`. Shared values already written above
    // are preserved (the prompt skips set keys).
    if should_write_lock(total, succeeded) {
        super::onboarding::onboard_llm_providers(home, &target, &selected).await;
    }

    // Persist Distro.lock iff the run earned it (full success or empty
    // selection). A partial run deliberately writes NO lock so a re-run
    // actually retries the missing capsules instead of short-circuiting on a
    // stale member set — see `should_write_lock`.
    // Plain resume has no grant side effect. An explicit grant request covers
    // the complete verified set, including members completed in earlier batches.
    let lock = create_lock_from_parts(
        schema_version,
        &distro_id,
        &distro_version,
        &expected_manifest_hash,
        locked,
    );
    let wrote_lock = persist_lock_if_earned_daemon(&target, total, succeeded, &lock).await?;

    eprintln!();
    if wrote_lock {
        eprintln!("{}", Theme::success("Installation complete."));
        // Apply capsule grants (opt-in) or print the discoverability hint.
        // On a grant failure the capsules are already installed and the lock
        // is written; this returns Err so init exits non-zero with the exact
        // manual command to finish.
        let grant_names = super::grant::completed_grant_names(
            opts.grant_capsules,
            &lock.capsules,
            &newly_installed_names,
        );
        super::grant::apply_or_hint_grants(&operator, &target, &grant_names, opts.grant_capsules)
            .await?;
        eprintln!("  Run {} to start.", Theme::prompt("astrid"));
        Ok(daemon_lease)
    } else {
        // Partial provision (0 < succeeded < total): no lock was written, so
        // a re-run retries the rest. Exit NON-ZERO so automation and the
        // in-conversation flow don't read a partial install as success —
        // `astrid init` exits 0 IFF the distro is fully provisioned.
        bail!(
            "Installation incomplete: {succeeded}/{total} capsule(s) installed — \
             re-run `astrid init` to retry the rest."
        )
    }
}
