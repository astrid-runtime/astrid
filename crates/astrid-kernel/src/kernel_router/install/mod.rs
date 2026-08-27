//! Kernel-side `KernelRequest::InstallCapsule` handler.
//!
//! Delegates to the shared install library at [`astrid_capsule_install`].
//! Ordinary path-only installs are unchanged: remote shapes are rejected, a
//! locally signed artifact installs automatically, and no Station lock state
//! is touched.
//!
//! A typed [`StationInstallBinding`] changes the flow into one owner/capsule
//! critical section guarded by [`crate::Kernel::lock_capsule_view`]:
//!
//! 1. Verify the expected prior owner lock state inside that guard.
//! 2. Stage the caller's artifact exactly once into daemon-private storage,
//!    hashing during the copy and rejecting symlinks, non-regular files,
//!    oversize inputs, or size/SHA-256/BLAKE3 mismatches against the bound
//!    lock. The caller's path is never reopened after validation.
//! 3. Inspect authority, stage env values, and unpack/install exclusively
//!    from the retained staged copy.
//! 4. Commit the bound lock with a compare-and-swap over the exact prior
//!    slot bytes captured under the guard, then reconcile the runtime.
//!    Once the package bytes are durably installed, an activation failure
//!    never rolls the matching lock back.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_capsule_install::{
    AuthorityDecision, InstallOptions, InstallOutput, InstallPhase,
    inspect_archive_for_principal_with_layout, inspect_directory_for_principal_with_layout,
};
use astrid_core::kernel_api::{
    CapsuleInstallAuthority, CapsuleInstallEnv, CapsuleInstallProvenance, StationInstallBinding,
};
use astrid_events::kernel_api::KernelResponse;

mod env;
mod station;
#[cfg(test)]
mod station_regression_tests;
#[cfg(test)]
mod tests;

use env::stage_env_values;
use station::{StagedArchive, StationLease};

/// Handle `KernelRequest::InstallCapsule` by delegating to the shared
/// install library.
pub(super) struct InstallCapsuleRequest<'a> {
    pub(super) caller: &'a astrid_core::principal::PrincipalId,
    pub(super) requested_target: Option<&'a astrid_core::principal::PrincipalId>,
    pub(super) source: &'a str,
    pub(super) workspace: bool,
    pub(super) provenance: Option<&'a CapsuleInstallProvenance>,
    pub(super) authority: CapsuleInstallAuthority,
    pub(super) env: &'a [CapsuleInstallEnv],
    pub(super) station_binding: &'a Option<StationInstallBinding>,
}

pub(super) async fn handle_install_capsule(
    kernel: &Arc<crate::Kernel>,
    request: InstallCapsuleRequest<'_>,
) -> KernelResponse {
    let InstallCapsuleRequest {
        caller,
        requested_target,
        source,
        workspace,
        provenance,
        authority,
        env,
        station_binding,
    } = request;
    if workspace {
        return KernelResponse::Error(
            "workspace installs are CLI-only — the daemon has no meaningful CWD; \
             use a daemon install (drop the --workspace flag) instead"
                .to_string(),
        );
    }

    let caller_path = match local_install_path(source) {
        Ok(path) => path,
        Err(error) => return KernelResponse::Error(error),
    };

    let target = requested_target.unwrap_or(caller);
    // Resolve the immutable UID before any environment or package mutation.
    // A caller may name only a principal already present in the authenticated
    // directory; aliases never become durable package authorities.
    if let Err(error) = kernel
        .principal_directory
        .uid_for(target)
        .map_err(|error| format!("resolve target principal {target}: {error}"))
    {
        return KernelResponse::Error(error);
    }

    // The Station binding moves lock verification, artifact staging, package
    // installation, and the lock commit into one guarded critical section.
    let mut station_guard: Option<(StationLease, StagedArchive)> = None;
    if let Some(binding) = station_binding {
        match station::acquire_verified(kernel, target, binding, &caller_path).await {
            Ok(lease_and_staged) => {
                if let Err(error) =
                    validate_station_bound_provenance(provenance, &lease_and_staged.1)
                {
                    return KernelResponse::Error(error);
                }
                station_guard = Some(lease_and_staged);
            },
            Err(error) => return KernelResponse::Error(error),
        }
    } else if let Err(error) = validate_install_provenance(&caller_path, provenance) {
        return KernelResponse::Error(error);
    }

    let install_source: &Path = match station_guard.as_ref() {
        Some((_, staged)) => staged.file.path(),
        None => caller_path.as_path(),
    };
    let env_transaction = match stage_env_values(kernel, target, install_source, env).await {
        Ok(transaction) => transaction,
        Err(error) => return KernelResponse::Error(error),
    };

    let home = kernel.astrid_home.clone();

    let options = InstallOptions {
        workspace: false,
        original_source: Some(source.to_string()),
        skip_import_check: false,
        // Kernel-side installs run unattended — no human to answer
        // elicit() during the lifecycle hook. A capsule that depends
        // on install-time elicit must be configured via env before
        // being installed through this path.
        lifecycle_bus: None,
        storage: kernel.principal_store.clone().map(Arc::new),
        provenance_distro: provenance.and_then(|value| value.distro.clone()),
        provenance_source_digest: provenance.and_then(|value| value.source_digest.clone()),
    };

    let output = match run_authorized_install(
        kernel,
        target,
        install_source.to_path_buf(),
        home,
        options,
        authority,
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            if let Some(transaction) = env_transaction {
                transaction.rollback(kernel).await;
            }
            return KernelResponse::Error(error);
        },
    };

    // Package bytes are now durable. Commiting the bound lock under the
    // still-held guard is the operation's single atomic boundary; activation
    // failures afterwards leave both the matching lock and package intact.
    if let Some(binding) = station_binding
        && let Some((lease, _staged)) = station_guard.take()
        && let Err(error) = station::commit(kernel, target, binding, lease).await
    {
        if let Some(transaction) = env_transaction {
            transaction.rollback(kernel).await;
        }
        return KernelResponse::Error(error);
    }

    // Reconcile the exact installed capsule into the live runtime. An upgrade
    // must create a new runtime generation even when its bytes/hash are
    // unchanged (configuration and lifecycle state may have changed); merely
    // calling `ensure_principal_loaded` would return early on the old view.
    if let Err(error) = activate_installed_capsule(kernel, target, &output).await {
        if let Some(transaction) = env_transaction {
            transaction.rollback(kernel).await;
        }
        return KernelResponse::Error(error);
    }

    KernelResponse::Success(install_output_json(&output))
}

fn local_install_path(source: &str) -> Result<PathBuf, String> {
    let is_remote = source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("github.com/")
        || source.starts_with('@')
        || source.starts_with("gh:");
    if is_remote {
        return Err(format!(
            "kernel-side install accepts only local paths; resolve '{source}' via the \
             gateway registry route first (the daemon never fetches URLs)"
        ));
    }
    let path = std::path::PathBuf::from(source.strip_prefix("file://").unwrap_or(source));
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("source path does not exist: {}", path.display()))
    }
}

async fn run_authorized_install(
    kernel: &Arc<crate::Kernel>,
    principal: &astrid_core::principal::PrincipalId,
    path: PathBuf,
    home: astrid_core::dirs::AstridHome,
    options: InstallOptions,
    authority: CapsuleInstallAuthority,
) -> Result<InstallOutput, String> {
    let workspace_layout = kernel.workspace_layout.clone();
    let workspace_root = kernel.workspace_root.clone();
    let principal = principal.clone();
    let is_archive = path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("capsule"));
    let source_display = path.display().to_string();
    let authority =
        daemon_authority_decision(&path, &home, &principal, &workspace_layout, authority)?;
    let task = if is_archive {
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::unpack_and_install_authorized_for_principal_in_workspace(
                &path,
                &home,
                options,
                &principal,
                Some(&workspace_root),
                &authority,
                &workspace_layout,
            )
        })
    } else if path.is_dir() {
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::install_from_local_path_authorized_for_principal_in_workspace(
                &path,
                &home,
                options,
                &principal,
                Some(&workspace_root),
                &authority,
                &workspace_layout,
            )
        })
    } else {
        return Err(format!(
            "source must be a directory containing Capsule.toml or a *.capsule archive: \
             {source_display}"
        ));
    };
    task.await
        .map_err(|error| format!("install task panicked: {error}"))?
        .map_err(|error| format!("install failed: {error:#}"))
}

fn daemon_authority_decision(
    path: &Path,
    home: &astrid_core::dirs::AstridHome,
    principal: &astrid_core::principal::PrincipalId,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
    authority: CapsuleInstallAuthority,
) -> Result<AuthorityDecision, String> {
    if authority == CapsuleInstallAuthority::Automatic {
        return Ok(AuthorityDecision::Automatic);
    }
    let inspection = if path.is_file() {
        inspect_archive_for_principal_with_layout(path, home, principal, false, workspace_layout)
    } else {
        inspect_directory_for_principal_with_layout(path, home, principal, false, workspace_layout)
    }
    .map_err(|error| format!("inspect capsule install authority: {error:#}"))?;
    Ok(match authority {
        CapsuleInstallAuthority::Automatic => AuthorityDecision::Automatic,
        CapsuleInstallAuthority::ExplicitApproval => AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest,
        },
        CapsuleInstallAuthority::OperatorDistribution => AuthorityDecision::OperatorDistribution {
            content_digest: inspection.content_digest,
        },
    })
}

const MAX_PROVENANCE_TEXT_BYTES: usize = 128;
const MAX_SOURCE_DIGEST_BYTES: u64 = 64 * 1024 * 1024;

/// Validate bounded descriptive provenance independent of any byte source.
fn validate_provenance_shape(provenance: &CapsuleInstallProvenance) -> Result<(), String> {
    if let Some(distro) = provenance.distro.as_deref()
        && (distro.is_empty()
            || distro.len() > MAX_PROVENANCE_TEXT_BYTES
            || distro.chars().any(char::is_control))
    {
        return Err(
            "install provenance distro must be 1..=128 bytes and contain no control characters"
                .to_owned(),
        );
    }
    if let Some(expected) = provenance.source_digest.as_deref()
        && (expected.len() != 71
            || !expected.starts_with("blake3:")
            || !expected[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(
            "install provenance source_digest must be canonical blake3:<64 lowercase hex>"
                .to_owned(),
        );
    }
    Ok(())
}

fn provenance_source_digest_mismatch(expected: &str, actual: &str) -> String {
    format!("install provenance source_digest mismatch: expected {expected}, got {actual}")
}

/// Validate and bind provenance directly to the already-staged Station bytes;
/// the caller-owned source path is deliberately not touched again.
fn validate_station_bound_provenance(
    provenance: Option<&CapsuleInstallProvenance>,
    staged: &StagedArchive,
) -> Result<(), String> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    validate_provenance_shape(provenance)?;
    if let Some(expected) = provenance.source_digest.as_deref()
        && expected != staged.source_blake3
    {
        return Err(provenance_source_digest_mismatch(
            expected,
            &staged.source_blake3,
        ));
    }
    Ok(())
}

/// Validate and, when supplied, bind source provenance to the exact local
/// archive bytes before the install transaction stages env or publishes a
/// durable package. The wire accepts only canonical lowercase BLAKE3 text;
/// callers cannot use a path or an arbitrary label as a digest.
fn validate_install_provenance(
    source: &Path,
    provenance: Option<&CapsuleInstallProvenance>,
) -> Result<(), String> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    validate_provenance_shape(provenance)?;
    let Some(expected) = provenance.source_digest.as_deref() else {
        return Ok(());
    };
    let metadata = std::fs::metadata(source)
        .map_err(|error| format!("inspect provenance source {}: {error}", source.display()))?;
    if !metadata.is_file() {
        return Err(
            "install provenance source_digest is supported only for a local capsule archive"
                .to_owned(),
        );
    }
    if metadata.len() > MAX_SOURCE_DIGEST_BYTES {
        return Err(format!(
            "install provenance source exceeds {MAX_SOURCE_DIGEST_BYTES}-byte digest limit"
        ));
    }
    let bytes = std::fs::read(source)
        .map_err(|error| format!("read provenance source {}: {error}", source.display()))?;
    let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    if actual != expected {
        return Err(provenance_source_digest_mismatch(expected, &actual));
    }
    Ok(())
}

async fn activate_installed_capsule(
    kernel: &Arc<crate::Kernel>,
    caller: &astrid_core::principal::PrincipalId,
    output: &InstallOutput,
) -> Result<(), String> {
    let manifest =
        astrid_capsule::discovery::load_manifest(&output.target_dir.join("Capsule.toml"))
            .map_err(|error| format!("installed capsule could not be activated: {error}"))?;
    let id = astrid_capsule_types::CapsuleId::from_static(&manifest.package.name);
    kernel
        .reload_one_capsule(&id, caller)
        .await
        .map_err(|error| format!("capsule installed on disk but live activation failed: {error:#}"))
}

fn install_output_json(o: &InstallOutput) -> serde_json::Value {
    serde_json::json!({
        "target_dir": o.target_dir.display().to_string(),
        "phase": match o.phase {
            InstallPhase::Install => "install",
            InstallPhase::Upgrade => "upgrade",
        },
        "installed_version": o.installed_version,
        "previous_version": o.previous_version,
        "wasm_hash": o.wasm_hash,
        "env_path": o.env_path.display().to_string(),
        "env_needs_prompt": o.env_needs_prompt,
        "missing_imports": o.missing_imports.iter().map(|m| serde_json::json!({
            "namespace": m.namespace,
            "interface": m.interface,
            "requirement": m.requirement,
        })).collect::<Vec<_>>(),
        "export_conflicts": o.export_conflicts.iter().map(|c| serde_json::json!({
            "interface": c.interface,
            "existing_capsule": c.existing_capsule,
        })).collect::<Vec<_>>(),
    })
}
