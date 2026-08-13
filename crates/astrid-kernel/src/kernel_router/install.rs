//! Kernel-side `InstallCapsule` handler.
//!
//! Delegates to the shared install library at
//! [`astrid_capsule_install`]. The handler is **path-only**: network
//! sources (`@org/repo`, GitHub URLs, `gh:`, raw HTTPS)
//! are rejected with a structured error. The daemon must not fetch
//! arbitrary bytes during an install — that posture is enforced here.
//!
//! Flow:
//!
//! 1. Resolve the source string to a local path (rejecting remote shapes
//!    and `file://` is stripped to a real path).
//! 2. Hand the path to the authorized archive/directory installer. The daemon
//!    has no human interaction channel here, so only artifacts signed by this
//!    runtime's build identity are accepted automatically.
//! 3. On success, content-addressing has populated `bin/<hash>.wasm` /
//!    `wit/<hash>.wit` and the per-capsule directory now holds the
//!    manifest + meta. Reconcile that exact capsule into a fresh live runtime
//!    generation so installs and upgrades take effect without daemon restart.
//! 4. Serialize the [`InstallOutput`] as a flat JSON payload the
//!    dashboard can render.
//!
//! [`InstallOutput`]: astrid_capsule_install::InstallOutput

use std::sync::Arc;

use astrid_capsule_install::{AuthorityDecision, InstallOptions, InstallOutput, InstallPhase};
use astrid_events::kernel_api::KernelResponse;

/// Handle `KernelRequest::InstallCapsule` by delegating to the shared
/// install library.
pub(super) async fn handle_install_capsule(
    kernel: &Arc<crate::Kernel>,
    caller: &astrid_core::principal::PrincipalId,
    source: &str,
    workspace: bool,
) -> KernelResponse {
    if workspace {
        return KernelResponse::Error(
            "workspace installs are CLI-only — the daemon has no meaningful CWD; \
             use a daemon install (drop the --workspace flag) instead"
                .to_string(),
        );
    }

    // Reject anything that smells like a remote source. The gateway's
    // registry route resolves `id[@version]` → release artifact →
    // cached local archive, then hands the kernel a path here.
    // Anything URL-shaped is rejected.
    let is_remote = source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("github.com/")
        || source.starts_with('@')
        || source.starts_with("gh:");
    if is_remote {
        return KernelResponse::Error(format!(
            "kernel-side install accepts only local paths; resolve '{source}' via the \
             gateway registry route first (the daemon never fetches URLs)"
        ));
    }

    let path_str = source.strip_prefix("file://").unwrap_or(source);
    let path = std::path::PathBuf::from(path_str);
    if !path.exists() {
        return KernelResponse::Error(format!("source path does not exist: {}", path.display()));
    }

    let home = match astrid_core::dirs::AstridHome::resolve() {
        Ok(h) => h,
        Err(e) => return KernelResponse::Error(format!("resolve AstridHome: {e}")),
    };

    let opts = InstallOptions {
        workspace: false,
        original_source: Some(source.to_string()),
        skip_import_check: false,
        // Kernel-side installs run unattended — no human to answer
        // elicit() during the lifecycle hook. A capsule that depends
        // on install-time elicit must be configured via env before
        // being installed through this path.
        lifecycle_bus: None,
    };

    let is_archive = path.is_file()
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("capsule"));

    let install_result = if is_archive {
        let p = path.clone();
        let h = home.clone();
        let principal = caller.clone();
        let workspace_layout = kernel.workspace_layout.clone();
        let workspace_root = kernel.workspace_root.clone();
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::unpack_and_install_authorized_for_principal_in_workspace(
                &p,
                &h,
                opts,
                &principal,
                Some(&workspace_root),
                &AuthorityDecision::Automatic,
                &workspace_layout,
            )
        })
        .await
    } else if path.is_dir() {
        let p = path.clone();
        let h = home.clone();
        let principal = caller.clone();
        let workspace_layout = kernel.workspace_layout.clone();
        let workspace_root = kernel.workspace_root.clone();
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::install_from_local_path_authorized_for_principal_in_workspace(
                &p,
                &h,
                opts,
                &principal,
                Some(&workspace_root),
                &AuthorityDecision::Automatic,
                &workspace_layout,
            )
        })
        .await
    } else {
        return KernelResponse::Error(format!(
            "source must be a directory containing Capsule.toml or a *.capsule archive: {}",
            path.display()
        ));
    };

    let output = match install_result {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return KernelResponse::Error(format!("install failed: {e:#}")),
        Err(e) => return KernelResponse::Error(format!("install task panicked: {e}")),
    };

    // Reconcile the exact installed capsule into the live runtime. An upgrade
    // must create a new runtime generation even when its bytes/hash are
    // unchanged (configuration and lifecycle state may have changed); merely
    // calling `ensure_principal_loaded` would return early on the old view.
    if let Err(error) = activate_installed_capsule(kernel, caller, &output).await {
        return KernelResponse::Error(error);
    }

    KernelResponse::Success(install_output_json(&output))
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
