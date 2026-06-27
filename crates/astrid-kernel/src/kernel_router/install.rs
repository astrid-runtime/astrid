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
//! 2. Hand the path to either [`unpack_and_install`] (for `*.capsule`
//!    archives) or [`install_from_local_path`] (for directories).
//! 3. On success, content-addressing has populated `bin/<hash>.wasm` /
//!    `wit/<hash>.wit` and the per-capsule directory now holds the
//!    manifest + meta. Trigger
//!    [`load_all_capsules`](crate::Kernel::load_all_capsules) so the
//!    new capsule is live without a daemon restart.
//! 4. Serialize the [`InstallOutput`] as a flat JSON payload the
//!    dashboard can render.
//!
//! [`unpack_and_install`]: astrid_capsule_install::unpack_and_install
//! [`install_from_local_path`]: astrid_capsule_install::install_from_local_path
//! [`InstallOutput`]: astrid_capsule_install::InstallOutput

use std::sync::Arc;

use astrid_capsule_install::{InstallOptions, InstallOutput, InstallPhase};
use astrid_events::kernel_api::KernelResponse;

/// Handle `KernelRequest::InstallCapsule` by delegating to the shared
/// install library.
pub(super) async fn handle_install_capsule(
    kernel: &Arc<crate::Kernel>,
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
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::unpack_and_install(&p, &h, opts)
        })
        .await
    } else if path.is_dir() {
        let p = path.clone();
        let h = home.clone();
        tokio::task::spawn_blocking(move || {
            astrid_capsule_install::install_from_local_path(&p, &h, opts)
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

    // Pick up the new capsule without a daemon restart. The loader
    // is idempotent on already-registered IDs.
    kernel.load_all_capsules().await;

    KernelResponse::Success(install_output_json(&output))
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
