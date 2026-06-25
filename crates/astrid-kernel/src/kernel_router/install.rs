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
             use a system install (drop the --workspace flag) instead"
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

    // The admin/gateway install path is trusted (it required an authenticated
    // admin principal to reach this handler), so auto-approve the capsule's
    // declared capabilities (#995). Without this the freshly-installed capsule
    // would load inert on the `load_all_capsules` call below. Best-effort: a
    // failure here only means the capsule loads inert until an operator runs
    // `astrid capsule approve`, which is the fail-secure direction. Off the
    // async executor — it re-reads the manifest and writes the record (blocking
    // `std::fs`), the same way the install above runs in `spawn_blocking`.
    {
        let home = home.clone();
        let target_dir = output.target_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || auto_approve_admin_install(&home, &target_dir))
                .await
        {
            tracing::warn!(error = %e, "admin install: auto-approve task failed");
        }
    }

    // Pick up the new capsule without a daemon restart. The loader
    // is idempotent on already-registered IDs.
    kernel.load_all_capsules().await;

    KernelResponse::Success(install_output_json(&output))
}

/// Auto-approve the capability fingerprint of the capsule just installed under
/// `target_dir` for the install principal (#995). The admin install path is
/// trusted, so its capsules become active without an interactive prompt.
fn auto_approve_admin_install(home: &astrid_core::dirs::AstridHome, target_dir: &std::path::Path) {
    let capsule_id = target_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    let Some(capsule_id) = capsule_id else {
        tracing::warn!("admin install: target dir has no name; cannot record approval");
        return;
    };
    let manifest_path = target_dir.join("Capsule.toml");
    let manifest = match astrid_capsule::discovery::load_manifest(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                capsule = %capsule_id,
                error = %e,
                "admin install: could not re-read manifest to record approval; \
                 capsule will load inert until approved"
            );
            return;
        },
    };
    let fingerprint = astrid_capsule::security::approval::capability_fingerprint(&manifest);
    let principal = astrid_capsule_install::install_principal();
    // Key on the manifest's package name — the exact id the engine consults at
    // load — not the on-disk directory name, so they can never diverge.
    if let Err(e) = astrid_capsule::security::approval::approve(
        home,
        &principal,
        &manifest.package.name,
        fingerprint,
    ) {
        tracing::warn!(
            capsule = %capsule_id,
            %principal,
            error = %e,
            "admin install: failed to record capability approval; \
             capsule will load inert until approved"
        );
    }
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
