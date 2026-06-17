//! Install a capsule from a directory on disk.
//!
//! By the time we get here, the source has already been resolved to
//! a real directory containing a `Capsule.toml`. GitHub clones and
//! `.capsule` archive unpacks — all of that happens in the CLI
//! before this is called. Archive unpack
//! lives in [`crate::archive::unpack_and_install`], which staged the
//! archive into a tempdir and then forwards here.
//!
//! ## Order
//!
//! Pre-flight reads happen before any mutation of `target_dir`:
//!
//! 1. Parse manifest.
//! 2. Check export conflicts (advisory).
//! 3. Hash WASM at source → `bin/<hash>.wasm`.
//! 4. Hash WIT at source → `wit/<hash>.wit`.
//!
//! If any of those fail we haven't touched `target_dir` and the
//! existing install is intact. Only then do we:
//!
//! 5. Backup existing `target_dir` (rename to `.bak`).
//! 6. Copy non-WASM tree → `target_dir` (excludes `*.wasm` and
//!    `wit/`).
//! 7. Restore `.env.json` from the backup if present.
//! 8. Run lifecycle hook with bytes from `bin/`.
//! 9. Write `meta.json`.
//! 10. Cleanup backup.
//!
//! Failure after step 6 restores the backup over `target_dir`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use astrid_capsule::discovery::load_manifest;
use astrid_capsule::engine::wasm::host_state::LifecyclePhase;
use astrid_core::dirs::AstridHome;
use astrid_events::EventBus;

use crate::copy::copy_capsule_dir;
use crate::lifecycle::run_lifecycle;
use crate::manifest_check::{
    ExportConflict, MissingImport, check_export_conflicts, validate_imports,
};
use crate::meta::{CapsuleMeta, read_meta, write_meta};
use crate::paths::{resolve_env_path, resolve_target_dir, restore_env_from_backup};
use crate::wasm::{WasmAddressed, content_address_wasm};
use crate::wit::{content_address_wit, materialize_wit_mirror, version_map_to_strings};

/// Knobs passed to [`install_from_local_path`].
#[derive(Default)]
pub struct InstallOptions {
    /// Install into `<cwd>/.astrid/capsules/` instead of the
    /// principal's home directory.
    pub workspace: bool,
    /// The source string the user originally typed (e.g. a GitHub
    /// URL). Stored verbatim in `meta.json` so
    /// `astrid capsule update` can re-fetch from the same place.
    /// `None` for direct local-path installs where the source IS the
    /// path.
    pub original_source: Option<String>,
    /// Skip the post-install import-satisfaction warning. CLI's batch
    /// distro init sets this — every capsule in a distro is installed
    /// together so partial-state warnings aren't useful.
    pub skip_import_check: bool,
    /// External event bus to plumb through the lifecycle hook. The
    /// CLI passes one with a stdin elicit handler subscribed. The
    /// kernel-side handler passes `None` — no human at the daemon end
    /// to answer prompts.
    pub lifecycle_bus: Option<EventBus>,
}

/// What an install produced.
///
/// The library reports diagnostics back to the caller as data rather
/// than printing — CLI renders to stderr, gateway returns them as
/// structured fields a dashboard can display.
#[derive(Debug)]
pub struct InstallOutput {
    /// Final on-disk location of the capsule's per-install directory.
    pub target_dir: PathBuf,
    /// Whether this was a first install or an upgrade.
    pub phase: InstallPhase,
    /// Version we just installed.
    pub installed_version: String,
    /// Version that was previously installed, if any.
    pub previous_version: Option<String>,
    /// BLAKE3 hex of the WASM binary, if the capsule had one.
    pub wasm_hash: Option<String>,
    /// Path of `.env.json` for this capsule. The CLI checks if the
    /// file exists; if not and the manifest declares `[env]` entries,
    /// it prompts. Kernel-side ignores.
    pub env_path: PathBuf,
    /// True when the manifest has `[env]` entries that don't yet have
    /// values on disk. Caller decides whether to prompt or surface as
    /// a "needs configuration" hint.
    pub env_needs_prompt: bool,
    /// Non-optional imports the capsule needs that aren't satisfied
    /// by another currently-installed capsule. Empty when
    /// `skip_import_check` was set.
    pub missing_imports: Vec<MissingImport>,
    /// Other installed capsules that already export interfaces this
    /// capsule also exports. Informational only — coexistence is
    /// valid.
    pub export_conflicts: Vec<ExportConflict>,
}

/// Whether the install ran as a fresh install or upgraded an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPhase {
    /// First install — no prior `meta.json` at the target.
    Install,
    /// Upgrade over an existing install.
    Upgrade,
}

impl InstallPhase {
    fn to_lifecycle(self) -> LifecyclePhase {
        match self {
            Self::Install => LifecyclePhase::Install,
            Self::Upgrade => LifecyclePhase::Upgrade,
        }
    }
}

/// Install a capsule from `source_dir` (a directory containing
/// `Capsule.toml`).
///
/// # Errors
///
/// Propagates manifest-parse errors, content-addressing failures,
/// copy / lifecycle / meta-write failures. The target directory is
/// rolled back from backup on any failure that happens after the
/// rename.
// `options` is taken by value because callers conventionally build
// it inline at the call site and don't reuse the struct afterwards.
// `too_many_lines`: the body reads as one coherent ordered list of
// install phases; chopping it into smaller fns would only spread the
// rollback / error-propagation paths across modules.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn install_from_local_path(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
) -> anyhow::Result<InstallOutput> {
    let manifest_path = source_dir.join("Capsule.toml");
    if !manifest_path.exists() {
        bail!("No Capsule.toml found in {}", source_dir.display());
    }
    let manifest = load_manifest(&manifest_path).context("failed to load Capsule manifest")?;
    let id = manifest.package.name.clone();
    let installed_version = manifest.package.version.clone();

    // Pre-flight checks — pure reads, no target mutation.
    let export_conflicts = check_export_conflicts(&manifest)?;

    // Resolve target. The parent must exist before we attempt the
    // backup-rename later; create it now.
    let target_dir = resolve_target_dir(home, &id, options.workspace)?;
    let parent = target_dir.parent().context("target dir has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    // Phase detection from existing meta (read-only).
    let existing_meta = read_meta(&target_dir);
    let (phase, previous_version) = if let Some(ref meta) = existing_meta {
        (InstallPhase::Upgrade, Some(meta.version.clone()))
    } else {
        (InstallPhase::Install, None)
    };

    // Source-direct content-addressing. Nothing under target_dir is
    // touched yet — if any of these fail the existing install (if
    // any) is intact.
    let wasm = content_address_wasm(home, source_dir, &manifest)
        .context("failed to content-address WASM binary")?;
    let wit_files =
        content_address_wit(home, source_dir).context("failed to content-address WIT files")?;

    // Backup the existing install (rename to .bak). Any failure from
    // this point onward must restore the backup over target_dir.
    let backup_dir = if target_dir.exists() {
        let backup = target_dir.with_extension("bak");
        if backup.exists() {
            std::fs::remove_dir_all(&backup)
                .with_context(|| format!("failed to remove stale backup {}", backup.display()))?;
        }
        std::fs::rename(&target_dir, &backup).with_context(|| {
            format!(
                "failed to rename {} → {}",
                target_dir.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };

    // Copy non-WASM tree to target. Excludes `*.wasm` and `wit/`.
    if let Err(e) = copy_capsule_dir(source_dir, &target_dir) {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(e).context("failed to copy capsule source to target");
    }

    // Preserve existing .env.json (user configuration survives reinstall).
    if let Some(ref backup) = backup_dir {
        restore_env_from_backup(home, backup, &id);
    }

    // Lifecycle hook — bytes from the content store, not the target.
    if let Some(ref w) = wasm {
        let lifecycle_result = run_lifecycle(
            &target_dir,
            w.bytes.clone(),
            &manifest,
            phase.to_lifecycle(),
            previous_version.as_deref(),
            options.lifecycle_bus.clone(),
        );
        if let Err(e) = lifecycle_result {
            rollback(&target_dir, backup_dir.as_deref());
            return Err(e);
        }
    }

    // Persist meta.json.
    let now = chrono::Utc::now().to_rfc3339();
    let meta = CapsuleMeta {
        version: installed_version.clone(),
        installed_at: existing_meta
            .as_ref()
            .map_or_else(|| now.clone(), |m| m.installed_at.clone()),
        updated_at: now,
        source: options
            .original_source
            .clone()
            .or_else(|| existing_meta.and_then(|m| m.source)),
        imports: version_map_to_strings(&manifest.imports, |d| d.version.to_string()),
        exports: version_map_to_strings(&manifest.exports, |d| d.version.to_string()),
        wasm_hash: wasm.as_ref().map(|w: &WasmAddressed| w.hash.clone()),
        wit_files,
    };
    if let Err(e) = write_meta(&target_dir, &meta) {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(e);
    }

    // Mirror the capsule's WIT into the principal's `home://wit/` so the
    // system capsule's `list_interfaces` / `read_interface` tools can
    // read it — the canonical content store is BLAKE3-keyed and outside
    // any VFS scheme a capsule can reach. Best-effort: the capsule is
    // already installed and committed, so a mirror failure must not roll
    // it back. It degrades introspection visibility, not the install.
    if let Err(e) =
        materialize_wit_mirror(home, &crate::paths::install_principal(), &meta.wit_files)
    {
        tracing::warn!(
            capsule = %id,
            error = %format!("{e:#}"),
            "failed to materialize home://wit mirror; introspection tools may not see this capsule's interfaces"
        );
    }

    // Determine env-prompt signal for the caller.
    let env_path = resolve_env_path(home, &id)?;
    let env_needs_prompt = !manifest.env.is_empty() && !env_path.exists();

    let missing_imports = if options.skip_import_check {
        Vec::new()
    } else {
        validate_imports(&manifest)
    };

    // Cleanup the backup — success path.
    if let Some(backup) = backup_dir
        && let Err(e) = std::fs::remove_dir_all(&backup)
    {
        tracing::warn!(path = %backup.display(), error = %e, "failed to remove install backup");
    }

    Ok(InstallOutput {
        target_dir,
        phase,
        installed_version,
        previous_version,
        wasm_hash: wasm.map(|w| w.hash),
        env_path,
        env_needs_prompt,
        missing_imports,
        export_conflicts,
    })
}

/// Restore `backup_dir` over `target_dir`. Best-effort — logs and
/// continues on failure since we're already in an error path.
fn rollback(target_dir: &Path, backup_dir: Option<&Path>) {
    let _ = std::fs::remove_dir_all(target_dir);
    if let Some(backup) = backup_dir
        && let Err(e) = std::fs::rename(backup, target_dir)
    {
        tracing::error!(
            target = %target_dir.display(),
            backup = %backup.display(),
            error = %e,
            "failed to restore install backup on rollback"
        );
    }
}
