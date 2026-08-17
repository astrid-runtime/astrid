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
//! Windows user installs validate or provision the private Astrid and
//! principal boundaries before any read traverses the principal namespace.
//!
//! Pre-flight reads happen before any mutation of `target_dir`:
//!
//! 1. Parse manifest.
//! 2. Check export conflicts (advisory).
//! 3. Hash WASM at source → `bin/<hash>.wasm`.
//! 4. Hash WIT at source → `wit/store/<hash>.wit`.
//!
//! If any of those fail we haven't touched `target_dir` and the
//! existing install is intact. Only then do we:
//!
//! 5. Provision the remaining user or checked-workspace target boundary.
//! 6. Backup existing `target_dir` (rename to `.bak`).
//! 7. Copy non-WASM tree → `target_dir` (excludes `*.wasm` and
//!    `wit/`).
//! 8. Preserve durable env state through daemon control storage; no native
//!    env file is copied from the backup.
//! 9. Run lifecycle hook with bytes from `bin/`.
//! 10. Write `meta.json`.
//! 11. Cleanup backup.
//!
//! Failure after step 7 restores the backup over `target_dir`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::discovery::load_manifest;
use astrid_capsule::engine::wasm::host_state::LifecyclePhase;
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_events::EventBus;
use astrid_storage::RuntimePrincipalStore;

use crate::authority::{
    AuthorityDecision, AuthorityReceiptTransaction, InstalledAuthority,
    authority_for_install_source, authorize_install, inspect_directory_for_principal_in_workspace,
};
use crate::copy::copy_capsule_dir;
use crate::lifecycle::{run_lifecycle_for_principal, run_lifecycle_for_principal_with_storage};
use crate::manifest_check::{
    ExportConflict, MissingImport, check_export_conflicts_in_storage,
    check_export_conflicts_in_workspace, validate_imports_in_storage,
    validate_imports_in_workspace,
};
use crate::meta::{CapsuleMeta, read_meta, write_meta};
use crate::paths::{resolve_cache_target_dir, resolve_target_dir_for_in_workspace};
use crate::storage::read_durable_meta;
use crate::wasm::{WasmAddressed, content_address_wasm};
use crate::wit::{content_address_wit, version_map_to_strings};

#[derive(Clone, Copy)]
pub(crate) struct InstallWorkspace<'a> {
    pub(crate) root: Option<&'a Path>,
    pub(crate) layout: &'a WorkspaceLayout,
}

#[derive(Clone, Copy)]
pub(crate) struct ExpectedCapsuleIdentity<'a> {
    pub(crate) id: &'a CapsuleId,
    pub(crate) version: Option<&'a str>,
}

/// Knobs passed to [`install_from_local_path`].
#[derive(Default)]
pub struct InstallOptions {
    /// Install into the selected project's capsules directory instead of the
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
    /// Authoritative principal store used to publish the package. When set,
    /// the native target is only a verified disposable materialization; the
    /// durable package is committed before this function reports success.
    /// It may be absent only for an explicitly external workspace install;
    /// non-workspace callers fail closed and must route through the typed
    /// kernel install API.
    pub storage: Option<Arc<RuntimePrincipalStore>>,
    /// Bounded distro provenance copied into the durable `meta.json` package
    /// record. These fields are integrity/audit metadata only.
    pub provenance_distro: Option<String>,
    /// Canonical source-artifact digest copied into durable metadata.
    pub provenance_source_digest: Option<String>,
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
    /// Legacy env path slot retained for wire compatibility. It is always
    /// empty; durable configuration is queried through daemon storage.
    pub env_path: PathBuf,
    /// True when the manifest declares `[env]` entries. The CLI's prompt
    /// consults daemon storage and skips fields already configured.
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
/// This is a privileged embedding API: calling it treats the caller as the
/// local operator and records the exact artifact as operator-authorized. Code
/// handling an untrusted user or network source should inspect it and call an
/// `*_authorized_*` variant with an explicit [`AuthorityDecision`].
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
    install_from_local_path_with_layout(source_dir, home, options, &WorkspaceLayout::default())
}

/// Install a capsule using an explicit workspace layout.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn install_from_local_path_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    install_from_local_path_for_principal_with_layout(
        source_dir,
        home,
        options,
        &crate::paths::install_principal(),
        workspace_layout,
    )
}

/// Install a capsule for an explicit principal.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn install_from_local_path_for_principal(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
) -> anyhow::Result<InstallOutput> {
    install_from_local_path_for_principal_with_layout(
        source_dir,
        home,
        options,
        target_principal,
        &WorkspaceLayout::default(),
    )
}

/// Install a capsule for an explicit principal and workspace layout.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn install_from_local_path_for_principal_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let workspace_root = std::env::current_dir().ok();
    install_from_local_path_for_principal_in_workspace(
        source_dir,
        home,
        options,
        target_principal,
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Install a capsule with explicit principal and workspace inputs.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn install_from_local_path_for_principal_in_workspace(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    install_from_local_path_internal(
        source_dir,
        home,
        options,
        target_principal,
        InstallWorkspace {
            root: workspace_root,
            layout: workspace_layout,
        },
        None,
        None,
    )
}

/// Install for an explicit principal only when the loaded manifest identity
/// equals `expected`. When `expected_version` is present, the manifest version
/// must match it too. Both comparisons happen before any install mutation.
///
/// # Errors
///
/// Returns an error when the manifest identity or expected version differs,
/// or when any ordinary install validation or filesystem operation fails.
#[allow(clippy::needless_pass_by_value)]
pub fn install_from_local_path_checked_for_principal(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: &CapsuleId,
    expected_version: Option<&str>,
) -> anyhow::Result<InstallOutput> {
    install_from_local_path_checked_for_principal_with_layout(
        source_dir,
        home,
        options,
        target_principal,
        expected,
        expected_version,
        &WorkspaceLayout::default(),
    )
}

/// Checked install for an explicit principal and workspace layout.
#[allow(clippy::needless_pass_by_value)]
pub fn install_from_local_path_checked_for_principal_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: &CapsuleId,
    expected_version: Option<&str>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let workspace_root = std::env::current_dir().ok();
    install_from_local_path_checked_for_principal_in_workspace(
        source_dir,
        home,
        options,
        target_principal,
        InstallWorkspace {
            root: workspace_root.as_deref(),
            layout: workspace_layout,
        },
        ExpectedCapsuleIdentity {
            id: expected,
            version: expected_version,
        },
    )
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn install_from_local_path_checked_for_principal_in_workspace(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    workspace: InstallWorkspace<'_>,
    expected: ExpectedCapsuleIdentity<'_>,
) -> anyhow::Result<InstallOutput> {
    install_from_local_path_internal(
        source_dir,
        home,
        options,
        target_principal,
        workspace,
        Some(expected),
        None,
    )
}

/// Install a local capsule directory after enforcing one digest-bound
/// authority decision.
///
/// # Errors
///
/// Returns an error when provenance is invalid, the decision does not accept
/// this exact artifact, or ordinary installation fails.
#[allow(clippy::needless_pass_by_value)]
pub fn install_from_local_path_authorized_for_principal_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    decision: &AuthorityDecision,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let workspace_root = std::env::current_dir().ok();
    install_from_local_path_authorized_for_principal_in_workspace(
        source_dir,
        home,
        options,
        target_principal,
        workspace_root.as_deref(),
        decision,
        workspace_layout,
    )
}

/// Authorized local install using explicit workspace inputs.
///
/// # Errors
///
/// Returns an error when provenance is invalid, the decision does not accept
/// this exact artifact, or ordinary installation fails.
#[allow(clippy::needless_pass_by_value)]
pub fn install_from_local_path_authorized_for_principal_in_workspace(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    workspace_root: Option<&Path>,
    decision: &AuthorityDecision,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let inspection = inspect_directory_for_principal_in_workspace(
        source_dir,
        home,
        target_principal,
        options.workspace,
        workspace_root,
        workspace_layout,
    )?;
    let authority = authorize_install(&inspection, decision)?;
    install_from_local_path_internal(
        source_dir,
        home,
        options,
        target_principal,
        InstallWorkspace {
            root: workspace_root,
            layout: workspace_layout,
        },
        None,
        Some(authority),
    )
}

/// Checked-identity variant of
/// [`install_from_local_path_authorized_for_principal_with_layout`].
///
/// # Errors
///
/// Also fails when the inspected manifest identity or version differs from
/// the caller's expected release.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn install_from_local_path_checked_authorized_for_principal_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: &CapsuleId,
    expected_version: Option<&str>,
    decision: &AuthorityDecision,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let workspace_root = std::env::current_dir().ok();
    install_from_local_path_checked_authorized_for_principal_in_workspace(
        source_dir,
        home,
        options,
        target_principal,
        expected,
        expected_version,
        workspace_root.as_deref(),
        decision,
        workspace_layout,
    )
}

/// Checked authorized local install using explicit workspace inputs.
///
/// # Errors
///
/// Returns an error for rejected provenance, identity/version mismatch, or an
/// ordinary installation failure.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn install_from_local_path_checked_authorized_for_principal_in_workspace(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    expected: &CapsuleId,
    expected_version: Option<&str>,
    workspace_root: Option<&Path>,
    decision: &AuthorityDecision,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallOutput> {
    let inspection = inspect_directory_for_principal_in_workspace(
        source_dir,
        home,
        target_principal,
        options.workspace,
        workspace_root,
        workspace_layout,
    )?;
    if inspection.capsule_id != *expected {
        bail!(
            "capsule identity mismatch: expected '{expected}', manifest declares '{}'",
            inspection.capsule_id
        );
    }
    if let Some(expected_version) = expected_version
        && inspection.version != expected_version
    {
        bail!(
            "capsule version mismatch for '{expected}': expected '{expected_version}', manifest declares '{}'",
            inspection.version
        );
    }
    let authority = authorize_install(&inspection, decision)?;
    install_from_local_path_internal(
        source_dir,
        home,
        options,
        target_principal,
        InstallWorkspace {
            root: workspace_root,
            layout: workspace_layout,
        },
        Some(ExpectedCapsuleIdentity {
            id: expected,
            version: expected_version,
        }),
        Some(authority),
    )
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub(crate) fn install_from_local_path_internal(
    source_dir: &Path,
    home: &AstridHome,
    options: InstallOptions,
    target_principal: &PrincipalId,
    workspace: InstallWorkspace<'_>,
    expected: Option<ExpectedCapsuleIdentity<'_>>,
    installed_authority: Option<InstalledAuthority>,
) -> anyhow::Result<InstallOutput> {
    if !options.workspace && options.storage.is_none() {
        bail!(
            "non-workspace capsule installation requires the authoritative \
             RuntimePrincipalStore; route the request through KernelRequest::InstallCapsule"
        );
    }
    let checked_workspace = if options.workspace {
        let root = workspace
            .root
            .context("workspace install requires a workspace root")?;
        Some(
            workspace
                .layout
                .resolve(root)
                .context("selected workspace state path is unsafe")?,
        )
    } else {
        None
    };
    let manifest_path = source_dir.join("Capsule.toml");
    if !manifest_path.exists() {
        bail!("No Capsule.toml found in {}", source_dir.display());
    }
    let manifest = load_manifest(&manifest_path).context("failed to load Capsule manifest")?;
    let id = CapsuleId::new(manifest.package.name.clone())?;
    if let Some(expected) = expected
        && id != *expected.id
    {
        bail!(
            "capsule identity mismatch: expected '{}', manifest declares '{id}'",
            expected.id
        );
    }
    let installed_version = manifest.package.version.clone();
    if let Some(expected_version) = expected.and_then(|expected| expected.version)
        && installed_version != expected_version
    {
        bail!(
            "capsule version mismatch for '{id}': expected '{expected_version}', manifest declares '{installed_version}'"
        );
    }

    // Re-verify the exact source immediately before any target mutation. This
    // closes the gap between pre-install approval and the transactional copy,
    // including provenance-envelope swaps that leave content bytes unchanged.
    let mut installed_authority =
        authority_for_install_source(source_dir, &manifest, installed_authority)?;

    // Pre-flight checks — pure reads, no target mutation.
    let export_conflicts = if let Some(store) = options.storage.as_ref() {
        let uid = store
            .principal_directory()
            .uid_for(target_principal)
            .with_context(|| format!("resolve durable uid for principal {target_principal}"))?;
        check_export_conflicts_in_storage(&manifest, store, uid)?
    } else {
        check_export_conflicts_in_workspace(
            &manifest,
            home,
            target_principal,
            workspace.root,
            workspace.layout,
        )?
    };

    // Resolve and provision the target boundary before the backup rename.
    // Windows must create a fresh user/principal tree through the typed home
    // boundaries so it never inherits an ambient parent ACL.
    // A storage-backed install gets a fresh, owner- and generation-scoped
    // disposable target. The durable registry remains authoritative; the
    // native directory is never used to infer whether an install exists.
    let cache_scope = if let Some(store) = options.storage.as_ref() {
        let uid = store
            .principal_directory()
            .uid_for(target_principal)
            .with_context(|| format!("resolve durable uid for principal {target_principal}"))?;
        let archive = crate::storage::canonical_capsule_archive(source_dir)
            .context("canonicalize capsule archive for cache generation")?;
        let digest = blake3::hash(&archive).to_hex().to_string();
        let target = resolve_cache_target_dir(
            home,
            uid,
            id.as_str(),
            &digest,
            options.workspace,
            workspace.root,
            workspace.layout,
        )?;
        Some((uid, digest, target))
    } else {
        None
    };
    let target_dir = cache_scope.as_ref().map_or_else(
        || {
            resolve_target_dir_for_in_workspace(
                home,
                target_principal,
                id.as_str(),
                options.workspace,
                workspace.root,
                workspace.layout,
            )
        },
        |(_, _, target)| Ok(target.clone()),
    )?;
    if let Some(selection) = &checked_workspace {
        let cache_parent = cache_scope.as_ref().map_or_else(
            || PathBuf::from("capsules").join(id.as_str()),
            |(uid, _, _)| {
                PathBuf::from("capsules")
                    .join(uid.to_string())
                    .join(id.as_str())
            },
        );
        selection
            .ensure_directory(&cache_parent)
            .context("failed to create checked workspace capsule directory")?;
        let cache_relative = cache_scope.as_ref().map_or_else(
            || cache_parent.clone(),
            |(uid, digest, _)| {
                PathBuf::from("capsules")
                    .join(uid.to_string())
                    .join(id.as_str())
                    .join(digest)
            },
        );
        selection
            .resolve_directory(cache_relative)
            .context("workspace capsule target changed after selection")?;
        selection
            .verify_tree("capsules")
            .context("workspace capsule tree contains an unsafe redirect")?;
    } else {
        let parent = target_dir.parent().context("target dir has no parent")?;
        if cache_scope.is_some() {
            astrid_core::platform_fs::verify_no_redirects(parent)
                .context("capsule cache parent is redirected or unsafe")?;
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            astrid_core::platform_fs::verify_no_redirects(parent)
                .context("capsule cache parent changed during creation")?;
        } else {
            #[cfg(not(windows))]
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    // Phase detection comes from the durable registry whenever an authorized
    // store is supplied. The native target is only a disposable cache and may
    // be absent or stale after restart; consulting it would let cache residue
    // overwrite the authoritative generation.
    let existing_meta = options.storage.as_ref().map_or_else(
        || Ok(read_meta(&target_dir)),
        |store| read_durable_meta(store, target_principal, id.as_str()),
    )?;
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
    installed_authority.wasm_hash_pinned = true;
    installed_authority.approved_wasm_hash = wasm.as_ref().map(|w| w.hash.clone());
    let wit_files =
        content_address_wit(home, source_dir).context("failed to content-address WIT files")?;

    // The pending marker lives outside capsule-writable VFS roots. If the
    // process dies during target replacement, load fails closed until the
    // interrupted authority transaction is inspected and repaired.
    let authority_transaction =
        AuthorityReceiptTransaction::stage(home, &target_dir, &installed_authority)?;

    // Backup the existing install (rename to .bak). Any failure from
    // this point onward must restore the backup over target_dir.
    let backup_dir = if target_dir.exists() {
        let backup = target_dir.with_extension("bak");
        if let Some(selection) = &checked_workspace {
            selection
                .verify()
                .context("workspace changed before install backup")?;
            let backup_name = backup
                .file_name()
                .context("workspace capsule backup has no file name")?;
            selection
                .resolve_directory(Path::new("capsules").join(backup_name))
                .context("workspace capsule backup path is unsafe")?;
        }
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

    if let Some(selection) = &checked_workspace {
        selection
            .verify()
            .context("workspace changed before capsule copy")?;
    }

    // Copy non-WASM tree to target. Excludes `*.wasm` and `wit/`.
    if let Err(e) = copy_capsule_dir(source_dir, &target_dir) {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(e).context("failed to copy capsule source to target");
    }

    // Lifecycle hook — bytes from the content store, not the target.
    if let Some(ref w) = wasm {
        let lifecycle_result = options.storage.as_ref().map_or_else(
            || {
                run_lifecycle_for_principal(
                    &target_dir,
                    w.bytes.clone(),
                    &manifest,
                    home,
                    target_principal,
                    phase.to_lifecycle(),
                    previous_version.as_deref(),
                    options.lifecycle_bus.clone(),
                )
            },
            |storage| {
                run_lifecycle_for_principal_with_storage(
                    &target_dir,
                    w.bytes.clone(),
                    &manifest,
                    home,
                    target_principal,
                    storage,
                    phase.to_lifecycle(),
                    previous_version.as_deref(),
                    options.lifecycle_bus.clone(),
                )
            },
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
            .or_else(|| existing_meta.as_ref().and_then(|m| m.source.clone())),
        imports: version_map_to_strings(&manifest.imports, |d| d.version.to_string()),
        exports: version_map_to_strings(&manifest.exports, |d| d.version.to_string()),
        wasm_hash: wasm.as_ref().map(|w: &WasmAddressed| w.hash.clone()),
        wit_files,
        // Provenance fields are stamped by the distro install path
        // (offline `.shuttle`), not the generic local install.
        provenance_distro: options.provenance_distro.clone().or_else(|| {
            existing_meta
                .as_ref()
                .and_then(|meta| meta.provenance_distro.clone())
        }),
        provenance_source_digest: options.provenance_source_digest.clone().or_else(|| {
            existing_meta
                .as_ref()
                .and_then(|meta| meta.provenance_source_digest.clone())
        }),
        ..Default::default()
    };
    if let Err(e) = write_meta(&target_dir, &meta) {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(e);
    }
    if let Some(store) = options.storage.as_ref()
        && let Err(error) = crate::storage::publish_directory_package(
            store,
            target_principal,
            source_dir,
            &target_dir,
            &meta,
            &installed_authority,
        )
    {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(error).context("failed to publish authoritative capsule package");
    }
    if let Some(selection) = &checked_workspace {
        let validation = (|| {
            selection
                .resolve_directory(Path::new("capsules").join(id.as_str()))
                .context("workspace capsule target changed during install")?;
            selection
                .verify_tree("capsules")
                .context("workspace capsule tree changed during install")?;
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(error) = validation {
            rollback(&target_dir, backup_dir.as_deref());
            return Err(error);
        }
    }
    if let Err(e) = authority_transaction.commit() {
        rollback(&target_dir, backup_dir.as_deref());
        return Err(e);
    }

    // Durable env values live in daemon control storage.  The install library
    // cannot inspect that authority directly, so the CLI always gets a prompt
    // signal for manifests with env declarations; its storage-backed prompt is
    // idempotent and skips fields already present.
    let env_path = PathBuf::new();
    let env_needs_prompt = !manifest.env.is_empty();

    let missing_imports = if options.skip_import_check {
        Vec::new()
    } else if let Some(store) = options.storage.as_ref() {
        let uid = store
            .principal_directory()
            .uid_for(target_principal)
            .with_context(|| format!("resolve durable uid for principal {target_principal}"))?;
        validate_imports_in_storage(&manifest, store, uid)?
    } else {
        validate_imports_in_workspace(
            &manifest,
            home,
            target_principal,
            workspace.root,
            workspace.layout,
        )
    };

    // Cleanup the backup — success path.
    if let Some(backup) = backup_dir
        && let Err(e) = std::fs::remove_dir_all(&backup)
    {
        tracing::warn!(path = %backup.display(), error = %e, "failed to remove install backup");
    }

    if let Some(selection) = &checked_workspace {
        selection
            .verify_tree("capsules")
            .context("workspace capsule tree changed before install completion")?;
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
