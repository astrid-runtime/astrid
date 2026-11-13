//! Explicit admission of the durable native runtime file tree.
//!
//! The runtime tree is a host-facing source snapshot. Its durable regular
//! files become system-owned named content; only the hosted volume and live
//! IPC socket remain outside the volume.

use std::path::{Component, Path, PathBuf};

use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};
use astrid_core::dirs::AstridHome;
use astrid_core::platform_fs::StagingScope;

use super::{
    ContiguousFileIngest, PackedProjectionIngest, RuntimePrincipalStore, StateOwner,
    runtime_tree_active::{ACTIVE_PROJECTION_NAME, ActiveProjectionEntry, ReceiptPhase},
};

use super::runtime_tree_active as active;
mod active_receipt;
pub(super) mod admission;
#[cfg(test)]
mod key_recovery_tests;
#[cfg(test)]
mod lifecycle_tests;
use active_receipt::ActiveReceiptDeriver;
mod projection;
mod restoration;
mod retirement;
use retirement::transition_retiring_projection;
mod stopped_recovery;
#[cfg(test)]
mod stopped_staging_matrix_tests;
use projection::confined_projection_path;
#[cfg(test)]
use projection::write_projection_file;
pub(super) use restoration::restore_projection;

const VOLUME_PATH_PREFIX: &str = "volume";
const SOCKET_PATH: &str = "run/system.sock";
const CANONICAL_VOLUME: &str = "astrid.volume";
const MIGRATING_VOLUME: &str = "astrid.migrating";
const LEGACY_VAR_VOLUME: &str = "var/astrid.volume";
const DIRECTORY_STORE_PREFIX: &str = "var/principal-store";
const QUARANTINE_PREFIX: &str = "quarantine/principal-store";
const TRANSIENT_PREFIX: &str = "run";
const RUNTIME_KEY_PROJECTION: &str = "keys/runtime.key";
const STAGING_JOURNAL_PROJECTION: &str = "var/content-staging/intents.v1.log";
const TRANSACTION_STAGING_PATHS: &[&str] = &[
    "etc/.layout-version.next",
    "var/migrations/.layout-v1-to-v2.intent.next",
    "var/migrations/.layout-v1-to-v2.retiring.next",
    "var/migrations/.layout-v1-to-v2.complete.next",
];
const HOST_EXECUTABLES: &[&str] = &["astrid", "astrid-daemon", "bin/astrid", "bin/astrid-daemon"];

/// One regular file discovered in the native runtime tree.
///
/// The source path is retained only for the immediate packed admission. The
/// name, length, and modification time form the host-side receipt identity
/// used by the kernel to skip an unchanged tree on later boots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTreeEntry {
    name: ContentName,
    source_path: PathBuf,
    logical_bytes: u64,
    modified_nanos: i128,
}

impl RuntimeTreeEntry {
    /// Borrow the slash-separated catalog name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the source file length captured by the scan.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Return the source modification time as signed Unix nanoseconds.
    #[must_use]
    pub const fn modified_nanos(&self) -> i128 {
        self.modified_nanos
    }
}

/// Scan the native runtime tree without reading file payloads.
pub(super) fn scan(runtime_root: &Path) -> StorageResult<Vec<RuntimeTreeEntry>> {
    scan_with_receipt(runtime_root, None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanPolicy {
    Admission,
    Publication,
}

fn scan_with_receipt(
    runtime_root: &Path,
    receipt: Option<&active::ActiveProjectionReceipt>,
) -> StorageResult<Vec<RuntimeTreeEntry>> {
    scan_with_policy(runtime_root, receipt, ScanPolicy::Admission)
}

fn scan_with_policy(
    runtime_root: &Path,
    receipt: Option<&active::ActiveProjectionReceipt>,
    policy: ScanPolicy,
) -> StorageResult<Vec<RuntimeTreeEntry>> {
    tracing::trace!(target: "astrid_storage::runtime_tree_scan", "scan runtime source tree");
    let metadata = std::fs::symlink_metadata(runtime_root)
        .map_err(|error| tree_error(runtime_root, format!("inspect source root: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(tree_error(
            runtime_root,
            "source root is not a real directory".to_owned(),
        ));
    }

    let mut files = Vec::new();
    collect_files(runtime_root, runtime_root, &mut files, receipt, policy)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
        .into_iter()
        .map(|(_, path, metadata)| {
            let name = content_name_from_relative(&path, runtime_root)?;
            let modified_nanos = modified_nanos(&metadata, &path)?;
            Ok(RuntimeTreeEntry {
                name,
                source_path: path,
                logical_bytes: metadata.len(),
                modified_nanos,
            })
        })
        .collect()
}

/// Walk `runtime_root` and publish its durable regular files as one packed
/// system-owned content batch.
pub(super) fn admit(store: &RuntimePrincipalStore, runtime_root: &Path) -> StorageResult<()> {
    let entries = scan(runtime_root)?;
    let validated = entries
        .into_iter()
        .map(|entry| ContiguousFileIngest::new(entry.name, entry.source_path, entry.logical_bytes));
    store.put_contiguous_files(StateOwner::System, validated)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, std::fs::Metadata)>,
    receipt: Option<&active::ActiveProjectionReceipt>,
    policy: ScanPolicy,
) -> StorageResult<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| tree_error(directory, format!("read directory: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tree_error(directory, format!("read directory entry: {error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| tree_error(&path, "source entry escaped runtime root".to_owned()))?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| tree_error(&path, format!("inspect source entry: {error}")))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(tree_error(
                &path,
                "source tree contains a symbolic link".to_owned(),
            ));
        }
        // Sockets and other host-special entries are never catalog content.
        // Ignore them so a stale endpoint cannot fail admission of the
        // regular files that make up the runtime snapshot.
        if let Some(relative_text) = relative.to_str() {
            let relative_text = normalize_relative_path(relative_text);
            if is_excluded(&relative_text) {
                continue;
            }
            if metadata.is_dir() {
                if policy == ScanPolicy::Publication && relative_text == STAGING_JOURNAL_PROJECTION
                {
                    return Err(tree_error(
                        &path,
                        "pack-open staging journal is not a regular file",
                    ));
                }
                // Only scoped RETIRING recovery reserves temporary-shaped
                // directories. Ordinary admission retains its existing rules.
                if let Some(receipt) = receipt
                    && astrid_core::platform_fs::is_structural_private_staging_name(
                        &entry.file_name(),
                    )
                    && !receipt.contains_inventory_name(&format!("{relative_text}/"))
                {
                    return Err(tree_error(
                        &path,
                        format!(
                            "retiring projection contains unreceipted host file {relative_text}"
                        ),
                    ));
                }
                collect_files(root, &path, files, receipt, policy)?;
            } else if metadata.is_file() {
                files.push((relative_text, path, metadata));
            } else if policy == ScanPolicy::Publication {
                return Err(tree_error(
                    &path,
                    "running projection contains an unadmitted special entry",
                ));
            }
        } else if metadata.is_dir() || metadata.is_file() || policy == ScanPolicy::Publication {
            return Err(tree_error(
                &path,
                "source entry path is not valid UTF-8".to_owned(),
            ));
        }
    }
    Ok(())
}

fn modified_nanos(metadata: &std::fs::Metadata, path: &Path) -> StorageResult<i128> {
    let modified = metadata
        .modified()
        .map_err(|error| tree_error(path, format!("read source modification time: {error}")))?;
    let duration = match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).map_err(|_| {
            tree_error(
                path,
                "source modification time exceeds receipt range".to_owned(),
            )
        })?,
        Err(error) => {
            let nanos = i128::try_from(error.duration().as_nanos()).map_err(|_| {
                tree_error(
                    path,
                    "source modification time exceeds receipt range".to_owned(),
                )
            })?;
            nanos.checked_neg().ok_or_else(|| {
                tree_error(
                    path,
                    "source modification time exceeds receipt range".to_owned(),
                )
            })?
        },
    };
    Ok(duration)
}

fn content_name_from_relative(path: &Path, root: &Path) -> StorageResult<ContentName> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| tree_error(path, "source entry escaped runtime root".to_owned()))?;
    let mut name = String::new();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(tree_error(
                path,
                "source entry has a non-normal path component".to_owned(),
            ));
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| tree_error(path, "source entry path is not valid UTF-8".to_owned()))?;
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(segment);
    }
    ContentName::new(name).map_err(|error| {
        tree_error(
            path,
            format!("source entry is not a valid content name: {error}"),
        )
    })
}

fn normalize_relative_path(relative: &str) -> String {
    relative.replace('\\', "/")
}

fn is_path_or_descendant(relative: &str, prefix: &str) -> bool {
    relative == prefix || relative.starts_with(&format!("{prefix}/"))
}

pub(super) fn is_excluded(relative: &str) -> bool {
    relative == CANONICAL_VOLUME
        || relative == ACTIVE_PROJECTION_NAME
        || relative == LEGACY_VAR_VOLUME
        || is_path_or_descendant(relative, VOLUME_PATH_PREFIX)
        || (relative.starts_with(&format!("{TRANSIENT_PREFIX}/"))
            && !is_path_or_descendant(relative, &format!("{TRANSIENT_PREFIX}/capsules")))
        || is_path_or_descendant(relative, DIRECTORY_STORE_PREFIX)
        || HOST_EXECUTABLES.contains(&relative)
        || relative == SOCKET_PATH
        || relative == MIGRATING_VOLUME
        || TRANSACTION_STAGING_PATHS.contains(&relative)
}

pub(super) fn is_retired_legacy_projection(home: &AstridHome, name: &str) -> bool {
    [home.state_db_path(), home.cow_dir()]
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(home.root())
                .ok()
                .and_then(|relative| relative.to_str())
                .map(ToOwned::to_owned)
        })
        .any(|relative| normalize_relative_path(&relative) == name)
}
/// Admit an incomplete legacy-store tree as durable System-owned quarantine.
///
/// Residue is published only after its source bytes are read without
/// following redirects. The host tree is removed only after the complete
/// quarantine batch is flushed, so an interrupted quarantine fails closed
/// with the source still present and retries under a fresh generation.
pub(super) fn quarantine_principal_store(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    let source = home.principal_store_path();
    validate_legacy_retirement_candidate(&source)?;
    let mut files = Vec::new();
    collect_files(&source, &source, &mut files, None, ScanPolicy::Admission)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let generation = next_quarantine_generation(store)?;
    let mut ingests = Vec::with_capacity(files.len());
    for (relative, path, metadata) in files {
        let name = ContentName::new(format!("{QUARANTINE_PREFIX}/{generation}/{relative}"))
            .map_err(|error| tree_error(&path, format!("validate quarantine name: {error}")))?;
        ingests.push(ContiguousFileIngest::new(name, path, metadata.len()));
    }
    store.put_contiguous_files(StateOwner::System, ingests)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(&source, format!("flush quarantine: {error}")))?;
    astrid_core::dirs::retire_legacy_source_tree(&source)
        .map_err(|error| tree_error(&source, format!("retire quarantine source: {error}")))
}

/// Refuse ingest before publication unless the source is a real same-device
/// tree with no redirects or special entries.
fn validate_legacy_retirement_candidate(source: &Path) -> StorageResult<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| tree_error(source, format!("inspect retirement source: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(tree_error(
            source,
            "retirement source is redirected or not a directory".to_owned(),
        ));
    }
    let root_device = legacy_tree_device(&metadata);
    validate_retirement_tree(source, root_device)
}

#[cfg(unix)]
fn legacy_tree_device(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(not(unix))]
fn legacy_tree_device(_metadata: &std::fs::Metadata) -> u64 {
    0
}

fn validate_retirement_tree(path: &Path, root_device: u64) -> StorageResult<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| tree_error(path, format!("inspect retirement source: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(tree_error(
            path,
            "retirement source contains a symbolic link".to_owned(),
        ));
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(tree_error(
            path,
            "retirement source contains a special file".to_owned(),
        ));
    }
    if legacy_tree_device(&metadata) != root_device {
        return Err(tree_error(
            path,
            "retirement source crosses a filesystem boundary".to_owned(),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)
        .map_err(|error| tree_error(path, format!("validate retirement source: {error}")))?;
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)
        .map_err(|error| tree_error(path, format!("read retirement source: {error}")))?
    {
        let child = entry
            .map_err(|error| tree_error(path, format!("read retirement entry: {error}")))?
            .path();
        validate_retirement_tree(&child, root_device)?;
    }
    Ok(())
}

fn next_quarantine_generation(store: &RuntimePrincipalStore) -> StorageResult<u32> {
    let names = store
        .content()
        .list_prefix(&StateOwner::System, QUARANTINE_PREFIX)
        .map_err(|error| tree_error_home(QUARANTINE_PREFIX, error))?;
    let mut next = 0_u32;
    for entry in names {
        let Some(relative) = entry.name().as_str().strip_prefix(QUARANTINE_PREFIX) else {
            continue;
        };
        let Some(generation) = relative.trim_start_matches('/').split('/').next() else {
            continue;
        };
        if let Ok(value) = generation.parse::<u32>() {
            next = next.max(value.saturating_add(1));
        }
    }
    Ok(next)
}

fn tree_error_home(path: &str, error: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime tree {path}: {error}"))
}

/// Preserve a pre-cutover runtime signing key across volume initialization.
///
/// A first open may discover an installed runtime key before a volume exists.
/// The key must enter system-owned volume content before the durable-root
/// cleanup, or later capsule verification sees a newly generated identity.
fn ingest_runtime_key(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    let source = home.runtime_key_path();
    let metadata = match std::fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(tree_error(&source, format!("inspect runtime key: {error}"))),
    };
    if metadata.file_type().is_symlink() {
        return Err(tree_error(
            &source,
            "runtime key contains a symbolic link".to_owned(),
        ));
    }
    if !metadata.is_file() {
        return Err(tree_error(
            &source,
            "runtime key is not a regular file".to_owned(),
        ));
    }

    let name = ContentName::new(RUNTIME_KEY_PROJECTION.to_owned()).map_err(|error| {
        tree_error(
            &source,
            format!("runtime key is not a valid content name: {error}"),
        )
    })?;
    if store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| tree_error(&source, format!("inspect runtime key: {error}")))?
        .is_some()
    {
        return Ok(());
    }

    store.put_contiguous_files(
        StateOwner::System,
        [ContiguousFileIngest::new(name, source, metadata.len())],
    )
}

/// Materialize the compatibility sentinel from durable volume authority.
fn seed_layout_version(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    let name = ContentName::new("etc/layout-version".to_owned())
        .map_err(|error| tree_error(home.root(), format!("validate layout sentinel: {error}")))?;
    if store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), format!("inspect layout sentinel: {error}")))?
        .is_some()
    {
        return Ok(());
    }
    store.replace_contiguous_files_removing_exact(
        StateOwner::System,
        [PackedProjectionIngest::bytes(
            name,
            astrid_core::dirs::LAYOUT_VERSION.as_bytes().to_vec(),
        )],
        &[],
        None,
    )
}

/// Publish current running projection changes, then retire their host files.
pub(super) fn pack_and_retire_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    // Reserve first so new staging ops cannot start during RETIRING. Commit
    // after the durable receipt and before host delete; Drop restores Open on
    // failure so retry keeps live staging.
    let staging_close = crate::principal_state::lifecycle::staging::reserve_for_retirement(store)
        .map_err(|error| {
        tree_error(
            home.root(),
            format!("close content staging before retirement: {error}"),
        )
    })?;
    if home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?
        .as_deref()
        == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION)
    {
        return legacy_projection_pack(home, store, staging_close);
    }
    // This one walk retains the validation pass's special-entry rejection;
    // ordinary admission scans intentionally have a different contract.
    let scanned = scan_with_policy(home.root(), None, ScanPolicy::Publication)?;
    if !scanned.is_empty() {
        let receipt = active::read(home, store)?;
        match receipt {
            Some(receipt) if receipt.phase() == ReceiptPhase::Active => {
                publish_scanned_projection(home, store, &receipt, scanned)?;
            },
            Some(receipt) => {
                validate_retiring_host_subset(home, &receipt, &scanned)?;
            },
            None => {
                if !is_exactly_pack_open_staging_journal(&scanned) {
                    let names = scanned
                        .iter()
                        .map(|entry| entry.name().as_str())
                        .collect::<Vec<_>>();
                    return Err(tree_error(
                        home.root(),
                        format!(
                            "active projection receipt is missing for surviving host projection: {names:?}"
                        ),
                    ));
                }
            },
        }
    }
    transition_retiring_projection(home, store)?;
    if let Some(token) = staging_close {
        token.commit();
    }
    retirement::retire_current_projection(home, store)?;
    active::clear(store, home).map(|_| ())
}

fn is_staging_generation(name: &str) -> bool {
    name.strip_prefix("var/content-staging/generations/")
        .is_some_and(|name| name.ends_with(".sealed"))
}

fn active_projection_entries(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<Vec<ActiveProjectionEntry>> {
    let entries = store
        .content()
        .list(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("list active projection: {error}")))?;
    Ok(entries
        .into_iter()
        .filter(|entry| !is_excluded(entry.name().as_str()))
        .filter(|entry| !is_retired_legacy_projection(home, entry.name().as_str()))
        .map(|entry| ActiveProjectionEntry {
            name: entry.name().clone(),
            file: entry.file(),
            logical_bytes: entry.logical_bytes(),
        })
        .collect())
}

fn receipt_ingest(
    home: &AstridHome,
    phase: ReceiptPhase,
    entries: &[ActiveProjectionEntry],
    staging_scope: Option<StagingScope>,
) -> StorageResult<PackedProjectionIngest> {
    let bytes = active::encode(home, phase, entries, staging_scope)?;
    Ok(PackedProjectionIngest::bytes(
        active::active_projection_name()?,
        bytes,
    ))
}

fn rotate_active_receipt(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    entries: &[ActiveProjectionEntry],
) -> StorageResult<()> {
    let receipt = receipt_ingest(home, ReceiptPhase::Active, entries, None)?;
    store.replace_contiguous_files_removing_exact(StateOwner::System, [receipt], &[], None)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush active receipt: {error}")))
}

pub(super) fn establish_active_receipt(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    // ACTIVE records what was actually materialized, not everything owned by
    // System. Capsule installs can add volume-only WASM while a host projection
    // survives an idle exit. Claiming those names here would turn their host
    // absence into a deletion on the next publication. RETIRING still records
    // the complete durable inventory through active_projection_entries.
    let projected = scan(home.root())?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<std::collections::BTreeSet<_>>();
    let entries = active_projection_entries(home, store)?
        .into_iter()
        .filter(|entry| {
            projected.contains(&entry.name)
                || projection::surviving_directory(home.root(), entry.name.as_str())
        })
        .collect::<Vec<_>>();
    rotate_active_receipt(home, store, &entries)
}

fn publish_active_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    let receipt = active::read(home, store)?.ok_or_else(|| {
        tree_error(
            home.root(),
            "active projection receipt is missing for host publication",
        )
    })?;
    let scanned = scan(home.root())?;
    publish_scanned_projection(home, store, &receipt, scanned)
}

fn publish_scanned_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    receipt: &active::ActiveProjectionReceipt,
    scanned: Vec<RuntimeTreeEntry>,
) -> StorageResult<()> {
    let surviving = scanned
        .iter()
        .map(RuntimeTreeEntry::name)
        .cloned()
        .collect::<Vec<_>>();
    let mut removals = active::removals(receipt, &surviving)?;
    removals.retain(|name| !projection::surviving_directory(home.root(), name.as_str()));
    let receipt_entries = scanned
        .iter()
        .map(|entry| (entry.name().clone(), entry.logical_bytes()))
        .collect::<Vec<_>>();
    let mut derived = ActiveReceiptDeriver {
        home: home.clone(),
        entries: receipt_entries,
        retained: &[],
    };
    let ingests = scanned.into_iter().map(|entry| {
        PackedProjectionIngest::File(ContiguousFileIngest::new(
            entry.name,
            entry.source_path,
            entry.logical_bytes,
        ))
    });
    store.replace_contiguous_files_removing_exact(
        StateOwner::System,
        ingests,
        &removals,
        Some(&mut derived),
    )?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush active projection: {error}")))?;
    Ok(())
}

fn legacy_projection_pack(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    staging_close: Option<crate::principal_state::staging::StagingCloseToken>,
) -> StorageResult<()> {
    admit(store, home.root())?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush volume projection: {error}")))?;
    if let Some(token) = staging_close {
        token.commit();
    }
    retirement::retire_legacy_projection(home, store)
}
fn tree_io_error(error: &std::io::Error) -> StorageError {
    StorageError::Connection(error.to_string())
}

fn tree_error(path: &Path, detail: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime tree {}: {detail}", path.display()))
}

/// Reconcile a surviving running projection before volume-backed restore.
///
/// A stopped CLI home has only the hosted volume. A daemon interrupted before
/// post-exit retirement still owns its host projection, however, and that tree
/// may contain generations newer than the last packed volume. Admit and flush
/// it first so the subsequent projection restore mounts the newest admitted
/// generation instead of rewinding the host tree.
pub(super) fn reconcile_running_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    allow_receiptless_bootstrap: bool,
) -> StorageResult<()> {
    let layout_version = home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?;
    if layout_version.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        return Ok(());
    }

    if !allow_receiptless_bootstrap && let Some(prepared) = stopped_recovery::recover(home, store)?
    {
        restoration::restore_after_recovery(prepared)?;
        establish_active_receipt(home, store)?;
        return Ok(());
    }
    let surviving = validate_surviving_projection(home.root(), home.root())?;
    let receipt = active::read_relocatable(home, store)?;
    match receipt {
        None => {
            let scanned = scan(home.root())?;
            if surviving
                && (!allow_receiptless_bootstrap || !is_bootstrap_surviving_projection(&scanned))
            {
                let names = scanned
                    .iter()
                    .map(|entry| entry.name().as_str())
                    .collect::<Vec<_>>();
                return Err(tree_error(
                    home.root(),
                    format!(
                        "active projection receipt is missing for surviving host projection: {names:?}"
                    ),
                ));
            }
        },
        Some(receipt) if !receipt.root_matches(home)? => {
            // A portable active-volume copy is volume-authoritative. Host
            // bytes are neither admitted nor allowed beyond trusted bootstrap
            // sentinels; the copied receipt is simply rebound to the new root.
            if receipt.phase() != ReceiptPhase::Active {
                return Err(tree_error(
                    home.root(),
                    "active projection receipt root does not match this durable root",
                ));
            }
            let scanned = scan(home.root())?;
            if surviving && !is_bootstrap_surviving_projection(&scanned) {
                return Err(tree_error(
                    home.root(),
                    "relocated active receipt is permitted only for trusted bootstrap files",
                ));
            }
            restore_projection(home, store, &store.content)?;
        },
        Some(receipt) => match receipt.phase() {
            ReceiptPhase::Active => {
                let scanned = scan(home.root())?;
                if surviving && !is_bootstrap_surviving_projection(&scanned) {
                    publish_active_projection(home, store)?;
                } else {
                    restore_projection(home, store, &store.content)?;
                }
            },
            ReceiptPhase::Retiring => {
                let scoped_receipt = receipt.staging_scope().map(|_| &receipt);
                let scanned = scan_with_receipt(home.root(), scoped_receipt)?;
                if let Some(prepared) =
                    restoration::discharge_scoped_staging(home, store, &receipt, &scanned)?
                {
                    restoration::restore_after_recovery(prepared)?;
                } else {
                    validate_retiring_host_subset(home, &receipt, &scanned)?;
                    restore_projection(home, store, &store.content)?;
                }
            },
        },
    }
    if active::read_relocatable(home, store)?.is_some() {
        establish_active_receipt(home, store)?;
    } else {
        restore_projection(home, store, &store.content)?;
        establish_active_receipt(home, store)?;
    }
    Ok(())
}

fn validate_retiring_host_subset(
    home: &AstridHome,
    receipt: &super::runtime_tree_active::ActiveProjectionReceipt,
    scanned: &[RuntimeTreeEntry],
) -> StorageResult<()> {
    for entry in scanned {
        if !receipt.contains_inventory_name(entry.name().as_str()) {
            return Err(tree_error(
                home.root(),
                format!(
                    "retiring projection contains unreceipted host file {}",
                    entry.name().as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn is_bootstrap_surviving_projection(scanned: &[RuntimeTreeEntry]) -> bool {
    !scanned.is_empty()
        && scanned.iter().all(|entry| {
            matches!(
                entry.name().as_str(),
                "etc/layout-version" | RUNTIME_KEY_PROJECTION | STAGING_JOURNAL_PROJECTION
            )
        })
}

/// Pack-open materializes the staging journal before retirement can run.
///
/// That one enumerated regular file is not a surviving projection and must not
/// be admitted without an ACTIVE receipt. Directories, symlinks, siblings,
/// alternate spellings, and the broader bootstrap set keep fail-closed;
/// redirects still fail in preflight.
fn is_exactly_pack_open_staging_journal(scanned: &[RuntimeTreeEntry]) -> bool {
    matches!(
        scanned,
        [entry] if entry.name().as_str() == STAGING_JOURNAL_PROJECTION
    )
}

/// Validate redirects and unadmitted specials before any destructive restore.
///
/// Returns whether the tree contains a regular projection candidate. Excluded
/// host endpoints and media paths remain outside authority and cannot make an
/// otherwise volume-only home look like a surviving projection.
fn validate_surviving_projection(root: &Path, directory: &Path) -> StorageResult<bool> {
    if tracing::enabled!(target: "astrid_storage::runtime_tree_scan", tracing::Level::TRACE)
        && root == directory
    {
        tracing::trace!(target: "astrid_storage::runtime_tree_scan", "validate running projection tree");
    }
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| tree_error(directory, format!("read running projection: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tree_error(directory, format!("read projection entry: {error}")))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut has_projection = false;
    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| tree_error(&path, format!("inspect projection: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(tree_error(
                &path,
                "running projection contains a symbolic link".to_owned(),
            ));
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| tree_error(&path, "projection entry escaped runtime root".to_owned()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| tree_error(&path, "projection path is not valid UTF-8".to_owned()))?;
        let relative = normalize_relative_path(relative);
        if is_excluded(relative.as_str()) {
            continue;
        }
        if metadata.is_dir() {
            if relative.as_str() == STAGING_JOURNAL_PROJECTION {
                return Err(tree_error(
                    &path,
                    "pack-open staging journal is not a regular file".to_owned(),
                ));
            }
            has_projection |= validate_surviving_projection(root, &path)?;
        } else if metadata.is_file() {
            has_projection = true;
        } else {
            return Err(tree_error(
                &path,
                "running projection contains an unadmitted special entry".to_owned(),
            ));
        }
    }
    Ok(has_projection)
}

/// Publish the live running projection without retiring its host files.
pub(super) fn publish_running_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    if home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?
        .as_deref()
        == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION)
    {
        return legacy_projection_pack_publish_only(home, store);
    }
    publish_active_projection(home, store)
}

fn legacy_projection_pack_publish_only(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    admit(store, home.root())?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush running projection: {error}")))
}

#[cfg(test)]
mod tests;
