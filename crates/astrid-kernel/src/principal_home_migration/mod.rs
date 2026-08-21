//! Migration of ordinary released principal-home files into named content.
//!
//! The durable owner is always the immutable [`PrincipalUid`].  A current
//! [`PrincipalId`] is used only to select the legacy source directory.  The
//! destination is the stable owner-local `home/` subtree, independent of the
//! mutable visible alias. Dedicated migrations own
//! policy, capsule installation, environment, audit, token, tmp, and
//! operator-log paths; this module refuses to absorb any of them.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_storage::{
    AstridFilesystem, FilesystemEntryKind, FilesystemError, FilesystemPath, PrincipalDirectory,
    RuntimePrincipalStore, StateOwner,
};
const RECEIPT_PREFIX: &str = "principal-home-";
const RECEIPT_SUFFIX: &str = ".json";
const RECEIPT_PAGE_MARKER: &str = ".page-";
// The production page bound remains 512 entries. Tests use a smaller bound
// so the durable-store paging regression stays fast enough for every kernel
// test run while exercising the identical rollover and receipt logic.
#[cfg(not(test))]
const PAGE_ENTRY_LIMIT: usize = 512;
#[cfg(test)]
const PAGE_ENTRY_LIMIT: usize = 64;
const MAX_RECEIPT_INDEX_BYTES: usize = 1024 * 1024;
const MAX_RECEIPT_PAGE_BYTES: usize = 8 * 1024 * 1024;
const READBACK_CHUNK_BYTES: u64 = 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4096;

mod paths;
mod publish;
mod receipts;
mod types;
mod unbound;

pub(super) type HomeFilesystem = AstridFilesystem<
    StateOwner,
    astrid_storage::engine::DurableEngine<
        StateOwner,
        astrid_storage::Blake3ObjectIdentityV1,
        astrid_storage::StateOwnerCodecV2,
    >,
>;
use paths::{
    append_relative, conflict_fs, conflict_path, destination_name, invalid_source,
    is_dedicated_path, logical_relative, receipt_path_for_display, receipt_uid_for_alias,
    source_exists, storage_error,
};
#[cfg(test)]
use receipts::page_path;
use receipts::{
    EntryKind, MigrationEntry, MigrationReceipt, PageWriter, read_page, read_receipt, receipt_path,
    remove_stale_pages, validate_receipt_pages, write_receipt,
};
use types::{ByteCount, ContentDigest, EntryCount, InventoryDigest, PageCount, ReceiptSchema};
pub(crate) use unbound::admit_unbound_legacy_principal_homes;

/// Copy ordinary files for every admitted legacy principal.
pub(crate) fn migrate_legacy_principal_homes(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    principals: &PrincipalDirectory,
) -> io::Result<()> {
    let source_root = home.home_dir();
    let metadata = match fs::symlink_metadata(&source_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_source(&source_root, "not a regular directory"));
    }
    astrid_core::platform_fs::validate_private_directory(&source_root)?;
    astrid_core::platform_fs::verify_no_redirects(&source_root)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;

    let entries = fs::read_dir(&source_root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("scan {}: {error}", source_root.display()),
        )
    })?;
    for entry in entries {
        let entry = entry?;
        let alias_name = entry.file_name();
        let alias_text = alias_name.to_str().ok_or_else(|| {
            invalid_source(&entry.path(), "principal directory name is not UTF-8")
        })?;
        let alias = PrincipalId::new(alias_text.to_owned()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("legacy principal directory {alias_text:?} is invalid: {error}"),
            )
        })?;
        // A migration receipt is immutable provenance and takes precedence
        // over the mutable alias directory. If an alias was deleted and then
        // reused, never stream the surviving old source into the replacement
        // UID; fail closed instead.
        let receipt_uid = receipt_uid_for_alias(home, &alias)?;
        let live_uid = principals.uid_for(&alias).ok();
        let uid = match (receipt_uid, live_uid) {
            (Some(receipt), Some(live)) if receipt != live => {
                return Err(conflict_path(
                    &entry.path(),
                    "migration receipt UID differs from the live alias binding",
                ));
            },
            (Some(receipt), _) => receipt,
            (None, Some(live)) => live,
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("legacy principal {alias} has no durable UID"),
                ));
            },
        };
        migrate_one_principal(home, store, uid, &alias, &entry.path())?;
    }
    Ok(())
}

/// Snapshot only ordinary entries owned by this migration.
///
/// Dedicated subtrees (capsules, env, audit, logs, and other released
/// operational paths) are excluded because their own migrations bind and
/// retire them. The fields use the same digest/count/byte inventory as the
/// ordinary-home receipt. `present` distinguishes an absent source from an
/// existing source containing only dedicated entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrincipalHomeSourceIdentity {
    pub(crate) digest: String,
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
    pub(crate) present: bool,
}

pub(crate) fn legacy_ordinary_source_snapshot(
    home: &AstridHome,
    alias: &PrincipalId,
) -> io::Result<PrincipalHomeSourceIdentity> {
    let principal_home = home.principal_home(alias);
    let source = principal_home.root();
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PrincipalHomeSourceIdentity {
                digest: "absent".to_owned(),
                entries: 0,
                bytes: 0,
                present: false,
            });
        },
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_source(source, "not a regular directory"));
    }
    let summary = summarize_inventory(source)?;
    Ok(PrincipalHomeSourceIdentity {
        digest: summary.digest.as_str().to_owned(),
        entries: summary.count.get(),
        bytes: summary.bytes.get(),
        present: true,
    })
}

/// Retire only the ordinary source entries named by each durable migration
/// receipt.  A fresh recursive snapshot is never an authority for deletion:
/// if an operator writes a new file after import, the receipt-bound inventory
/// differs and this function fails closed while preserving that file.
pub(crate) fn retire_migrated_legacy_principal_homes(
    home: &AstridHome,
    principals: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, uid) in principals.bindings() {
        let root = home.principal_home(&alias).root().to_path_buf();
        if source_exists(&root)? {
            retire_one_receipted_source(home, &alias, uid, &root)?;
        }
    }
    Ok(())
}

/// Verify that no legacy principal source has reappeared after a completed
/// cut-over. Any source root, including an empty structural directory, is a
/// hard boot failure: the existing-ledger path never performs cleanup.
pub(crate) fn verify_migrated_legacy_principal_sources_retired(
    home: &AstridHome,
    principals: &PrincipalDirectory,
) -> io::Result<()> {
    let home_root = home.home_dir();
    let mut entries = match fs::read_dir(&home_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let live = principals
        .bindings()
        .into_iter()
        .map(|(alias, _)| alias.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(entry) = entries.next().transpose()? {
        let alias_name = entry.file_name();
        let alias = alias_name
            .to_str()
            .ok_or_else(|| invalid_source(&entry.path(), "principal directory is not UTF-8"))?;
        if !live.contains(alias) {
            return Err(conflict_path(
                &entry.path(),
                "legacy principal source has no current alias binding",
            ));
        }
        let principal = PrincipalId::new(alias.to_owned()).map_err(|error| {
            invalid_source(&entry.path(), &format!("invalid principal alias: {error}"))
        })?;
        let uid = principals.uid_for(&principal).map_err(|error| {
            conflict_path(
                &entry.path(),
                &format!("legacy principal has no durable UID: {error}"),
            )
        })?;
        let root = entry.path();
        let Some(receipt) = read_receipt(&receipt_path(home, uid))? else {
            return Err(conflict_path(
                &root,
                "legacy principal source has no migration receipt",
            ));
        };
        if receipt.uid != uid {
            return Err(conflict_path(
                &root,
                "legacy principal source receipt UID differs from live binding",
            ));
        }
        return Err(conflict_path(
            &root,
            "legacy principal source reappeared after cut-over",
        ));
    }
    Ok(())
}

fn retire_one_receipted_source(
    home: &AstridHome,
    alias: &PrincipalId,
    uid: PrincipalUid,
    root: &Path,
) -> io::Result<()> {
    let receipt_path = receipt_path(home, uid);
    let receipt = read_receipt(&receipt_path)?.ok_or_else(|| {
        conflict_path(
            root,
            &format!("legacy principal {alias} has no migration receipt"),
        )
    })?;
    if receipt.uid != uid || receipt.alias != *alias {
        return Err(conflict_path(
            &receipt_path,
            "migration receipt identity differs from the live binding",
        ));
    }
    let inventory = summarize_inventory(root)?;
    if inventory.count != receipt.entry_count
        || inventory.bytes != receipt.bytes
        || inventory.digest != receipt.inventory_digest
    {
        return Err(conflict_path(
            root,
            "legacy source inventory changed after its durable migration receipt",
        ));
    }
    validate_receipt_pages(home, uid, &receipt)?;
    for page_number in (0..receipt.page_count.get()).rev() {
        let page = read_page(home, uid, page_number)?;
        for entry in page.entries.into_iter().rev() {
            let relative = Path::new(&entry.source);
            if logical_relative(relative)? != entry.source {
                return Err(invalid_source(
                    &receipt_path,
                    "receipt source path is not canonical",
                ));
            }
            let path = root.join(relative);
            match entry.kind {
                EntryKind::Directory => {
                    let metadata = fs::symlink_metadata(&path).map_err(|error| {
                        conflict_path(&path, &format!("receipt directory disappeared: {error}"))
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(invalid_source(&path, "receipt directory changed type"));
                    }
                    astrid_core::platform_fs::verify_no_redirects(&path)?;
                    if fs::read_dir(&path)?.next().transpose()?.is_some() {
                        return Err(conflict_path(
                            &path,
                            "receipt directory contains an unretired entry",
                        ));
                    }
                    fs::remove_dir(&path).map_err(io::Error::other)?;
                    sync_parent(&path)?;
                },
                EntryKind::File => {
                    let (bytes, digest) = digest_file(&path)?;
                    if bytes != entry.bytes || digest != entry.digest {
                        return Err(conflict_path(
                            &path,
                            "receipt file changed before retirement",
                        ));
                    }
                    fs::remove_file(&path).map_err(io::Error::other)?;
                    sync_parent(&path)?;
                },
            }
        }
    }
    retire_empty_tree(root)
}

fn retire_empty_tree(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_source(
            path,
            "legacy structural path is not a directory",
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(conflict_path(
                &child,
                "unretired legacy entry remains after receipt-bound migration",
            ));
        }
        retire_empty_tree(&child)?;
    }
    fs::remove_dir(path).map_err(io::Error::other)?;
    sync_parent(path)?;
    Ok(())
}

// Windows retirement uses write-through platform helpers; retain the common
// fallible signature for the cross-platform migration flow.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn migrate_one_principal(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    alias: &PrincipalId,
    source: &Path,
) -> io::Result<()> {
    let receipt_path = receipt_path(home, uid);
    if let Some(receipt) = read_receipt(&receipt_path)? {
        // The alias is retained as migration provenance only.  PrincipalId
        // aliases are mutable, so a rename must not hide an already migrated
        // owner-local home tree.
        if receipt.schema != ReceiptSchema::V2 || receipt.uid != uid {
            return Err(conflict_path(
                &receipt_path,
                "receipt identity does not match the live principal mapping",
            ));
        }
        if source_exists(source)? {
            let inventory = summarize_inventory(source)?;
            if inventory.count != receipt.entry_count
                || inventory.bytes != receipt.bytes
                || inventory.digest != receipt.inventory_digest
            {
                return Err(conflict_path(
                    source,
                    "legacy source inventory differs from durable receipt",
                ));
            }
        }
        verify_destinations(home, store, uid, &receipt)?;
        return Ok(());
    }

    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    let mut preflight = InventorySummary::default();
    walk_inventory(source, |entry| {
        preflight.update(&entry)?;
        preflight_entry(&filesystem, source, &entry)
    })?;
    let preflight = preflight.finish();
    if preflight.count == 0 {
        remove_stale_pages(home, uid)?;
        return write_empty_receipt(home, uid, alias, preflight);
    }

    // Replace only private page artifacts from an interrupted attempt.
    remove_stale_pages(home, uid)?;
    ensure_directory(
        &filesystem,
        &FilesystemPath::new("home").map_err(|error| storage_error(&error))?,
    )?;

    let mut published = InventorySummary::default();
    let mut pages = PageWriter::new(home, uid);
    let mut entries = Vec::new();
    walk_inventory(source, |entry| {
        published.update(&entry)?;
        entries.push(entry.clone());
        pages.push(entry)
    })?;
    publish::publish_inventory(store, &filesystem, uid, source, entries)?;
    let page_count = pages.finish()?;
    let published = published.finish();
    if published != preflight {
        return Err(conflict_path(
            source,
            "legacy source changed between migration preflight and publication",
        ));
    }

    let receipt = MigrationReceipt {
        schema: ReceiptSchema::V2,
        uid,
        alias: alias.clone(),
        inventory_digest: published.digest,
        entry_count: published.count,
        bytes: published.bytes,
        page_count: PageCount::new(page_count),
    };
    verify_destinations(home, store, uid, &receipt)?;
    write_receipt(&receipt_path, &receipt)?;
    Ok(())
}

fn write_empty_receipt(
    home: &AstridHome,
    uid: PrincipalUid,
    alias: &PrincipalId,
    inventory: InventorySummaryFinal,
) -> io::Result<()> {
    let receipt = MigrationReceipt {
        schema: ReceiptSchema::V2,
        uid,
        alias: alias.clone(),
        inventory_digest: inventory.digest,
        entry_count: inventory.count,
        bytes: inventory.bytes,
        page_count: PageCount::ZERO,
    };
    write_receipt(&receipt_path(home, uid), &receipt)
}

fn summarize_inventory(source: &Path) -> io::Result<InventorySummaryFinal> {
    let mut summary = InventorySummary::default();
    walk_inventory(source, |entry| summary.update(&entry))?;
    Ok(summary.finish())
}

fn walk_inventory(
    source: &Path,
    mut callback: impl FnMut(MigrationEntry) -> io::Result<()>,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_source(source, "not a regular directory"));
    }
    astrid_core::platform_fs::validate_private_directory(source)?;
    astrid_core::platform_fs::verify_no_redirects(source)?;
    walk_directory(source, Path::new(""), &mut callback)
}

fn walk_directory(
    root: &Path,
    relative: &Path,
    callback: &mut impl FnMut(MigrationEntry) -> io::Result<()>,
) -> io::Result<()> {
    let path = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_source(&path, "redirected entry"));
    }
    if !metadata.is_dir() {
        return Err(invalid_source(&path, "expected directory"));
    }
    astrid_core::platform_fs::verify_no_redirects(&path)?;

    for child in fs::read_dir(&path)? {
        let child = child?;
        let child_path = child.path();
        let child_relative = append_relative(relative, &child.file_name())?;
        let metadata = fs::symlink_metadata(&child_path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_source(&child_path, "redirected entry"));
        }
        if is_dedicated_path(&child_relative) {
            // Dedicated component migrations retain authority over their
            // subtree. Still reject redirects and special entries at the
            // boundary so this migration never silently follows one.
            if !metadata.is_dir() && !metadata.is_file() {
                return Err(invalid_source(&child_path, "special dedicated entry"));
            }
            astrid_core::platform_fs::verify_no_redirects(&child_path)?;
            continue;
        }
        let relative_text = logical_relative(&child_relative)?;
        if metadata.is_dir() {
            callback(MigrationEntry {
                source: relative_text.clone(),
                destination: destination_name(&relative_text),
                kind: EntryKind::Directory,
                bytes: ByteCount::ZERO,
                digest: ContentDigest::empty(),
            })?;
            walk_directory(root, &child_relative, callback)?;
        } else if metadata.is_file() {
            let (bytes, digest) = digest_file(&child_path)?;
            callback(MigrationEntry {
                source: relative_text.clone(),
                destination: destination_name(&relative_text),
                kind: EntryKind::File,
                bytes,
                digest,
            })?;
        } else {
            return Err(invalid_source(&child_path, "special entry"));
        }
    }
    Ok(())
}

#[derive(Default)]
struct InventorySummary {
    hasher: blake3::Hasher,
    count: EntryCount,
    bytes: ByteCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InventorySummaryFinal {
    digest: InventoryDigest,
    count: EntryCount,
    bytes: ByteCount,
}

impl InventorySummary {
    fn update(&mut self, entry: &MigrationEntry) -> io::Result<()> {
        let bytes = serde_json::to_vec(entry).map_err(io::Error::other)?;
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("legacy inventory entry is too large"))?;
        self.hasher.update(&byte_len.to_le_bytes());
        self.hasher.update(&bytes);
        self.count = self
            .count
            .checked_add(EntryCount::new(1))
            .ok_or_else(|| io::Error::other("legacy inventory entry count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(entry.bytes)
            .ok_or_else(|| io::Error::other("legacy inventory byte count overflow"))?;
        Ok(())
    }

    fn finish(self) -> InventorySummaryFinal {
        InventorySummaryFinal {
            digest: InventoryDigest::from_blake3(self.hasher.finalize()),
            count: self.count,
            bytes: self.bytes,
        }
    }
}

fn preflight_entry(
    filesystem: &AstridFilesystem<
        StateOwner,
        astrid_storage::engine::DurableEngine<
            StateOwner,
            astrid_storage::Blake3ObjectIdentityV1,
            astrid_storage::StateOwnerCodecV2,
        >,
    >,
    source_root: &Path,
    entry: &MigrationEntry,
) -> io::Result<()> {
    let destination = FilesystemPath::new(entry.destination.clone()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid logical destination {}: {error}", entry.destination),
        )
    })?;
    match entry.kind {
        EntryKind::Directory => match filesystem.stat(&destination) {
            Ok(existing) if existing.kind() == FilesystemEntryKind::Directory => {},
            Ok(_) => {
                return Err(conflict_fs(
                    &destination,
                    "destination kind conflicts with source directory",
                ));
            },
            Err(FilesystemError::NotFound(_)) => {},
            Err(error) => return Err(storage_error(&error)),
        },
        EntryKind::File => match filesystem.stat(&destination) {
            Ok(existing) if existing.kind() == FilesystemEntryKind::File => {
                verify_file_content(filesystem, &destination, entry)?;
            },
            Ok(_) => {
                return Err(conflict_fs(
                    &destination,
                    "destination kind conflicts with source file",
                ));
            },
            Err(FilesystemError::NotFound(_)) => {},
            Err(error) => return Err(storage_error(&error)),
        },
    }

    // A missing destination ancestor is allowed only when its corresponding
    // source ancestor is a directory that this migration will publish. Walk
    // all the way to `home` so an existing file at a higher ancestor cannot be
    // hidden by a missing child lookup.
    let mut destination_parent = destination
        .as_str()
        .rsplit_once('/')
        .map_or_else(String::new, |(parent, _)| parent.to_owned());
    let source_path = source_root.join(&entry.source);
    let mut source_parent = source_path.parent().map(Path::to_path_buf);
    while !destination_parent.is_empty() {
        let parent_path = FilesystemPath::new(destination_parent.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid destination parent {destination_parent:?}: {error}"),
            )
        })?;
        match filesystem.stat(&parent_path) {
            Ok(existing) if existing.kind() == FilesystemEntryKind::Directory => {},
            Ok(_) => {
                return Err(conflict_fs(
                    &parent_path,
                    "destination parent is not a directory",
                ));
            },
            Err(FilesystemError::NotFound(_)) => {
                let source_parent_path = source_parent.as_deref().ok_or_else(|| {
                    conflict_fs(&parent_path, "destination parent has no source directory")
                })?;
                let metadata = fs::symlink_metadata(source_parent_path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(conflict_fs(
                        &parent_path,
                        "destination parent has no source directory",
                    ));
                }
            },
            Err(error) => return Err(storage_error(&error)),
        }
        if destination_parent == "home" {
            break;
        }
        destination_parent = destination_parent
            .rsplit_once('/')
            .map_or_else(String::new, |(parent, _)| parent.to_owned());
        source_parent = source_parent.and_then(|path| path.parent().map(Path::to_path_buf));
    }
    Ok(())
}

fn ensure_directory(
    filesystem: &AstridFilesystem<
        StateOwner,
        astrid_storage::engine::DurableEngine<
            StateOwner,
            astrid_storage::Blake3ObjectIdentityV1,
            astrid_storage::StateOwnerCodecV2,
        >,
    >,
    destination: &FilesystemPath,
) -> io::Result<()> {
    match filesystem.stat(destination) {
        Ok(existing) if existing.kind() == FilesystemEntryKind::Directory => Ok(()),
        Ok(_) => Err(conflict_fs(
            destination,
            "destination kind conflicts with source directory",
        )),
        Err(FilesystemError::NotFound(_)) => match filesystem.create_dir(destination) {
            Ok(()) => Ok(()),
            Err(FilesystemError::AlreadyExists(_)) => match filesystem.stat(destination) {
                Ok(existing) if existing.kind() == FilesystemEntryKind::Directory => Ok(()),
                Ok(_) => Err(conflict_fs(
                    destination,
                    "destination kind changed during migration",
                )),
                Err(error) => Err(storage_error(&error)),
            },
            Err(error) => Err(storage_error(&error)),
        },
        Err(error) => Err(storage_error(&error)),
    }
}

fn verify_destinations(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    receipt: &MigrationReceipt,
) -> io::Result<()> {
    let filesystem = AstridFilesystem::new(store.content(), StateOwner::Principal(uid));
    let mut summary = InventorySummary::default();
    let mut count = 0_u64;
    for page_number in 0..receipt.page_count.get() {
        let page = read_page(home, uid, page_number)?;
        if page.page != page_number {
            return Err(conflict_path(
                &receipt_path_for_display(uid),
                "receipt page sequence is not canonical",
            ));
        }
        for entry in page.entries {
            summary.update(&entry)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("receipt entry count overflow"))?;
            let destination = FilesystemPath::new(entry.destination.clone()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid receipt destination {}: {error}", entry.destination),
                )
            })?;
            match entry.kind {
                EntryKind::Directory => {
                    let actual = filesystem
                        .stat(&destination)
                        .map_err(|error| storage_error(&error))?;
                    if actual.kind() != FilesystemEntryKind::Directory {
                        return Err(conflict_fs(
                            &destination,
                            "receipt destination is not a directory",
                        ));
                    }
                },
                EntryKind::File => verify_file_content(&filesystem, &destination, &entry)?,
            }
        }
    }
    let summary = summary.finish();
    if count != receipt.entry_count
        || summary.count != receipt.entry_count
        || summary.bytes != receipt.bytes
        || summary.digest != receipt.inventory_digest
    {
        return Err(conflict_path(
            &receipt_path_for_display(uid),
            "receipt inventory digest is not canonical",
        ));
    }
    Ok(())
}

fn verify_file_content(
    filesystem: &AstridFilesystem<
        StateOwner,
        astrid_storage::engine::DurableEngine<
            StateOwner,
            astrid_storage::Blake3ObjectIdentityV1,
            astrid_storage::StateOwnerCodecV2,
        >,
    >,
    destination: &FilesystemPath,
    expected: &MigrationEntry,
) -> io::Result<()> {
    let actual = filesystem
        .stat(destination)
        .map_err(|error| storage_error(&error))?;
    if actual.kind() != FilesystemEntryKind::File || actual.logical_bytes() != expected.bytes.get()
    {
        return Err(conflict_fs(
            destination,
            "destination metadata differs from receipt",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0_u64;
    while offset < expected.bytes.get() {
        let length = expected
            .bytes
            .get()
            .saturating_sub(offset)
            .min(READBACK_CHUNK_BYTES);
        let content = filesystem
            .read(destination, offset, length)
            .map_err(|error| storage_error(&error))?;
        if u64::try_from(content.len()).ok() != Some(length) {
            return Err(conflict_fs(
                destination,
                "destination read-back length differs from receipt",
            ));
        }
        hasher.update(&content);
        offset = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::other("destination read-back length overflow"))?;
    }
    let digest = ContentDigest::from_blake3(hasher.finalize());
    if digest != expected.digest {
        return Err(conflict_fs(
            destination,
            "destination read-back differs from receipt",
        ));
    }
    Ok(())
}

fn digest_file(path: &Path) -> io::Result<(ByteCount, ContentDigest)> {
    validate_regular_file(path)?;
    astrid_core::platform_fs::verify_no_redirects(path)?;
    let before = fs::metadata(path)?.len();
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let read =
            u64::try_from(read).map_err(|_| io::Error::other("legacy file read too large"))?;
        bytes = bytes
            .checked_add(read)
            .ok_or_else(|| io::Error::other("legacy file length overflow"))?;
    }
    if bytes != before || fs::metadata(path)?.len() != before {
        return Err(conflict_path(
            path,
            "legacy file changed while being inventoried",
        ));
    }
    Ok((
        ByteCount::new(bytes),
        ContentDigest::from_blake3(hasher.finalize()),
    ))
}

fn validate_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_source(path, "ordinary entry is not a regular file"));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "ordinary legacy file is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "ordinary legacy file is group/world writable: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
