//! Contiguous physical publication of ordinary home-import files.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use astrid_storage::{
    ContentName, ContiguousFileIngest, FilesystemEntryKind, FilesystemError, FilesystemPath,
    RuntimePrincipalStore, StateOwner,
};

use super::paths::{conflict_fs, conflict_path, storage_error};
use super::receipts::{EntryKind, MigrationEntry};
use super::{digest_file, ensure_directory, validate_regular_file, verify_file_content};

pub(super) fn publish_inventory(
    store: &RuntimePrincipalStore,
    filesystem: &super::HomeFilesystem,
    uid: astrid_core::identity::PrincipalUid,
    source: &Path,
    entries: impl IntoIterator<Item = MigrationEntry>,
) -> io::Result<()> {
    let mut pending: BTreeMap<String, Vec<MigrationEntry>> = BTreeMap::new();
    for entry in entries {
        let destination = FilesystemPath::new(entry.destination.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid logical destination {}: {error}", entry.destination),
            )
        })?;
        match entry.kind {
            EntryKind::Directory => ensure_directory(filesystem, &destination)?,
            EntryKind::File => {
                let parent = destination
                    .as_str()
                    .rsplit_once('/')
                    .map_or_else(String::new, |(parent, _)| parent.to_owned());
                pending.entry(parent).or_default().push(entry);
            },
        }
    }
    for files in pending.values() {
        publish_directory_files(store, filesystem, uid, source, files)?;
    }
    Ok(())
}

fn publish_directory_files(
    store: &RuntimePrincipalStore,
    filesystem: &super::HomeFilesystem,
    uid: astrid_core::identity::PrincipalUid,
    source_root: &Path,
    files: &[MigrationEntry],
) -> io::Result<()> {
    let mut new_files = Vec::new();
    for entry in files {
        let source = source_root.join(&entry.source);
        let destination = FilesystemPath::new(entry.destination.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid logical destination {}: {error}", entry.destination),
            )
        })?;
        let (bytes, digest) = digest_file(&source)?;
        if bytes != entry.bytes || digest != entry.digest {
            return Err(conflict_path(
                &source,
                "legacy source changed during migration",
            ));
        }
        match filesystem.stat(&destination) {
            Ok(existing) => {
                if existing.kind() != FilesystemEntryKind::File {
                    return Err(conflict_fs(
                        &destination,
                        "destination kind conflicts with source file",
                    ));
                }
                verify_file_content(filesystem, &destination, entry)?;
            },
            Err(FilesystemError::NotFound(_)) => {
                astrid_core::platform_fs::verify_no_redirects(&source)?;
                validate_regular_file(&source)?;
                let name = ContentName::new(destination.as_str().to_owned()).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid content name {}: {error}", destination.as_str()),
                    )
                })?;
                new_files.push(ContiguousFileIngest::new(name, source, entry.bytes.get()));
            },
            Err(error) => return Err(storage_error(&error)),
        }
    }
    if new_files.is_empty() {
        return Ok(());
    }
    store
        .put_contiguous_files(StateOwner::Principal(uid), new_files)
        .map_err(|error| io::Error::other(format!("contiguous home import failed: {error}")))?;
    for entry in files {
        let destination = FilesystemPath::new(entry.destination.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid logical destination {}: {error}", entry.destination),
            )
        })?;
        if filesystem.stat(&destination).is_ok() {
            verify_file_content(filesystem, &destination, entry)?;
        }
    }
    Ok(())
}
