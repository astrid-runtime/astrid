//! Migration reader for the per-generation-directory staging format.

use std::fs::ReadDir;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::{StagingIntent, load_intent, load_intent_from_file};
use super::{StagedContentId, connection};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    PrivateDirectory, private_file_identity, validate_private_regular_file,
};

pub(super) const WRITING_DIRECTORY: &str = "writing";
pub(super) const READY_DIRECTORY: &str = "ready";
pub(super) const CONTENT_FILE: &str = "content.bin";
pub(super) const INTENT_FILE: &str = "intent.v2";
pub(super) const PUBLISHED_FILE: &str = "published.v1";
pub(super) const PUBLISHED_MARKER: &[u8] = b"astrid-content-stage-published-v1\n";

pub(super) struct LegacyReady {
    pub(super) directory_name: PathBuf,
    pub(super) capability: PrivateDirectory,
    pub(super) intent: StagingIntent,
    pub(super) content: Option<PathBuf>,
}

/// Inspect every recoverable legacy key without mutating the filesystem.
///
/// Migration uses this pass to reject cross-entry key collisions before
/// recovery promotes, quarantines, or cleans any legacy evidence.
pub(super) fn inspect_migration_intents(root: &Path) -> StorageResult<Option<Vec<StagingIntent>>> {
    let writing = root.join(WRITING_DIRECTORY);
    let ready = root.join(READY_DIRECTORY);
    let writing_exists = legacy_queue_exists(&writing)?;
    let ready_exists = legacy_queue_exists(&ready)?;
    if !writing_exists && !ready_exists {
        return Ok(None);
    }

    let mut intents = Vec::new();
    if writing_exists {
        for entry in read_directory(&writing)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate legacy staging writes {}: {error}",
                    writing.display()
                ))
            })?;
            if let Some(intent) = inspect_writing_intent(&entry)? {
                intents.push(intent);
            }
        }
    }
    if ready_exists {
        for entry in read_directory(&ready)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate legacy staging queue {}: {error}",
                    ready.display()
                ))
            })?;
            let directory = entry.path();
            let (sequence, id) = parse_ready_name(&entry.file_name().to_string_lossy())?;
            validate_stage_directory(&directory)?;
            let intent_path = directory.join(INTENT_FILE);
            match std::fs::symlink_metadata(&intent_path) {
                Ok(_) => {
                    let intent = load_intent(&intent_path)?;
                    if intent.sequence != sequence || intent.id != id {
                        return Err(connection(format!(
                            "legacy staged intent does not match ready directory {}",
                            directory.display()
                        )));
                    }
                    let content_path = directory.join(CONTENT_FILE);
                    match std::fs::symlink_metadata(&content_path) {
                        Ok(_) => {
                            let logical_bytes = validate_private_regular_file(&content_path)?;
                            if logical_bytes != intent.logical_bytes {
                                return Err(connection(format!(
                                    "legacy staged content length changed after seal in {}",
                                    directory.display()
                                )));
                            }
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                        Err(error) => {
                            return Err(connection(format!(
                                "inspect legacy staged content {}: {error}",
                                content_path.display()
                            )));
                        },
                    }
                    intents.push(intent);
                },
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && (published(&directory)? || directory_is_empty(&directory)?) => {},
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(connection(format!(
                        "legacy staging directory {} is missing required entries",
                        directory.display()
                    )));
                },
                Err(error) => {
                    return Err(connection(format!(
                        "inspect legacy staged intent {}: {error}",
                        intent_path.display()
                    )));
                },
            }
        }
    }
    Ok(Some(intents))
}

fn inspect_writing_intent(entry: &std::fs::DirEntry) -> StorageResult<Option<StagingIntent>> {
    let path = entry.path();
    if !stage_entry_is_directory(&path)? {
        return Ok(None);
    }
    validate_stage_directory(&path)?;
    let Some(id) = entry
        .file_name()
        .to_str()
        .and_then(|name| Uuid::parse_str(name).ok())
        .map(StagedContentId)
    else {
        return Ok(None);
    };
    let intent_path = path.join(INTENT_FILE);
    match std::fs::symlink_metadata(&intent_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(connection(format!(
                "inspect legacy staged intent {}: {error}",
                intent_path.display()
            )));
        },
        Ok(_) => {},
    }
    let intent = load_intent(&intent_path)?;
    if intent.id != id {
        return Err(connection(format!(
            "legacy staged intent does not match writing directory {}",
            path.display()
        )));
    }
    let content_path = path.join(CONTENT_FILE);
    let logical_bytes = validate_private_regular_file(&content_path)?;
    if logical_bytes != intent.logical_bytes {
        return Err(connection(format!(
            "legacy staged content length changed after seal in {}",
            path.display()
        )));
    }
    Ok(Some(intent))
}

pub(super) fn recover(
    root: &Path,
    root_directory: &PrivateDirectory,
    quarantine: &Path,
    quarantine_directory: &PrivateDirectory,
) -> StorageResult<Option<(PathBuf, Vec<LegacyReady>)>> {
    let writing = root.join(WRITING_DIRECTORY);
    let ready = root.join(READY_DIRECTORY);
    let writing_exists = legacy_queue_exists(&writing)?;
    let ready_exists = legacy_queue_exists(&ready)?;
    if !writing_exists && !ready_exists {
        return Ok(None);
    }
    let writing_directory = root_directory.ensure_child(Path::new(WRITING_DIRECTORY))?;
    let ready_directory = root_directory.ensure_child(Path::new(READY_DIRECTORY))?;
    recover_writing(
        &writing,
        &writing_directory,
        &ready_directory,
        quarantine,
        quarantine_directory,
    )?;

    let mut pending = Vec::new();
    for entry_name in ready_directory.entries()? {
        let entry_name = PathBuf::from(entry_name);
        let directory = ready.join(&entry_name);
        let (sequence, id) = parse_ready_name(&entry_name.to_string_lossy())?;
        let capability = ready_directory.open_child(&entry_name)?;
        if published_in(&directory, &capability)? || capability.entries()?.is_empty() {
            cleanup_in(&ready_directory, &entry_name, &capability)?;
            continue;
        }
        let intent_path = directory.join(INTENT_FILE);
        let mut intent_file = capability.open_file(Path::new(INTENT_FILE))?;
        let intent = load_intent_from_file(&intent_path, &mut intent_file)?;
        if intent.sequence != sequence || intent.id != id {
            return Err(connection(format!(
                "legacy staged intent does not match ready directory {}",
                directory.display()
            )));
        }
        let content_path = directory.join(CONTENT_FILE);
        let content = capability
            .contains(Path::new(CONTENT_FILE))?
            .then_some(content_path);
        if let Some(content) = &content {
            let logical_bytes = capability
                .open_file(Path::new(CONTENT_FILE))?
                .metadata()
                .map_err(|error| {
                    connection(format!(
                        "inspect legacy staged content {}: {error}",
                        content.display()
                    ))
                })?
                .len();
            if logical_bytes != intent.logical_bytes {
                return Err(connection(format!(
                    "legacy staged content length changed after seal in {}",
                    directory.display()
                )));
            }
        }
        validate_stage_entries_in(&directory, &capability, content.is_some())?;
        pending.push(LegacyReady {
            directory_name: entry_name,
            capability,
            intent,
            content,
        });
    }
    Ok(Some((ready, pending)))
}

fn legacy_queue_exists(path: &Path) -> StorageResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            validate_stage_directory(path)?;
            Ok(true)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(connection(format!(
            "inspect legacy staging queue {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn cleanup_in(
    parent: &PrivateDirectory,
    directory_name: &Path,
    directory: &PrivateDirectory,
) -> StorageResult<()> {
    for name in [CONTENT_FILE, INTENT_FILE, PUBLISHED_FILE] {
        if directory.contains(Path::new(name))? {
            directory.remove_file(Path::new(name))?;
        }
    }
    directory.sync()?;
    parent.remove_directory(directory_name)?;
    parent.sync()
}

fn recover_writing(
    writing: &Path,
    writing_directory: &PrivateDirectory,
    ready_directory: &PrivateDirectory,
    quarantine: &Path,
    quarantine_directory: &PrivateDirectory,
) -> StorageResult<()> {
    for entry_name in writing_directory.entries()? {
        let entry_name = PathBuf::from(entry_name);
        let path = writing.join(&entry_name);
        if !writing_directory.entry_is_directory(&entry_name)? {
            move_file_to_quarantine(
                writing_directory,
                &entry_name,
                quarantine,
                quarantine_directory,
                "legacy-unsealed",
            )?;
            continue;
        }
        let capability = writing_directory.open_child(&entry_name)?;
        let id = entry_name
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| Uuid::parse_str(name).ok())
            .map(StagedContentId);
        let recovered = id
            .and_then(|id| {
                let intent_path = path.join(INTENT_FILE);
                capability
                    .open_file(Path::new(INTENT_FILE))
                    .and_then(|mut file| load_intent_from_file(&intent_path, &mut file))
                    .ok()
                    .map(|intent| (id, intent))
            })
            .filter(|(id, intent)| *id == intent.id)
            .and_then(|(id, intent)| {
                capability
                    .open_file(Path::new(CONTENT_FILE))
                    .and_then(|file| {
                        file.metadata()
                            .map(|metadata| metadata.len())
                            .map_err(|error| connection(format!("inspect staged content: {error}")))
                    })
                    .ok()
                    .filter(|length| *length == intent.logical_bytes)
                    .map(|_| (id, intent))
            });
        let Some((id, intent)) = recovered else {
            move_directory_to_quarantine(
                writing_directory,
                &entry_name,
                quarantine,
                quarantine_directory,
                "legacy-unsealed",
            )?;
            continue;
        };
        let destination_name = PathBuf::from(ready_name(intent.sequence, id));
        if ready_directory.contains(&destination_name)? {
            move_directory_to_quarantine(
                writing_directory,
                &entry_name,
                quarantine,
                quarantine_directory,
                "legacy-duplicate",
            )?;
            continue;
        }
        writing_directory.rename_child_to(&entry_name, ready_directory, &destination_name)?;
        writing_directory.sync()?;
        ready_directory.sync()?;
    }
    Ok(())
}

fn published(directory: &Path) -> StorageResult<bool> {
    let marker = directory.join(PUBLISHED_FILE);
    match std::fs::symlink_metadata(&marker) {
        Ok(_) => {
            validate_private_regular_file(&marker)?;
            let bytes = std::fs::read(&marker).map_err(|error| {
                connection(format!(
                    "read legacy publication marker {}: {error}",
                    marker.display()
                ))
            })?;
            Ok(bytes == PUBLISHED_MARKER)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(connection(format!(
            "inspect legacy publication marker {}: {error}",
            marker.display()
        ))),
    }
}

fn published_in(directory: &Path, capability: &PrivateDirectory) -> StorageResult<bool> {
    if !capability.contains(Path::new(PUBLISHED_FILE))? {
        return Ok(false);
    }
    let marker = directory.join(PUBLISHED_FILE);
    let mut file = capability.open_file(Path::new(PUBLISHED_FILE))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|error| {
        connection(format!(
            "read legacy publication marker {}: {error}",
            marker.display()
        ))
    })?;
    Ok(bytes == PUBLISHED_MARKER)
}

fn directory_is_empty(directory: &Path) -> StorageResult<bool> {
    match read_directory(directory)?.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(connection(format!(
            "enumerate legacy staging entry {}: {error}",
            directory.display()
        ))),
    }
}

fn validate_stage_entries_in(
    directory: &Path,
    capability: &PrivateDirectory,
    content_exists: bool,
) -> StorageResult<()> {
    let mut expected = if content_exists {
        vec![CONTENT_FILE, INTENT_FILE]
    } else {
        vec![INTENT_FILE]
    };
    for name in capability.entries()? {
        let Some(name) = name.to_str() else {
            return Err(connection(format!(
                "legacy staging directory {} contains a non-UTF-8 entry",
                directory.display()
            )));
        };
        if let Some(position) = expected.iter().position(|expected| *expected == name) {
            expected.swap_remove(position);
        } else if name != PUBLISHED_FILE {
            return Err(connection(format!(
                "legacy staging directory {} contains unexpected entry {name:?}",
                directory.display()
            )));
        }
    }
    if expected.is_empty() {
        Ok(())
    } else {
        Err(connection(format!(
            "legacy staging directory {} is missing required entries",
            directory.display()
        )))
    }
}

fn parse_ready_name(name: &str) -> StorageResult<(u64, StagedContentId)> {
    let Some((sequence, id)) = name.split_once('-') else {
        return Err(connection(format!(
            "invalid legacy staged-write directory name {name:?}"
        )));
    };
    let sequence = sequence.parse::<u64>().map_err(|_| {
        connection(format!(
            "invalid legacy staged-write sequence in directory {name:?}"
        ))
    })?;
    let id = Uuid::parse_str(id)
        .map(StagedContentId)
        .map_err(|_| connection(format!("invalid legacy staged-write id in {name:?}")))?;
    if name != ready_name(sequence, id) {
        return Err(connection(format!(
            "non-canonical legacy staged-write directory name {name:?}"
        )));
    }
    Ok((sequence, id))
}

fn ready_name(sequence: u64, id: StagedContentId) -> String {
    format!("{sequence:020}-{id}")
}

fn read_directory(path: &Path) -> StorageResult<ReadDir> {
    std::fs::read_dir(path).map_err(|error| {
        connection(format!(
            "read legacy staging directory {}: {error}",
            path.display()
        ))
    })
}

fn quarantine_name(
    source_name: &Path,
    quarantine: &PrivateDirectory,
    classification: &str,
) -> StorageResult<PathBuf> {
    let source_name = source_name
        .to_str()
        .ok_or_else(|| connection("legacy staging entry name is not valid UTF-8".to_owned()))?;
    let mut suffix = 0_u64;
    loop {
        let candidate = PathBuf::from(format!("{source_name}.{classification}.{suffix}"));
        if !quarantine.contains(&candidate)? {
            return Ok(candidate);
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("legacy quarantine sequence exhausted".to_owned()))?;
    }
}

fn move_directory_to_quarantine(
    source: &PrivateDirectory,
    source_name: &Path,
    _quarantine_path: &Path,
    quarantine: &PrivateDirectory,
    classification: &str,
) -> StorageResult<()> {
    let destination = quarantine_name(source_name, quarantine, classification)?;
    source.rename_child_to(source_name, quarantine, &destination)?;
    source.sync()?;
    quarantine.sync()
}

fn move_file_to_quarantine(
    source: &PrivateDirectory,
    source_name: &Path,
    _quarantine_path: &Path,
    quarantine: &PrivateDirectory,
    classification: &str,
) -> StorageResult<()> {
    let destination = quarantine_name(source_name, quarantine, classification)?;
    let identity = private_file_identity(&source.open_file(source_name)?)?;
    source.rename_to_with_identity(source_name, quarantine, &destination, identity)?;
    source.sync()?;
    quarantine.sync()
}

pub(super) fn validate_stage_directory(path: &Path) -> StorageResult<()> {
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!(
            "validate legacy staging directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect legacy staging directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(connection(format!(
            "legacy staging entry {} is redirected or not a directory",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn stage_entry_is_directory(path: &Path) -> StorageResult<bool> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect legacy staging entry {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(connection(format!(
            "legacy staging entry {} is redirected",
            path.display()
        )));
    }
    Ok(metadata.is_dir())
}
