//! Migration reader for the per-generation-directory staging format.

use std::fs::ReadDir;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::{StagingIntent, load_intent};
use super::{StagedContentId, connection};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    ensure_private_directory, sync_directory, validate_private_regular_file,
};

pub(super) const WRITING_DIRECTORY: &str = "writing";
pub(super) const READY_DIRECTORY: &str = "ready";
pub(super) const CONTENT_FILE: &str = "content.bin";
pub(super) const INTENT_FILE: &str = "intent.v2";
pub(super) const PUBLISHED_FILE: &str = "published.v1";
pub(super) const PUBLISHED_MARKER: &[u8] = b"astrid-content-stage-published-v1\n";

pub(super) struct LegacyReady {
    pub(super) directory: PathBuf,
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
    if !writing.exists() && !ready.exists() {
        return Ok(None);
    }

    let mut intents = Vec::new();
    if writing.exists() {
        validate_stage_directory(&writing)?;
        for entry in read_directory(&writing)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate legacy staging writes {}: {error}",
                    writing.display()
                ))
            })?;
            let path = entry.path();
            if !stage_entry_is_directory(&path)? {
                continue;
            }
            validate_stage_directory(&path)?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
                .map(StagedContentId)
            else {
                continue;
            };
            if let Ok(intent) = load_intent(&path.join(INTENT_FILE))
                && intent.id == id
                && validate_private_regular_file(&path.join(CONTENT_FILE))
                    .is_ok_and(|length| length == intent.logical_bytes)
            {
                intents.push(intent);
            }
        }
    }
    if ready.exists() {
        validate_stage_directory(&ready)?;
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

pub(super) fn recover(
    root: &Path,
    quarantine: &Path,
) -> StorageResult<Option<(PathBuf, Vec<LegacyReady>)>> {
    let writing = root.join(WRITING_DIRECTORY);
    let ready = root.join(READY_DIRECTORY);
    if !writing.exists() && !ready.exists() {
        return Ok(None);
    }
    ensure_private_directory(&writing)?;
    ensure_private_directory(&ready)?;
    ensure_private_directory(quarantine)?;
    recover_writing(&writing, &ready, quarantine)?;

    let mut pending = Vec::new();
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
        if published(&directory)? || directory_is_empty(&directory)? {
            cleanup(&directory)?;
            continue;
        }
        let intent = load_intent(&directory.join(INTENT_FILE))?;
        if intent.sequence != sequence || intent.id != id {
            return Err(connection(format!(
                "legacy staged intent does not match ready directory {}",
                directory.display()
            )));
        }
        let content_path = directory.join(CONTENT_FILE);
        let content = match std::fs::symlink_metadata(&content_path) {
            Ok(_) => Some(content_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(connection(format!(
                    "inspect legacy staged content {}: {error}",
                    content_path.display()
                )));
            },
        };
        if let Some(content) = &content {
            let logical_bytes = validate_private_regular_file(content)?;
            if logical_bytes != intent.logical_bytes {
                return Err(connection(format!(
                    "legacy staged content length changed after seal in {}",
                    directory.display()
                )));
            }
        }
        validate_stage_entries(&directory, content.is_some())?;
        pending.push(LegacyReady {
            directory,
            intent,
            content,
        });
    }
    Ok(Some((ready, pending)))
}

pub(super) fn cleanup(directory: &Path) -> StorageResult<()> {
    for name in [CONTENT_FILE, INTENT_FILE, PUBLISHED_FILE] {
        let path = directory.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(connection(format!(
                    "remove legacy staging file {}: {error}",
                    path.display()
                )));
            },
        }
    }
    std::fs::remove_dir(directory).map_err(|error| {
        connection(format!(
            "remove legacy staging directory {}: {error}",
            directory.display()
        ))
    })
}

fn recover_writing(writing: &Path, ready: &Path, quarantine: &Path) -> StorageResult<()> {
    for entry in read_directory(writing)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate incomplete legacy staging writes {}: {error}",
                writing.display()
            ))
        })?;
        let path = entry.path();
        if !stage_entry_is_directory(&path)? {
            move_to_quarantine(&path, quarantine, "legacy-unsealed")?;
            continue;
        }
        validate_stage_directory(&path)?;
        let id = entry
            .file_name()
            .to_str()
            .and_then(|name| Uuid::parse_str(name).ok())
            .map(StagedContentId);
        let recovered = id
            .and_then(|id| {
                load_intent(&path.join(INTENT_FILE))
                    .ok()
                    .map(|intent| (id, intent))
            })
            .filter(|(id, intent)| *id == intent.id)
            .and_then(|(id, intent)| {
                validate_private_regular_file(&path.join(CONTENT_FILE))
                    .ok()
                    .filter(|length| *length == intent.logical_bytes)
                    .map(|_| (id, intent))
            });
        let Some((id, intent)) = recovered else {
            move_to_quarantine(&path, quarantine, "legacy-unsealed")?;
            continue;
        };
        let destination = ready.join(ready_name(intent.sequence, id));
        if destination.exists() {
            move_to_quarantine(&path, quarantine, "legacy-duplicate")?;
            continue;
        }
        std::fs::rename(&path, &destination).map_err(|error| {
            connection(format!(
                "recover legacy staging entry {} as {}: {error}",
                path.display(),
                destination.display()
            ))
        })?;
        sync_directory(writing)?;
        sync_directory(ready)?;
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

fn validate_stage_entries(directory: &Path, content_exists: bool) -> StorageResult<()> {
    let mut expected = if content_exists {
        vec![CONTENT_FILE, INTENT_FILE]
    } else {
        vec![INTENT_FILE]
    };
    for entry in read_directory(directory)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate legacy staging directory {}: {error}",
                directory.display()
            ))
        })?;
        let name = entry.file_name();
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

fn move_to_quarantine(source: &Path, quarantine: &Path, classification: &str) -> StorageResult<()> {
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| connection("legacy staging entry name is not valid UTF-8".to_owned()))?;
    let mut suffix = 0_u64;
    let destination = loop {
        let candidate = quarantine.join(format!("{source_name}.{classification}.{suffix}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("legacy quarantine sequence exhausted".to_owned()))?;
    };
    std::fs::rename(source, &destination).map_err(|error| {
        connection(format!(
            "quarantine legacy staging entry {} as {}: {error}",
            source.display(),
            destination.display()
        ))
    })?;
    if let Some(parent) = source.parent() {
        sync_directory(parent)?;
    }
    sync_directory(quarantine)
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
