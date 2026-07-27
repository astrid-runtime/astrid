//! Native namespace recovery, validation, and conservative cleanup.

use std::fs::{ReadDir, read_dir};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::load_intent;
use super::{
    CONTENT_FILE, INTENT_FILE, PUBLISHED_FILE, PUBLISHED_MARKER, ReadyStagedContent,
    StagedContentId, connection,
};
use crate::error::StorageResult;
use crate::principal_state::native_io::{sync_directory, validate_private_regular_file};

pub(super) enum ReadyRecoveryState {
    Published,
    Empty,
    Pending,
}

pub(super) fn recover_writing(
    writing: &Path,
    ready: &Path,
    quarantine: &Path,
) -> StorageResult<()> {
    for entry in read_directory(writing)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate incomplete staging writes {}: {error}",
                writing.display()
            ))
        })?;
        let path = entry.path();
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
            let destination = move_to_quarantine(&path, quarantine, "unsealed")?;
            tracing::warn!(
                source = %path.display(),
                quarantine = %destination.display(),
                "preserved incomplete native content staging entry"
            );
            continue;
        };
        let destination = ready.join(ready_name(intent.sequence, id));
        if destination.exists() {
            let quarantined = move_to_quarantine(&path, quarantine, "duplicate")?;
            tracing::warn!(
                source = %path.display(),
                quarantine = %quarantined.display(),
                "preserved duplicate sealed content staging entry"
            );
            continue;
        }
        std::fs::rename(&path, &destination).map_err(|error| {
            connection(format!(
                "recover sealed staging entry {} as {}: {error}",
                path.display(),
                destination.display()
            ))
        })?;
        sync_directory(writing)?;
        sync_directory(ready)?;
    }
    Ok(())
}

pub(super) fn next_sequence(ready: &Path) -> StorageResult<u64> {
    let mut maximum = None::<u64>;
    for entry in read_directory(ready)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate staged write sequences {}: {error}",
                ready.display()
            ))
        })?;
        let (sequence, _) = parse_ready_name(&entry.file_name().to_string_lossy())?;
        maximum = Some(maximum.map_or(sequence, |current| current.max(sequence)));
    }
    match maximum {
        Some(value) => value
            .checked_add(1)
            .ok_or_else(|| connection("staged-write sequence exhausted".to_owned())),
        None => Ok(0),
    }
}

pub(super) fn load_ready(
    staging_root: &Path,
    directory: PathBuf,
    sequence: u64,
    id: StagedContentId,
) -> StorageResult<ReadyStagedContent> {
    ensure_existing_directory(&directory)?;
    let intent = load_intent(&directory.join(INTENT_FILE))?;
    if intent.sequence != sequence || intent.id != id {
        return Err(connection(format!(
            "staged intent does not match ready directory {}",
            directory.display()
        )));
    }
    let logical_bytes = validate_private_regular_file(&directory.join(CONTENT_FILE))?;
    if logical_bytes != intent.logical_bytes {
        return Err(connection(format!(
            "staged content length changed after seal in {}",
            directory.display()
        )));
    }
    validate_stage_entries(&directory)?;
    Ok(ReadyStagedContent::from_intent(
        staging_root.to_path_buf(),
        directory,
        intent,
    ))
}

pub(super) fn ready_recovery_state(directory: &Path) -> StorageResult<ReadyRecoveryState> {
    ensure_existing_directory(directory)?;
    let marker_path = directory.join(PUBLISHED_FILE);
    let marker = match std::fs::symlink_metadata(&marker_path) {
        Ok(_) => {
            validate_private_regular_file(&marker_path)?;
            Some(std::fs::read(&marker_path).map_err(|error| {
                connection(format!(
                    "read staged publication marker {}: {error}",
                    marker_path.display()
                ))
            })?)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(connection(format!(
                "inspect staged publication marker {}: {error}",
                marker_path.display()
            )));
        },
    };
    if marker.as_deref() == Some(PUBLISHED_MARKER) {
        return Ok(ReadyRecoveryState::Published);
    }

    match read_directory(directory)?.next() {
        None => Ok(ReadyRecoveryState::Empty),
        Some(Ok(_)) => Ok(ReadyRecoveryState::Pending),
        Some(Err(error)) => Err(connection(format!(
            "enumerate staging entry {}: {error}",
            directory.display()
        ))),
    }
}

pub(super) fn ready_name(sequence: u64, id: StagedContentId) -> String {
    format!("{sequence:020}-{id}")
}

pub(super) fn parse_ready_name(name: &str) -> StorageResult<(u64, StagedContentId)> {
    let Some((sequence, id)) = name.split_once('-') else {
        return Err(connection(format!(
            "invalid staged-write directory name {name:?}"
        )));
    };
    let sequence = sequence.parse::<u64>().map_err(|_| {
        connection(format!(
            "invalid staged-write sequence in directory {name:?}"
        ))
    })?;
    let id = Uuid::parse_str(id)
        .map(StagedContentId)
        .map_err(|_| connection(format!("invalid staged-write id in directory {name:?}")))?;
    if name != ready_name(sequence, id) {
        return Err(connection(format!(
            "non-canonical staged-write directory name {name:?}"
        )));
    }
    Ok((sequence, id))
}

pub(super) fn remove_known_stage_files(directory: &Path) -> StorageResult<()> {
    validate_stage_entries(directory)?;
    for name in [CONTENT_FILE, INTENT_FILE, PUBLISHED_FILE] {
        let path = directory.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(connection(format!(
                    "remove staging file {}: {error}",
                    path.display()
                )));
            },
        }
    }
    std::fs::remove_dir(directory).map_err(|error| {
        connection(format!(
            "remove staging directory {}: {error}",
            directory.display()
        ))
    })
}

pub(super) fn read_directory(path: &Path) -> StorageResult<ReadDir> {
    read_dir(path).map_err(|error| {
        connection(format!(
            "read staging directory {}: {error}",
            path.display()
        ))
    })
}

fn move_to_quarantine(
    source: &Path,
    quarantine: &Path,
    classification: &str,
) -> StorageResult<PathBuf> {
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| connection("staging entry name is not valid UTF-8".to_owned()))?;
    let mut suffix = 0_u64;
    let destination = loop {
        let candidate = quarantine.join(format!("{source_name}.{classification}.{suffix}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("staging quarantine sequence exhausted".to_owned()))?;
    };
    std::fs::rename(source, &destination).map_err(|error| {
        connection(format!(
            "quarantine staging entry {} as {}: {error}",
            source.display(),
            destination.display()
        ))
    })?;
    if let Some(parent) = source.parent() {
        sync_directory(parent)?;
    }
    sync_directory(quarantine)?;
    Ok(destination)
}

fn ensure_existing_directory(path: &Path) -> StorageResult<()> {
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!(
            "validate staging directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect staging directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(connection(format!(
            "staging entry {} is redirected or not a directory",
            path.display()
        )));
    }
    Ok(())
}

fn validate_stage_entries(directory: &Path) -> StorageResult<()> {
    for entry in read_directory(directory)? {
        let entry = entry.map_err(|error| {
            connection(format!(
                "enumerate staging entry {}: {error}",
                directory.display()
            ))
        })?;
        let name = entry.file_name();
        if name != CONTENT_FILE && name != INTENT_FILE && name != PUBLISHED_FILE {
            return Err(connection(format!(
                "unexpected file in staging entry {}",
                entry.path().display()
            )));
        }
        validate_private_regular_file(&entry.path())?;
    }
    Ok(())
}
