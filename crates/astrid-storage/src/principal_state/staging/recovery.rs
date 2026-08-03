//! Native staged-generation recovery and validation.

use std::fs::{ReadDir, read_dir};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::{StagingIntent, load_generation_footer};
use super::journal::{StageKey, StageKey as JournalStageKey};
use super::{ReadyStagedContent, StagedContentId, connection, open_generation_name};
use crate::error::StorageResult;
use crate::principal_state::native_io::{rename_private_entry, sync_directory};

pub(super) enum GenerationName {
    Open,
    Sealed(StageKey),
}

pub(super) fn load_generation(
    staging_root: &Path,
    path: PathBuf,
    intent: StagingIntent,
) -> StorageResult<ReadyStagedContent> {
    validate_generation(&path, &intent)?;
    Ok(ReadyStagedContent::from_intent(
        staging_root.to_path_buf(),
        path,
        intent,
    ))
}

pub(super) fn validate_generation(path: &Path, intent: &StagingIntent) -> StorageResult<()> {
    let expected = sealed_generation_name(intent.sequence, intent.id);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected.as_str()) {
        return Err(connection(format!(
            "staged generation path is not canonical: {}",
            path.display()
        )));
    }
    let footer = load_generation_footer(path)?;
    if &footer != intent {
        return Err(connection(format!(
            "staged generation footer changed after seal in {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn sealed_generation_name(sequence: u64, id: StagedContentId) -> String {
    format!("{sequence:020}-{id}.sealed")
}

pub(super) fn parse_generation_name(name: &str) -> StorageResult<GenerationName> {
    if let Some(id) = name.strip_suffix(".open") {
        let id = Uuid::parse_str(id)
            .map(StagedContentId)
            .map_err(|_| connection(format!("invalid open generation name {name:?}")))?;
        if name != open_generation_name(id) {
            return Err(connection(format!(
                "non-canonical open generation name {name:?}"
            )));
        }
        return Ok(GenerationName::Open);
    }
    let Some(stem) = name.strip_suffix(".sealed") else {
        return Err(connection(format!(
            "invalid staged generation name {name:?}"
        )));
    };
    let Some((sequence, id)) = stem.split_once('-') else {
        return Err(connection(format!(
            "invalid sealed generation name {name:?}"
        )));
    };
    let sequence = sequence.parse::<u64>().map_err(|_| {
        connection(format!(
            "invalid staged-write sequence in generation {name:?}"
        ))
    })?;
    let id = Uuid::parse_str(id)
        .map(StagedContentId)
        .map_err(|_| connection(format!("invalid staged-write id in generation {name:?}")))?;
    if name != sealed_generation_name(sequence, id) {
        return Err(connection(format!(
            "non-canonical staged generation name {name:?}"
        )));
    }
    Ok(GenerationName::Sealed(JournalStageKey { sequence, id }))
}

pub(super) fn read_directory(path: &Path) -> StorageResult<ReadDir> {
    read_dir(path).map_err(|error| {
        connection(format!(
            "read staging directory {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn move_to_quarantine(
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
    rename_private_entry(source, &destination)?;
    if let Some(parent) = source.parent() {
        sync_directory(parent)?;
    }
    sync_directory(quarantine)?;
    Ok(destination)
}
