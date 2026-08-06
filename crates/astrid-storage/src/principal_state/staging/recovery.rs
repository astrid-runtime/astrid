//! Native staged-generation recovery and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{DirEntry, ReadDir, read_dir};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::{StagingIntent, load_generation_footer, load_generation_footer_with_identity};
use super::journal::{
    JournalRecord, StageKey, StageKey as JournalStageKey, append_records, flush_journal,
};
use super::retirement::{create_marker, remove as remove_generation};
use super::{
    JournalState, ReadyStagedContent, StagedContentId, StagingFaultInjector, StagingFaultPoint,
    claim_generation_key, connection, open_generation_name,
};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    PrivateFileIdentity, open_private_file, private_file_identity, rename_private_entry,
    sync_directory, validate_private_regular_file,
};

struct RecoveryScan {
    recovered: Vec<StagingIntent>,
    completed_with_sealed: BTreeSet<StageKey>,
    namespace_changed: bool,
}

struct RecoveryContext<'a> {
    generations: &'a Path,
    quarantine: &'a Path,
    journal: &'a JournalState,
    retired: &'a BTreeMap<StageKey, PathBuf>,
    sequences: &'a mut BTreeMap<u64, StagedContentId>,
    identifiers: &'a mut BTreeMap<StagedContentId, u64>,
}

/// Reconcile native generation names with the recovered intent journal.
pub(super) fn recover_generations(
    generations: &Path,
    quarantine: &Path,
    journal: &mut JournalState,
    faults: &dyn StagingFaultInjector,
) -> StorageResult<()> {
    let entries = collect_entries(generations)?;
    let mut sequences = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    for key in journal.pending.keys().chain(journal.completed.iter()) {
        claim_generation_key(&mut sequences, &mut identifiers, *key)?;
    }
    let retired = discover_retired(&entries, journal, &mut sequences, &mut identifiers)?;
    let scan = scan_entries(
        entries,
        RecoveryContext {
            generations,
            quarantine,
            journal,
            retired: &retired,
            sequences: &mut sequences,
            identifiers: &mut identifiers,
        },
    )?;
    let cleanup_changed = finish_retirements(generations, journal, &retired, &scan)?;
    flush_recovery_namespace(
        generations,
        journal,
        faults,
        scan.namespace_changed || cleanup_changed,
    )?;
    publish_recovered(generations, journal, faults, scan.recovered)?;
    validate_pending(generations, journal)
}

fn collect_entries(generations: &Path) -> StorageResult<Vec<DirEntry>> {
    read_directory(generations)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            connection(format!(
                "enumerate staged generations {}: {error}",
                generations.display()
            ))
        })
}

fn discover_retired(
    entries: &[DirEntry],
    journal: &JournalState,
    sequences: &mut BTreeMap<u64, StagedContentId>,
    identifiers: &mut BTreeMap<StagedContentId, u64>,
) -> StorageResult<BTreeMap<StageKey, PathBuf>> {
    let mut retired = BTreeMap::new();
    for entry in entries {
        let name = entry.file_name();
        let Ok(GenerationName::Retired(key)) = parse_generation_name(&name.to_string_lossy())
        else {
            continue;
        };
        if journal.pending.contains_key(&key) {
            return Err(connection(format!(
                "retired staged generation {} is still pending",
                entry.path().display()
            )));
        }
        claim_generation_key(sequences, identifiers, key)?;
        validate_private_regular_file(&entry.path())?;
        retired.insert(key, entry.path());
    }
    Ok(retired)
}

fn scan_entries(
    entries: Vec<DirEntry>,
    mut context: RecoveryContext<'_>,
) -> StorageResult<RecoveryScan> {
    let mut scan = RecoveryScan {
        recovered: Vec::new(),
        completed_with_sealed: BTreeSet::new(),
        namespace_changed: false,
    };
    for entry in entries {
        scan_entry(&entry, &mut context, &mut scan)?;
    }
    Ok(scan)
}

fn scan_entry(
    entry: &DirEntry,
    context: &mut RecoveryContext<'_>,
    scan: &mut RecoveryScan,
) -> StorageResult<()> {
    let path = entry.path();
    match parse_generation_name(&entry.file_name().to_string_lossy()) {
        Ok(GenerationName::Open) => move_and_mark(scan, &path, context.quarantine, "unsealed"),
        Ok(GenerationName::Retired(_)) => Ok(()),
        Ok(GenerationName::Sealed(key)) if context.retired.contains_key(&key) => {
            move_to_quarantine(&path, context.quarantine, "published")?;
            scan.namespace_changed = true;
            Ok(())
        },
        Ok(GenerationName::Sealed(key)) if context.journal.completed.contains(&key) => {
            let tombstone = context
                .generations
                .join(retired_generation_name(key.sequence, key.id));
            rename_private_entry(&path, &tombstone)?;
            remove_generation(&tombstone)?;
            scan.completed_with_sealed.insert(key);
            scan.namespace_changed = true;
            Ok(())
        },
        Ok(GenerationName::Sealed(key)) if context.journal.pending.contains_key(&key) => Ok(()),
        Ok(GenerationName::Sealed(key)) => recover_or_quarantine(
            scan,
            &path,
            context.quarantine,
            key,
            context.sequences,
            context.identifiers,
        ),
        Err(_) => move_and_mark(scan, &path, context.quarantine, "orphan"),
    }
}

fn move_and_mark(
    scan: &mut RecoveryScan,
    path: &Path,
    quarantine: &Path,
    classification: &str,
) -> StorageResult<()> {
    move_to_quarantine(path, quarantine, classification)?;
    scan.namespace_changed = true;
    Ok(())
}

fn recover_or_quarantine(
    scan: &mut RecoveryScan,
    path: &Path,
    quarantine: &Path,
    key: StageKey,
    sequences: &mut BTreeMap<u64, StagedContentId>,
    identifiers: &mut BTreeMap<StagedContentId, u64>,
) -> StorageResult<()> {
    let Ok(intent) = load_generation_footer(path) else {
        return move_and_mark(scan, path, quarantine, "orphan");
    };
    if StageKey::from_intent(&intent) != key {
        return Err(connection(format!(
            "orphan staged generation footer disagrees with {}",
            path.display()
        )));
    }
    claim_generation_key(sequences, identifiers, key)?;
    scan.recovered.push(intent);
    Ok(())
}

fn finish_retirements(
    generations: &Path,
    journal: &JournalState,
    retired: &BTreeMap<StageKey, PathBuf>,
    scan: &RecoveryScan,
) -> StorageResult<bool> {
    let mut changed = false;
    for key in journal.completed.iter().copied() {
        if scan.completed_with_sealed.contains(&key) {
            continue;
        }
        if let Some(tombstone) = retired.get(&key) {
            remove_generation(tombstone)?;
            changed = true;
        } else {
            create_marker(generations, key)?;
            remove_generation(&generations.join(retired_generation_name(key.sequence, key.id)))?;
            changed = true;
        }
    }
    for (key, tombstone) in retired {
        if !journal.completed.contains(key) {
            remove_generation(tombstone)?;
            changed = true;
        }
    }
    Ok(changed)
}

fn flush_recovery_namespace(
    generations: &Path,
    journal: &JournalState,
    faults: &dyn StagingFaultInjector,
    namespace_changed: bool,
) -> StorageResult<()> {
    if !journal.completed.is_empty() {
        // A durable retired name makes any generation bytes non-publishable on
        // Windows; Unix additionally flushes the final directory state.
        sync_directory(generations)?;
        faults.fail(StagingFaultPoint::RecoveryCleanupDirectoryFlushed)
    } else if namespace_changed {
        sync_directory(generations)
    } else {
        Ok(())
    }
}

fn publish_recovered(
    generations: &Path,
    journal: &mut JournalState,
    faults: &dyn StagingFaultInjector,
    mut recovered: Vec<StagingIntent>,
) -> StorageResult<()> {
    if recovered.is_empty() {
        return Ok(());
    }
    sync_directory(generations)?;
    faults.fail(StagingFaultPoint::RecoveryGenerationDirectoryFlushed)?;
    recovered.sort_by_key(StageKey::from_intent);
    let records = recovered
        .iter()
        .cloned()
        .map(JournalRecord::Sealed)
        .collect::<Vec<_>>();
    append_records(&mut journal.file, &records)?;
    flush_journal(&journal.file)?;
    for intent in recovered {
        journal
            .pending
            .insert(StageKey::from_intent(&intent), intent);
    }
    Ok(())
}

fn validate_pending(generations: &Path, journal: &JournalState) -> StorageResult<()> {
    for intent in journal.pending.values() {
        let path = generations.join(sealed_generation_name(intent.sequence, intent.id));
        validate_generation(&path, intent)?;
    }
    Ok(())
}

pub(super) enum GenerationName {
    Open,
    Sealed(StageKey),
    Retired(StageKey),
}

pub(super) fn load_generation(
    staging_root: &Path,
    path: PathBuf,
    intent: StagingIntent,
) -> StorageResult<ReadyStagedContent> {
    let (_, source_identity) = open_generation(&path, &intent, None)?;
    Ok(ReadyStagedContent::from_intent(
        staging_root.to_path_buf(),
        path,
        intent,
        source_identity,
    ))
}

pub(super) fn validate_generation(path: &Path, intent: &StagingIntent) -> StorageResult<()> {
    open_generation(path, intent, None).map(|_| ())
}

pub(super) fn open_generation(
    path: &Path,
    intent: &StagingIntent,
    expected_identity: Option<PrivateFileIdentity>,
) -> StorageResult<(std::fs::File, PrivateFileIdentity)> {
    let expected = sealed_generation_name(intent.sequence, intent.id);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected.as_str()) {
        return Err(connection(format!(
            "staged generation path is not canonical: {}",
            path.display()
        )));
    }
    let footer = load_generation_footer_with_identity(path)?;
    if &footer.intent != intent {
        return Err(connection(format!(
            "staged generation footer changed after seal in {}",
            path.display()
        )));
    }
    let file = open_private_file(path)?;
    let actual = private_file_identity(&file)?;
    if footer
        .source_identity
        .is_some_and(|sealed| sealed != actual)
        || expected_identity.is_some_and(|expected| expected != actual)
    {
        return Err(connection(format!(
            "staged generation source identity changed after seal in {}",
            path.display()
        )));
    }
    Ok((file, actual))
}

pub(super) fn sealed_generation_name(sequence: u64, id: StagedContentId) -> String {
    format!("{sequence:020}-{id}.sealed")
}

pub(super) fn retired_generation_name(sequence: u64, id: StagedContentId) -> String {
    format!("{sequence:020}-{id}.published")
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
    let (stem, retired) = if let Some(stem) = name.strip_suffix(".sealed") {
        (stem, false)
    } else if let Some(stem) = name.strip_suffix(".published") {
        (stem, true)
    } else {
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
    let canonical = if retired {
        retired_generation_name(sequence, id)
    } else {
        sealed_generation_name(sequence, id)
    };
    if name != canonical {
        return Err(connection(format!(
            "non-canonical staged generation name {name:?}"
        )));
    }
    let key = JournalStageKey { sequence, id };
    Ok(if retired {
        GenerationName::Retired(key)
    } else {
        GenerationName::Sealed(key)
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
