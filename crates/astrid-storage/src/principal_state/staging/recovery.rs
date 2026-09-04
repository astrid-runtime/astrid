//! Native staged-generation recovery and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{ReadDir, read_dir};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::format::{
    GenerationOwnerScan, StagingIntent, inspect_generation_footer_owner,
    is_runtime_forbidden_user_owner, load_generation_footer_from_file,
};
use super::journal::{
    JournalRecord, StageKey, StageKey as JournalStageKey, append_records, flush_journal,
    scan_runtime_forbidden_user_without_repair,
};
use super::retirement::{create_marker_in, remove_in as remove_generation_in};
use super::{
    JOURNAL_FILE, JournalState, ReadyStagedContent, StagedContentId, StagingFaultInjector,
    StagingFaultPoint, claim_generation_key, connection, open_generation_name,
};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    PrivateDirectory, PrivateFileIdentity, private_file_identity,
};

struct RecoveryScan {
    recovered: Vec<StagingIntent>,
    completed_with_sealed: BTreeSet<StageKey>,
    namespace_changed: bool,
}

/// Prove a staging area contains no canonical User before any recovery write.
pub(super) fn reject_runtime_forbidden_staging(
    root: &PrivateDirectory,
    generations: &PrivateDirectory,
    quarantine: &PrivateDirectory,
) -> StorageResult<()> {
    if root.contains(Path::new(JOURNAL_FILE))? {
        let mut journal = root.open_file(Path::new(JOURNAL_FILE))?;
        let scan = scan_runtime_forbidden_user_without_repair(&mut journal).map_err(|error| {
            connection(format!("inspect staging journal without repair: {error}"))
        })?;
        if let Some(error) = scan.scan_error {
            return Err(connection(format!(
                "staging journal owner preflight could not prove complete coverage: {error}"
            )));
        }
        if scan.contains_user {
            return Err(connection(
                "explicit user owner in staging journal is not runtime-admitted".to_owned(),
            ));
        }
    }
    for directory in [generations, quarantine] {
        for name in directory.entries()? {
            let name = PathBuf::from(name);
            if !directory.entry_is_file(&name)? {
                continue;
            }
            let mut file = directory.open_file(&name)?;
            let path = PathBuf::from(format!("staging generation {}", name.display()));
            match inspect_generation_footer_owner(&path, &mut file)? {
                GenerationOwnerScan::User => {
                    return Err(connection(format!(
                        "explicit user owner in staged generation {} is not runtime-admitted",
                        name.display()
                    )));
                },
                GenerationOwnerScan::Admitted | GenerationOwnerScan::Terminal => {},
                GenerationOwnerScan::Malformed(detail) => {
                    return Err(connection(format!(
                        "staged generation {} owner preflight failed: {detail}",
                        name.display()
                    )));
                },
            }
        }
    }
    Ok(())
}

struct RecoveryContext<'a> {
    generations_path: &'a Path,
    generations: &'a PrivateDirectory,
    quarantine_path: &'a Path,
    quarantine: &'a PrivateDirectory,
    journal: &'a JournalState,
    retired: &'a BTreeMap<StageKey, PathBuf>,
    sequences: &'a mut BTreeMap<u64, StagedContentId>,
    identifiers: &'a mut BTreeMap<StagedContentId, u64>,
}

/// Reconcile native generation names with the recovered intent journal.
pub(super) fn recover_generations(
    generations_path: &Path,
    generations: &PrivateDirectory,
    quarantine_path: &Path,
    quarantine: &PrivateDirectory,
    journal: &mut JournalState,
    faults: &dyn StagingFaultInjector,
) -> StorageResult<()> {
    let entries = collect_entries(generations)?;
    let mut sequences = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    for key in journal.pending.keys().chain(journal.completed.iter()) {
        claim_generation_key(&mut sequences, &mut identifiers, *key)?;
    }
    let retired = discover_retired(
        generations_path,
        generations,
        &entries,
        journal,
        &mut sequences,
        &mut identifiers,
    )?;
    let scan = scan_entries(
        entries,
        RecoveryContext {
            generations_path,
            generations,
            quarantine_path,
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
    validate_pending(generations_path, generations, journal)
}

fn collect_entries(generations: &PrivateDirectory) -> StorageResult<Vec<PathBuf>> {
    generations
        .entries()
        .map(|entries| entries.into_iter().map(PathBuf::from).collect())
}

fn discover_retired(
    generations_path: &Path,
    generations: &PrivateDirectory,
    entries: &[PathBuf],
    journal: &JournalState,
    sequences: &mut BTreeMap<u64, StagedContentId>,
    identifiers: &mut BTreeMap<StagedContentId, u64>,
) -> StorageResult<BTreeMap<StageKey, PathBuf>> {
    let mut retired = BTreeMap::new();
    for name in entries {
        let Ok(GenerationName::Retired(key)) = parse_generation_name(&name.to_string_lossy())
        else {
            continue;
        };
        if journal.pending.contains_key(&key) {
            return Err(connection(format!(
                "retired staged generation {} is still pending",
                generations_path.join(name).display()
            )));
        }
        claim_generation_key(sequences, identifiers, key)?;
        generations.open_file(name)?;
        retired.insert(key, name.clone());
    }
    Ok(retired)
}

fn scan_entries(
    entries: Vec<PathBuf>,
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
    name: &Path,
    context: &mut RecoveryContext<'_>,
    scan: &mut RecoveryScan,
) -> StorageResult<()> {
    match parse_generation_name(&name.to_string_lossy()) {
        Ok(GenerationName::Open) => move_and_mark(scan, name, context, "unsealed"),
        Ok(GenerationName::Retired(_)) => Ok(()),
        Ok(GenerationName::Sealed(key)) if context.retired.contains_key(&key) => {
            move_to_quarantine_in(
                context.generations,
                name,
                context.quarantine,
                context.quarantine_path,
                "published",
            )?;
            scan.namespace_changed = true;
            Ok(())
        },
        Ok(GenerationName::Sealed(key)) if context.journal.completed.contains(&key) => {
            let tombstone = PathBuf::from(retired_generation_name(key.sequence, key.id));
            let identity = private_file_identity(&context.generations.open_file(name)?)?;
            context
                .generations
                .rename_with_identity(name, &tombstone, identity)?;
            context.generations.remove_file(&tombstone)?;
            scan.completed_with_sealed.insert(key);
            scan.namespace_changed = true;
            Ok(())
        },
        Ok(GenerationName::Sealed(key)) if context.journal.pending.contains_key(&key) => Ok(()),
        Ok(GenerationName::Sealed(key)) => recover_or_quarantine(scan, name, context, key),
        Err(_) => move_and_mark(scan, name, context, "orphan"),
    }
}

fn move_and_mark(
    scan: &mut RecoveryScan,
    name: &Path,
    context: &RecoveryContext<'_>,
    classification: &str,
) -> StorageResult<()> {
    move_to_quarantine_in(
        context.generations,
        name,
        context.quarantine,
        context.quarantine_path,
        classification,
    )?;
    scan.namespace_changed = true;
    Ok(())
}

fn recover_or_quarantine(
    scan: &mut RecoveryScan,
    name: &Path,
    context: &mut RecoveryContext<'_>,
    key: StageKey,
) -> StorageResult<()> {
    let path = context.generations_path.join(name);
    let Ok(mut file) = context.generations.open_file(name) else {
        return move_and_mark(scan, name, context, "orphan");
    };
    let footer = match load_generation_footer_from_file(&path, &mut file) {
        Ok(footer) => footer,
        Err(error) if is_runtime_forbidden_user_owner(&error) => {
            return Err(connection(format!(
                "explicit user owner in staged generation {} is not runtime-admitted",
                path.display()
            )));
        },
        Err(_) => return move_and_mark(scan, name, context, "orphan"),
    };
    let intent = footer.intent;
    if StageKey::from_intent(&intent) != key {
        return Err(connection(format!(
            "orphan staged generation footer disagrees with {}",
            path.display()
        )));
    }
    claim_generation_key(context.sequences, context.identifiers, key)?;
    scan.recovered.push(intent);
    Ok(())
}

fn finish_retirements(
    generations: &PrivateDirectory,
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
            generations.remove_file(tombstone)?;
            changed = true;
        } else {
            create_marker_in(generations, key)?;
            remove_generation_in(generations, key)?;
            changed = true;
        }
    }
    for (key, tombstone) in retired {
        if !journal.completed.contains(key) {
            generations.remove_file(tombstone)?;
            changed = true;
        }
    }
    Ok(changed)
}

fn flush_recovery_namespace(
    generations: &PrivateDirectory,
    journal: &JournalState,
    faults: &dyn StagingFaultInjector,
    namespace_changed: bool,
) -> StorageResult<()> {
    if !journal.completed.is_empty() {
        // A durable retired name makes any generation bytes non-publishable on
        // Windows; Unix additionally flushes the final directory state.
        generations.sync()?;
        faults.fail(StagingFaultPoint::RecoveryCleanupDirectoryFlushed)
    } else if namespace_changed {
        generations.sync()
    } else {
        Ok(())
    }
}

fn publish_recovered(
    generations: &PrivateDirectory,
    journal: &mut JournalState,
    faults: &dyn StagingFaultInjector,
    mut recovered: Vec<StagingIntent>,
) -> StorageResult<()> {
    if recovered.is_empty() {
        return Ok(());
    }
    generations.sync()?;
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

fn validate_pending(
    generations_path: &Path,
    generations: &PrivateDirectory,
    journal: &JournalState,
) -> StorageResult<()> {
    for intent in journal.pending.values() {
        let path = generations_path.join(sealed_generation_name(intent.sequence, intent.id));
        open_generation_in(generations, &path, intent, None)?;
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
    directory: &PrivateDirectory,
    path: PathBuf,
    intent: StagingIntent,
) -> StorageResult<ReadyStagedContent> {
    let (_, source_identity) = open_generation_in(directory, &path, &intent, None)?;
    Ok(ReadyStagedContent::from_intent(
        staging_root.to_path_buf(),
        path,
        intent,
        source_identity,
    ))
}

pub(super) fn open_generation_in(
    directory: &PrivateDirectory,
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
    let file = directory.open_file(Path::new(&expected))?;
    validate_generation_file(path, intent, expected_identity, file)
}

fn validate_generation_file(
    path: &Path,
    intent: &StagingIntent,
    expected_identity: Option<PrivateFileIdentity>,
    mut file: std::fs::File,
) -> StorageResult<(std::fs::File, PrivateFileIdentity)> {
    let actual = private_file_identity(&file)?;
    let footer = load_generation_footer_from_file(path, &mut file)?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        connection(format!(
            "rewind staged generation handle {}: {error}",
            path.display()
        ))
    })?;
    if &footer.intent != intent {
        return Err(connection(format!(
            "staged generation footer changed after seal in {}",
            path.display()
        )));
    }
    if footer.source_identity != actual
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

fn move_to_quarantine_in(
    source_directory: &PrivateDirectory,
    source_name: &Path,
    quarantine_directory: &PrivateDirectory,
    quarantine_path: &Path,
    classification: &str,
) -> StorageResult<PathBuf> {
    let source_name_text = source_name
        .to_str()
        .ok_or_else(|| connection("staging entry name is not valid UTF-8".to_owned()))?;
    let mut suffix = 0_u64;
    let destination_name = loop {
        let candidate = PathBuf::from(format!("{source_name_text}.{classification}.{suffix}"));
        if !quarantine_directory.contains(&candidate)? {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("staging quarantine sequence exhausted".to_owned()))?;
    };
    let identity = private_file_identity(&source_directory.open_file(source_name)?)?;
    source_directory.rename_to_with_identity(
        source_name,
        quarantine_directory,
        &destination_name,
        identity,
    )?;
    source_directory.sync()?;
    quarantine_directory.sync()?;
    Ok(quarantine_path.join(destination_name))
}
