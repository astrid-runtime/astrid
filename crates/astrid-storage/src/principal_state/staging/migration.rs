//! Crash-safe migration from per-generation staging directories.

use std::io::Read;
use std::path::{Path, PathBuf};

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;

use super::format::{
    LegacyStagingIntent, LegacyStagingOwner, StagingIntent, append_generation_footer,
    encode_intent, load_intent, load_legacy_intent,
};
use super::journal::{JournalRecord, StageKey, append_records, flush_journal};
use super::legacy::{self, LegacyReady};
use super::recovery::{open_generation_in, read_directory, sealed_generation_name};
use super::{
    JournalState, StagingFaultInjector, StagingFaultPoint, claim_generation_key, connection,
};
use crate::error::StorageResult;
use crate::principal_state::StateOwner;
use crate::principal_state::native_io::{
    PrivateDirectory, atomic_write, ensure_private_directory, private_file_identity, sync_directory,
};

pub(super) const LEGACY_INTENT_FILE: &str = "intent.v1";

pub(super) struct MigrationDirectories<'a> {
    pub(super) root_path: &'a Path,
    pub(super) root: &'a PrivateDirectory,
    pub(super) generations_path: &'a Path,
    pub(super) generations: &'a PrivateDirectory,
    pub(super) quarantine_path: &'a Path,
    pub(super) quarantine: &'a PrivateDirectory,
}

struct AliasIntentMigration {
    directory: PathBuf,
    legacy_path: PathBuf,
    current_path: PathBuf,
    legacy: LegacyStagingIntent,
    migrated: StagingIntent,
}

pub(in crate::principal_state) fn migrate_alias_owner_intents(
    root: &Path,
    mut resolve: impl FnMut(&PrincipalId) -> StorageResult<PrincipalUid>,
) -> StorageResult<()> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => ensure_private_directory(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(connection(format!(
                "inspect legacy staging root {}: {error}",
                root.display()
            )));
        },
    }
    let mut migrations = Vec::new();
    let mut current_intents = Vec::new();
    for name in [legacy::WRITING_DIRECTORY, legacy::READY_DIRECTORY] {
        let queue = root.join(name);
        match std::fs::symlink_metadata(&queue) {
            Ok(_) => ensure_private_directory(&queue)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(connection(format!(
                    "inspect legacy staging queue {}: {error}",
                    queue.display()
                )));
            },
        }
        for entry in read_directory(&queue)? {
            let entry = entry.map_err(|error| {
                connection(format!(
                    "enumerate legacy staging queue {}: {error}",
                    queue.display()
                ))
            })?;
            let path = entry.path();
            if let Some(intent) = inspect_current_intent(&path)? {
                current_intents.push(intent);
            }
            if let Some(migration) = inspect_alias_intent(&path, &mut resolve)? {
                migrations.push(migration);
            }
        }
    }
    let mut intents = current_intents;
    intents.extend(
        migrations
            .iter()
            .map(|migration| migration.migrated.clone()),
    );
    validate_intent_keys(None, &intents)?;
    for migration in migrations {
        apply_alias_intent_migration(&migration)?;
    }
    Ok(())
}

fn inspect_current_intent(directory: &Path) -> StorageResult<Option<StagingIntent>> {
    if !legacy::stage_entry_is_directory(directory)? {
        return Ok(None);
    }
    legacy::validate_stage_directory(directory)?;
    let path = directory.join(legacy::INTENT_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => load_intent(&path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(connection(format!(
            "inspect UID staged intent {}: {error}",
            path.display()
        ))),
    }
}

fn inspect_alias_intent(
    directory: &Path,
    resolve: &mut impl FnMut(&PrincipalId) -> StorageResult<PrincipalUid>,
) -> StorageResult<Option<AliasIntentMigration>> {
    if !legacy::stage_entry_is_directory(directory)? {
        return Ok(None);
    }
    legacy::validate_stage_directory(directory)?;
    let legacy_path = directory.join(LEGACY_INTENT_FILE);
    match std::fs::symlink_metadata(&legacy_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(connection(format!(
                "inspect legacy staged intent {}: {error}",
                legacy_path.display()
            )));
        },
        Ok(_) => {},
    }
    let legacy = load_legacy_intent(&legacy_path)?;
    let owner = match &legacy.owner {
        LegacyStagingOwner::System => StateOwner::System,
        LegacyStagingOwner::Principal(alias) => StateOwner::Principal(resolve(alias)?),
    };
    let migrated = StagingIntent {
        sequence: legacy.sequence,
        id: legacy.id,
        owner,
        name: legacy.name.clone(),
        profile: legacy.profile,
        logical_bytes: legacy.logical_bytes,
    };
    let current_path = directory.join(legacy::INTENT_FILE);
    match std::fs::symlink_metadata(&current_path) {
        Ok(_) => {
            if load_intent(&current_path)? != migrated {
                return Err(connection(format!(
                    "legacy and UID staging intents disagree in {}",
                    directory.display()
                )));
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(connection(format!(
                "inspect UID staged intent {}: {error}",
                current_path.display()
            )));
        },
    }
    Ok(Some(AliasIntentMigration {
        directory: directory.to_path_buf(),
        legacy_path,
        current_path,
        legacy,
        migrated,
    }))
}

fn apply_alias_intent_migration(migration: &AliasIntentMigration) -> StorageResult<()> {
    if load_legacy_intent(&migration.legacy_path)? != migration.legacy {
        return Err(connection(format!(
            "legacy staged intent changed during migration in {}",
            migration.directory.display()
        )));
    }
    match std::fs::symlink_metadata(&migration.current_path) {
        Ok(_) => {
            if load_intent(&migration.current_path)? != migration.migrated {
                return Err(connection(format!(
                    "legacy and UID staging intents disagree in {}",
                    migration.directory.display()
                )));
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(
                &migration.current_path,
                &encode_intent(&migration.migrated)?,
            )?;
        },
        Err(error) => {
            return Err(connection(format!(
                "inspect UID staged intent {}: {error}",
                migration.current_path.display()
            )));
        },
    }
    std::fs::remove_file(&migration.legacy_path).map_err(|error| {
        connection(format!(
            "remove migrated staged intent {}: {error}",
            migration.legacy_path.display()
        ))
    })?;
    sync_directory(&migration.directory)
}

pub(super) fn migrate_legacy(
    directories: &MigrationDirectories<'_>,
    journal: &mut JournalState,
    faults: &dyn StagingFaultInjector,
) -> StorageResult<()> {
    let Some(intents) = legacy::inspect_migration_intents(directories.root_path)? else {
        return Ok(());
    };
    validate_intent_keys(Some(journal), &intents)?;
    let Some((_legacy_ready, entries)) = legacy::recover(
        directories.root_path,
        directories.root,
        directories.quarantine_path,
        directories.quarantine,
    )?
    else {
        return Ok(());
    };
    let mut new_entries = Vec::new();
    for entry in entries {
        let key = StageKey::from_intent(&entry.intent);
        let target_name = PathBuf::from(sealed_generation_name(key.sequence, key.id));
        let target = directories.generations_path.join(&target_name);
        if journal.completed.contains(&key) {
            remove_completed(
                directories.root,
                directories.generations,
                &entry,
                &target_name,
            )?;
            continue;
        }
        prepare_generation(
            directories.generations,
            &entry,
            &target,
            &target_name,
            faults,
        )?;
        directories.generations.sync()?;
        open_generation_in(directories.generations, &target, &entry.intent, None)?;
        match journal.pending.get(&key) {
            Some(existing) if existing == &entry.intent => {},
            Some(_) => return Err(intent_disagreement(key)),
            None => new_entries.push(entry),
        }
    }

    persist_new_entries(journal, &new_entries)?;
    for entry in new_entries {
        let ready_directory = directories
            .root
            .open_child(Path::new(legacy::READY_DIRECTORY))?;
        legacy::cleanup_in(&ready_directory, &entry.directory_name, &entry.capability)?;
    }
    cleanup_already_journalled(
        directories.root_path,
        directories.root,
        directories.quarantine_path,
        directories.quarantine,
        journal,
    )?;
    directories
        .root
        .open_child(Path::new(legacy::READY_DIRECTORY))?
        .sync()
}

fn remove_completed(
    root: &PrivateDirectory,
    generations: &PrivateDirectory,
    entry: &LegacyReady,
    target: &Path,
) -> StorageResult<()> {
    if generations.contains(target)? {
        generations.remove_file(target)?;
        generations.sync()?;
    }
    let ready = root.open_child(Path::new(legacy::READY_DIRECTORY))?;
    legacy::cleanup_in(&ready, &entry.directory_name, &entry.capability)
}

fn prepare_generation(
    generations: &PrivateDirectory,
    entry: &LegacyReady,
    target: &Path,
    target_name: &Path,
    faults: &dyn StagingFaultInjector,
) -> StorageResult<()> {
    match (&entry.content, generations.contains(target_name)?) {
        (Some(_source), false) => {
            let content_name = Path::new(legacy::CONTENT_FILE);
            let identity = private_file_identity(&entry.capability.open_file(content_name)?)?;
            entry.capability.rename_to_with_identity(
                content_name,
                generations,
                target_name,
                identity,
            )?;
            // The footer mutates the renamed inode. Make both sides of the
            // rename durable first, otherwise a crash can resurrect the inode
            // at its legacy name with a new-format footer that the legacy
            // reader correctly rejects.
            entry.capability.sync()?;
            generations.sync()?;
            faults.fail(StagingFaultPoint::MigrationNamespaceFlushed)?;
        },
        (Some(_source), true) => {
            if !file_prefix_equal_in(
                &entry.capability,
                Path::new(legacy::CONTENT_FILE),
                generations,
                target_name,
                entry.intent.logical_bytes,
            )? {
                return Err(connection(format!(
                    "legacy and journalled staged generations disagree for {}-{}",
                    entry.intent.sequence, entry.intent.id
                )));
            }
            entry
                .capability
                .remove_file(Path::new(legacy::CONTENT_FILE))?;
        },
        (None, true) => {},
        (None, false) => {
            return Err(connection(format!(
                "durable legacy staged intent lost content for {}-{}",
                entry.intent.sequence, entry.intent.id
            )));
        },
    }
    ensure_footer(generations, target, target_name, entry)
}

fn validate_intent_keys(
    journal: Option<&JournalState>,
    intents: &[StagingIntent],
) -> StorageResult<()> {
    let mut sequences = std::collections::BTreeMap::new();
    let mut identifiers = std::collections::BTreeMap::new();
    let mut legacy_intents = std::collections::BTreeMap::new();
    if let Some(journal) = journal {
        for key in journal.pending.keys().chain(journal.completed.iter()) {
            claim_generation_key(&mut sequences, &mut identifiers, *key)?;
        }
    }
    for intent in intents {
        let key = StageKey::from_intent(intent);
        claim_generation_key(&mut sequences, &mut identifiers, key)?;
        if let Some(existing) = legacy_intents.insert(key, intent.clone())
            && existing != *intent
        {
            return Err(intent_disagreement(key));
        }
        if let Some(journal) = journal
            && let Some(existing) = journal.pending.get(&key)
            && existing != intent
        {
            return Err(intent_disagreement(key));
        }
    }
    Ok(())
}

fn ensure_footer(
    generations: &PrivateDirectory,
    target: &Path,
    target_name: &Path,
    entry: &LegacyReady,
) -> StorageResult<()> {
    let current_footer = generations
        .open_file(target_name)
        .and_then(|mut file| super::format::load_generation_footer_from_file(target, &mut file));
    match current_footer {
        Ok(existing) if existing.intent == entry.intent => Ok(()),
        Ok(_) => Err(connection(format!(
            "legacy staged footer disagrees for {}-{}",
            entry.intent.sequence, entry.intent.id
        ))),
        Err(_) => {
            let physical_bytes = generations
                .open_file(target_name)?
                .metadata()
                .map_err(|error| {
                    connection(format!(
                        "inspect migrated staged generation {}: {error}",
                        target.display()
                    ))
                })?
                .len();
            if physical_bytes < entry.intent.logical_bytes {
                return Err(connection(format!(
                    "migrated staged generation is shorter than its legacy intent for {}-{}",
                    entry.intent.sequence, entry.intent.id
                )));
            }
            let mut file = generations.open_file_rw(target_name)?;
            // A crash while migration appends the new footer can retain any
            // prefix of that footer. The legacy intent remains authoritative
            // until cleanup, so discard only bytes beyond its recorded
            // logical length and recreate the footer.
            file.set_len(entry.intent.logical_bytes).map_err(|error| {
                connection(format!(
                    "truncate torn migrated footer {}: {error}",
                    target.display()
                ))
            })?;
            let source_identity = private_file_identity(&file)?;
            append_generation_footer(&mut file, &entry.intent, source_identity)?;
            file.sync_all().map_err(|error| {
                connection(format!(
                    "flush migrated staged generation {}: {error}",
                    target.display()
                ))
            })
        },
    }
}

fn persist_new_entries(journal: &mut JournalState, entries: &[LegacyReady]) -> StorageResult<()> {
    let records: Vec<_> = entries
        .iter()
        .map(|entry| JournalRecord::Sealed(entry.intent.clone()))
        .collect();
    if records.is_empty() {
        return Ok(());
    }
    append_records(&mut journal.file, &records)?;
    flush_journal(&journal.file)?;
    for entry in entries {
        journal
            .pending
            .insert(StageKey::from_intent(&entry.intent), entry.intent.clone());
    }
    Ok(())
}

fn cleanup_already_journalled(
    root: &Path,
    root_directory: &PrivateDirectory,
    quarantine: &Path,
    quarantine_directory: &PrivateDirectory,
    journal: &JournalState,
) -> StorageResult<()> {
    let Some((_, entries)) =
        legacy::recover(root, root_directory, quarantine, quarantine_directory)?
    else {
        return Ok(());
    };
    let ready_directory = root_directory.open_child(Path::new(legacy::READY_DIRECTORY))?;
    for entry in entries {
        let key = StageKey::from_intent(&entry.intent);
        if journal.pending.get(&key) == Some(&entry.intent) {
            legacy::cleanup_in(&ready_directory, &entry.directory_name, &entry.capability)?;
        }
    }
    Ok(())
}

fn file_prefix_equal_in(
    left_directory: &PrivateDirectory,
    left_name: &Path,
    right_directory: &PrivateDirectory,
    right_name: &Path,
    logical_bytes: u64,
) -> StorageResult<bool> {
    let mut left = left_directory.open_file(left_name)?;
    let mut right = right_directory.open_file(right_name)?;
    if left
        .metadata()
        .map_err(|error| connection(format!("inspect legacy comparison source: {error}")))?
        .len()
        != logical_bytes
        || right
            .metadata()
            .map_err(|error| connection(format!("inspect migrated generation: {error}")))?
            .len()
            < logical_bytes
    {
        return Ok(false);
    }
    let mut left_buffer = vec![0_u8; 65_536].into_boxed_slice();
    let mut right_buffer = vec![0_u8; 65_536].into_boxed_slice();
    let buffer_len = u64::try_from(left_buffer.len())
        .map_err(|_| connection("legacy comparison length overflow".to_owned()))?;
    let mut remaining = logical_bytes;
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer_len))
            .map_err(|_| connection("legacy comparison length overflow".to_owned()))?;
        let left_read = read_for_comparison(&mut left, &mut left_buffer[..wanted], "legacy")?;
        let right_read =
            read_for_comparison(&mut right, &mut right_buffer[..wanted], "journalled")?;
        if left_read == 0
            || left_read != right_read
            || left_buffer[..left_read] != right_buffer[..right_read]
        {
            return Ok(false);
        }
        remaining = remaining
            .checked_sub(
                u64::try_from(left_read)
                    .map_err(|_| connection("legacy comparison length overflow".to_owned()))?,
            )
            .ok_or_else(|| connection("legacy comparison length underflow".to_owned()))?;
    }
    Ok(true)
}

fn read_for_comparison(
    file: &mut std::fs::File,
    buffer: &mut [u8],
    description: &str,
) -> StorageResult<usize> {
    file.read(buffer).map_err(|error| {
        connection(format!(
            "read {description} staged content for migration: {error}"
        ))
    })
}

fn intent_disagreement(key: StageKey) -> crate::error::StorageError {
    connection(format!(
        "staged intent disagrees with another record for {}-{}",
        key.sequence, key.id
    ))
}
