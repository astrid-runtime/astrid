//! Crash-safe migration from per-generation staging directories.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use super::format::{append_generation_footer, load_generation_footer};
use super::journal::{JournalRecord, StageKey, append_records, flush_journal};
use super::legacy::{self, LegacyReady};
use super::recovery::{sealed_generation_name, validate_generation};
use super::{JournalState, connection, remove_generation};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    open_private_file, sync_directory, validate_private_regular_file,
};

pub(super) fn migrate_legacy(
    root: &Path,
    generations: &Path,
    quarantine: &Path,
    journal: &mut JournalState,
) -> StorageResult<()> {
    let Some((legacy_ready, entries)) = legacy::recover(root, quarantine)? else {
        return Ok(());
    };
    let mut new_entries = Vec::new();
    for entry in entries {
        let key = StageKey::from_intent(&entry.intent);
        let target = generations.join(sealed_generation_name(key.sequence, key.id));
        if journal.completed.contains(&key) {
            remove_completed(&entry, &target)?;
            continue;
        }
        prepare_generation(&entry, &target)?;
        sync_directory(generations)?;
        validate_generation(&target, &entry.intent)?;
        match journal.pending.get(&key) {
            Some(existing) if existing == &entry.intent => {},
            Some(_) => return Err(intent_disagreement(key)),
            None => new_entries.push(entry),
        }
    }

    persist_new_entries(journal, &new_entries)?;
    for entry in new_entries {
        legacy::cleanup(&entry.directory)?;
    }
    cleanup_already_journalled(root, quarantine, journal)?;
    sync_directory(&legacy_ready)
}

fn remove_completed(entry: &LegacyReady, target: &Path) -> StorageResult<()> {
    if target.exists() {
        remove_generation(target)?;
        if let Some(parent) = target.parent() {
            sync_directory(parent)?;
        }
    }
    legacy::cleanup(&entry.directory)
}

fn prepare_generation(entry: &LegacyReady, target: &Path) -> StorageResult<()> {
    match (&entry.content, target.exists()) {
        (Some(source), false) => {
            std::fs::rename(source, target).map_err(|error| {
                connection(format!(
                    "migrate legacy staged content {} as {}: {error}",
                    source.display(),
                    target.display()
                ))
            })?;
        },
        (Some(source), true) => {
            if !file_prefix_equal(source, target, entry.intent.logical_bytes)? {
                return Err(connection(format!(
                    "legacy and journalled staged generations disagree for {}-{}",
                    entry.intent.sequence, entry.intent.id
                )));
            }
            std::fs::remove_file(source).map_err(|error| {
                connection(format!(
                    "remove duplicate legacy staged content {}: {error}",
                    source.display()
                ))
            })?;
        },
        (None, true) => {},
        (None, false) => {
            return Err(connection(format!(
                "durable legacy staged intent lost content for {}-{}",
                entry.intent.sequence, entry.intent.id
            )));
        },
    }
    ensure_footer(target, entry)
}

fn ensure_footer(target: &Path, entry: &LegacyReady) -> StorageResult<()> {
    match load_generation_footer(target) {
        Ok(existing) if existing == entry.intent => Ok(()),
        Ok(_) => Err(connection(format!(
            "legacy staged footer disagrees for {}-{}",
            entry.intent.sequence, entry.intent.id
        ))),
        Err(_) => {
            let physical_bytes = validate_private_regular_file(target)?;
            if physical_bytes < entry.intent.logical_bytes {
                return Err(connection(format!(
                    "migrated staged generation is shorter than its legacy intent for {}-{}",
                    entry.intent.sequence, entry.intent.id
                )));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(target)
                .map_err(|error| {
                    connection(format!(
                        "open legacy staged generation {}: {error}",
                        target.display()
                    ))
                })?;
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
            append_generation_footer(&mut file, &entry.intent)?;
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
    quarantine: &Path,
    journal: &JournalState,
) -> StorageResult<()> {
    let Some((_, entries)) = legacy::recover(root, quarantine)? else {
        return Ok(());
    };
    for entry in entries {
        let key = StageKey::from_intent(&entry.intent);
        if journal.pending.get(&key) == Some(&entry.intent) {
            legacy::cleanup(&entry.directory)?;
        }
    }
    Ok(())
}

fn file_prefix_equal(left: &Path, right: &Path, logical_bytes: u64) -> StorageResult<bool> {
    if validate_private_regular_file(left)? != logical_bytes
        || validate_private_regular_file(right)? < logical_bytes
    {
        return Ok(false);
    }
    let mut left = open_private_file(left)?;
    let mut right = open_private_file(right)?;
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
            .ok_or_else(|| connection("legacy comparison underflow".to_owned()))?;
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
        "legacy staged intent disagrees with journal for {}-{}",
        key.sequence, key.id
    ))
}
