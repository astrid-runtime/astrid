//! Journaled multi-executable replacement and rollback.

use super::acl::validate_trusted_parent_acl_for_create;
use super::io::{
    acquire_named_private_lock, copy_file_synced, flush_file, move_file, replace_file_checked,
    stage_transaction_copy, stage_transaction_copy_authenticated, stage_unique_bytes,
    test_maybe_interrupt_after_replace, test_maybe_interrupt_before_commit, volume_root,
};
use super::path::{
    TrustedPathGuard, hash_locked_regular_file, validate_local_absolute_path,
    validate_private_file, verify_regular_file, verify_trusted_regular_file,
};
use super::prelude::*;
use super::private_file::PRIVATE_FILE_TRANSACTION_LOCK;

pub(in crate::platform_fs) fn replace_executable_set(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
) -> io::Result<()> {
    validate_local_absolute_path(install_dir)?;
    validate_local_absolute_path(extract_dir)?;
    let install_guard = TrustedPathGuard::capture(install_dir)?;
    let extract_guard = TrustedPathGuard::capture(extract_dir)?;
    validate_trusted_parent_acl_for_create(install_dir)?;
    let _transaction_lock = acquire_transaction_lock(install_dir)?;
    recover_executable_transaction_locked(install_dir)?;
    install_guard.verify()?;
    extract_guard.verify()?;

    let journal = prepare_executable_transaction(
        install_dir,
        extract_dir,
        names,
        &install_guard,
        &extract_guard,
    )?;
    let transaction_id = &journal.transaction_id;
    if let Err(error) = write_transaction_journal(install_dir, &journal) {
        let recovery = recover_executable_transaction_locked(install_dir);
        return Err(recovery_error(&error, recovery));
    }
    let result =
        finish_executable_transaction(install_dir, &journal, transaction_id, &install_guard);
    if let Err(error) = result {
        let recovery = recover_executable_transaction_locked(install_dir);
        return Err(recovery_error(&error, recovery));
    }
    cleanup_rollback_files(install_dir, &journal);
    Ok(())
}

pub(super) const TRANSACTION_JOURNAL: &str = ".astrid-update.transaction.json";
pub(super) const TRANSACTION_LOCK: &str = ".astrid-update.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutableTransaction {
    version: u32,
    transaction_id: String,
    entries: Vec<ExecutableTransactionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutableTransactionEntry {
    name: String,
    staged: String,
    rollback: Option<String>,
    displaced: String,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

pub(super) fn acquire_transaction_lock(install_dir: &Path) -> io::Result<File> {
    acquire_named_private_lock(
        &install_dir.join(TRANSACTION_LOCK),
        "another Astrid executable replacement",
    )
}

pub(super) fn acquire_private_file_transaction_lock(parent: &Path) -> io::Result<File> {
    acquire_named_private_lock(
        &parent.join(PRIVATE_FILE_TRANSACTION_LOCK),
        "another Astrid private-file write",
    )
}

pub(super) fn finish_executable_transaction(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    transaction_id: &str,
    install_guard: &TrustedPathGuard,
) -> io::Result<()> {
    for (index, entry) in journal.entries.iter().enumerate() {
        install_guard.verify()?;
        let live = install_dir.join(&entry.name);
        let staged = install_dir.join(&entry.staged);
        let displaced = install_dir.join(&entry.displaced);
        if entry.had_live {
            replace_file_checked(&live, &staged, Some(&displaced))?;
        } else {
            move_file(&staged, &live)?;
        }
        if hash_locked_regular_file(&live)? != entry.new_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed executable digest changed",
            ));
        }
        test_maybe_interrupt_after_replace(index);
    }

    // Preserve the prior authenticated executables as conventional backups.
    // Rollback copies stay independent and live until the journal commit point.
    for entry in &journal.entries {
        if let Some(rollback_name) = &entry.rollback {
            install_guard.verify()?;
            let rollback = install_dir.join(rollback_name);
            let backup = install_dir.join(format!("{}.bak", entry.name));
            let staged_backup = stage_transaction_copy(
                install_dir,
                &rollback,
                &format!(".{}.{}.backup", entry.name, transaction_id),
            )?;
            if backup.exists() {
                verify_trusted_regular_file(&backup)?;
                let displaced =
                    install_dir.join(format!(".{}.{}.old-backup", entry.name, transaction_id));
                replace_file_checked(&backup, &staged_backup, Some(&displaced))?;
                std::fs::remove_file(displaced)?;
            } else {
                move_file(&staged_backup, &backup)?;
            }
        }
    }
    install_guard.verify()?;
    cleanup_precommit_files(install_dir, journal)?;
    test_maybe_interrupt_before_commit();
    remove_transaction_journal(install_dir)
}

pub(super) fn prepare_executable_transaction(
    install_dir: &Path,
    extract_dir: &Path,
    names: &[&str],
    install_guard: &TrustedPathGuard,
    extract_guard: &TrustedPathGuard,
) -> io::Result<ExecutableTransaction> {
    let install_volume = volume_root(install_dir)?;
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let mut journal = ExecutableTransaction {
        version: 1,
        transaction_id: transaction_id.clone(),
        entries: Vec::with_capacity(names.len()),
    };
    for name in names {
        let source = extract_dir.join(name);
        verify_regular_file(&source)?;
        extract_guard.verify()?;
        install_guard.verify()?;
        let staged_name = format!(".{name}.{transaction_id}.new");
        let (temporary, new_hash) =
            stage_transaction_copy_authenticated(install_dir, &source, &staged_name)?;
        if volume_root(&temporary)? != install_volume {
            let _ = std::fs::remove_file(&temporary);
            cleanup_transaction_files(install_dir, &journal);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "staged executable is not on the live executable volume",
            ));
        }
        let live = install_dir.join(name);
        let had_live = live.exists();
        let (rollback, old_hash) = if had_live {
            verify_regular_file(&live)?;
            let rollback_name = format!(".{name}.{transaction_id}.rollback");
            let (_, old_hash) =
                stage_transaction_copy_authenticated(install_dir, &live, &rollback_name)?;
            (Some(rollback_name), Some(old_hash))
        } else {
            (None, None)
        };
        journal.entries.push(ExecutableTransactionEntry {
            name: (*name).to_owned(),
            staged: staged_name,
            rollback,
            displaced: format!(".{name}.{transaction_id}.displaced"),
            had_live,
            old_hash,
            new_hash,
        });
    }
    Ok(journal)
}

pub(super) fn write_transaction_journal(
    install_dir: &Path,
    journal: &ExecutableTransaction,
) -> io::Result<()> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if journal_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an executable replacement transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(install_dir, &bytes, "astrid-update-journal")?;
    move_file(&staged, &journal_path)?;
    flush_file(&journal_path)
}

pub(super) fn read_transaction_journal(
    install_dir: &Path,
) -> io::Result<Option<ExecutableTransaction>> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if !journal_path.exists() {
        return Ok(None);
    }
    validate_private_file(&journal_path)?;
    let bytes = std::fs::read(&journal_path)?;
    let journal: ExecutableTransaction = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if journal.version != 1 || journal.entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or empty executable replacement journal",
        ));
    }
    for entry in &journal.entries {
        validate_transaction_entry(&journal.transaction_id, entry)?;
    }
    Ok(Some(journal))
}

pub(super) fn validate_transaction_entry(
    transaction_id: &str,
    entry: &ExecutableTransactionEntry,
) -> io::Result<()> {
    let valid_component = |value: &str| {
        let mut components = Path::new(value).components();
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
    };
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if transaction_id.len() != 32
        || !transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !valid_component(&entry.name)
        || !valid_component(&entry.staged)
        || !valid_component(&entry.displaced)
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !valid_component(name))
        || !entry.staged.contains(transaction_id)
        || !entry.displaced.contains(transaction_id)
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !name.contains(transaction_id))
        || entry.had_live != entry.rollback.is_some()
        || entry.had_live != entry.old_hash.is_some()
        || !valid_digest(&entry.new_hash)
        || entry
            .old_hash
            .as_deref()
            .is_some_and(|hash| !valid_digest(hash))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid executable replacement journal entry",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn recover_executable_transaction(install_dir: &Path) -> io::Result<()> {
    let _transaction_lock = acquire_transaction_lock(install_dir)?;
    recover_executable_transaction_locked(install_dir)
}

pub(super) fn recover_executable_transaction_locked(install_dir: &Path) -> io::Result<()> {
    let Some(journal) = read_transaction_journal(install_dir)? else {
        return Ok(());
    };
    let guard = TrustedPathGuard::capture(install_dir)?;
    let mut failures = Vec::new();
    for entry in journal.entries.iter().rev() {
        guard.verify()?;
        let live = install_dir.join(&entry.name);
        let result = if entry.had_live {
            restore_transaction_entry(install_dir, entry)
        } else if live.exists() {
            std::fs::remove_file(&live)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            failures.push(format!("{}: {error}", live.display()));
        }
    }
    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "executable replacement recovery is still pending ({}); retry after releasing open executable handles",
            failures.join("; ")
        )));
    }
    remove_transaction_journal(install_dir)?;
    cleanup_transaction_files(install_dir, &journal);
    Ok(())
}

pub(super) fn restore_transaction_entry(
    install_dir: &Path,
    entry: &ExecutableTransactionEntry,
) -> io::Result<()> {
    let old_hash = entry.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing rollback content hash")
    })?;
    let live = install_dir.join(&entry.name);
    if live.exists() && hash_locked_regular_file(&live)? == old_hash {
        return Ok(());
    }
    let rollback = install_dir.join(
        entry
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    verify_regular_file(&rollback)?;
    if hash_locked_regular_file(&rollback)? != old_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rollback executable does not match its journaled digest",
        ));
    }
    let restore = stage_transaction_copy(
        install_dir,
        &rollback,
        &format!(".{}.{}.restore", entry.name, uuid::Uuid::new_v4().simple()),
    )?;
    if live.exists() {
        let displaced = install_dir.join(&entry.displaced);
        let _ = std::fs::remove_file(&displaced);
        replace_file_checked(&live, &restore, Some(&displaced))?;
    } else if let Err(error) = move_file(&restore, &live) {
        // A ReplaceFileW partial-mutation error can leave the live name absent.
        // A direct copy is a final supported fallback; the rollback source is
        // deliberately retained until the journal commit point.
        let _ = std::fs::remove_file(&restore);
        copy_file_synced(&rollback, &live).map_err(|copy_error| {
            io::Error::new(
                copy_error.kind(),
                format!(
                    "could not restore an absent live executable ({error}); copy fallback failed: {copy_error}"
                ),
            )
        })?;
    }
    if !live.exists() || hash_locked_regular_file(&live)? != old_hash {
        return Err(io::Error::other(
            "rollback did not restore the journaled live executable",
        ));
    }
    Ok(())
}

pub(super) fn remove_transaction_journal(install_dir: &Path) -> io::Result<()> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    match std::fs::remove_file(journal_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn cleanup_transaction_files(install_dir: &Path, journal: &ExecutableTransaction) {
    for entry in &journal.entries {
        let _ = std::fs::remove_file(install_dir.join(&entry.staged));
        let _ = std::fs::remove_file(install_dir.join(&entry.displaced));
        if let Some(rollback) = &entry.rollback {
            let _ = std::fs::remove_file(install_dir.join(rollback));
        }
    }
}

pub(super) fn cleanup_precommit_files(
    install_dir: &Path,
    journal: &ExecutableTransaction,
) -> io::Result<()> {
    for entry in &journal.entries {
        for path in [
            install_dir.join(&entry.staged),
            install_dir.join(&entry.displaced),
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

pub(super) fn cleanup_rollback_files(install_dir: &Path, journal: &ExecutableTransaction) {
    for entry in &journal.entries {
        if let Some(rollback) = &entry.rollback {
            let _ = std::fs::remove_file(install_dir.join(rollback));
        }
    }
}

pub(super) fn recovery_error(install_error: &io::Error, recovery: io::Result<()>) -> io::Error {
    match recovery {
        Ok(()) => io::Error::new(
            install_error.kind(),
            format!(
                "executable replacement failed and the prior set was restored: {install_error}"
            ),
        ),
        Err(recovery_error) => io::Error::new(
            install_error.kind(),
            format!(
                "executable replacement failed: {install_error}; recovery remains journaled: {recovery_error}"
            ),
        ),
    }
}
