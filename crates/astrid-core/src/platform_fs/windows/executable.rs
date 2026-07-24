//! Journaled multi-executable replacement and rollback.

use super::error::with_context;
use super::io::{
    FileContract, PreparationCleanup, acquire_named_private_lock, flush_guarded_file,
    guarded_file_exists, hash_guarded_regular_file, move_guarded_file, open_guarded_regular_file,
    read_guarded_regular_file, remove_guarded_file, replace_file_checked, stage_transaction_copy,
    stage_transaction_copy_authenticated, stage_unique_bytes, test_maybe_interrupt_after_replace,
    test_maybe_interrupt_before_commit, volume_root,
};
use super::path::{BoundaryContract, TrustedPathGuard, validate_local_absolute_path};
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
    install_guard.verify_contract(BoundaryContract::TrustedForCreate)?;
    extract_guard.verify()?;
    let _transaction_lock = acquire_transaction_lock(install_dir, &install_guard)?;
    recover_executable_transaction_locked(install_dir, &install_guard)?;
    install_guard.verify_contract(BoundaryContract::TrustedForCreate)?;

    let journal = prepare_executable_transaction(
        install_dir,
        extract_dir,
        names,
        &install_guard,
        &extract_guard,
    )?;
    let transaction_id = &journal.transaction_id;
    if let Err(error) = write_transaction_journal(install_dir, &journal, &install_guard) {
        let recovery = recover_executable_transaction_locked(install_dir, &install_guard);
        if recovery.is_ok() {
            cleanup_transaction_files(install_dir, &journal, &install_guard);
        }
        return Err(recovery_error(error, recovery));
    }
    let result =
        finish_executable_transaction(install_dir, &journal, transaction_id, &install_guard);
    if let Err(error) = result {
        let recovery = recover_executable_transaction_locked(install_dir, &install_guard);
        return Err(recovery_error(error, recovery));
    }
    cleanup_rollback_files(install_dir, &journal, &install_guard);
    Ok(())
}

pub(super) const TRANSACTION_JOURNAL: &str = ".astrid-update.transaction.json";
pub(super) const TRANSACTION_LOCK: &str = ".astrid-update.lock";

#[cfg(test)]
pub(super) static TEST_PREPARATION_FAIL_AT_ENTRY: std::sync::Mutex<Option<usize>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn test_maybe_fail_preparation(index: usize) -> io::Result<()> {
    let mut fault = TEST_PREPARATION_FAIL_AT_ENTRY
        .lock()
        .expect("preparation fault lock");
    if *fault == Some(index) {
        *fault = None;
        Err(io::Error::from_raw_os_error(5))
    } else {
        Ok(())
    }
}

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
    #[serde(default, rename = "displaced", skip_serializing_if = "Option::is_none")]
    legacy_displaced: Option<String>,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

pub(super) fn acquire_transaction_lock(
    install_dir: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<File> {
    acquire_named_private_lock(
        guard,
        &install_dir.join(TRANSACTION_LOCK),
        "another Astrid executable replacement",
    )
}

pub(super) fn acquire_private_file_transaction_lock(
    parent: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<File> {
    acquire_named_private_lock(
        guard,
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
    install_guard.with_verified_mutation(
        "executable transaction commit",
        BoundaryContract::TrustedForCreate,
        || {
            for (index, entry) in journal.entries.iter().enumerate() {
                let live = install_dir.join(&entry.name);
                let staged = install_dir.join(&entry.staged);
                if entry.had_live {
                    replace_file_checked(install_guard, &live, &staged)?;
                } else {
                    move_guarded_file(install_guard, &staged, &live)?;
                }
                if hash_guarded_regular_file(
                    install_guard,
                    &live,
                    FileContract::Trusted,
                    BoundaryContract::TrustedForCreate,
                )? != entry.new_hash
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("installed executable digest changed: {}", live.display()),
                    ));
                }
                test_maybe_interrupt_after_replace(index);
            }

            // Preserve the prior authenticated executables as conventional backups.
            // Rollback copies stay independent and live until the journal commit point.
            for entry in &journal.entries {
                if let Some(rollback_name) = &entry.rollback {
                    let rollback = install_dir.join(rollback_name);
                    let backup = install_dir.join(format!("{}.bak", entry.name));
                    let staged_backup = stage_transaction_copy(
                        install_guard,
                        install_guard,
                        FileContract::ExactPrivate,
                        BoundaryContract::TrustedForCreate,
                        install_dir,
                        &rollback,
                        &format!(".{}.{}.backup", entry.name, transaction_id),
                    )?;
                    let mut backup_cleanup = PreparationCleanup::new(install_guard);
                    backup_cleanup.track(staged_backup.clone());
                    if guarded_file_exists(install_guard, &backup)? {
                        drop(open_guarded_regular_file(
                            install_guard,
                            &backup,
                            FileContract::Trusted,
                        )?);
                        replace_file_checked(install_guard, &backup, &staged_backup)?;
                    } else {
                        move_guarded_file(install_guard, &staged_backup, &backup)?;
                    }
                    backup_cleanup.disarm();
                }
            }
            cleanup_precommit_files(install_dir, journal, install_guard)?;
            test_maybe_interrupt_before_commit();
            Ok(())
        },
    )?;
    install_guard.verify_contract(BoundaryContract::TrustedForCreate)?;
    remove_guarded_file(install_guard, &install_dir.join(TRANSACTION_JOURNAL))
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
    let mut cleanup = PreparationCleanup::new(install_guard);
    for name in names {
        let source = extract_dir.join(name);
        extract_guard.verify()?;
        install_guard.verify()?;
        let staged_name = format!(".{name}.{transaction_id}.new");
        let (temporary, new_hash) = stage_transaction_copy_authenticated(
            install_guard,
            extract_guard,
            FileContract::Trusted,
            BoundaryContract::TrustedForCreate,
            install_dir,
            &source,
            &staged_name,
        )?;
        cleanup.track(temporary.clone());
        #[cfg(test)]
        test_maybe_fail_preparation(journal.entries.len())?;
        if volume_root(&temporary)? != install_volume {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "staged executable is not on the live executable volume",
            ));
        }
        let live = install_dir.join(name);
        let had_live = guarded_file_exists(install_guard, &live)?;
        let (rollback, old_hash) = if had_live {
            let rollback_name = format!(".{name}.{transaction_id}.rollback");
            let (rollback_path, old_hash) = stage_transaction_copy_authenticated(
                install_guard,
                install_guard,
                FileContract::Trusted,
                BoundaryContract::TrustedForCreate,
                install_dir,
                &live,
                &rollback_name,
            )?;
            cleanup.track(rollback_path);
            (Some(rollback_name), Some(old_hash))
        } else {
            (None, None)
        };
        journal.entries.push(ExecutableTransactionEntry {
            name: (*name).to_owned(),
            staged: staged_name,
            rollback,
            legacy_displaced: None,
            had_live,
            old_hash,
            new_hash,
        });
    }
    cleanup.disarm();
    Ok(journal)
}

pub(super) fn write_transaction_journal(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if guarded_file_exists(guard, &journal_path)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an executable replacement transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(guard, install_dir, &bytes, "astrid-update-journal")?;
    #[cfg(test)]
    if let Err(error) = super::io::test_maybe_fail_journal_rename() {
        let _ = remove_guarded_file(guard, &staged);
        return Err(error);
    }
    if let Err(error) = move_guarded_file(guard, &staged, &journal_path) {
        let _ = remove_guarded_file(guard, &staged);
        return Err(error);
    }
    flush_guarded_file(
        guard,
        &journal_path,
        FileContract::ExactPrivate,
        BoundaryContract::TrustedForCreate,
    )
}

pub(super) fn read_transaction_journal(
    install_dir: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<Option<ExecutableTransaction>> {
    let journal_path = install_dir.join(TRANSACTION_JOURNAL);
    if !guarded_file_exists(guard, &journal_path)? {
        return Ok(None);
    }
    let bytes = read_guarded_regular_file(
        guard,
        &journal_path,
        FileContract::ExactPrivate,
        BoundaryContract::TrustedForCreate,
    )?;
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
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !valid_component(name))
        || entry
            .legacy_displaced
            .as_deref()
            .is_some_and(|name| !valid_component(name))
        || !entry.staged.contains(transaction_id)
        || entry
            .rollback
            .as_deref()
            .is_some_and(|name| !name.contains(transaction_id))
        || entry
            .legacy_displaced
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
    let guard = TrustedPathGuard::capture(install_dir)?;
    let _transaction_lock = acquire_transaction_lock(install_dir, &guard)?;
    recover_executable_transaction_locked(install_dir, &guard)
}

pub(super) fn recover_executable_transaction_locked(
    install_dir: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let Some(journal) = read_transaction_journal(install_dir, guard)? else {
        return Ok(());
    };
    guard.with_verified_mutation(
        "executable transaction recovery",
        BoundaryContract::TrustedForCreate,
        || {
        let mut failures = Vec::new();
        for entry in journal.entries.iter().rev() {
            let live = install_dir.join(&entry.name);
            let result = if entry.had_live {
                restore_transaction_entry(install_dir, entry, guard)
            } else if guarded_file_exists(guard, &live)? {
                remove_guarded_file(guard, &live)
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
        Ok(())
    },
    )?;
    guard.verify_contract(BoundaryContract::TrustedForCreate)?;
    remove_guarded_file(guard, &install_dir.join(TRANSACTION_JOURNAL))?;
    cleanup_transaction_files(install_dir, &journal, guard);
    Ok(())
}

pub(super) fn restore_transaction_entry(
    install_dir: &Path,
    entry: &ExecutableTransactionEntry,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let old_hash = entry.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing rollback content hash")
    })?;
    let live = install_dir.join(&entry.name);
    if guarded_file_exists(guard, &live)?
        && hash_guarded_regular_file(
            guard,
            &live,
            FileContract::Trusted,
            BoundaryContract::TrustedForCreate,
        )? == old_hash
    {
        return Ok(());
    }
    let rollback = install_dir.join(
        entry
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    if hash_guarded_regular_file(
        guard,
        &rollback,
        FileContract::ExactPrivate,
        BoundaryContract::TrustedForCreate,
    )? != old_hash
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rollback executable does not match its journaled digest",
        ));
    }
    let restore = stage_transaction_copy(
        guard,
        guard,
        FileContract::ExactPrivate,
        BoundaryContract::TrustedForCreate,
        install_dir,
        &rollback,
        &format!(".{}.{}.restore", entry.name, uuid::Uuid::new_v4().simple()),
    )?;
    let mut restore_cleanup = PreparationCleanup::new(guard);
    restore_cleanup.track(restore.clone());
    if guarded_file_exists(guard, &live)? {
        replace_file_checked(guard, &live, &restore)?;
    } else {
        move_guarded_file(guard, &restore, &live)?;
    }
    restore_cleanup.disarm();
    if !guarded_file_exists(guard, &live)?
        || hash_guarded_regular_file(
            guard,
            &live,
            FileContract::Trusted,
            BoundaryContract::TrustedForCreate,
        )? != old_hash
    {
        return Err(io::Error::other(
            "rollback did not restore the journaled live executable",
        ));
    }
    Ok(())
}

pub(super) fn cleanup_transaction_files(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    guard: &TrustedPathGuard,
) {
    for entry in &journal.entries {
        let _ = remove_guarded_file(guard, &install_dir.join(&entry.staged));
        if let Some(displaced) = &entry.legacy_displaced {
            let _ = remove_guarded_file(guard, &install_dir.join(displaced));
        }
        if let Some(rollback) = &entry.rollback {
            let _ = remove_guarded_file(guard, &install_dir.join(rollback));
        }
    }
}

pub(super) fn cleanup_precommit_files(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    for entry in &journal.entries {
        let mut paths = vec![install_dir.join(&entry.staged)];
        if let Some(displaced) = &entry.legacy_displaced {
            paths.push(install_dir.join(displaced));
        }
        for path in paths {
            match remove_guarded_file(guard, &path) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

pub(super) fn cleanup_rollback_files(
    install_dir: &Path,
    journal: &ExecutableTransaction,
    guard: &TrustedPathGuard,
) {
    for entry in &journal.entries {
        if let Some(rollback) = &entry.rollback {
            let _ = remove_guarded_file(guard, &install_dir.join(rollback));
        }
    }
}

pub(super) fn recovery_error(install_error: io::Error, recovery: io::Result<()>) -> io::Error {
    match recovery {
        Ok(()) => with_context(
            install_error,
            "replacement failed and the prior journaled state was restored",
        ),
        Err(recovery_error) => with_context(
            install_error,
            format!("replacement failed and recovery remains journaled: {recovery_error}"),
        ),
    }
}
