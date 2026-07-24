//! Recoverable single-file reads and writes for private Astrid state.

use super::executable::{acquire_private_file_transaction_lock, recovery_error};
use super::io::{
    FileContract, PreparationCleanup, flush_guarded_file, guarded_file_exists,
    hash_guarded_regular_file, move_guarded_file, open_guarded_regular_file,
    read_guarded_regular_file, remove_guarded_file, replace_file_checked, stage_transaction_copy,
    stage_transaction_copy_authenticated, stage_unique_bytes, validate_file_contract,
};
use super::path::{
    BoundaryContract, TrustedPathGuard, file_identity, validate_local_absolute_path,
};
use super::prelude::*;

pub(in crate::platform_fs) fn read_private_file_to_string(path: &Path) -> io::Result<String> {
    validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows file has no parent directory",
        )
    })?;
    let guard = TrustedPathGuard::capture(parent)?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent, &guard)?;
    recover_private_file_transaction_locked(parent, &guard)?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;

    let mut file = open_guarded_regular_file(&guard, path, FileContract::ExactPrivate)?;
    let identity = file_identity(&file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    validate_file_contract(
        file.as_raw_handle().cast(),
        path,
        FileContract::ExactPrivate,
    )?;
    if file_identity(&file)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file identity changed while reading",
        ));
    }
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    Ok(contents)
}

pub(in crate::platform_fs) fn atomic_write_private_file(
    path: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows file has no parent directory",
        )
    })?;
    let target_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file has no final path component",
        )
    })?;
    let target_name_lower = target_name.to_string_lossy().to_ascii_lowercase();
    if target_name_lower.starts_with(".astrid-private.")
        || target_name_lower == PRIVATE_FILE_TRANSACTION_JOURNAL
        || target_name_lower == PRIVATE_FILE_TRANSACTION_LOCK
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file name conflicts with Astrid recovery metadata",
        ));
    }
    let guard = TrustedPathGuard::capture(parent)?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent, &guard)?;
    recover_private_file_transaction_locked(parent, &guard)?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    if guarded_file_exists(&guard, path)? {
        drop(open_guarded_regular_file(
            &guard,
            path,
            FileContract::ExactPrivate,
        )?);
    }

    let journal = prepare_private_file_transaction(path, bytes, &guard)?;
    if let Err(error) = write_private_file_transaction_journal(parent, &journal, &guard) {
        let recovery = recover_private_file_transaction_locked(parent, &guard);
        if recovery.is_ok() {
            cleanup_private_file_transaction_files(parent, &journal, &guard);
        }
        return Err(recovery_error(error, recovery));
    }
    if let Err(error) = finish_private_file_transaction(parent, &journal, &guard) {
        let recovery = recover_private_file_transaction_locked(parent, &guard);
        return Err(recovery_error(error, recovery));
    }
    cleanup_private_file_transaction_files(parent, &journal, &guard);
    Ok(())
}

pub(super) const PRIVATE_FILE_TRANSACTION_JOURNAL: &str = ".astrid-private-write.transaction.json";
pub(super) const PRIVATE_FILE_TRANSACTION_LOCK: &str = ".astrid-private-write.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateFileTransaction {
    version: u32,
    transaction_id: String,
    target: Vec<u16>,
    staged: String,
    rollback: Option<String>,
    #[serde(default, rename = "displaced", skip_serializing_if = "Option::is_none")]
    legacy_displaced: Option<String>,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

pub(super) fn prepare_private_file_transaction(
    path: &Path,
    bytes: &[u8],
    guard: &TrustedPathGuard,
) -> io::Result<PrivateFileTransaction> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let target = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file has no final path component",
        )
    })?;
    let target = target.encode_wide().collect::<Vec<_>>();
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let staged = format!(".astrid-private.{transaction_id}.new");
    let mut cleanup = PreparationCleanup::new(guard);
    let staged_path = stage_unique_bytes(guard, parent, bytes, "astrid-private-write")?;
    cleanup.track(staged_path.clone());
    let new_hash = hash_guarded_regular_file(
        guard,
        &staged_path,
        FileContract::ExactPrivate,
        BoundaryContract::ExactPrivateDirectory,
    )?;
    let deterministic_staged = parent.join(&staged);
    move_guarded_file(guard, &staged_path, &deterministic_staged)?;
    cleanup.track(deterministic_staged);

    let had_live = guarded_file_exists(guard, path)?;
    let (rollback, old_hash) = if had_live {
        let rollback_name = format!(".astrid-private.{transaction_id}.rollback");
        let (rollback_path, old_hash) = stage_transaction_copy_authenticated(
            guard,
            guard,
            FileContract::ExactPrivate,
            BoundaryContract::ExactPrivateDirectory,
            parent,
            path,
            &rollback_name,
        )?;
        cleanup.track(rollback_path);
        (Some(rollback_name), Some(old_hash))
    } else {
        (None, None)
    };
    let journal = PrivateFileTransaction {
        version: 1,
        transaction_id: transaction_id.clone(),
        target,
        staged,
        rollback,
        legacy_displaced: None,
        had_live,
        old_hash,
        new_hash,
    };
    cleanup.disarm();
    Ok(journal)
}

pub(super) fn write_private_file_transaction_journal(
    parent: &Path,
    journal: &PrivateFileTransaction,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if guarded_file_exists(guard, &journal_path)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a private-file write transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(guard, parent, &bytes, "astrid-private-write-journal")?;
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
        BoundaryContract::ExactPrivateDirectory,
    )
}

pub(super) fn read_private_file_transaction_journal(
    parent: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<Option<PrivateFileTransaction>> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if !guarded_file_exists(guard, &journal_path)? {
        return Ok(None);
    }
    let bytes = read_guarded_regular_file(
        guard,
        &journal_path,
        FileContract::ExactPrivate,
        BoundaryContract::ExactPrivateDirectory,
    )?;
    let journal: PrivateFileTransaction = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    validate_private_file_transaction(&journal)?;
    Ok(Some(journal))
}

pub(super) fn validate_private_file_transaction(
    journal: &PrivateFileTransaction,
) -> io::Result<()> {
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    let target = OsString::from_wide(&journal.target);
    if journal.version != 1
        || journal.transaction_id.len() != 32
        || !journal
            .transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || journal.target.is_empty()
        || journal.target.contains(&0)
        || !is_single_path_component(&target)
        || !is_single_path_component(OsStr::new(&journal.staged))
        || journal
            .rollback
            .as_deref()
            .is_some_and(|name| !is_single_path_component(OsStr::new(name)))
        || journal
            .legacy_displaced
            .as_deref()
            .is_some_and(|name| !is_single_path_component(OsStr::new(name)))
        || !journal.staged.contains(&journal.transaction_id)
        || journal
            .rollback
            .as_deref()
            .is_some_and(|name| !name.contains(&journal.transaction_id))
        || journal
            .legacy_displaced
            .as_deref()
            .is_some_and(|name| !name.contains(&journal.transaction_id))
        || journal.had_live != journal.rollback.is_some()
        || journal.had_live != journal.old_hash.is_some()
        || !valid_digest(&journal.new_hash)
        || journal
            .old_hash
            .as_deref()
            .is_some_and(|hash| !valid_digest(hash))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid private-file write journal",
        ));
    }
    Ok(())
}

pub(super) fn is_single_path_component(value: &OsStr) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

pub(super) fn finish_private_file_transaction(
    parent: &Path,
    journal: &PrivateFileTransaction,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    guard.with_verified_mutation(
        "private-file transaction commit",
        BoundaryContract::ExactPrivateDirectory,
        || {
            let live = parent.join(OsString::from_wide(&journal.target));
            let staged = parent.join(&journal.staged);
            if journal.had_live {
                replace_file_checked(guard, &live, &staged)?;
            } else {
                move_guarded_file(guard, &staged, &live)?;
            }
            if hash_guarded_regular_file(
                guard,
                &live,
                FileContract::ExactPrivate,
                BoundaryContract::ExactPrivateDirectory,
            )? != journal.new_hash
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "installed private file digest changed",
                ));
            }
            remove_guarded_file_if_exists(guard, &staged)
        },
    )?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    remove_guarded_file(guard, &parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL))
}

pub(super) fn recover_private_file_transaction_locked(
    parent: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let Some(journal) = read_private_file_transaction_journal(parent, guard)? else {
        return Ok(());
    };
    guard.with_verified_mutation(
        "private-file transaction recovery",
        BoundaryContract::ExactPrivateDirectory,
        || {
            let live = parent.join(OsString::from_wide(&journal.target));
            if journal.had_live {
                restore_private_file_transaction(parent, &journal, &live, guard)?;
            } else if guarded_file_exists(guard, &live)? {
                remove_guarded_file(guard, &live)?;
            }
            Ok(())
        },
    )?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
    remove_guarded_file(guard, &parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL))?;
    cleanup_private_file_transaction_files(parent, &journal, guard);
    Ok(())
}

pub(super) fn restore_private_file_transaction(
    parent: &Path,
    journal: &PrivateFileTransaction,
    live: &Path,
    guard: &TrustedPathGuard,
) -> io::Result<()> {
    let old_hash = journal.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing private rollback digest",
        )
    })?;
    if guarded_file_exists(guard, live)?
        && hash_guarded_regular_file(
            guard,
            live,
            FileContract::ExactPrivate,
            BoundaryContract::ExactPrivateDirectory,
        )? == old_hash
    {
        return Ok(());
    }
    let rollback = parent.join(
        journal
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    if hash_guarded_regular_file(
        guard,
        &rollback,
        FileContract::ExactPrivate,
        BoundaryContract::ExactPrivateDirectory,
    )? != old_hash
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private rollback does not match its journaled digest",
        ));
    }
    let restore_name = format!(
        ".astrid-private.{}.{}.restore",
        journal.transaction_id,
        uuid::Uuid::new_v4().simple()
    );
    let restore = stage_transaction_copy(
        guard,
        guard,
        FileContract::ExactPrivate,
        BoundaryContract::ExactPrivateDirectory,
        parent,
        &rollback,
        &restore_name,
    )?;
    let mut restore_cleanup = PreparationCleanup::new(guard);
    restore_cleanup.track(restore.clone());
    if guarded_file_exists(guard, live)? {
        replace_file_checked(guard, live, &restore)?;
    } else {
        move_guarded_file(guard, &restore, live)?;
    }
    restore_cleanup.disarm();
    if hash_guarded_regular_file(
        guard,
        live,
        FileContract::ExactPrivate,
        BoundaryContract::ExactPrivateDirectory,
    )? != old_hash
    {
        return Err(io::Error::other(
            "rollback did not restore the journaled private file",
        ));
    }
    Ok(())
}

fn remove_guarded_file_if_exists(guard: &TrustedPathGuard, path: &Path) -> io::Result<()> {
    match remove_guarded_file(guard, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn cleanup_private_file_transaction_files(
    parent: &Path,
    journal: &PrivateFileTransaction,
    guard: &TrustedPathGuard,
) {
    let _ = remove_guarded_file(guard, &parent.join(&journal.staged));
    if let Some(displaced) = &journal.legacy_displaced {
        let _ = remove_guarded_file(guard, &parent.join(displaced));
    }
    if let Some(rollback) = &journal.rollback {
        let _ = remove_guarded_file(guard, &parent.join(rollback));
    }
}
