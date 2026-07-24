//! Recoverable single-file reads and writes for private Astrid state.

use super::acl::validate_private_acl;
use super::executable::{acquire_private_file_transaction_lock, recovery_error};
use super::io::{
    copy_file_synced, flush_file, move_file, replace_file_checked, stage_transaction_copy,
    stage_transaction_copy_authenticated, stage_unique_bytes,
};
use super::path::{
    TrustedPathGuard, file_identity, hash_locked_regular_file, open_locked_regular_file,
    restrict_private_file, validate_local_absolute_path, validate_private_file,
    verify_regular_file,
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
    validate_private_acl(parent, true)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent)?;
    recover_private_file_transaction_locked(parent)?;
    guard.verify()?;

    let mut locked = open_locked_regular_file(path)?;
    validate_private_acl(path, false)?;
    if file_identity(&locked.file)? != locked.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file identity changed before reading",
        ));
    }
    let mut contents = String::new();
    locked.file.read_to_string(&mut contents)?;
    if file_identity(&locked.file)? != locked.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file identity changed while reading",
        ));
    }
    guard.verify()?;
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
    validate_private_acl(parent, true)?;
    let _transaction_lock = acquire_private_file_transaction_lock(parent)?;
    recover_private_file_transaction_locked(parent)?;
    guard.verify()?;
    if path.exists() {
        validate_private_file(path)?;
    }

    let journal = prepare_private_file_transaction(path, bytes)?;
    if let Err(error) = write_private_file_transaction_journal(parent, &journal) {
        let recovery = recover_private_file_transaction_locked(parent);
        if recovery.is_ok() {
            cleanup_private_file_transaction_files(parent, &journal);
        }
        return Err(recovery_error(&error, recovery));
    }
    if let Err(error) = finish_private_file_transaction(parent, &journal, &guard) {
        let recovery = recover_private_file_transaction_locked(parent);
        return Err(recovery_error(&error, recovery));
    }
    cleanup_private_file_transaction_files(parent, &journal);
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
    displaced: String,
    had_live: bool,
    old_hash: Option<String>,
    new_hash: String,
}

pub(super) fn prepare_private_file_transaction(
    path: &Path,
    bytes: &[u8],
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
    let staged_path = stage_unique_bytes(parent, bytes, "astrid-private-write")?;
    let new_hash = match hash_locked_regular_file(&staged_path) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = std::fs::remove_file(&staged_path);
            return Err(error);
        },
    };
    let deterministic_staged = parent.join(&staged);
    if let Err(error) = move_file(&staged_path, &deterministic_staged) {
        let _ = std::fs::remove_file(&staged_path);
        return Err(error);
    }

    let had_live = path.exists();
    let (rollback, old_hash) = if had_live {
        let rollback_name = format!(".astrid-private.{transaction_id}.rollback");
        let (rollback_path, old_hash) =
            match stage_transaction_copy_authenticated(parent, path, &rollback_name) {
                Ok(result) => result,
                Err(error) => {
                    let _ = std::fs::remove_file(&deterministic_staged);
                    return Err(error);
                },
            };
        if let Err(error) = restrict_private_file(&rollback_path) {
            let _ = std::fs::remove_file(&rollback_path);
            let _ = std::fs::remove_file(&deterministic_staged);
            return Err(error);
        }
        (Some(rollback_name), Some(old_hash))
    } else {
        (None, None)
    };
    Ok(PrivateFileTransaction {
        version: 1,
        transaction_id: transaction_id.clone(),
        target,
        staged,
        rollback,
        displaced: format!(".astrid-private.{transaction_id}.displaced"),
        had_live,
        old_hash,
        new_hash,
    })
}

pub(super) fn write_private_file_transaction_journal(
    parent: &Path,
    journal: &PrivateFileTransaction,
) -> io::Result<()> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if journal_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a private-file write transaction is already pending",
        ));
    }
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let staged = stage_unique_bytes(parent, &bytes, "astrid-private-write-journal")?;
    if let Err(error) = move_file(&staged, &journal_path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    flush_file(&journal_path)
}

pub(super) fn read_private_file_transaction_journal(
    parent: &Path,
) -> io::Result<Option<PrivateFileTransaction>> {
    let journal_path = parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL);
    if !journal_path.exists() {
        return Ok(None);
    }
    validate_private_file(&journal_path)?;
    let bytes = std::fs::read(&journal_path)?;
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
        || !is_single_path_component(OsStr::new(&journal.displaced))
        || journal
            .rollback
            .as_deref()
            .is_some_and(|name| !is_single_path_component(OsStr::new(name)))
        || !journal.staged.contains(&journal.transaction_id)
        || !journal.displaced.contains(&journal.transaction_id)
        || journal
            .rollback
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
    guard.verify()?;
    let live = parent.join(OsString::from_wide(&journal.target));
    let staged = parent.join(&journal.staged);
    let displaced = parent.join(&journal.displaced);
    if journal.had_live {
        replace_file_checked(&live, &staged, Some(&displaced))?;
    } else {
        move_file(&staged, &live)?;
    }
    validate_private_file(&live)?;
    if hash_locked_regular_file(&live)? != journal.new_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed private file digest changed",
        ));
    }
    guard.verify()?;
    remove_file_if_exists(&staged)?;
    remove_file_if_exists(&displaced)?;
    remove_private_file_transaction_journal(parent)
}

pub(super) fn recover_private_file_transaction_locked(parent: &Path) -> io::Result<()> {
    let Some(journal) = read_private_file_transaction_journal(parent)? else {
        return Ok(());
    };
    let guard = TrustedPathGuard::capture(parent)?;
    guard.verify()?;
    let live = parent.join(OsString::from_wide(&journal.target));
    if journal.had_live {
        restore_private_file_transaction(parent, &journal, &live)?;
    } else if live.exists() {
        verify_regular_file(&live)?;
        std::fs::remove_file(&live)?;
    }
    guard.verify()?;
    remove_private_file_transaction_journal(parent)?;
    cleanup_private_file_transaction_files(parent, &journal);
    Ok(())
}

pub(super) fn restore_private_file_transaction(
    parent: &Path,
    journal: &PrivateFileTransaction,
    live: &Path,
) -> io::Result<()> {
    let old_hash = journal.old_hash.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing private rollback digest",
        )
    })?;
    if live.exists()
        && validate_private_file(live).is_ok()
        && hash_locked_regular_file(live)? == old_hash
    {
        return Ok(());
    }
    if live.exists() {
        verify_regular_file(live)?;
    }
    let rollback = parent.join(
        journal
            .rollback
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing rollback file"))?,
    );
    validate_private_file(&rollback)?;
    if hash_locked_regular_file(&rollback)? != old_hash {
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
    let restore = stage_transaction_copy(parent, &rollback, &restore_name)?;
    if let Err(error) = restrict_private_file(&restore) {
        let _ = std::fs::remove_file(&restore);
        return Err(error);
    }
    if live.exists() {
        let displaced = parent.join(&journal.displaced);
        remove_file_if_exists(&displaced)?;
        replace_file_checked(live, &restore, Some(&displaced))?;
    } else if let Err(error) = move_file(&restore, live) {
        let _ = std::fs::remove_file(&restore);
        copy_file_synced(&rollback, live).map_err(|copy_error| {
            io::Error::new(
                copy_error.kind(),
                format!(
                    "could not restore an absent private file ({error}); copy fallback failed: {copy_error}"
                ),
            )
        })?;
        restrict_private_file(live)?;
    }
    validate_private_file(live)?;
    if hash_locked_regular_file(live)? != old_hash {
        return Err(io::Error::other(
            "rollback did not restore the journaled private file",
        ));
    }
    Ok(())
}

pub(super) fn remove_private_file_transaction_journal(parent: &Path) -> io::Result<()> {
    remove_file_if_exists(&parent.join(PRIVATE_FILE_TRANSACTION_JOURNAL))
}

pub(super) fn cleanup_private_file_transaction_files(
    parent: &Path,
    journal: &PrivateFileTransaction,
) {
    let _ = std::fs::remove_file(parent.join(&journal.staged));
    let _ = std::fs::remove_file(parent.join(&journal.displaced));
    if let Some(rollback) = &journal.rollback {
        let _ = std::fs::remove_file(parent.join(rollback));
    }
}

pub(super) fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
