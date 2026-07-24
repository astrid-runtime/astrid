//! Shared same-volume staging, locking, hashing, and replacement primitives.

use super::path::{
    file_identity, hash_locked_regular_file, hash_open_file, open_locked_regular_file,
    restrict_private_file, validate_private_file, wide_path,
};
use super::prelude::*;

pub(super) fn acquire_named_private_lock(path: &Path, owner_description: &str) -> io::Result<File> {
    let (file, created) = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?,
            false,
        ),
        Err(error) => return Err(error),
    };
    if created {
        restrict_private_file(path)?;
    } else {
        validate_private_file(path)?;
    }
    // `File::try_lock` is stable since Rust 1.89 (below the workspace's 1.95
    // MSRV) and its Windows backend is `LockFileEx` with exclusive,
    // fail-immediately flags. Keeping the standard API avoids another locking
    // dependency while retaining the native cross-process primitive.
    file.try_lock().map_err(|error| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("{owner_description} owns {}: {error}", path.display()),
        )
    })?;
    Ok(file)
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum TestReplaceFault {
    NoMutation(u32),
    OldMovedToBackup(u32),
}

#[cfg(test)]
pub(super) static TEST_REPLACE_FAULT: std::sync::Mutex<Option<TestReplaceFault>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) fn test_replace_fault(
    live: &Path,
    _replacement: &Path,
    backup: Option<&Path>,
) -> Option<io::Result<()>> {
    let fault = TEST_REPLACE_FAULT.lock().expect("fault lock").take()?;
    match fault {
        TestReplaceFault::NoMutation(code) => {
            Some(Err(io::Error::from_raw_os_error(code.cast_signed())))
        },
        TestReplaceFault::OldMovedToBackup(code) => {
            let result = backup
                .ok_or_else(|| io::Error::other("fault requires a backup path"))
                .and_then(|backup| move_file(live, backup))
                .and_then(|()| Err(io::Error::from_raw_os_error(code.cast_signed())));
            Some(result)
        },
    }
}

#[cfg(not(test))]
pub(super) fn test_maybe_interrupt_after_replace(_: usize) {}

#[cfg(test)]
pub(super) static TEST_CRASH_AFTER_REPLACE: std::sync::Mutex<Option<usize>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
pub(super) static TEST_ABORT_AFTER_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) static TEST_ABORT_INSIDE_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) static TEST_PAUSE_INSIDE_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(super) fn test_maybe_pause_inside_replace() {
    if TEST_PAUSE_INSIDE_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
        println!("astrid-private-replace-ready");
        std::io::stdout().flush().expect("flush pause marker");
        let mut release = String::new();
        std::io::stdin()
            .read_line(&mut release)
            .expect("read pause release");
    }
}

#[cfg(test)]
pub(super) fn test_maybe_interrupt_after_replace(index: usize) {
    if index == 0 && TEST_ABORT_AFTER_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::abort();
    }
    let should_interrupt = *TEST_CRASH_AFTER_REPLACE.lock().expect("crash lock") == Some(index);
    assert!(
        !should_interrupt,
        "simulated process interruption after executable replacement"
    );
}

#[cfg(not(test))]
pub(super) fn test_maybe_interrupt_before_commit() {}

#[cfg(test)]
pub(super) static TEST_CRASH_BEFORE_COMMIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

#[cfg(test)]
pub(super) fn test_maybe_interrupt_before_commit() {
    let should_interrupt = *TEST_CRASH_BEFORE_COMMIT.lock().expect("commit crash lock");
    assert!(
        !should_interrupt,
        "simulated process interruption before transaction commit"
    );
}

pub(super) fn stage_transaction_copy(
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<PathBuf> {
    stage_transaction_copy_authenticated(install_dir, source, file_name).map(|(path, _hash)| path)
}

pub(super) fn stage_transaction_copy_authenticated(
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<(PathBuf, String)> {
    let mut source = open_locked_regular_file(source)?;
    let source_identity = source.identity;
    let source_hash = hash_open_file(&mut source.file)?;
    source.file.seek(io::SeekFrom::Start(0))?;
    let destination = install_dir.join(file_name);
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)?;
    let result = (|| {
        io::copy(&mut source.file, &mut output)?;
        output.flush()?;
        output.sync_all()
    })();
    drop(output);
    if let Err(error) = result {
        let _ = std::fs::remove_file(&destination);
        return Err(error);
    }
    if file_identity(&source.file)? != source_identity {
        let _ = std::fs::remove_file(&destination);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source executable identity changed while staging",
        ));
    }
    let staged_hash = match hash_locked_regular_file(&destination) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = std::fs::remove_file(&destination);
            return Err(error);
        },
    };
    if staged_hash != source_hash {
        let _ = std::fs::remove_file(&destination);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged executable does not match its locked source handle",
        ));
    }
    Ok((destination, source_hash))
}

pub(super) fn copy_file_synced(source: &Path, destination: &Path) -> io::Result<()> {
    let mut input = open_locked_regular_file(source)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    io::copy(&mut input.file, &mut output)?;
    output.flush()?;
    output.sync_all()
}

pub(super) fn flush_file(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    // `sync_all` maps to the supported `FlushFileBuffers` operation. We make
    // no claim that Windows durably commits subsequent namespace operations.
    file.sync_all()
}

pub(super) fn stage_unique_bytes(parent: &Path, bytes: &[u8], label: &str) -> io::Result<PathBuf> {
    for _ in 0..16 {
        let temporary = parent.join(format!(".{label}.{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut output = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let write_result = (|| {
            output.write_all(bytes)?;
            output.flush()?;
            output.sync_all()
        })();
        drop(output);
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = restrict_private_file(&temporary) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        return Ok(temporary);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private staging path",
    ))
}

pub(super) fn replace_file_checked(
    live: &Path,
    replacement: &Path,
    backup: Option<&Path>,
) -> io::Result<()> {
    let result = replace_file_raw(live, replacement, backup);
    let Err(error) = result else {
        return Ok(());
    };
    let code = error.raw_os_error().map(i32::cast_unsigned);
    let documented_partial_mutation = matches!(
        code,
        Some(
            ERROR_UNABLE_TO_REMOVE_REPLACED
                | ERROR_UNABLE_TO_MOVE_REPLACEMENT
                | ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
        )
    );

    // ReplaceFileW documents three failures that may happen after one or more
    // namespace mutations. Always inspect all names, and for those codes
    // immediately reconcile an absent live name before returning. The caller's
    // transaction rollback copy remains independent of these three paths.
    let live_exists = live.exists();
    let backup_exists = backup.is_some_and(Path::exists);
    let replacement_exists = replacement.exists();
    if !live_exists && (documented_partial_mutation || backup_exists || replacement_exists) {
        let candidate = backup
            .filter(|path| path.exists())
            .or_else(|| replacement.exists().then_some(replacement));
        if let Some(candidate) = candidate
            && let Err(move_error) = move_file(candidate, live)
            && !live.exists()
            && let Err(copy_error) = copy_file_synced(candidate, live)
        {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "ReplaceFileW failed after mutation ({error}); live executable was absent and reconciliation failed ({move_error}; {copy_error})"
                ),
            ));
        }
    }
    if !live.exists() {
        return Err(io::Error::new(
            error.kind(),
            format!(
                "ReplaceFileW failed ({error}); live executable is absent while recovery artifacts remain"
            ),
        ));
    }
    Err(error)
}

pub(super) fn replace_file_raw(
    live: &Path,
    replacement: &Path,
    backup: Option<&Path>,
) -> io::Result<()> {
    #[cfg(test)]
    if let Some(result) = test_replace_fault(live, replacement, backup) {
        return result;
    }
    let live = wide_path(live)?;
    let replacement = wide_path(replacement)?;
    let backup = backup.map(wide_path).transpose()?;
    let backup_ptr = backup.as_ref().map_or(null(), Vec::as_ptr);
    // SAFETY: all optional and required path buffers are NUL terminated and
    // live for the call; reserved pointers are null as required by Win32.
    if unsafe {
        ReplaceFileW(
            live.as_ptr(),
            replacement.as_ptr(),
            backup_ptr,
            0,
            null(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    #[cfg(test)]
    {
        test_maybe_pause_inside_replace();
        if TEST_ABORT_INSIDE_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
            std::process::abort();
        }
    }
    Ok(())
}

pub(super) fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    // SAFETY: both path buffers are NUL terminated and live for the call.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn volume_root(path: &Path) -> io::Result<Vec<u16>> {
    let wide = wide_path(path)?;
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: `wide` is NUL terminated and `buffer` is writable for the
    // capacity supplied to Win32.
    if unsafe {
        GetVolumePathNameW(
            wide.as_ptr(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).expect("Windows maximum path buffer fits in u32"),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = buffer.iter().position(|unit| *unit == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows volume path was not NUL terminated",
        )
    })?;
    buffer.truncate(length);
    for unit in &mut buffer {
        if (*unit >= u16::from(b'A')) && (*unit <= u16::from(b'Z')) {
            *unit = unit
                .checked_add(u16::from(b'a' - b'A'))
                .expect("ASCII uppercase plus case offset fits u16");
        }
    }
    Ok(buffer)
}
