//! Shared same-volume staging, locking, hashing, and replacement primitives.

use super::acl::{
    PrivateSecurityDescriptor, apply_private_acl_to_handle, validate_private_acl_handle,
    validate_trusted_file_acl_handle,
};
use super::error::with_context;
use super::path::{
    BoundaryContract, OwnedHandle, TrustedPathGuard, file_identity, hash_open_file, wide_path,
};
use super::prelude::*;

#[derive(Clone, Copy)]
pub(super) enum FileContract {
    Trusted,
    ExactPrivate,
}

pub(super) struct PreparationCleanup<'a> {
    guard: &'a TrustedPathGuard,
    paths: Vec<PathBuf>,
    armed: bool,
}

impl<'a> PreparationCleanup<'a> {
    pub(super) fn new(guard: &'a TrustedPathGuard) -> Self {
        Self {
            guard,
            paths: Vec::new(),
            armed: true,
        }
    }

    pub(super) fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for PreparationCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            for path in self.paths.iter().rev() {
                let _ = remove_guarded_file(self.guard, path);
            }
        }
    }
}

pub(super) fn acquire_named_private_lock(
    guard: &TrustedPathGuard,
    path: &Path,
    owner_description: &str,
) -> io::Result<File> {
    let file = match create_guarded_private_file_with_share(
        guard,
        path,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let name = guarded_child_name(guard, path)?;
            let handle = open_guarded_child_with_options(
                guard,
                name,
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
            )?;
            validate_private_acl_handle(handle.0, false, &path.display().to_string())?;
            let raw = handle.0;
            std::mem::forget(handle);
            // SAFETY: ownership transfers from OwnedHandle exactly once.
            unsafe { File::from_raw_handle(raw.cast()) }
        },
        Err(error) => return Err(error),
    };
    // `File::try_lock` is stable since Rust 1.89 (below the workspace's 1.95
    // MSRV) and its Windows backend is `LockFileEx` with exclusive,
    // fail-immediately flags. Keeping the standard API avoids another locking
    // dependency while retaining the native cross-process primitive.
    file.try_lock().map_err(|error| {
        with_context(
            error.into(),
            format!("{owner_description} owns {}", path.display()),
        )
    })?;
    validate_private_acl_handle(
        file.as_raw_handle().cast(),
        false,
        &path.display().to_string(),
    )?;
    guard.verify()?;
    Ok(file)
}

#[cfg(test)]
pub(super) static TEST_RENAME_FAULT: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) static TEST_JOURNAL_RENAME_FAULT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) static TEST_PROBE_FILE_CREATE_ACL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) static TEST_SAW_FILE_CREATE_ACL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(super) fn test_maybe_fail_journal_rename() -> io::Result<()> {
    if TEST_JOURNAL_RENAME_FAULT.swap(false, std::sync::atomic::Ordering::SeqCst) {
        Err(io::Error::from_raw_os_error(5))
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn test_probe_created_file_acl(handle: HANDLE, disposition: u32) -> io::Result<()> {
    if disposition == FILE_CREATE
        && TEST_PROBE_FILE_CREATE_ACL.swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        validate_private_acl_handle(handle, false, "newly created private file")?;
        TEST_SAW_FILE_CREATE_ACL.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn test_rename_fault() -> Option<io::Result<()>> {
    let code = TEST_RENAME_FAULT.lock().expect("fault lock").take()?;
    Some(Err(io::Error::from_raw_os_error(code.cast_signed())))
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
    destination_guard: &TrustedPathGuard,
    source_guard: &TrustedPathGuard,
    source_file_contract: FileContract,
    source_boundary_contract: BoundaryContract,
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<PathBuf> {
    stage_transaction_copy_authenticated(
        destination_guard,
        source_guard,
        source_file_contract,
        source_boundary_contract,
        install_dir,
        source,
        file_name,
    )
    .map(|(path, _hash)| path)
}

pub(super) fn stage_transaction_copy_authenticated(
    destination_guard: &TrustedPathGuard,
    source_guard: &TrustedPathGuard,
    source_file_contract: FileContract,
    source_boundary_contract: BoundaryContract,
    install_dir: &Path,
    source: &Path,
    file_name: &str,
) -> io::Result<(PathBuf, String)> {
    let source_path = source;
    let mut source_file =
        open_guarded_regular_file(source_guard, source_path, source_file_contract)?;
    let source_identity = file_identity(&source_file)?;
    let source_hash = hash_open_file(&mut source_file)?;
    source_file.seek(io::SeekFrom::Start(0))?;
    let destination = install_dir.join(file_name);
    let mut output = create_guarded_private_file(destination_guard, &destination)?;
    let mut cleanup = PreparationCleanup::new(destination_guard);
    cleanup.track(destination.clone());
    let result = (|| {
        io::copy(&mut source_file, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        let staged_hash = hash_open_file(&mut output)?;
        if staged_hash != source_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staged executable does not match its locked source handle",
            ));
        }
        validate_private_acl_handle(
            output.as_raw_handle().cast(),
            false,
            &destination.display().to_string(),
        )?;
        Ok(())
    })();
    drop(output);
    if let Err(error) = result {
        let _ = remove_guarded_file(destination_guard, &destination);
        return Err(error);
    }
    if let Err(error) = validate_file_contract(
        source_file.as_raw_handle().cast(),
        source_path,
        source_file_contract,
    ) {
        let _ = remove_guarded_file(destination_guard, &destination);
        return Err(error);
    }
    source_guard.verify_contract(source_boundary_contract)?;
    match file_identity(&source_file) {
        Ok(identity) if identity == source_identity => {},
        Ok(_) => {
            let _ = remove_guarded_file(destination_guard, &destination);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "source executable identity changed while staging",
            ));
        },
        Err(error) => {
            let _ = remove_guarded_file(destination_guard, &destination);
            return Err(error);
        },
    }
    destination_guard.verify()?;
    cleanup.disarm();
    Ok((destination, source_hash))
}

pub(super) fn stage_unique_bytes(
    guard: &TrustedPathGuard,
    parent: &Path,
    bytes: &[u8],
    label: &str,
) -> io::Result<PathBuf> {
    for _ in 0..16 {
        let temporary = parent.join(format!(".{label}.{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut output = match create_guarded_private_file(guard, &temporary) {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let write_result = (|| {
            output.write_all(bytes)?;
            output.flush()?;
            output.sync_all()?;
            validate_private_acl_handle(
                output.as_raw_handle().cast(),
                false,
                &temporary.display().to_string(),
            )
        })();
        drop(output);
        if let Err(error) = write_result {
            let _ = remove_guarded_file(guard, &temporary);
            return Err(error);
        }
        if let Err(error) = guard.verify() {
            let _ = remove_guarded_file(guard, &temporary);
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
    guard: &TrustedPathGuard,
    live: &Path,
    replacement: &Path,
) -> io::Result<()> {
    #[cfg(test)]
    if let Some(result) = test_rename_fault() {
        return result;
    }
    rename_guarded_file(guard, replacement, live, true).map_err(|error| {
        with_context(
            error,
            format!(
                "could not atomically replace {} with handle-locked source {}",
                live.display(),
                replacement.display()
            ),
        )
    })?;
    #[cfg(test)]
    {
        test_maybe_pause_inside_replace();
        if TEST_ABORT_INSIDE_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
            std::process::abort();
        }
    }
    Ok(())
}

pub(super) fn move_guarded_file(
    guard: &TrustedPathGuard,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    rename_guarded_file(guard, source, destination, false)
}

pub(super) fn remove_guarded_file(guard: &TrustedPathGuard, path: &Path) -> io::Result<()> {
    let name = guarded_child_name(guard, path)?;
    let handle = open_guarded_child(guard, name, DELETE | FILE_READ_ATTRIBUTES)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `handle` is live and the fixed-size disposition buffer is valid.
    if unsafe {
        SetFileInformationByHandle(
            handle.0,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>())
                .expect("FILE_DISPOSITION_INFO fits in u32"),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn guarded_file_exists(guard: &TrustedPathGuard, path: &Path) -> io::Result<bool> {
    let name = guarded_child_name(guard, path)?;
    match open_guarded_child(guard, name, FILE_READ_ATTRIBUTES) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn open_guarded_regular_file(
    guard: &TrustedPathGuard,
    path: &Path,
    file_contract: FileContract,
) -> io::Result<File> {
    let name = guarded_child_name(guard, path)?;
    let handle = open_guarded_child_locked(guard, name, GENERIC_READ | READ_CONTROL)?;
    validate_file_contract(handle.0, path, file_contract)?;
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers from the forgotten OwnedHandle exactly once.
    Ok(unsafe { File::from_raw_handle(raw.cast()) })
}

pub(super) fn validate_file_contract(
    handle: HANDLE,
    path: &Path,
    contract: FileContract,
) -> io::Result<()> {
    let description = path.display().to_string();
    match contract {
        FileContract::Trusted => validate_trusted_file_acl_handle(handle, &description),
        FileContract::ExactPrivate => validate_private_acl_handle(handle, false, &description),
    }
}

pub(super) fn hash_guarded_regular_file(
    guard: &TrustedPathGuard,
    path: &Path,
    file_contract: FileContract,
    boundary_contract: BoundaryContract,
) -> io::Result<String> {
    let mut file = open_guarded_regular_file(guard, path, file_contract)?;
    let hash = hash_open_file(&mut file)?;
    validate_file_contract(file.as_raw_handle().cast(), path, file_contract)?;
    guard.verify_contract(boundary_contract)?;
    Ok(hash)
}

pub(super) fn read_guarded_regular_file(
    guard: &TrustedPathGuard,
    path: &Path,
    file_contract: FileContract,
    boundary_contract: BoundaryContract,
) -> io::Result<Vec<u8>> {
    let mut file = open_guarded_regular_file(guard, path, file_contract)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    validate_file_contract(file.as_raw_handle().cast(), path, file_contract)?;
    guard.verify_contract(boundary_contract)?;
    Ok(bytes)
}

pub(super) fn flush_guarded_file(
    guard: &TrustedPathGuard,
    path: &Path,
    file_contract: FileContract,
    boundary_contract: BoundaryContract,
) -> io::Result<()> {
    let name = guarded_child_name(guard, path)?;
    let handle = open_guarded_child_locked(guard, name, GENERIC_WRITE | READ_CONTROL)?;
    validate_file_contract(handle.0, path, file_contract)?;
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers from the forgotten OwnedHandle exactly once.
    let file = unsafe { File::from_raw_handle(raw.cast()) };
    file.sync_all()?;
    validate_file_contract(file.as_raw_handle().cast(), path, file_contract)?;
    guard.verify_contract(boundary_contract)
}

fn rename_guarded_file(
    guard: &TrustedPathGuard,
    source: &Path,
    destination: &Path,
    replace: bool,
) -> io::Result<()> {
    let source_name = guarded_child_name(guard, source)?;
    let destination_name = guarded_child_name(guard, destination)?;
    let source = open_guarded_child(guard, source_name, DELETE | FILE_READ_ATTRIBUTES)?;
    let destination_wide = destination_name.encode_wide().collect::<Vec<_>>();
    let name_bytes = destination_wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Windows file name is too long")
        })?;
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let populated_bytes = header
        .checked_add(usize::try_from(name_bytes).expect("u32 length fits usize"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer overflow"))?;
    let buffer_bytes = populated_bytes.max(size_of::<FILE_RENAME_INFO>());
    // `Vec<usize>` supplies native pointer alignment and zero-initializes the
    // full fixed header, including the trailing FileName element/padding that
    // `size_of::<FILE_RENAME_INFO>()` requires even for a one-unit name.
    let mut buffer = vec![0_usize; buffer_bytes.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the usize buffer is sufficiently aligned and sized for the
    // variable-length FILE_RENAME_INFO followed by the UTF-16 component.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = guard.authority_handle();
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            destination_wide.as_ptr(),
            (*info).FileName.as_mut_ptr(),
            destination_wide.len(),
        );
    }
    // SAFETY: source and root-directory handles are live, and the aligned
    // variable-length buffer contains exactly `buffer_bytes` initialized bytes.
    if unsafe {
        SetFileInformationByHandle(
            source.0,
            FileRenameInfo,
            info.cast(),
            u32::try_from(buffer_bytes).expect("rename buffer length fits u32"),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn guarded_child_name<'a>(guard: &TrustedPathGuard, path: &'a Path) -> io::Result<&'a OsStr> {
    if path.parent() != Some(guard.authority_boundary()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "handle-relative Windows mutation escaped authority boundary {}: {}",
                guard.authority_boundary().display(),
                path.display()
            ),
        ));
    }
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "handle-relative Windows mutation has no final component",
        )
    })
}

fn open_guarded_child(
    guard: &TrustedPathGuard,
    name: &OsStr,
    desired_access: u32,
) -> io::Result<OwnedHandle> {
    open_guarded_child_with_options(
        guard,
        name,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
}

fn open_guarded_child_locked(
    guard: &TrustedPathGuard,
    name: &OsStr,
    desired_access: u32,
) -> io::Result<OwnedHandle> {
    open_guarded_child_with_options(guard, name, desired_access, FILE_SHARE_READ, FILE_OPEN)
}

fn create_guarded_private_file(guard: &TrustedPathGuard, path: &Path) -> io::Result<File> {
    create_guarded_private_file_with_share(guard, path, FILE_SHARE_READ)
}

fn create_guarded_private_file_with_share(
    guard: &TrustedPathGuard,
    path: &Path,
    share_access: u32,
) -> io::Result<File> {
    let name = guarded_child_name(guard, path)?;
    let handle = open_guarded_child_with_options(
        guard,
        name,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | DELETE,
        share_access,
        FILE_CREATE,
    )?;
    if let Err(error) = validate_private_acl_handle(handle.0, false, &path.display().to_string()) {
        let _ = mark_file_for_deletion(handle.0);
        return Err(error);
    }
    let raw = handle.0;
    std::mem::forget(handle);
    // SAFETY: ownership transfers from the forgotten OwnedHandle exactly once.
    Ok(unsafe { File::from_raw_handle(raw.cast()) })
}

pub(super) fn restrict_guarded_private_file(
    guard: &TrustedPathGuard,
    path: &Path,
) -> io::Result<()> {
    let name = guarded_child_name(guard, path)?;
    let handle = open_guarded_child_locked(guard, name, GENERIC_READ | READ_CONTROL | WRITE_DAC)?;
    apply_private_acl_to_handle(handle.0, false)?;
    validate_private_acl_handle(handle.0, false, &path.display().to_string())?;
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)
}

fn mark_file_for_deletion(handle: HANDLE) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `handle` is live with DELETE access and the fixed-size
    // disposition buffer remains live for the call.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>())
                .expect("FILE_DISPOSITION_INFO fits in u32"),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct DeleteCreatedFileOnDrop {
    handle: HANDLE,
    armed: bool,
}

impl DeleteCreatedFileOnDrop {
    fn new(handle: HANDLE, armed: bool) -> Self {
        Self { handle, armed }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DeleteCreatedFileOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = mark_file_for_deletion(self.handle);
        }
    }
}

fn open_guarded_child_with_options(
    guard: &TrustedPathGuard,
    name: &OsStr,
    desired_access: u32,
    share_access: u32,
    disposition: u32,
) -> io::Result<OwnedHandle> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid handle-relative Windows file name",
        ));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Windows file name is too long")
        })?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let security_descriptor = if disposition == FILE_CREATE {
        Some(PrivateSecurityDescriptor::new(false)?)
    } else {
        None
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES fits in u32"),
        RootDirectory: guard.authority_handle(),
        ObjectName: &raw const unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: security_descriptor
            .as_ref()
            .map_or(null(), PrivateSecurityDescriptor::as_ptr),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: all descriptor/name/output buffers remain live for the call;
    // RootDirectory is the retained authority handle and the name is relative.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            desired_access | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            share_access,
            disposition,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(io::Error::from_raw_os_error(code.cast_signed()));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile returned an invalid relative child handle",
        ));
    }
    let handle = OwnedHandle(handle);
    let mut delete_created = DeleteCreatedFileOnDrop::new(handle.0, disposition == FILE_CREATE);
    #[cfg(test)]
    test_probe_created_file_acl(handle.0, disposition)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the relative child handle is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "handle-relative Windows mutation source is redirected or not a regular file",
        ));
    }
    delete_created.disarm();
    Ok(handle)
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
