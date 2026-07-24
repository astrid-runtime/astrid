//! Identity-locked Windows paths, handles, and trusted authority boundaries.

#[cfg(test)]
use super::acl::validate_trusted_file_acl_handle;
use super::acl::{
    PrivateSecurityDescriptor, validate_private_acl_handle,
    validate_trusted_parent_acl_for_create_handle, validate_trusted_parent_acl_handle,
};
use super::error::with_context;
use super::prelude::*;

pub(super) struct OwnedHandle(pub(super) HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `OwnedHandle` is constructed only from successful Win32
            // handle-returning calls and closes that handle exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn mark_directory_for_deletion(handle: HANDLE) -> io::Result<()> {
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

struct DeleteCreatedDirectoryOnDrop {
    handle: HANDLE,
    armed: bool,
}

impl DeleteCreatedDirectoryOnDrop {
    fn new(handle: HANDLE, armed: bool) -> Self {
        Self { handle, armed }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DeleteCreatedDirectoryOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = mark_directory_for_deletion(self.handle);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) volume: u32,
    pub(super) index_high: u32,
    pub(super) index_low: u32,
}

pub(super) struct LockedPathComponent {
    path: PathBuf,
    identity: FileIdentity,
    handle: OwnedHandle,
}

/// Keeps the caller-selected authority boundary open against rename.
///
/// Ancestors are retained as identity handles with delete sharing so opening a
/// system ancestor does not claim authority the caller does not have. The
/// boundary handle requests write-attributes access and omits delete sharing:
/// Windows only grants an effective exclusive directory open when write access
/// was requested. Identity comparison before and after a namespace mutation is
/// defense in depth; the ACL check rejects write/delete authority for other
/// principals.
pub(super) struct TrustedPathGuard {
    components: Vec<LockedPathComponent>,
    authority_boundary: PathBuf,
}

#[cfg(test)]
pub(super) static TEST_MOVE_ANCESTOR_DURING_DIRECTORY_CREATE: std::sync::Mutex<
    Option<(PathBuf, PathBuf)>,
> = std::sync::Mutex::new(None);
#[cfg(test)]
pub(super) static TEST_FAIL_DIRECTORY_CREATE_AFTER_COMPONENT: std::sync::Mutex<Option<usize>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
pub(super) static TEST_DIRECTORY_CREATE_COMPONENTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) static TEST_PROBE_DIR_CREATE_ACL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) static TEST_SAW_DIR_CREATE_ACL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct CreatedPrivateDirectories {
    entries: Vec<(PathBuf, OwnedHandle)>,
    armed: bool,
}

impl CreatedPrivateDirectories {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            armed: true,
        }
    }

    fn last_handle(&self) -> Option<HANDLE> {
        self.entries.last().map(|(_, handle)| handle.0)
    }

    fn push(&mut self, path: PathBuf, handle: OwnedHandle) {
        self.entries.push((path, handle));
    }

    fn iter(&self) -> impl Iterator<Item = &(PathBuf, OwnedHandle)> {
        self.entries.iter()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn cleanup(&mut self) -> io::Result<()> {
        self.armed = false;
        let mut first_error = None;
        while let Some((path, handle)) = self.entries.pop() {
            if let Err(error) = mark_directory_for_deletion(handle.0)
                && first_error.is_none()
            {
                first_error = Some(with_context(
                    error,
                    format!(
                        "could not remove partially created private Windows directory {}",
                        path.display()
                    ),
                ));
            }
            // Closing the child before processing its parent makes each
            // directory empty before the parent's delete disposition is set.
            drop(handle);
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for CreatedPrivateDirectories {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum BoundaryContract {
    TrustedForCreate,
    ExactPrivateDirectory,
}

impl TrustedPathGuard {
    pub(super) fn capture(path: &Path) -> io::Result<Self> {
        validate_local_absolute_path(path)?;
        let mut components: Vec<LockedPathComponent> = Vec::new();
        let mut current = PathBuf::new();
        let mut rooted = false;
        for component in path.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::RootDir) {
                rooted = true;
            }
            if !rooted {
                continue;
            }
            let metadata = match std::fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path contains a redirect or non-directory component: {}",
                        current.display()
                    ),
                ));
            }
            let (handle, identity) = if let Some(parent) = components.last() {
                open_directory_identity_relative(
                    parent.handle.0,
                    component.as_os_str(),
                    current == path,
                )?
            } else if current == path {
                open_locked_directory(&current)?
            } else {
                open_directory_identity(&current, true)?
            };
            components.push(LockedPathComponent {
                path: current.clone(),
                identity,
                handle,
            });
        }
        if components.last().map(|component| component.path.as_path()) != Some(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "trusted Windows authority boundary does not exist: {}",
                    path.display()
                ),
            ));
        }
        // System ancestors such as the volume root and `Users` deliberately
        // grant limited authority to principals outside Astrid's trust set.
        // They remain open as identity handles while the caller-selected owned
        // directory is the rename-locked ACL authority boundary. Critical
        // child mutations resolve relative to that boundary handle, so an
        // ancestor rename cannot redirect the operation into another tree.
        let result = Self {
            components,
            authority_boundary: path.to_path_buf(),
        };
        validate_trusted_parent_acl_handle(
            result.authority_handle(),
            &result.authority_boundary.display().to_string(),
        )?;
        Ok(result)
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        let mut parent_handle: Option<OwnedHandle> = None;
        for component in &self.components {
            let (handle, identity) = if let Some(parent) = &parent_handle {
                let name = component.path.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "captured Windows descendant has no final component",
                    )
                })?;
                open_directory_identity_relative(parent.0, name, false)?
            } else {
                open_directory_identity(&component.path, true)?
            };
            if identity != component.identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path changed during a security-sensitive operation: {}",
                        component.path.display()
                    ),
                ));
            }
            parent_handle = Some(handle);
        }
        validate_trusted_parent_acl_handle(
            self.authority_handle(),
            &self.authority_boundary.display().to_string(),
        )
    }

    pub(super) fn verify_contract(&self, contract: BoundaryContract) -> io::Result<()> {
        self.verify()?;
        match contract {
            BoundaryContract::TrustedForCreate => validate_trusted_parent_acl_for_create_handle(
                self.authority_handle(),
                &self.authority_boundary.display().to_string(),
            ),
            BoundaryContract::ExactPrivateDirectory => validate_private_acl_handle(
                self.authority_handle(),
                true,
                &self.authority_boundary.display().to_string(),
            ),
        }
    }

    pub(super) fn authority_boundary(&self) -> &Path {
        &self.authority_boundary
    }

    pub(super) fn authority_handle(&self) -> HANDLE {
        self.components
            .last()
            .expect("captured Windows path has an authority component")
            .handle
            .0
    }

    pub(super) fn create_private_descendants(&self, target: &Path) -> io::Result<()> {
        let relative = target.strip_prefix(&self.authority_boundary).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "private Windows directory is outside its retained authority boundary: {}",
                    target.display()
                ),
            )
        })?;
        let names = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name.to_os_string()),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "private Windows directory contains a non-normal component: {}",
                        target.display()
                    ),
                )),
            })
            .collect::<io::Result<Vec<_>>>()?;
        if names.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "private Windows directory already exists: {}",
                    target.display()
                ),
            ));
        }

        let mut created = CreatedPrivateDirectories::with_capacity(names.len());
        let result = (|| {
            self.verify_contract(BoundaryContract::TrustedForCreate)?;
            let mut current = self.authority_boundary.clone();
            for (index, name) in names.iter().enumerate() {
                let parent = created
                    .last_handle()
                    .unwrap_or_else(|| self.authority_handle());
                current.push(name);
                let handle = create_private_directory_relative(parent, name)?;
                created.push(current.clone(), handle);
                validate_private_acl_handle(
                    created
                        .last_handle()
                        .expect("created directory handle was just retained"),
                    true,
                    &current.display().to_string(),
                )?;

                #[cfg(test)]
                after_test_directory_component(index)?;
                #[cfg(not(test))]
                let _ = index;
            }

            self.verify_contract(BoundaryContract::TrustedForCreate)?;
            for (path, handle) in created.iter() {
                validate_private_acl_handle(handle.0, true, &path.display().to_string())?;
            }
            // The retained component handles are the authority proof. Reopening
            // `target` here would conflict with their DELETE access and
            // intentionally non-delete-sharing cleanup contract.
            Ok(())
        })();

        match result {
            Ok(()) => {
                created.disarm();
                Ok(())
            },
            Err(error) => match created.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(with_context(
                    error,
                    format!(
                        "private Windows directory creation failed and partial cleanup also failed: {cleanup_error}"
                    ),
                )),
            },
        }
    }

    /// Runs a handle-relative mutation while the authority handle stays live.
    ///
    /// The caller's full ACL contract and every captured identity are checked
    /// both before and after the operation. Panics are resumed only after a
    /// best-effort verification, so test interruptions cannot silently bypass
    /// the security postcondition or replace the original panic.
    pub(super) fn with_verified_mutation<T>(
        &self,
        operation: &str,
        contract: BoundaryContract,
        action: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.verify_contract(contract)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        let verification = self.verify_contract(contract);
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                if let Err(error) = verification {
                    eprintln!(
                        "{operation} panicked and Windows authority verification failed: {error}"
                    );
                }
                std::panic::resume_unwind(payload);
            },
        };
        match (result, verification) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(operation_error), Err(verification_error)) => Err(with_context(
                operation_error,
                format!(
                    "{operation} failed and authority-boundary verification also failed: {verification_error}"
                ),
            )),
        }
    }
}

#[cfg(test)]
fn after_test_directory_component(index: usize) -> io::Result<()> {
    TEST_DIRECTORY_CREATE_COMPONENTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let should_fail = {
        let mut fault = TEST_FAIL_DIRECTORY_CREATE_AFTER_COMPONENT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *fault == Some(index) {
            *fault = None;
            true
        } else {
            false
        }
    };
    if should_fail {
        return Err(io::Error::from_raw_os_error(5));
    }

    if index != 0 {
        return Ok(());
    }
    let move_paths = TEST_MOVE_ANCESTOR_DURING_DIRECTORY_CREATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((from, to)) = move_paths {
        std::fs::rename(from, to)?;
    }
    Ok(())
}

#[cfg(test)]
fn test_probe_created_directory_acl(handle: HANDLE, disposition: u32) -> io::Result<()> {
    if disposition == FILE_CREATE
        && TEST_PROBE_DIR_CREATE_ACL.swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        validate_private_acl_handle(handle, true, "newly created private directory")?;
        TEST_SAW_DIR_CREATE_ACL.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(())
}

fn create_private_directory_relative(parent: HANDLE, name: &OsStr) -> io::Result<OwnedHandle> {
    let security = PrivateSecurityDescriptor::new(true)?;
    let (handle, _) = open_directory_identity_relative_with_options(
        parent,
        name,
        true,
        WRITE_DAC | DELETE,
        FILE_CREATE,
        Some(&security),
    )?;
    Ok(handle)
}

fn open_directory_identity_relative(
    parent: HANDLE,
    name: &OsStr,
    lock_against_rename: bool,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    open_directory_identity_relative_with_access(parent, name, lock_against_rename, 0)
}

fn open_directory_identity_relative_with_access(
    parent: HANDLE,
    name: &OsStr,
    lock_against_rename: bool,
    extra_access: u32,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    open_directory_identity_relative_with_options(
        parent,
        name,
        lock_against_rename,
        extra_access,
        FILE_OPEN,
        None,
    )
}

fn open_directory_identity_relative_with_options(
    parent: HANDLE,
    name: &OsStr,
    lock_against_rename: bool,
    extra_access: u32,
    disposition: u32,
    security_descriptor: Option<&PrivateSecurityDescriptor>,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid handle-relative Windows directory component",
        ));
    }
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows directory name is too long",
            )
        })?;
    let unicode = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES fits in u32"),
        RootDirectory: parent,
        ObjectName: &raw const unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: security_descriptor.map_or(null(), PrivateSecurityDescriptor::as_ptr),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    let desired_access = FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE
        | extra_access
        | if lock_against_rename {
            FILE_TRAVERSE | FILE_WRITE_ATTRIBUTES
        } else {
            0
        };
    let share_access = FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | if lock_against_rename {
            0
        } else {
            FILE_SHARE_DELETE
        };
    // SAFETY: descriptors and output buffers remain live for the call, and
    // the component is resolved relative to the retained parent handle.
    let result = unsafe {
        NtCreateFile(
            &raw mut handle,
            desired_access,
            &raw const attributes,
            &raw mut status,
            null(),
            0,
            share_access,
            disposition,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
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
            "NtCreateFile returned an invalid relative directory handle",
        ));
    }
    let handle = OwnedHandle(handle);
    let mut delete_created =
        DeleteCreatedDirectoryOnDrop::new(handle.0, disposition == FILE_CREATE);
    #[cfg(test)]
    test_probe_created_directory_acl(handle.0, disposition)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle and output buffer are live.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted Windows descendant is redirected or not a directory",
        ));
    }
    let result = (
        handle,
        FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    );
    delete_created.disarm();
    Ok(result)
}

pub(super) fn open_locked_directory(path: &Path) -> io::Result<(OwnedHandle, FileIdentity)> {
    open_directory_identity(path, false)
}

pub(super) fn open_directory_identity(
    path: &Path,
    allow_delete_sharing: bool,
) -> io::Result<(OwnedHandle, FileIdentity)> {
    let wide = wide_path(path)?;
    let share = FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | if allow_delete_sharing {
            FILE_SHARE_DELETE
        } else {
            0
        };
    let desired_access = FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | if allow_delete_sharing {
            0
        } else {
            FILE_TRAVERSE | FILE_WRITE_ATTRIBUTES
        };
    // SAFETY: the path is NUL terminated; null security/template pointers are
    // permitted. OPEN_REPARSE_POINT prevents following a late redirect.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `info` is a valid output buffer.
    if unsafe { GetFileInformationByHandle(handle.0, &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "trusted Windows path is a reparse point: {}",
                path.display()
            ),
        ));
    }
    Ok((
        handle,
        FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    ))
}

#[cfg(test)]
pub(super) struct LockedRegularFile {
    pub(super) file: File,
    pub(super) identity: FileIdentity,
}

#[cfg(test)]
pub(super) fn open_locked_regular_file(path: &Path) -> io::Result<LockedRegularFile> {
    verify_no_redirects(path)?;
    let wide = wide_path(path)?;
    // SAFETY: the path is NUL terminated. Read sharing permits concurrent
    // readers, while withholding write/delete sharing binds bytes and identity
    // for the lifetime of the returned File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        // SAFETY: ownership has not yet been transferred to File.
        unsafe {
            CloseHandle(handle);
        }
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        // SAFETY: ownership has not yet been transferred to File.
        unsafe {
            CloseHandle(handle);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted Windows file is redirected or not regular: {}",
                path.display()
            ),
        ));
    }
    // SAFETY: `handle` is a unique owned file handle and ownership transfers
    // exactly once into `File`.
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    validate_trusted_file_acl_handle(handle, &path.display().to_string())?;
    Ok(LockedRegularFile {
        file,
        identity: FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    })
}

pub(in crate::platform_fs) fn default_astrid_home_root() -> io::Result<PathBuf> {
    let local_data = BaseDirs::new()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Windows LocalAppData known folder is unavailable",
            )
        })?
        .data_local_dir()
        .to_path_buf();
    validate_local_absolute_path(&local_data)?;
    TrustedPathGuard::capture(&local_data)?.verify()?;
    Ok(local_data.join("Astrid").join("Runtime"))
}

pub(in crate::platform_fs) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    if path.exists() {
        let guard = TrustedPathGuard::capture(path)?;
        return guard.verify_contract(BoundaryContract::ExactPrivateDirectory);
    }

    let existing_parent = nearest_existing_ancestor(path)?;
    let guard = TrustedPathGuard::capture(&existing_parent)?;
    guard.create_private_descendants(path)
}

pub(in crate::platform_fs) fn restrict_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    super::io::restrict_guarded_private_file(&guard, path)
}

pub(in crate::platform_fs) fn validate_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    drop(super::io::open_guarded_regular_file(
        &guard,
        path,
        super::io::FileContract::ExactPrivate,
    )?);
    guard.verify_contract(BoundaryContract::ExactPrivateDirectory)
}

pub(super) fn nearest_existing_ancestor(path: &Path) -> io::Result<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => return Ok(current),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path ancestor is not a directory: {}", current.display()),
                ));
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
        if !current.pop() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Windows path has no existing directory ancestor",
            ));
        }
    }
}

pub(in crate::platform_fs) fn verify_no_redirects(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "security-sensitive Windows path must be absolute without traversal: {}",
                path.display()
            ),
        ));
    }

    let mut current = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir) {
            rooted = true;
        }
        if !rooted {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "security-sensitive Windows path contains a reparse point: {}",
                    current.display()
                ),
            ));
        }
    }
    let guard_path = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => path.to_path_buf(),
        Ok(_) => path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?
            .to_path_buf(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => nearest_existing_ancestor(path)?,
        Err(error) => return Err(error),
    };
    TrustedPathGuard::capture(&guard_path)?.verify()
}

pub(super) fn validate_local_absolute_path(path: &Path) -> io::Result<()> {
    let mut components = path.components();
    let local_disk = matches!(
        components.next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    ) && matches!(components.next(), Some(Component::RootDir));
    if !local_disk {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "security-sensitive Windows path must use a local absolute volume: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn hash_open_file(input: &mut File) -> io::Result<String> {
    input.seek(io::SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    io::copy(input, &mut hasher)?;
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the File owns a live Windows handle and `info` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume: info.dwVolumeSerialNumber,
        index_high: info.nFileIndexHigh,
        index_low: info.nFileIndexLow,
    })
}

pub(super) fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

pub(super) fn wide_text(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
