//! Identity-locked Windows paths, handles, and trusted authority boundaries.

use super::acl::{
    apply_private_acl, validate_private_acl, validate_trusted_file_acl,
    validate_trusted_parent_acl, validate_trusted_parent_acl_for_create,
};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity {
    pub(super) volume: u32,
    pub(super) index_high: u32,
    pub(super) index_low: u32,
}

pub(super) struct LockedPathComponent {
    path: PathBuf,
    identity: FileIdentity,
    _handle: OwnedHandle,
}

/// Keeps every existing directory component open without delete sharing.
///
/// Windows path APIs are otherwise susceptible to check/use swaps. Holding
/// these handles prevents rename/delete of checked components for the lifetime
/// of the operation. Identity comparison before each mutation is defense in
/// depth and makes a same-user test hook observable; same-user races are
/// authority-equivalent, while the ACL check rejects write/delete authority
/// for other principals.
pub(super) struct TrustedPathGuard {
    components: Vec<LockedPathComponent>,
    authority_boundary: PathBuf,
}

impl TrustedPathGuard {
    pub(super) fn capture(path: &Path) -> io::Result<Self> {
        validate_local_absolute_path(path)?;
        let mut components = Vec::new();
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
            let (handle, identity) = open_locked_directory(&current)?;
            components.push(LockedPathComponent {
                path: current.clone(),
                identity,
                _handle: handle,
            });
        }
        // System ancestors such as the volume root and `Users` deliberately
        // grant limited authority to principals outside Astrid's trust set.
        // They are still opened without delete sharing and identity-checked,
        // but the caller-selected owned directory is the ACL authority
        // boundary. Every security-sensitive caller separately enforces its
        // stronger exact/private contract there where required.
        validate_trusted_parent_acl(path)?;
        Ok(Self {
            components,
            authority_boundary: path.to_path_buf(),
        })
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        for component in &self.components {
            let (_, identity) = open_directory_identity(&component.path, true)?;
            if identity != component.identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path changed during a security-sensitive operation: {}",
                        component.path.display()
                    ),
                ));
            }
        }
        validate_trusted_parent_acl(&self.authority_boundary)
    }
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
    // SAFETY: the path is NUL terminated; null security/template pointers are
    // permitted. OPEN_REPARSE_POINT prevents following a late redirect.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
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

pub(super) struct LockedRegularFile {
    pub(super) file: File,
    pub(super) identity: FileIdentity,
}

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
    validate_trusted_file_acl(path)?;
    Ok(LockedRegularFile {
        file,
        identity: FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
    })
}

pub(super) fn hash_locked_regular_file(path: &Path) -> io::Result<String> {
    let mut locked = open_locked_regular_file(path)?;
    hash_open_file(&mut locked.file)
}

pub(super) fn verify_trusted_regular_file(path: &Path) -> io::Result<()> {
    let _locked = open_locked_regular_file(path)?;
    Ok(())
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
        if !std::fs::metadata(path)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("private path is not a directory: {}", path.display()),
            ));
        }
        validate_private_acl(path, true)?;
        return guard.verify();
    }

    let existing_parent = nearest_existing_ancestor(path)?;
    let guard = TrustedPathGuard::capture(&existing_parent)?;
    validate_trusted_parent_acl_for_create(&existing_parent)?;
    std::fs::create_dir_all(path)?;
    guard.verify()?;
    verify_no_redirects(path)?;
    if !std::fs::metadata(path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private path is not a directory: {}", path.display()),
        ));
    }
    apply_private_acl(path, true)?;
    validate_private_acl(path, true)?;
    TrustedPathGuard::capture(path)?.verify()
}

pub(in crate::platform_fs) fn restrict_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    verify_regular_file(path)?;
    apply_private_acl(path, false)?;
    validate_private_acl(path, false)?;
    guard.verify()
}

pub(in crate::platform_fs) fn validate_private_file(path: &Path) -> io::Result<()> {
    validate_local_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let guard = TrustedPathGuard::capture(parent)?;
    verify_regular_file(path)?;
    validate_private_acl(path, false)?;
    guard.verify()
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

pub(super) fn verify_regular_file(path: &Path) -> io::Result<()> {
    verify_no_redirects(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private Windows path is redirected or not a regular file: {}",
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
