//! Private native filesystem mechanics shared by store migrations and staging.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
#[cfg(not(windows))]
use std::io::Write;
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;

use crate::error::{StorageError, StorageResult};

#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrivateVolumeId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrivateFileId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrivateFileIdentity {
    volume: PrivateVolumeId,
    file: PrivateFileId,
}

impl PrivateFileIdentity {
    pub(super) const fn from_raw_parts(volume: u64, file: u64) -> Self {
        Self {
            volume: PrivateVolumeId(volume),
            file: PrivateFileId(file),
        }
    }

    pub(super) const fn raw_parts(self) -> (u64, u64) {
        (self.volume.0, self.file.0)
    }
}

/// An opened directory capability retained across runtime staging mutations.
#[derive(Debug)]
pub(super) struct PrivateDirectory {
    directory: Dir,
    #[cfg(unix)]
    sync_handle: File,
    path: PathBuf,
    identity: PrivateDirectoryIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrivateDirectoryIdentity {
    volume: PrivateVolumeId,
    directory: PrivateFileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateRenameIdentity {
    File(PrivateFileIdentity),
    Directory(PrivateDirectoryIdentity),
}

#[cfg(windows)]
mod windows;

impl PrivateDirectory {
    pub(super) fn open(path: &Path) -> StorageResult<Self> {
        let open = || {
            Dir::open_ambient_dir(path, cap_std::ambient_authority()).map_err(|error| {
                connection(format!(
                    "open private directory capability {}: {error}",
                    path.display()
                ))
            })
        };
        let directory = open()?;
        astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
            connection(format!(
                "validate private directory {}: {error}",
                path.display()
            ))
        })?;
        let confirmation = open()?;
        let identity = private_directory_identity(&directory)?;
        if identity != private_directory_identity(&confirmation)? {
            return Err(connection(format!(
                "private directory {} changed while it was opened",
                path.display()
            )));
        }
        #[cfg(unix)]
        let sync_handle = private_directory_sync_handle(&directory, path, identity)?;
        Ok(Self {
            directory,
            #[cfg(unix)]
            sync_handle,
            path: path.to_path_buf(),
            identity,
        })
    }

    pub(super) fn open_child(&self, name: &Path) -> StorageResult<Self> {
        self.validate_child_directory(name)?;
        let first = self.directory.open_dir(name).map_err(|error| {
            connection(format!(
                "open private directory {}: {error}",
                self.path.join(name).display()
            ))
        })?;
        self.validate_child_directory(name)?;
        let second = self.directory.open_dir(name).map_err(|error| {
            connection(format!(
                "reopen private directory {}: {error}",
                self.path.join(name).display()
            ))
        })?;
        let identity = private_directory_identity(&first)?;
        if identity != private_directory_identity(&second)? {
            return Err(connection(format!(
                "private directory {} changed while it was opened",
                self.path.join(name).display()
            )));
        }
        #[cfg(unix)]
        let sync_handle = private_directory_sync_handle(&first, &self.path.join(name), identity)?;
        Ok(Self {
            directory: first,
            #[cfg(unix)]
            sync_handle,
            path: self.path.join(name),
            identity,
        })
    }

    pub(super) fn ensure_child(&self, name: &Path) -> StorageResult<Self> {
        if !self.contains(name)? {
            self.directory.create_dir(name).map_err(|error| {
                connection(format!(
                    "create private directory {}: {error}",
                    self.path.join(name).display()
                ))
            })?;
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt as _;

                self.directory
                    .set_permissions(name, cap_std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        connection(format!(
                            "restrict private directory {}: {error}",
                            self.path.join(name).display()
                        ))
                    })?;
            }
            self.sync()?;
        }
        self.open_child(name)
    }

    pub(super) fn entry_is_directory(&self, name: &Path) -> StorageResult<bool> {
        let metadata = self.directory.symlink_metadata(name).map_err(|error| {
            connection(format!(
                "inspect private entry {}: {error}",
                self.path.join(name).display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(connection(format!(
                "private entry {} is redirected",
                self.path.join(name).display()
            )));
        }
        Ok(metadata.is_dir())
    }

    fn validate_child_directory(&self, name: &Path) -> StorageResult<()> {
        if !self.entry_is_directory(name)? {
            return Err(connection(format!(
                "private entry {} is not a directory",
                self.path.join(name).display()
            )));
        }
        Ok(())
    }

    pub(super) fn open_file(&self, name: &Path) -> StorageResult<File> {
        self.open_file_with_access(name, false)
    }

    pub(super) fn open_file_rw(&self, name: &Path) -> StorageResult<File> {
        self.open_file_with_access(name, true)
    }

    fn open_file_with_access(&self, name: &Path, write: bool) -> StorageResult<File> {
        let metadata = self.directory.symlink_metadata(name).map_err(|error| {
            connection(format!(
                "inspect private file {}: {error}",
                self.path.join(name).display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(connection(format!(
                "private file {} is redirected or not a regular file",
                self.path.join(name).display()
            )));
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).write(write);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = self
            .directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|error| {
                connection(format!(
                    "open private file {}: {error}",
                    self.path.join(name).display()
                ))
            })?;
        private_file_identity(&file)?;
        Ok(file)
    }

    pub(super) fn create_file(&self, name: &Path) -> StorageResult<File> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(PRIVATE_FILE_MODE);
        }
        let file = self
            .directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|error| {
                connection(format!(
                    "create private file {}: {error}",
                    self.path.join(name).display()
                ))
            })?;
        private_file_identity(&file)?;
        Ok(file)
    }

    pub(super) fn contains(&self, name: &Path) -> StorageResult<bool> {
        match self.directory.symlink_metadata(name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(connection(format!(
                "inspect private entry {}: {error}",
                self.path.join(name).display()
            ))),
        }
    }

    pub(super) fn entry_is_file(&self, name: &Path) -> StorageResult<bool> {
        match self.directory.symlink_metadata(name) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(connection(format!(
                "inspect private entry {}: {error}",
                self.path.join(name).display()
            ))),
        }
    }

    pub(super) fn entries(&self) -> StorageResult<Vec<OsString>> {
        self.directory
            .read_dir(Path::new("."))
            .map_err(|error| {
                connection(format!(
                    "read private directory {}: {error}",
                    self.path.display()
                ))
            })?
            .map(|entry| {
                entry.map(|entry| entry.file_name()).map_err(|error| {
                    connection(format!(
                        "enumerate private directory {}: {error}",
                        self.path.display()
                    ))
                })
            })
            .collect()
    }

    pub(super) fn remove_file(&self, name: &Path) -> StorageResult<()> {
        match self.directory.remove_file(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(connection(format!(
                "remove private file {}: {error}",
                self.path.join(name).display()
            ))),
        }
    }

    pub(super) fn remove_directory(&self, name: &Path) -> StorageResult<()> {
        self.directory.remove_dir(name).map_err(|error| {
            connection(format!(
                "remove private directory {}: {error}",
                self.path.join(name).display()
            ))
        })
    }

    pub(super) fn rename_with_identity(
        &self,
        source: &Path,
        destination: &Path,
        expected: PrivateFileIdentity,
    ) -> StorageResult<()> {
        let source_file = self.open_file(source)?;
        if private_file_identity(&source_file)? != expected {
            return Err(connection(format!(
                "private source {} changed before rename",
                self.path.join(source).display()
            )));
        }
        match self.directory.symlink_metadata(destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(connection(format!(
                    "inspect private rename destination {}: {error}",
                    self.path.join(destination).display()
                )));
            },
            Ok(_) => {
                return Err(connection(format!(
                    "private rename destination {} already exists",
                    self.path.join(destination).display()
                )));
            },
        }
        rename_no_replace(
            &self.directory,
            &self.path,
            source,
            &self.directory,
            &self.path,
            destination,
            PrivateRenameIdentity::File(expected),
        )
        .map_err(|error| {
            connection(format!(
                "rename private entry {} as {}: {error}",
                self.path.join(source).display(),
                self.path.join(destination).display()
            ))
        })?;
        let destination_file = self.open_file(destination)?;
        if private_file_identity(&destination_file)? != expected {
            return Err(connection(format!(
                "private destination {} does not name the verified source",
                self.path.join(destination).display()
            )));
        }
        Ok(())
    }

    pub(super) fn rename_to_with_identity(
        &self,
        source: &Path,
        destination_directory: &Self,
        destination: &Path,
        expected: PrivateFileIdentity,
    ) -> StorageResult<()> {
        let source_file = self.open_file(source)?;
        if private_file_identity(&source_file)? != expected {
            return Err(connection(format!(
                "private source {} changed before rename",
                self.path.join(source).display()
            )));
        }
        if destination_directory.contains(destination)? {
            return Err(connection(format!(
                "private rename destination {} already exists",
                destination_directory.path.join(destination).display()
            )));
        }
        rename_no_replace(
            &self.directory,
            &self.path,
            source,
            &destination_directory.directory,
            &destination_directory.path,
            destination,
            PrivateRenameIdentity::File(expected),
        )
        .map_err(|error| {
            connection(format!(
                "rename private entry {} as {}: {error}",
                self.path.join(source).display(),
                destination_directory.path.join(destination).display()
            ))
        })?;
        let destination_file = destination_directory.open_file(destination)?;
        if private_file_identity(&destination_file)? != expected {
            return Err(connection(format!(
                "private destination {} does not name the verified source",
                destination_directory.path.join(destination).display()
            )));
        }
        Ok(())
    }

    pub(super) fn rename_child_to(
        &self,
        source: &Path,
        destination_directory: &Self,
        destination: &Path,
    ) -> StorageResult<PrivateDirectory> {
        let source_directory = self.open_child(source)?;
        if destination_directory.contains(destination)? {
            return Err(connection(format!(
                "private rename destination {} already exists",
                destination_directory.path.join(destination).display()
            )));
        }
        rename_no_replace(
            &self.directory,
            &self.path,
            source,
            &destination_directory.directory,
            &destination_directory.path,
            destination,
            PrivateRenameIdentity::Directory(source_directory.identity),
        )
        .map_err(|error| {
            connection(format!(
                "rename private directory {} as {}: {error}",
                self.path.join(source).display(),
                destination_directory.path.join(destination).display()
            ))
        })?;
        let installed = destination_directory.open_child(destination)?;
        if installed.identity != source_directory.identity {
            return Err(connection(format!(
                "private destination {} does not name the verified directory",
                destination_directory.path.join(destination).display()
            )));
        }
        Ok(installed)
    }

    #[cfg_attr(not(unix), allow(clippy::unnecessary_wraps, clippy::unused_self))]
    pub(super) fn sync(&self) -> StorageResult<()> {
        #[cfg(unix)]
        {
            self.sync_handle.sync_all().map_err(|error| {
                connection(format!("flush directory {}: {error}", self.path.display()))
            })
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn private_directory_sync_handle(
    directory: &Dir,
    path: &Path,
    expected: PrivateDirectoryIdentity,
) -> StorageResult<File> {
    use cap_std::fs::OpenOptionsExt as _;

    // cap-std may retain an O_PATH descriptor for a directory on Linux. That
    // descriptor is suitable as openat authority but fsync returns EBADF.
    // Open `.` through the retained capability to obtain a read descriptor
    // suitable for durability, then bind it to the capability's identity.
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let handle = directory
        .open_with(Path::new("."), &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| {
            connection(format!(
                "open flush handle for private directory {}: {error}",
                path.display()
            ))
        })?;
    if private_directory_file_identity(&handle)? != expected {
        return Err(connection(format!(
            "flush handle for private directory {} names a different directory",
            path.display()
        )));
    }
    Ok(handle)
}

fn private_directory_identity(directory: &Dir) -> StorageResult<PrivateDirectoryIdentity> {
    let file = directory
        .try_clone()
        .map_err(|error| connection(format!("clone private directory handle: {error}")))?
        .into_std_file();
    private_directory_file_identity(&file)
}

fn private_directory_file_identity(file: &File) -> StorageResult<PrivateDirectoryIdentity> {
    let metadata = file
        .metadata()
        .map_err(|error| connection(format!("inspect private directory handle: {error}")))?;
    if !metadata.is_dir() {
        return Err(connection(
            "private directory handle is not a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(PrivateDirectoryIdentity {
            volume: PrivateVolumeId(metadata.dev()),
            directory: PrivateFileId(metadata.ino()),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns a live Windows directory handle and `info` is writable.
        #[allow(unsafe_code)]
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
            return Err(connection(format!(
                "inspect private Windows directory identity: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(PrivateDirectoryIdentity {
            volume: PrivateVolumeId(u64::from(info.dwVolumeSerialNumber)),
            directory: PrivateFileId(
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            ),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(connection(
            "private directory identity is unsupported on this platform".to_owned(),
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::PrivateDirectory;

    #[test]
    fn retained_directory_capability_has_a_durable_sync_handle() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let directory = PrivateDirectory::open(temporary.path()).expect("open private directory");

        directory
            .sync()
            .expect("flush through the retained directory capability");
    }
}

#[cfg(target_os = "linux")]
fn rename_no_replace(
    source_directory: &Dir,
    _source_directory_path: &Path,
    source: &Path,
    destination_directory: &Dir,
    _destination_directory_path: &Path,
    destination: &Path,
    _expected: PrivateRenameIdentity,
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both names and the retained directory descriptor remain valid
    // for the call. RENAME_NOREPLACE makes destination selection atomic.
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_no_replace(
    source_directory: &Dir,
    _source_directory_path: &Path,
    source: &Path,
    destination_directory: &Dir,
    _destination_directory_path: &Path,
    destination: &Path,
    _expected: PrivateRenameIdentity,
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both names and the retained directory descriptor remain valid
    // for the call. RENAME_EXCL makes destination selection atomic.
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::renameatx_np(
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_no_replace(
    _source_directory: &Dir,
    source_directory_path: &Path,
    source: &Path,
    _destination_directory: &Dir,
    destination_directory_path: &Path,
    destination: &Path,
    expected: PrivateRenameIdentity,
) -> std::io::Result<()> {
    let source_path = source_directory_path.join(source);
    let destination_path = destination_directory_path.join(destination);
    rename_windows_no_replace(&source_path, &destination_path, expected)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_no_replace(
    _source_directory: &Dir,
    _source_directory_path: &Path,
    _source: &Path,
    _destination_directory: &Dir,
    _destination_directory_path: &Path,
    _destination: &Path,
    _expected: PrivateRenameIdentity,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "capability-relative exclusive rename is unsupported",
    ))
}

#[cfg(windows)]
pub(in crate::principal_state) use windows::rename_windows_no_replace;

pub(super) fn private_file_identity(file: &File) -> StorageResult<PrivateFileIdentity> {
    let metadata = file
        .metadata()
        .map_err(|error| connection(format!("inspect private file handle: {error}")))?;
    if !metadata.is_file() {
        return Err(connection(
            "private file handle is not a regular file".to_owned(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(connection(
                "private file handle is a reparse point".to_owned(),
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(PrivateFileIdentity::from_raw_parts(
            metadata.dev(),
            metadata.ino(),
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns a live Windows handle and `info` is writable.
        #[allow(unsafe_code)]
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
            return Err(connection(format!(
                "inspect private Windows file identity: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(PrivateFileIdentity::from_raw_parts(
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(connection(
            "private file identity is unsupported on this platform".to_owned(),
        ))
    }
}

pub(super) fn ensure_private_directory(path: &Path) -> StorageResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(connection(format!(
                "private directory {} is redirected or not a directory",
                path.display()
            )));
        },
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(connection(format!(
                "inspect private directory {}: {error}",
                path.display()
            )));
        },
    }
    astrid_core::platform_fs::ensure_private_directory(path).map_err(|error| {
        connection(format!(
            "create private directory {}: {error}",
            path.display()
        ))
    })?;
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!(
            "validate private directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        connection(format!(
            "inspect private directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(connection(format!(
            "private directory {} is redirected or not a directory",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_private_regular_file(path: &Path) -> StorageResult<u64> {
    astrid_core::platform_fs::verify_no_redirects(path).map_err(|error| {
        connection(format!("validate private path {}: {error}", path.display()))
    })?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| connection(format!("inspect private file {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(connection(format!(
            "private file {} is redirected or not a regular file",
            path.display()
        )));
    }
    astrid_core::platform_fs::validate_private_file(path).map_err(|error| {
        connection(format!("validate private file {}: {error}", path.display()))
    })?;
    Ok(metadata.len())
}

pub(super) fn create_private_file(path: &Path) -> StorageResult<File> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("private file {} has no parent", path.display())))?;
    ensure_private_directory(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(PRIVATE_FILE_MODE);
    }
    let file = options
        .open(path)
        .map_err(|error| connection(format!("create private file {}: {error}", path.display())))?;
    astrid_core::platform_fs::restrict_private_file(path).map_err(|error| {
        connection(format!("restrict private file {}: {error}", path.display()))
    })?;
    validate_private_regular_file(path)?;
    Ok(file)
}

pub(super) fn open_private_file(path: &Path) -> StorageResult<File> {
    open_private_file_with_access(path, false)
}

fn open_private_file_with_access(path: &Path, write: bool) -> StorageResult<File> {
    validate_private_regular_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| connection(format!("open private file {}: {error}", path.display())))?;
    private_file_identity(&file)?;
    Ok(file)
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("path {} has no parent", path.display())))?;
    ensure_private_directory(parent)?;

    #[cfg(windows)]
    {
        astrid_core::platform_fs::atomic_write_private_file(path, bytes).map_err(|error| {
            connection(format!(
                "atomically write private file {}: {error}",
                path.display()
            ))
        })
    }

    #[cfg(not(windows))]
    {
        let temporary = temporary_path(path);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(PRIVATE_FILE_MODE);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            connection(format!(
                "open temporary state file {}: {error}",
                temporary.display()
            ))
        })?;
        let result = (|| {
            file.write_all(bytes).map_err(|error| {
                connection(format!(
                    "write temporary state file {}: {error}",
                    temporary.display()
                ))
            })?;
            file.sync_all().map_err(|error| {
                connection(format!(
                    "flush temporary state file {}: {error}",
                    temporary.display()
                ))
            })?;
            std::fs::rename(&temporary, path).map_err(|error| {
                connection(format!(
                    "publish state file {} as {}: {error}",
                    temporary.display(),
                    path.display()
                ))
            })?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

pub(super) fn quarantine_directory(path: &Path, classification: &str) -> StorageResult<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| connection(format!("path {} has no parent directory", path.display())))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| connection(format!("path {} is not valid UTF-8", path.display())))?;
    let mut suffix = 0_u64;
    let destination = loop {
        let candidate = parent.join(format!("{name}.{classification}.{suffix}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or_else(|| connection("too many quarantined directories".to_owned()))?;
    };
    rename_private_entry(path, &destination)?;
    sync_directory(parent)?;
    Ok(destination)
}

/// Rename an entry at the platform's durable namespace boundary.
///
/// Windows has no portable parent-directory flush equivalent, so the rename
/// itself must request write-through. Unix callers retain their existing
/// parent-directory synchronization after this atomic transition.
pub(super) fn rename_private_entry(source: &Path, destination: &Path) -> StorageResult<()> {
    astrid_core::platform_fs::rename_with_write_through(source, destination).map_err(|error| {
        connection(format!(
            "rename private entry {} as {}: {error}",
            source.display(),
            destination.display()
        ))
    })
}

#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
pub(super) fn sync_directory(path: &Path) -> StorageResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| connection(format!("flush directory {}: {error}", path.display())))
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(not(windows))]
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "state".into(), std::ffi::OsString::from);
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    path.with_file_name(name)
}

fn connection(message: String) -> StorageError {
    StorageError::Connection(message)
}
