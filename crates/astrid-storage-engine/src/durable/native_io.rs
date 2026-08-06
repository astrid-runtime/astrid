//! Capability-relative access to authoritative principal-store files.

use std::fs::File;
use std::io;
use std::path::Path;

use cap_std::fs::{Dir, OpenOptions};

use super::{DurableError, io_error};

pub(super) fn open_rw(directory: &Dir, name: &Path, create: bool) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options
        .create(create)
        .truncate(false)
        .read(true)
        .write(true);
    configure_no_follow(&mut options);
    let file = directory
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|source| io_error("open principal-store capability file", source))?;
    validate_regular(&file)?;
    Ok(file)
}

pub(super) fn create_private(directory: &Dir, name: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    configure_no_follow(&mut options);
    let file = directory
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|source| io_error("create principal-store capability file", source))?;
    validate_regular(&file)?;
    Ok(file)
}

pub(super) fn open_directory(
    parent: &Dir,
    name: &Path,
    create: bool,
) -> Result<Option<Dir>, DurableError> {
    let open = || -> io::Result<Dir> {
        validate_directory_entry(parent, name)?;
        let first = parent.open_dir(name)?;
        validate_directory_entry(parent, name)?;
        let second = parent.open_dir(name)?;
        if directory_identity(&first)? != directory_identity(&second)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "principal-store directory changed while it was opened",
            ));
        }
        Ok(first)
    };
    match open() {
        Ok(directory) => Ok(Some(directory)),
        Err(source) if source.kind() == io::ErrorKind::NotFound && !create => Ok(None),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            parent
                .create_dir(name)
                .or_else(|error| {
                    (error.kind() == io::ErrorKind::AlreadyExists)
                        .then_some(())
                        .ok_or(error)
                })
                .map_err(|source| {
                    io_error("create principal-store capability directory", source)
                })?;
            sync_directory(parent)?;
            open()
                .map(Some)
                .map_err(|source| io_error("open principal-store capability directory", source))
        },
        Err(source) => Err(io_error(
            "open principal-store capability directory",
            source,
        )),
    }
}

fn validate_directory_entry(parent: &Dir, name: &Path) -> io::Result<()> {
    let metadata = parent.symlink_metadata(name)?;
    if !metadata.is_dir() || directory_entry_is_redirected(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "principal-store capability entry is redirected or not a directory",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn directory_entry_is_redirected(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn directory_entry_is_redirected(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn directory_identity(directory: &Dir) -> io::Result<(u64, u64)> {
    let file = directory.try_clone()?.into_std_file();
    file_identity(&file)
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live Windows handle and `info` is writable.
    #[allow(unsafe_code)]
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> io::Result<(u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable private directory identity is unavailable",
    ))
}

fn configure_no_follow(options: &mut OpenOptions) {
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
}

fn validate_regular(file: &File) -> Result<(), DurableError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect principal-store capability file", source))?;
    if !metadata.is_file() || file_is_redirected(&metadata) {
        return Err(io_error(
            "validate principal-store capability file",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "principal-store capability entry is redirected or not a regular file",
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn file_is_redirected(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn file_is_redirected(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) fn sync_directory(directory: &Dir) -> Result<(), DurableError> {
    #[cfg(unix)]
    {
        directory
            .open(Path::new("."))
            .map(cap_std::fs::File::into_std)
            .and_then(|file| file.sync_all())
            .map_err(|source| io_error("flush principal-store directory capability", source))
    }

    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}
