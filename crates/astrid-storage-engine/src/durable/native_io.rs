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
