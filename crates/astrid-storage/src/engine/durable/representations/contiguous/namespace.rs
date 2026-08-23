//! Capability-pinned access to physical representation directories.

use std::fs::File;
use std::io;
use std::path::Path;

use cap_std::fs::{Dir, OpenOptions};

use crate::engine::durable::{DurableError, io_error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: VolumeId,
    file: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VolumeId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileId(u64);

pub(in crate::engine::durable) fn open_store_root(path: &Path) -> Result<Dir, DurableError> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
        .map_err(|source| io_error("open store root capability", source))
}

pub(in crate::engine::durable) fn open_representation_root(
    store_root: &Dir,
) -> Result<Dir, DurableError> {
    open_component(store_root, Path::new(super::super::DIRECTORY), false)
}

pub(in crate::engine::durable::representations) fn open_component(
    parent: &Dir,
    name: &Path,
    create: bool,
) -> Result<Dir, DurableError> {
    let open = || -> io::Result<Dir> {
        reject_redirect(parent, name, true)?;
        let first = parent.open_dir(name)?;
        reject_redirect(parent, name, true)?;
        let second = parent.open_dir(name)?;
        if directory_identity(&first)? != directory_identity(&second)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "representation directory changed while it was opened",
            ));
        }
        Ok(first)
    };
    match open() {
        Ok(directory) => Ok(directory),
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            parent
                .create_dir(name)
                .or_else(|source| {
                    (source.kind() == io::ErrorKind::AlreadyExists)
                        .then_some(())
                        .ok_or(source)
                })
                .map_err(|source| io_error("create representation directory capability", source))?;
            sync_directory(parent)
                .map_err(|source| io_error("flush representation parent capability", source))?;
            open().map_err(|source| io_error("pin representation directory capability", source))
        },
        Err(source) => Err(io_error("pin representation directory capability", source)),
    }
}

/// Synchronize directory metadata where the host exposes a usable flush operation.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
pub(in crate::engine::durable::representations) fn sync_directory(
    directory: &Dir,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        directory.open(Path::new("."))?.into_std().sync_all()
    }

    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

fn reject_redirect(parent: &Dir, name: &Path, directory: bool) -> io::Result<()> {
    let metadata = parent.symlink_metadata(name)?;
    if is_redirect(&metadata)
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "representation namespace entry is redirected or has the wrong type",
        ));
    }
    Ok(())
}

pub(in crate::engine::durable::representations) fn configure_no_follow(options: &mut OpenOptions) {
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

pub(in crate::engine::durable::representations) fn validate_opened_regular(
    file: &File,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || opened_file_is_redirected(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened representation entry is redirected or not a regular file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn opened_file_is_redirected(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn opened_file_is_redirected(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn is_redirect(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_redirect(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn directory_identity(directory: &Dir) -> io::Result<(u64, u64)> {
    let file = directory.try_clone()?.into_std_file();
    let identity = opened_file_identity(&file)?;
    Ok((identity.volume.0, identity.file.0))
}

#[cfg(unix)]
fn opened_file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        volume: VolumeId(metadata.dev()),
        file: FileId(metadata.ino()),
    })
}

#[cfg(windows)]
fn opened_file_identity(file: &File) -> io::Result<FileIdentity> {
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
    Ok(FileIdentity {
        volume: VolumeId(u64::from(info.dwVolumeSerialNumber)),
        file: FileId((u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)),
    })
}

#[cfg(not(any(unix, windows)))]
fn opened_file_identity(_file: &File) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable private file identity is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_sync_portability_contract_accepts_a_directory_capability() {
        let temporary = tempfile::tempdir().unwrap();
        let directory =
            Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority()).unwrap();

        sync_directory(&directory).unwrap();
    }
}
