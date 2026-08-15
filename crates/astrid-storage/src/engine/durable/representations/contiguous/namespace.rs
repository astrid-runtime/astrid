//! Capability-pinned access to one loose-blob generation.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, OpenOptions};

use crate::engine::durable::{DurableError, io_error};

pub(super) struct LooseBlobDirectory {
    directory: Dir,
    ambient_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    volume: VolumeId,
    file: FileId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VolumeId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileId(u64);

impl LooseBlobDirectory {
    pub(super) fn open(
        representation_root: &Dir,
        ambient_root: &Path,
        namespace_generation: u64,
        create: bool,
    ) -> Result<Self, DurableError> {
        let blobs = open_component(representation_root, Path::new("blobs"), create)?;
        let loose = open_component(&blobs, Path::new("loose"), create)?;
        let generation_name = format!("{namespace_generation:016x}");
        let directory = open_component(&loose, Path::new(&generation_name), create)?;
        Ok(Self {
            directory,
            ambient_path: ambient_root
                .join("blobs")
                .join("loose")
                .join(generation_name),
        })
    }

    pub(super) fn ambient_path(&self) -> &Path {
        &self.ambient_path
    }

    pub(super) fn open_regular(&self, name: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        configure_no_follow(&mut options);
        let file = self.directory.open_with(name, &options)?.into_std();
        validate_opened_regular(&file)?;
        Ok(file)
    }

    pub(super) fn create_new(&self, name: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        self.directory
            .open_with(name, &options)
            .map(cap_std::fs::File::into_std)
    }

    pub(super) fn hard_link(&self, source: &Path, destination: &Path) -> io::Result<()> {
        self.directory
            .hard_link(source, &self.directory, destination)
    }

    pub(super) fn remove_file(&self, name: &Path) -> io::Result<()> {
        self.directory.remove_file(name)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        sync_directory(&self.directory)
    }

    pub(super) const fn capability(&self) -> &Dir {
        &self.directory
    }
}

pub(in crate::engine::durable) fn open_store_root(path: &Path) -> Result<Dir, DurableError> {
    Dir::open_ambient_dir(path, cap_std::ambient_authority())
        .map_err(|source| io_error("open store root capability", source))
}

pub(in crate::engine::durable) fn open_representation_root(
    store_root: &Dir,
) -> Result<Dir, DurableError> {
    open_component(store_root, Path::new(super::super::DIRECTORY), false)
}

pub(super) fn retire_loose_blob_tree(root: &Dir) -> Result<(), DurableError> {
    let active = Path::new("blobs");
    let retired = Path::new(super::RETIRED_BLOBS_DIRECTORY);
    remove_directory_if_present(root, retired)?;
    match reject_redirect(root, active, true) {
        Ok(()) => {
            root.rename(active, root, retired)
                .map_err(|source| io_error("retire loose blob namespace", source))?;
            sync_directory(root)
                .map_err(|source| io_error("flush representation root capability", source))?;
        },
        Err(source) if source.kind() == io::ErrorKind::NotFound => {},
        Err(source) => return Err(io_error("inspect loose blob namespace", source)),
    }
    remove_directory_if_present(root, retired)?;
    sync_directory(root).map_err(|source| io_error("flush representation root capability", source))
}

fn remove_directory_if_present(parent: &Dir, name: &Path) -> Result<(), DurableError> {
    match reject_redirect(parent, name, true) {
        Ok(()) => parent
            .remove_dir_all(name)
            .map_err(|source| io_error("remove retired loose blob namespace", source)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect retired loose blob namespace", source)),
    }
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
                "loose blob directory changed while it was opened",
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
                .map_err(|source| io_error("create loose blob directory capability", source))?;
            sync_directory(parent)
                .map_err(|source| io_error("flush loose blob parent capability", source))?;
            open().map_err(|source| io_error("pin loose blob directory capability", source))
        },
        Err(source) => Err(io_error("pin loose blob directory capability", source)),
    }
}

pub(in crate::engine::durable::representations) fn sync_directory(
    directory: &Dir,
) -> io::Result<()> {
    directory.open(Path::new("."))?.into_std().sync_all()
}

pub(in crate::engine::durable::representations) fn reject_redirect(
    parent: &Dir,
    name: &Path,
    directory: bool,
) -> io::Result<()> {
    let metadata = parent.symlink_metadata(name)?;
    if is_redirect(&metadata)
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "loose blob namespace entry is redirected or has the wrong type",
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
pub(super) fn opened_file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        volume: VolumeId(metadata.dev()),
        file: FileId(metadata.ino()),
    })
}

#[cfg(windows)]
pub(super) fn opened_file_identity(file: &File) -> io::Result<FileIdentity> {
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
pub(super) fn opened_file_identity(_file: &File) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable private file identity is unavailable",
    ))
}
