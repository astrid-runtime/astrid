//! Capability-pinned access to one loose-blob generation.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, OpenOptions};

use crate::durable::{DurableError, io_error};

pub(super) struct LooseBlobDirectory {
    directory: Dir,
    ambient_path: PathBuf,
}

impl LooseBlobDirectory {
    pub(super) fn open(
        representation_root: &Path,
        namespace_generation: u64,
        create: bool,
    ) -> Result<Self, DurableError> {
        let root = open_root(representation_root)?;
        let blobs = open_component(&root, Path::new("blobs"), create)?;
        let loose = open_component(&blobs, Path::new("loose"), create)?;
        let generation_name = format!("{namespace_generation:016x}");
        let directory = open_component(&loose, Path::new(&generation_name), create)?;
        Ok(Self {
            directory,
            ambient_path: representation_root
                .join("blobs")
                .join("loose")
                .join(generation_name),
        })
    }

    pub(super) fn ambient_path(&self) -> &Path {
        &self.ambient_path
    }

    pub(super) fn open_regular(&self, name: &Path) -> io::Result<File> {
        reject_redirect(&self.directory, name, false)?;
        let first = self.directory.open(name)?.into_std();
        reject_redirect(&self.directory, name, false)?;
        let second = self.directory.open(name)?.into_std();
        if !first.metadata()?.is_file()
            || !second.metadata()?.is_file()
            || file_identity(&first)? != file_identity(&second)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "loose blob entry changed while it was opened",
            ));
        }
        Ok(first)
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
        self.directory.try_clone()?.into_std_file().sync_all()
    }

    pub(super) const fn capability(&self) -> &Dir {
        &self.directory
    }
}

fn open_root(path: &Path) -> Result<Dir, DurableError> {
    let parent_path = path
        .parent()
        .ok_or(DurableError::InvalidRepresentationState(
            "representation root has no parent",
        ))?;
    let name = path
        .file_name()
        .ok_or(DurableError::InvalidRepresentationState(
            "representation root has no final component",
        ))?;
    let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())
        .map_err(|source| io_error("open representation parent capability", source))?;
    open_component(&parent, Path::new(name), false)
}

fn open_component(parent: &Dir, name: &Path, create: bool) -> Result<Dir, DurableError> {
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
            parent
                .try_clone()
                .and_then(|directory| directory.into_std_file().sync_all())
                .map_err(|source| io_error("flush loose blob parent capability", source))?;
            open().map_err(|source| io_error("pin loose blob directory capability", source))
        },
        Err(source) => Err(io_error("pin loose blob directory capability", source)),
    }
}

fn reject_redirect(parent: &Dir, name: &Path, directory: bool) -> io::Result<()> {
    let metadata = parent.symlink_metadata(name)?;
    if metadata.file_type().is_symlink()
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
        "stable private file identity is unavailable",
    ))
}
