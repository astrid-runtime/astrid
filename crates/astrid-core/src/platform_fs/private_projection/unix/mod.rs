//! Descriptor-relative projection operations with one explicit hardware fence.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;

use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, SFlag, fstat, fstatat};
use nix::unistd::fsync;

use super::RelativePath;
use crate::platform_fs::{MountBoundary, nix_io_error};

mod anchor;
#[cfg(test)]
mod hooks;
#[cfg(test)]
mod tests;
mod write;

use anchor::{DirectoryChain, Root};

pub(super) struct Projection {
    root: Root,
    boundary: MountBoundary,
}

impl Projection {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let root = Root::open(path)?;
        let boundary = MountBoundary::new(&root.file)?;
        if anchor::make_private_directory(&root.file)? {
            fsync(&root.file).map_err(nix_io_error)?;
        }
        root.validate(&boundary)?;
        Ok(Self { root, boundary })
    }

    pub(super) fn snapshot(&self, relative: &RelativePath) -> io::Result<Option<Vec<u8>>> {
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) = self.directories(parents, false)? else {
            return Ok(None);
        };
        let parent = chain.directory();
        let Some(expected) = entry_stat(parent, name)? else {
            chain.validate(&self.boundary)?;
            return Ok(None);
        };
        require_regular(&expected)?;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let mut file = File::from(
            openat(
                parent,
                name.as_os_str(),
                flags,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(nix_io_error)?,
        );
        verify_identity(parent, name, &file, Identity::read(&expected))?;
        self.boundary.validate(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        verify_identity(parent, name, &file, Identity::read(&expected))?;
        chain.validate(&self.boundary)?;
        Ok(Some(bytes))
    }

    pub(super) fn ensure_directory(&self, relative: &RelativePath) -> io::Result<()> {
        let chain = self
            .directories(&relative.0, true)?
            .ok_or_else(invalid_path)?;
        chain.validate(&self.boundary)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        self.root.validate(&self.boundary)?;
        self.root.file.sync_all()?;
        #[cfg(test)]
        hooks::after(hooks::Event::RootSynced)?;
        // This is the second and final absolute ancestry walk in a successful
        // batch. Per-file operations use only the captured relative authority.
        self.root.validate_absolute(&self.boundary)
    }

    fn directories(
        &self,
        names: &[std::ffi::OsString],
        create: bool,
    ) -> io::Result<Option<DirectoryChain<'_>>> {
        DirectoryChain::walk(&self.root, &self.boundary, names, create)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    kind: nix::libc::mode_t,
}

impl Identity {
    fn read(stat: &FileStat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            kind: stat.st_mode & SFlag::S_IFMT.bits(),
        }
    }

    fn of(file: &File) -> io::Result<Self> {
        Ok(Self::read(&fstat(file).map_err(nix_io_error)?))
    }
}

fn entry_stat(parent: &File, name: &OsStr) -> io::Result<Option<FileStat>> {
    match fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(nix_io_error(error)),
    }
}

fn verify_identity(parent: &File, name: &OsStr, file: &File, expected: Identity) -> io::Result<()> {
    let current = entry_stat(parent, name)?.map(|stat| Identity::read(&stat));
    if Identity::of(file)? != expected || current != Some(expected) {
        return Err(invalid("projection entry identity changed"));
    }
    Ok(())
}

fn require_regular(stat: &FileStat) -> io::Result<()> {
    if stat.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() {
        return Err(invalid("projection destination is not a regular file"));
    }
    Ok(())
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "projection relative path is empty",
    )
}
