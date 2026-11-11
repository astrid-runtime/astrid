//! Descriptor-relative projection operations with one explicit hardware fence.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;

use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, SFlag, fstat, fstatat};
use nix::unistd::fsync;

use super::RelativePath;
use crate::platform_fs::{MountBoundary, StagingScope, nix_io_error};

mod anchor;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod hooks;
mod inspect;
#[cfg(all(test, target_os = "linux"))]
mod mount_tests;
#[cfg(test)]
mod tests;
mod write;

use anchor::{DirectoryChain, Root, WalkPolicy};

pub(super) use inspect::Inspection;

pub(super) struct Projection {
    root: Root,
    boundary: MountBoundary,
    staging_scope: Option<StagingScope>,
    pending_temporary: RefCell<Option<write::Temporary>>,
}

impl Projection {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_optional_staging(path, None)
    }

    pub(super) fn open_with_staging(path: &Path, scope: StagingScope) -> io::Result<Self> {
        Self::open_with_optional_staging(path, Some(scope))
    }

    fn open_with_optional_staging(
        path: &Path,
        staging_scope: Option<StagingScope>,
    ) -> io::Result<Self> {
        let root = Root::open(path)?;
        let boundary = MountBoundary::new(&root.file)?;
        let projection = Self {
            root,
            boundary,
            staging_scope,
            pending_temporary: RefCell::new(None),
        };
        let preparation = (|| {
            if anchor::make_private_directory(&projection.root.file)? {
                fsync(&projection.root.file).map_err(nix_io_error)?;
                #[cfg(test)]
                hooks::after(hooks::Event::RootRepairSynced)?;
            }
            projection.root.validate(&projection.boundary)
        })();
        if let Err(error) = preparation {
            // Repair may already have changed metadata. The caller cannot own
            // a failed constructor, so fence the captured root before returning.
            return Err(with_fence_error(error, projection.sync()));
        }
        Ok(projection)
    }

    pub(super) fn snapshot_to(
        &self,
        relative: &RelativePath,
        sink: &mut dyn io::Write,
    ) -> io::Result<Option<u64>> {
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) = self.directories(parents, WalkPolicy::Repair)? else {
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
        let length = io::copy(&mut file, sink)?;
        verify_identity(parent, name, &file, Identity::read(&expected))?;
        chain.validate(&self.boundary)?;
        Ok(Some(length))
    }

    pub(super) fn ensure_directory(&self, relative: &RelativePath) -> io::Result<()> {
        let chain = self
            .directories(&relative.0, WalkPolicy::Create)?
            .ok_or_else(invalid_path)?;
        chain.validate(&self.boundary)
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        let cleanup = self.cleanup_temporary();
        // Always fence the captured root, including after cleanup or privacy
        // repair failure. Failed cleanup must still prevent successful return.
        let fence = self.sync_root();
        match cleanup {
            Ok(()) => fence,
            Err(error) => Err(with_fence_error(error, fence)),
        }
    }

    fn sync_root(&self) -> io::Result<()> {
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
        policy: WalkPolicy,
    ) -> io::Result<Option<DirectoryChain<'_>>> {
        DirectoryChain::walk(&self.root, &self.boundary, names, policy)
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

fn with_fence_error(error: io::Error, fence: io::Result<()>) -> io::Error {
    match fence {
        Ok(()) => error,
        Err(fence) => io::Error::new(
            error.kind(),
            format!("{error}; captured-root durability fence failed: {fence}"),
        ),
    }
}
