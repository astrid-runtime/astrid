//! Descriptor-relative projection operations with one explicit hardware fence.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(test)]
use hooks::query_file_stat as fstat;
use nix::fcntl::{AtFlags, OFlag};
#[cfg(not(test))]
use nix::sys::stat::fstat;
use nix::sys::stat::{FileStat, SFlag, fstatat};
use nix::unistd::fsync;

use super::RelativePath;
use crate::platform_fs::{MountBoundary, StagingScope, nix_io_error};

mod anchor;
#[cfg(test)]
mod failure_tests;
#[cfg(test)]
mod hooks;
mod inspect;
#[cfg(test)]
mod last_chain_tests;
#[cfg(all(test, target_os = "linux"))]
mod mount_tests;
#[cfg(test)]
mod tests;
mod write;

use anchor::{DirectoryChain, LastDirectoryChain, Root, WalkPolicy};

pub(super) use inspect::Inspection;
pub(super) use write::{FileIdentity, Replacement};

pub(super) struct Projection {
    root: Root,
    boundary: MountBoundary,
    staging_scope: Option<StagingScope>,
    pending_temporary: RefCell<Option<write::Temporary>>,
    last_directories: LastDirectoryChain,
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
            last_directories: LastDirectoryChain::default(),
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
        write::snapshot_previous(self, &chain, name, sink)
    }

    pub(super) fn capture_replacement<'a>(
        &'a self,
        relative: &RelativePath,
        sink: &mut dyn io::Write,
    ) -> io::Result<(Replacement<'a>, Option<u64>)> {
        Replacement::capture(self, relative, sink)
    }

    pub(super) fn rollback_publication(
        &self,
        relative: &RelativePath,
        identity: FileIdentity,
        prior: Option<(&mut dyn io::Read, u64)>,
    ) -> io::Result<()> {
        match prior {
            Some((source, length)) => {
                let replacement = Replacement::for_existing(self, relative)?;
                replacement.require_identity(identity)?;
                replacement.write_from(source, length).1
            },
            None => self.remove_expected(relative, Some(identity)),
        }
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
        DirectoryChain::walk_reusing(
            &self.root,
            &self.boundary,
            names,
            policy,
            &self.last_directories,
        )
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

#[cfg(test)]
pub(super) fn take_relative_walks() -> usize {
    anchor::take_relative_walks()
}
#[cfg(test)]
pub(super) fn fail_replacement_fence() -> impl Drop {
    hooks::install(|event| {
        if event == hooks::Event::ParentSynced {
            return Err(io::Error::other("injected postrename fence failure"));
        }
        Ok(())
    })
}
