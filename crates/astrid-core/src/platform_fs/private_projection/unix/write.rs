//! Atomic replacement and rollback within captured directory authority.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write as _};

use nix::fcntl::{OFlag, openat, renameat};
use nix::sys::stat::{Mode, fchmod, fstat};
use nix::unistd::{UnlinkatFlags, fsync, getuid, unlinkat};

use super::anchor::WalkPolicy;
use super::{
    Identity, MountBoundary, Projection, RelativePath, entry_stat, invalid, invalid_path,
    nix_io_error, require_regular, verify_identity,
};

impl Projection {
    pub(in super::super) fn write(&self, relative: &RelativePath, bytes: &[u8]) -> io::Result<()> {
        self.cleanup_temporary()?;
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let chain = self
            .directories(parents, WalkPolicy::Create)?
            .ok_or_else(invalid_path)?;
        let parent = chain.directory();
        let previous = Existing::capture(parent, name, &self.boundary)?;
        let mut temporary = Temporary::create(parent, self.staging_scope)?;
        let result = (|| {
            temporary.make_private(&self.boundary)?;
            temporary.file.write_all(bytes)?;
            fsync(&temporary.file).map_err(nix_io_error)?;
            #[cfg(test)]
            super::hooks::after(super::hooks::Event::FileSynced)?;
            #[cfg(test)]
            super::hooks::after(super::hooks::Event::BeforeRename)?;
            chain.validate(&self.boundary)?;
            previous.validate(parent, name, &self.boundary)?;
            verify_identity(parent, &temporary.name, &temporary.file, temporary.identity)?;
            require_private_file(&temporary.file)?;
            renameat(parent, temporary.name.as_os_str(), parent, name.as_os_str())
                .map_err(nix_io_error)?;
            verify_identity(parent, name, &temporary.file, temporary.identity)?;
            require_private_file(&temporary.file)?;
            fsync(parent).map_err(nix_io_error)?;
            #[cfg(test)]
            super::hooks::after(super::hooks::Event::ParentSynced)?;
            chain.validate(&self.boundary)
        })();
        if let Err(error) = result {
            if let Err(cleanup) = temporary.cleanup(&self.boundary) {
                // One failed write owns at most one temporary. Later mutations
                // must discharge it before creating another rollback obligation.
                *self.pending_temporary.borrow_mut() = Some(temporary);
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; temporary cleanup failed: {cleanup}"),
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn cleanup_temporary(&self) -> io::Result<()> {
        let mut pending = self.pending_temporary.borrow_mut();
        if let Some(temporary) = pending.as_ref() {
            temporary.cleanup(&self.boundary)?;
        }
        pending.take();
        Ok(())
    }

    pub(in super::super) fn remove(&self, relative: &RelativePath) -> io::Result<()> {
        self.cleanup_temporary()?;
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) = self.directories(parents, WalkPolicy::Repair)? else {
            return Ok(());
        };
        let parent = chain.directory();
        let existing = Existing::capture(parent, name, &self.boundary)?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::BeforeUnlink)?;
        chain.validate(&self.boundary)?;
        existing.validate(parent, name, &self.boundary)?;
        if matches!(existing, Existing::Absent) {
            return Ok(());
        }
        unlinkat(parent, name.as_os_str(), UnlinkatFlags::NoRemoveDir).map_err(nix_io_error)?;
        fsync(parent).map_err(nix_io_error)?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::ParentSynced)?;
        chain.validate(&self.boundary)
    }

    /// Remove a durable-scope staging temporary with a private-file contract.
    ///
    /// Unlike [`Self::remove`], this path rejects ordinary/world-readable files
    /// and requires the basename to embed `scope`. Rollback must keep using
    /// [`Self::remove`] so prior host generations remain restorable.
    pub(in super::super) fn remove_staging(
        &self,
        relative: &RelativePath,
        scope: crate::platform_fs::StagingScope,
    ) -> io::Result<()> {
        let Some(bound) = self.staging_scope else {
            return Err(invalid(
                "staging removal requires a bound restoration scope",
            ));
        };
        if bound != scope {
            return Err(invalid(
                "staging removal scope does not match the bound writer",
            ));
        }
        let (name, _) = relative.0.split_last().ok_or_else(invalid_path)?;
        if !scope.matches_temporary_basename(name) {
            return Err(invalid(
                "staging removal name is outside the durable restoration scope",
            ));
        }
        self.remove_authorized_private_leaf(relative)
    }

    /// Remove a private single-link leaf under caller-established authority.
    ///
    /// Used for legacy etc sentinel cleanup after the receipt/etc gate has
    /// already classified names. Still enforces private ownership through the
    /// captured rooted unlink; never used for ordinary rollback.
    pub(in super::super) fn remove_authorized_private_leaf(
        &self,
        relative: &RelativePath,
    ) -> io::Result<()> {
        self.cleanup_temporary()?;
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) = self.directories(parents, WalkPolicy::Repair)? else {
            return Ok(());
        };
        let parent = chain.directory();
        let Some(stat) = entry_stat(parent, name)? else {
            chain.validate(&self.boundary)?;
            return Ok(());
        };
        require_regular(&stat)?;
        let identity = Identity::read(&stat);
        self.boundary.validate_device(stat.st_dev)?;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let file = File::from(
            openat(parent, name.as_os_str(), flags, Mode::empty()).map_err(nix_io_error)?,
        );
        verify_identity(parent, name, &file, identity)?;
        self.boundary.validate(&file)?;
        require_private_file(&file)?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::BeforeUnlink)?;
        chain.validate(&self.boundary)?;
        verify_identity(parent, name, &file, identity)?;
        require_private_file(&file)?;
        self.boundary.validate(&file)?;
        unlinkat(parent, name.as_os_str(), UnlinkatFlags::NoRemoveDir).map_err(nix_io_error)?;
        fsync(parent).map_err(nix_io_error)?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::ParentSynced)?;
        chain.validate(&self.boundary)
    }
}

enum Existing {
    Absent,
    Present {
        identity: Identity,
        #[cfg(target_os = "linux")]
        descriptor: File,
    },
}

impl Existing {
    fn capture(parent: &File, name: &OsStr, boundary: &MountBoundary) -> io::Result<Self> {
        let Some(stat) = entry_stat(parent, name)? else {
            return Ok(Self::Absent);
        };
        require_regular(&stat)?;
        let identity = Identity::read(&stat);
        boundary.validate_device(stat.st_dev)?;
        #[cfg(target_os = "linux")]
        {
            let flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
            let descriptor = File::from(
                openat(parent, name.as_os_str(), flags, Mode::empty()).map_err(nix_io_error)?,
            );
            verify_identity(parent, name, &descriptor, identity)?;
            boundary.validate(&descriptor)?;
            Ok(Self::Present {
                identity,
                descriptor,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self::Present { identity })
        }
    }

    fn validate(&self, parent: &File, name: &OsStr, boundary: &MountBoundary) -> io::Result<()> {
        let current = entry_stat(parent, name)?;
        match (self, current) {
            (Self::Absent, None) => Ok(()),
            (Self::Present { identity, .. }, Some(stat)) if Identity::read(&stat) == *identity => {
                boundary.validate_device(stat.st_dev)?;
                #[cfg(target_os = "linux")]
                if let Self::Present { descriptor, .. } = self {
                    verify_identity(parent, name, descriptor, *identity)?;
                    boundary.validate(descriptor)?;
                    // Reopening the live name also detects a same-inode bind
                    // mount installed after the original descriptor opened.
                    let flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
                    let current = File::from(
                        openat(parent, name.as_os_str(), flags, Mode::empty())
                            .map_err(nix_io_error)?,
                    );
                    verify_identity(parent, name, &current, *identity)?;
                    boundary.validate(&current)?;
                }
                Ok(())
            },
            _ => Err(invalid("projection destination changed before mutation")),
        }
    }
}

pub(super) struct Temporary {
    parent: File,
    name: OsString,
    file: File,
    identity: Identity,
}

impl Temporary {
    fn create(
        parent: &File,
        staging_scope: Option<crate::platform_fs::StagingScope>,
    ) -> io::Result<Self> {
        // Capture cleanup authority before creating any entry.
        let parent = parent.try_clone()?;
        let name = OsString::from(match staging_scope {
            Some(scope) => scope.temporary_basename(),
            None => format!(".astrid-private-{}", uuid::Uuid::new_v4().simple()),
        });
        let flags = OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_EXCL
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK;
        let file = File::from(
            openat(
                &parent,
                name.as_os_str(),
                flags,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(nix_io_error)?,
        );
        let identity = Identity::of(&file)?;
        Ok(Self {
            parent,
            name,
            file,
            identity,
        })
    }

    fn make_private(&self, boundary: &MountBoundary) -> io::Result<()> {
        fchmod(&self.file, Mode::from_bits_truncate(0o600)).map_err(nix_io_error)?;
        #[cfg(target_os = "macos")]
        crate::platform_fs::macos_acl::restrict(&self.file)?;
        boundary.validate(&self.file)?;
        require_private_file(&self.file)
    }

    fn cleanup(&self, boundary: &MountBoundary) -> io::Result<()> {
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::BeforeTemporaryCleanup)?;
        let parent = &self.parent;
        boundary.validate(parent)?;
        let Some(stat) = entry_stat(parent, &self.name)? else {
            // An earlier unlink can have succeeded before its fsync failed.
            fsync(parent).map_err(nix_io_error)?;
            return Ok(());
        };
        if Identity::read(&stat) != self.identity {
            return Err(invalid("temporary projection entry was replaced"));
        }
        boundary.validate(&self.file)?;
        unlinkat(parent, self.name.as_os_str(), UnlinkatFlags::NoRemoveDir)
            .map_err(nix_io_error)?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::TemporaryUnlinked)?;
        fsync(parent).map_err(nix_io_error)
    }
}

pub(super) fn require_private_file(file: &File) -> io::Result<()> {
    let stat = fstat(file).map_err(nix_io_error)?;
    require_regular(&stat)?;
    if stat.st_uid != getuid().as_raw() || stat.st_mode & 0o777 != 0o600 || stat.st_nlink != 1 {
        return Err(invalid("projection file is not private with a single link"));
    }
    #[cfg(target_os = "macos")]
    crate::platform_fs::macos_acl::validate(file)?;
    Ok(())
}
