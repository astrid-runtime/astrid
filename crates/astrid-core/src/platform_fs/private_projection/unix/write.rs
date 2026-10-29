//! Atomic replacement and rollback within captured directory authority.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write as _};

use nix::fcntl::{OFlag, openat, renameat};
use nix::sys::stat::{Mode, fchmod, fstat};
use nix::unistd::{UnlinkatFlags, fsync, getuid, unlinkat};

use super::{
    Identity, MountBoundary, Projection, RelativePath, entry_stat, invalid, invalid_path,
    nix_io_error, require_regular, verify_identity,
};

impl Projection {
    pub(in super::super) fn write(&self, relative: &RelativePath, bytes: &[u8]) -> io::Result<()> {
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let chain = self.directories(parents, true)?.ok_or_else(invalid_path)?;
        let parent = chain.directory();
        let previous = Existing::capture(parent, name, &self.boundary)?;
        let mut temporary = Temporary::create(parent)?;
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
            validate_new_file(&temporary.file)?;
            renameat(parent, temporary.name.as_os_str(), parent, name.as_os_str())
                .map_err(nix_io_error)?;
            verify_identity(parent, name, &temporary.file, temporary.identity)?;
            validate_new_file(&temporary.file)?;
            fsync(parent).map_err(nix_io_error)?;
            #[cfg(test)]
            super::hooks::after(super::hooks::Event::ParentSynced)?;
            chain.validate(&self.boundary)
        })();
        if let Err(error) = result {
            if let Err(cleanup) = temporary.cleanup(parent) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; temporary cleanup failed: {cleanup}"),
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub(in super::super) fn remove(&self, relative: &RelativePath) -> io::Result<()> {
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) = self.directories(parents, false)? else {
            return Ok(());
        };
        let parent = chain.directory();
        let existing = Existing::capture(parent, name, &self.boundary)?;
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
            let descriptor =
                File::from(openat(parent, name, flags, Mode::empty()).map_err(nix_io_error)?);
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
                        openat(parent, name, flags, Mode::empty()).map_err(nix_io_error)?,
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

struct Temporary {
    name: OsString,
    file: File,
    identity: Identity,
}

impl Temporary {
    fn create(parent: &File) -> io::Result<Self> {
        let name = OsString::from(format!(".astrid-private-{}", uuid::Uuid::new_v4().simple()));
        let flags = OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_EXCL
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK;
        let file = File::from(
            openat(
                parent,
                name.as_os_str(),
                flags,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(nix_io_error)?,
        );
        let identity = Identity::of(&file)?;
        Ok(Self {
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
        validate_new_file(&self.file)
    }

    fn cleanup(&self, parent: &File) -> io::Result<()> {
        let Some(stat) = entry_stat(parent, &self.name)? else {
            return Ok(());
        };
        if Identity::read(&stat) != self.identity {
            return Err(invalid("temporary projection entry was replaced"));
        }
        unlinkat(parent, self.name.as_os_str(), UnlinkatFlags::NoRemoveDir)
            .map_err(nix_io_error)?;
        fsync(parent).map_err(nix_io_error)
    }
}

fn validate_new_file(file: &File) -> io::Result<()> {
    let stat = fstat(file).map_err(nix_io_error)?;
    require_regular(&stat)?;
    if stat.st_uid != getuid().as_raw() || stat.st_mode & 0o777 != 0o600 || stat.st_nlink != 1 {
        return Err(invalid(
            "new projection file is not private with a single link",
        ));
    }
    #[cfg(target_os = "macos")]
    crate::platform_fs::macos_acl::validate(file)?;
    Ok(())
}
