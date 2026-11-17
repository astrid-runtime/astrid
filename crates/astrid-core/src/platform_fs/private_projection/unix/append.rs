//! Immutable root authority; per-open chains never enter a shared cache.

use super::anchor::{DirectoryChain, Root, WalkPolicy};
use super::{
    Identity, MountBoundary, RelativePath, entry_stat, fstat, invalid, invalid_path, nix_io_error,
    require_regular, verify_identity,
};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::getuid;
use std::ffi::OsStr;
use std::fs::File;
use std::io;

pub(in crate::platform_fs::private_projection) struct AppendRoot {
    root: Root,
    boundary: MountBoundary,
}

impl AppendRoot {
    pub(super) fn capture(root: &Root, boundary: &MountBoundary) -> io::Result<Self> {
        root.validate_absolute(boundary)?;
        let root = root.try_clone()?;
        boundary.validate(&root.file)?;
        let boundary = MountBoundary::new(&root.file)?;
        Ok(Self { root, boundary })
    }

    pub(in crate::platform_fs::private_projection) fn open_private_append(
        &self,
        relative: &RelativePath,
    ) -> io::Result<File> {
        self.root.validate_absolute(&self.boundary)?;
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let chain = DirectoryChain::walk(&self.root, &self.boundary, parents, WalkPolicy::Append)?
            .ok_or_else(|| invalid("append parent is missing"))?;
        let parent = chain.directory();
        let file = open_leaf(parent, name)?;
        let stat = fstat(&file).map_err(nix_io_error)?;
        require_regular(&stat)?;
        if stat.st_uid != getuid().as_raw() || stat.st_nlink != 1 {
            return Err(invalid("append file is not owned privately with one link"));
        }
        self.boundary.validate(&file)?;
        // Match native private-log repair, through the captured handle rather
        // than reopening an ambient pathname. Never truncate existing bytes.
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(nix_io_error)?;
        #[cfg(target_os = "macos")]
        crate::platform_fs::macos_acl::restrict(&file)?;
        file.sync_all()?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::BeforeAppendReturn)?;
        chain.validate(&self.boundary)?;
        verify_identity(parent, name, &file, Identity::read(&stat))?;
        super::write::require_private_file(&file)?;
        self.boundary.validate(&file)?;
        // A same-inode Linux bind mount can pass fstatat identity while the
        // opened source still names the prior mount. Confirm the live relative
        // object, retaining that observation until the final root check.
        #[cfg(target_os = "linux")]
        let _confirmation = self.confirm_live_leaf(parent, name, Identity::read(&stat))?;
        self.root.validate_absolute(&self.boundary)?;
        Ok(file)
    }

    #[cfg(target_os = "linux")]
    fn confirm_live_leaf(
        &self,
        parent: &File,
        name: &OsStr,
        expected: Identity,
    ) -> io::Result<File> {
        let flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let file = File::from(openat(parent, name, flags, Mode::empty()).map_err(nix_io_error)?);
        require_regular(&fstat(&file).map_err(nix_io_error)?)?;
        verify_identity(parent, name, &file, expected)?;
        self.boundary.validate(&file)?;
        Ok(file)
    }
}

fn open_leaf(parent: &File, name: &OsStr) -> io::Result<File> {
    if entry_stat(parent, name)?.is_some() {
        return open_existing(parent, name);
    }
    let flags = append_flags() | OFlag::O_CREAT | OFlag::O_EXCL;
    match openat(parent, name, flags, Mode::from_bits_truncate(0o600)) {
        Ok(file) => Ok(File::from(file)),
        // Another sink may create the same daily file. Acquire and validate its
        // current identity once; never retry indefinitely or overwrite it.
        Err(nix::errno::Errno::EEXIST) => open_existing(parent, name),
        Err(error) => Err(nix_io_error(error)),
    }
}

fn open_existing(parent: &File, name: &OsStr) -> io::Result<File> {
    let before = entry_stat(parent, name)?.ok_or_else(|| invalid("append leaf disappeared"))?;
    require_regular(&before)?;
    let file =
        File::from(openat(parent, name, append_flags(), Mode::empty()).map_err(nix_io_error)?);
    verify_identity(parent, name, &file, Identity::read(&before))?;
    Ok(file)
}

fn append_flags() -> OFlag {
    OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK
}

#[cfg(test)]
mod tests;
