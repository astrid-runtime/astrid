//! Read-only root-bound matching without create or privacy repair.

use std::fs::File;
use std::io;

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

use super::RelativePath;
use super::anchor::{DirectoryChain, Root, WalkPolicy};
use super::{
    Identity, MountBoundary, entry_stat, invalid_path, nix_io_error, require_regular,
    verify_identity,
};

pub(in crate::platform_fs::private_projection) struct Inspection {
    root: Root,
    boundary: MountBoundary,
}

impl Inspection {
    pub(in crate::platform_fs::private_projection) fn capture_append_root(
        &self,
    ) -> io::Result<super::AppendRoot> {
        super::AppendRoot::capture(&self.root, &self.boundary)
    }

    pub(in crate::platform_fs::private_projection) fn try_open(
        path: &std::path::Path,
    ) -> io::Result<Self> {
        let root = Root::open(path)?;
        let boundary = MountBoundary::new(&root.file)?;
        // Matching must never repair root privacy before durable restoration intent.
        root.validate(&boundary)?;
        Ok(Self { root, boundary })
    }

    pub(in crate::platform_fs::private_projection) fn open_writer(
        &self,
    ) -> io::Result<super::Projection> {
        self.confirm_absolute_root()?;
        #[cfg(test)]
        super::hooks::after(super::hooks::Event::BeforeBoundWriterClone)?;
        let root = self.root.try_clone()?;
        // Clone descriptors, never recapture a replacement at the same path.
        // The original mount proof must still accept the captured authority.
        root.validate_absolute(&self.boundary)?;
        self.boundary.validate(&root.file)?;
        let boundary = MountBoundary::new(&root.file)?;
        Ok(super::Projection {
            root,
            boundary,
            staging_scope: None,
            pending_temporary: std::cell::RefCell::new(None),
            last_directories: super::LastDirectoryChain::default(),
        })
    }

    pub(in crate::platform_fs::private_projection) fn matches_private_directory(
        &self,
        relative: &RelativePath,
    ) -> io::Result<bool> {
        match DirectoryChain::walk(&self.root, &self.boundary, &relative.0, WalkPolicy::Inspect) {
            Ok(Some(chain)) => {
                chain.validate(&self.boundary)?;
                Ok(true)
            },
            Ok(None) => Ok(false),
            Err(error) if is_non_match(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(in crate::platform_fs::private_projection) fn matches_private_file_from(
        &self,
        relative: &RelativePath,
        length: u64,
        expected: &mut dyn io::Read,
    ) -> io::Result<bool> {
        match self.read_matching_private_file(relative, length, expected) {
            Ok(matches) => Ok(matches),
            Err(error) if is_non_match(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(in crate::platform_fs::private_projection) fn confirm_absolute_root(
        &self,
    ) -> io::Result<()> {
        self.root.validate_absolute(&self.boundary)
    }

    fn read_matching_private_file(
        &self,
        relative: &RelativePath,
        length: u64,
        bytes: &mut dyn io::Read,
    ) -> io::Result<bool> {
        let (name, parents) = relative.0.split_last().ok_or_else(invalid_path)?;
        let Some(chain) =
            DirectoryChain::walk(&self.root, &self.boundary, parents, WalkPolicy::Inspect)?
        else {
            return Ok(false);
        };
        let parent = chain.directory();
        let Some(expected) = entry_stat(parent, name)? else {
            chain.validate(&self.boundary)?;
            return Ok(false);
        };
        require_regular(&expected)?;
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let mut file = File::from(
            openat(parent, name.as_os_str(), flags, Mode::empty()).map_err(nix_io_error)?,
        );
        verify_identity(parent, name, &file, Identity::read(&expected))?;
        self.boundary.validate(&file)?;
        super::write::require_private_file(&file)?;
        let matches = super::super::compare::matches_file_from(&mut file, length, bytes)?;
        verify_identity(parent, name, &file, Identity::read(&expected))?;
        super::write::require_private_file(&file)?;
        chain.validate(&self.boundary)?;
        Ok(matches)
    }
}

fn is_non_match(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
    )
}
