//! A shareable captured root: native raw-handle guards are operation-local.

mod confirmation;

use super::super::io::open_guarded_private_append;
use super::super::path::{BoundaryContract, TrustedPathGuard, file_identity};
use super::super::prelude::*;
use super::split_relative;

pub(in crate::platform_fs) struct AppendRoot {
    file: File,
    absolute: PathBuf,
}

impl AppendRoot {
    pub(super) fn captured(file: File, absolute: PathBuf) -> Self {
        Self { file, absolute }
    }

    pub(in crate::platform_fs) fn open_private_append(
        &self,
        relative: &[OsString],
    ) -> io::Result<File> {
        // capture_component compares the public full identity before reusing
        // this File; it cannot adopt a replacement at the original spelling.
        let root = TrustedPathGuard::capture_from_file(&self.absolute, &self.file)?;
        root.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        let (dirs, name) = split_relative(relative)?;
        let descendant = if dirs.is_empty() {
            None
        } else {
            Some(root.capture_descendant_directory(dirs, true)?)
        };
        let parent = descendant.as_ref().unwrap_or(&root);
        let file = open_guarded_private_append(parent, name)?;
        confirmation::finish(
            &mut NativeChecks,
            file,
            &self.file,
            parent,
            &root,
            &self.absolute,
        )
        .map_err(|error| match error {
            confirmation::Failure::Native(error) => error,
            confirmation::Failure::CrossVolume => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "append crosses a volume boundary",
            ),
        })
    }
}

struct NativeChecks;

impl confirmation::Checks<File, TrustedPathGuard, PathBuf, io::Error> for NativeChecks {
    fn volume(&mut self, handle: &File) -> io::Result<u32> {
        Ok(file_identity(handle)?.volume)
    }

    fn directory(&mut self, guard: &TrustedPathGuard) -> Option<io::Error> {
        guard
            .verify_contract(BoundaryContract::ExactPrivateDirectory)
            .err()
    }

    fn recapture(&mut self, path: &PathBuf, root: &File) -> Option<io::Error> {
        TrustedPathGuard::capture_from_file(path, root)
            .and_then(|guard| guard.verify_contract(BoundaryContract::ExactPrivateDirectory))
            .err()
    }
}
