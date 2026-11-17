//! A shareable captured root: native raw-handle guards are operation-local.

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
        if file_identity(&file)?.volume != file_identity(&self.file)?.volume {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "append crosses a volume boundary",
            ));
        }
        parent.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        root.verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        // Repeat the absolute identity observation before returning authority.
        TrustedPathGuard::capture_from_file(&self.absolute, &self.file)?
            .verify_contract(BoundaryContract::ExactPrivateDirectory)?;
        Ok(file)
    }
}
