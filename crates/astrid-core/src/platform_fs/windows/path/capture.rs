//! Capture operation-local guards from a path or a retained append authority.

use super::super::acl::validate_trusted_parent_acl_handle;
use super::super::prelude::*;
use super::{
    LockedPathComponent, TrustedPathGuard, descendant, open_directory_identity,
    open_directory_identity_relative, open_locked_directory, validate_local_absolute_path,
    verification,
};

impl TrustedPathGuard {
    pub(in crate::platform_fs::windows) fn capture(path: &Path) -> io::Result<Self> {
        Self::capture_with_directory(path, None)
    }

    pub(in crate::platform_fs::windows) fn capture_from_file(
        path: &Path,
        file: &File,
    ) -> io::Result<Self> {
        Self::capture_with_directory(path, Some((path, file)))
    }

    pub(super) fn capture_with_directory(
        path: &Path,
        captured: Option<(&Path, &File)>,
    ) -> io::Result<Self> {
        validate_local_absolute_path(path)?;
        let mut components: Vec<LockedPathComponent> = Vec::new();
        let mut current = PathBuf::new();
        let mut rooted = false;
        for component in path.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::RootDir) {
                rooted = true;
            }
            if !rooted {
                continue;
            }
            let metadata = match std::fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "trusted Windows path contains a redirect or non-directory component: {}",
                        current.display()
                    ),
                ));
            }
            let (handle, identity) = if let Some((root, file)) = captured
                && current == root
            {
                verification::capture_component(components.last(), &current, file)?
            } else if let Some(parent) = components.last() {
                open_directory_identity_relative(
                    parent.handle.0,
                    component.as_os_str(),
                    current == path,
                )?
            } else if current == path {
                open_locked_directory(&current)?
            } else {
                open_directory_identity(&current, true)?
            };
            components.push(LockedPathComponent {
                path: current.clone(),
                identity,
                handle,
            });
        }
        if components.last().map(|component| component.path.as_path()) != Some(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "trusted Windows authority boundary does not exist: {}",
                    path.display()
                ),
            ));
        }
        // System ancestors such as the volume root and `Users` deliberately
        // grant limited authority to principals outside Astrid's trust set.
        // They remain open as identity handles while the caller-selected owned
        // directory is the rename-locked ACL authority boundary. Critical
        // child mutations resolve relative to that boundary handle, so an
        // ancestor rename cannot redirect the operation into another tree.
        let result = Self {
            components,
            authority_boundary: path.to_path_buf(),
        };
        validate_trusted_parent_acl_handle(
            result.authority_handle(),
            &result.authority_boundary.display().to_string(),
        )?;
        Ok(result)
    }

    /// Duplicate the final authority handle as a `std::fs::File`.
    ///
    /// Uses `DuplicateHandle(DUPLICATE_SAME_ACCESS)` so the File keeps the
    /// same no-delete sharing that fences ancestor rename while this owner
    /// lives. Does not reopen by path and does not re-query identity.
    pub(in crate::platform_fs::windows) fn duplicate_authority_file(&self) -> io::Result<File> {
        let handle = descendant::duplicate_handle_same_access(self.authority_handle())?;
        Ok(File::from(handle))
    }
}
