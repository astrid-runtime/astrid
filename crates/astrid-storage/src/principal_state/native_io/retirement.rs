//! Captured directory authority for legacy cleanup, independent of its name.

use super::{PrivateDirectory, PrivateDirectoryIdentity, connection};
use crate::StorageResult;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A directory identity and its containing capability, never a deletable path.
/// The child handle is reopened only while needed: Windows directory handles
/// do not share deletion, so retaining one across a rename would block it.
pub(in crate::principal_state) struct CapturedDirectory {
    parent: PrivateDirectory,
    name: OsString,
    identity: PrivateDirectoryIdentity,
    path: PathBuf,
}

impl CapturedDirectory {
    pub(in crate::principal_state) fn open(path: &Path) -> StorageResult<Self> {
        let parent = PrivateDirectory::open(
            path.parent()
                .ok_or_else(|| connection("captured directory has no parent".to_owned()))?,
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| connection("captured directory has no child name".to_owned()))?
            .to_os_string();
        let child = parent.open_child(Path::new(&name))?;
        Ok(Self {
            parent,
            name,
            identity: child.identity,
            path: path.to_path_buf(),
        })
    }

    pub(in crate::principal_state) fn path(&self) -> &Path {
        &self.path
    }

    pub(in crate::principal_state) fn directory(&self) -> StorageResult<PrivateDirectory> {
        let child = self.parent.open_child(Path::new(&self.name))?;
        if child.identity != self.identity {
            return Err(connection(format!(
                "captured directory {} was replaced",
                self.path.display()
            )));
        }
        Ok(child)
    }

    pub(in crate::principal_state) fn remove(self) -> StorageResult<()> {
        // Validate the entire tree before the first unlink, preserving the
        // existing special-file and mount refusal. Then use the captured fd
        // for every traversal: the ambient path never becomes delete authority.
        let directory = self.directory()?;
        validate(&directory)?;
        self.directory()?;
        remove_contents(&directory, self.identity)?;
        directory.sync()?;
        drop(directory);
        self.stage_empty()?.remove_empty()
    }

    fn stage_empty(self) -> StorageResult<Self> {
        let directory = self.directory()?;
        if !directory.entries()?.is_empty() {
            return Err(connection(
                "captured retirement directory is not empty".to_owned(),
            ));
        }
        drop(directory);
        // Remove only a fresh private name, never the caller-visible name that
        // another owner can reuse after the verified directory moves away.
        let name = OsString::from(format!(".astrid-retired-{}", uuid::Uuid::new_v4()));
        let installed =
            self.parent
                .rename_child_to(Path::new(&self.name), &self.parent, Path::new(&name))?;
        if installed.identity != self.identity {
            return Err(connection(format!(
                "retain replaced retirement directory at {}",
                self.parent.path.join(&name).display()
            )));
        }
        drop(installed);
        let path = self.parent.path.join(&name);
        self.parent.sync().map_err(|error| {
            connection(format!(
                "retain staged retirement {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self {
            parent: self.parent,
            name,
            identity: self.identity,
            path,
        })
    }

    fn remove_empty(self) -> StorageResult<()> {
        let confirmation = self.directory()?;
        drop(confirmation);
        // There is no portable identity-conditioned rmdir. The remaining
        // empty-entry unlink targets our exclusive, unguessable staging name
        // inside the retained parent; it never targets the original name.
        self.parent.remove_directory(Path::new(&self.name))?;
        self.parent.sync()
    }
}

fn validate(directory: &PrivateDirectory) -> StorageResult<()> {
    astrid_core::dirs::validate_legacy_source_tree(&directory.path)
        .map_err(|error| connection(format!("validate captured retirement: {error}")))?;
    // The read-only platform probe uses paths for mount detection. Rebind the
    // path after that probe; it must still name the capability we will traverse.
    let confirmation = PrivateDirectory::open(&directory.path)?;
    if confirmation.identity != directory.identity {
        return Err(connection(
            "captured retirement path changed during validation".to_owned(),
        ));
    }
    Ok(())
}

fn remove_contents(
    directory: &PrivateDirectory,
    root: PrivateDirectoryIdentity,
) -> StorageResult<()> {
    for name in directory.entries()? {
        let name = Path::new(&name);
        if directory.entry_is_directory(name)? {
            let child = directory.open_child(name)?;
            if child.identity.volume != root.volume {
                return Err(connection(
                    "captured retirement crosses a filesystem boundary".to_owned(),
                ));
            }
            validate(&child)?;
            remove_contents(&child, root)?;
            child.sync()?;
            let expected = child.identity;
            drop(child);
            let confirmation = directory.open_child(name)?;
            if confirmation.identity != expected {
                return Err(connection(
                    "captured retirement child was replaced".to_owned(),
                ));
            }
            drop(confirmation);
            directory.remove_directory(name)?;
        } else {
            // No-follow regular-file open refuses redirects and special files.
            // Unlink is parent-relative and never follows a replacement link.
            let file = directory.open_file(name)?;
            if super::private_file_identity(&file)?.volume != root.volume {
                return Err(connection(
                    "captured retirement file crosses a filesystem boundary".to_owned(),
                ));
            }
            drop(file);
            directory.remove_file(name)?;
        }
    }
    directory.sync()
}

#[cfg(test)]
mod tests;
