//! Cleanup of captured private snapshot workspaces, independent of their name.

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
    database: Option<PrivateDirectoryIdentity>,
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
        let database = child
            .contains(Path::new("database"))?
            .then(|| child.open_child(Path::new("database")))
            .transpose()?
            .map(|database| database.identity);
        Ok(Self {
            parent,
            name,
            identity: child.identity,
            database,
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

    /// Remove the copied database beneath its exclusively owned private outer
    /// workspace. This is not authority to retire an operator's source tree.
    pub(in crate::principal_state) fn remove(self) -> StorageResult<()> {
        let directory = self.directory()?;
        // The outer workspace contains only our database child. Refuse foreign
        // entries before any deletion rather than adopting more cleanup scope.
        if directory.entries()?.iter().any(|name| name != "database") {
            return Err(connection(
                "captured snapshot workspace contains an unexpected entry".to_owned(),
            ));
        }
        // Validate the whole copy before unlinking. The retained private outer
        // capability owns traversal; an ambient path never becomes authority.
        validate(&directory)?;
        self.directory()?;
        self.remove_database(&directory)?;
        directory.sync()?;
        drop(directory);
        self.verify_empty()?;
        self.unlink_empty()
    }

    fn remove_database(&self, outer: &PrivateDirectory) -> StorageResult<()> {
        let name = Path::new("database");
        let Some(expected) = self.database else {
            if outer.contains(name)? {
                return Err(connection(
                    "uncaptured snapshot database appeared".to_owned(),
                ));
            }
            return Ok(());
        };
        let database = outer.open_child(name)?;
        if database.identity != expected || expected.volume != self.identity.volume {
            return Err(connection(
                "captured snapshot database was replaced".to_owned(),
            ));
        }
        remove_contents(&database, self.identity)?;
        database.sync()?;
        drop(database);
        // Release the child's Windows handle before empty-only removal, while
        // refusing an already replaced child before deleting its name.
        let confirmation = outer.open_child(name)?;
        if confirmation.identity != expected || !confirmation.entries()?.is_empty() {
            return Err(connection("captured snapshot database changed".to_owned()));
        }
        drop(confirmation);
        outer.remove_directory(name)
    }

    fn verify_empty(&self) -> StorageResult<()> {
        let directory = self.directory()?;
        if !directory.entries()?.is_empty() {
            return Err(connection(
                "captured snapshot workspace is not empty".to_owned(),
            ));
        }
        Ok(())
    }

    fn unlink_empty(self) -> StorageResult<()> {
        // Windows requires releasing the child directory handle before rmdir.
        // The atomic empty-only operation cannot move or delete a nonempty
        // replacement that appears after verify_empty. Never rename a late
        // replacement into a new private name merely to discover its identity.
        // No portable identity-conditioned rmdir exists: an empty replacement
        // in this final window is indistinguishable. The original workspace
        // name was created exclusively with private access; this is copy cleanup, not
        // a durable absence claim for operator data.
        self.parent.remove_directory(Path::new(&self.name))?;
        self.parent.sync()
    }
}

fn validate(directory: &PrivateDirectory) -> StorageResult<()> {
    astrid_core::dirs::validate_legacy_source_tree(&directory.path)
        .map_err(|error| connection(format!("validate captured retirement: {error}")))?;
    // The read-only platform probe uses paths for mount detection. Rebind the
    // path after that probe; it must still name the capability we will traverse.
    directory.confirm_path_binding()
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

#[cfg(not(windows))]
pub(in crate::principal_state) fn validate_retirement_tree(
    directory: &PrivateDirectory,
) -> StorageResult<()> {
    validate(directory)
}

pub(in crate::principal_state) fn remove_retirement_contents(
    directory: &PrivateDirectory,
) -> StorageResult<()> {
    remove_contents(directory, directory.identity)
}

#[cfg(test)]
mod tests;
