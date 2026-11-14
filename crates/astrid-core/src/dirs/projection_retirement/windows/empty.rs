//! Selected empty-subtree admission and retained-parent NTFS fences.

use super::super::{RetirementEntryKind, SelectedEntryChecker};
use super::{
    AsRawHandle, DeletionHooks, DirectoryIdentity, File, OsStr, Path, PathBuf, PlannedEntry,
    PreparedProjectionRetirement, RetirementMode, SelectedDirectories, delete_inventory,
    file_id_identity, invalid, io, list_child_entries, open_child_directory_for_capture,
    open_child_file_for_identity, require_identity,
};
use crate::platform_fs::windows::directory_capability::open_directory_flush_relative;
use std::os::windows::io::AsHandle as _;

impl PreparedProjectionRetirement {
    /// Remove only selected directory subtrees, preserving the captured remainder.
    ///
    /// Selection must be disjoint normal relative directories. Absent targets
    /// permit retry. Complete selected-file empty admission precedes any fence
    /// or unlink; no size queries are added to ordinary preparation/full retire.
    /// The caller owns durable authorization and catalog directory-marker policy.
    ///
    /// The authorizer receives every selected captured directory and file,
    /// including selected roots, as a borrowed HOME-relative path. All
    /// callbacks finish before the first fence/unlink; errors propagate.
    ///
    /// # Errors
    /// Returns an error for nonempty admission, changed inventory/identity,
    /// wrong engine volume/home, unsafe namespace or failed NTFS fences/delete.
    /// Late failure may leave earlier selected empty files removed; keep intent.
    /// Fresh size/namespace checks are point-in-time, not writer exclusion.
    pub fn retire_empty_subtrees(
        self,
        expected_volume: &File,
        selected: &[PathBuf],
        mut authorize: impl FnMut(&Path, RetirementEntryKind) -> io::Result<()>,
    ) -> io::Result<()> {
        self.retire_empty_with_hooks(
            expected_volume,
            selected,
            &mut authorize,
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        )
    }

    fn retire_empty_with_hooks(
        self,
        expected_volume: &File,
        selected: &[PathBuf],
        authorize: &mut dyn FnMut(&Path, RetirementEntryKind) -> io::Result<()>,
        before_unlink: &mut impl FnMut(&Path) -> io::Result<()>,
        before_sync: &mut impl FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let selected = SelectedDirectories::parse(selected)?;
        let mode = selected.mode();
        let expected = file_id_identity(expected_volume)?;
        self.require_bindings(expected)?;
        validate_targets(&self.inventory, &selected, &self.path)?;
        let mut admission = SelectedEntryChecker {
            home: &self.path,
            authorize,
        };
        // Identity was captured by prepare. Empty admission is a selected-only
        // stage here, using live FILE_READ_ATTRIBUTES handles, not listing EOF.
        validate_scope(
            self.root.file(),
            &self.path,
            &self.inventory,
            mode,
            false,
            Some(&mut admission),
        )?;
        self.require_bindings(expected)?;
        let mut hooks = DeletionHooks {
            before_unlink,
            sync_retained: |directory: &File, containing: Option<(&File, &OsStr)>, path: &Path| {
                self.require_bindings(expected)?;
                before_sync(path)?;
                match containing {
                    Some((parent, name)) => open_directory_flush_relative(
                        parent.as_handle(),
                        name,
                        directory.as_handle(),
                    )?
                    .flush()?,
                    None => self.root.flush_namespace()?,
                }
                self.require_bindings(expected)
            },
        };
        delete_inventory(
            self.root.file(),
            &self.path,
            &self.inventory,
            true,
            mode,
            None,
            &mut hooks,
        )?;
        self.require_bindings(expected)?;
        validate_scope(
            self.root.file(),
            &self.path,
            &self.inventory,
            mode,
            true,
            None,
        )?;
        self.require_bindings(expected)
    }

    fn require_bindings(&self, expected: DirectoryIdentity) -> io::Result<()> {
        self.require_root()?;
        self.require_volume(Some(expected))?;
        self.require_volume_current(Some(expected))
    }
}

fn validate_targets(
    inventory: &[PlannedEntry],
    selected: &SelectedDirectories,
    path: &Path,
) -> io::Result<()> {
    for (name, selection) in selected.children() {
        let Some(planned) = inventory
            .binary_search_by(|entry| entry.name.cmp(name))
            .ok()
            .map(|index| &inventory[index])
        else {
            continue;
        };
        if !planned.is_directory {
            return Err(invalid(
                &path.join(name),
                "selected path is obstructed by a file",
            ));
        }
        if selection.mode().partial() {
            validate_targets(&planned.children, selection, &path.join(name))?;
        }
    }
    Ok(())
}

// Only selected scopes and retained ancestors are revisited. Every immediate
// sibling name and FileId remains bound; unaffected descendant trees are not
// re-walked or claimed immutable against external writers.
pub(super) fn validate_scope(
    parent: &File,
    path: &Path,
    inventory: &[PlannedEntry],
    mode: RetirementMode<'_>,
    after: bool,
    mut admission: Option<&mut SelectedEntryChecker<'_>>,
) -> io::Result<()> {
    let expected = inventory
        .iter()
        .filter(|entry| !(after && mode.child(&entry.name).removes()))
        .collect::<Vec<_>>();
    let listed = list_child_entries(parent)?;
    if !listed
        .iter()
        .map(|entry| &entry.name)
        .eq(expected.iter().map(|entry| &entry.name))
    {
        return Err(invalid(path, "selected retirement inventory changed"));
    }
    let parent = parent.as_raw_handle().cast();
    for (current, planned) in listed.iter().zip(expected) {
        let child_path = path.join(&planned.name);
        require_identity(planned.identity, current.identity, &child_path)?;
        if planned.is_directory != current.is_directory {
            return Err(invalid(&child_path, "selected retirement type changed"));
        }
        let operation = mode.child(&planned.name);
        if planned.is_directory {
            let (directory, identity) = open_child_directory_for_capture(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            if operation.empty()
                && let Some(checker) = admission.as_deref_mut()
            {
                checker.check(&child_path, RetirementEntryKind::Directory)?;
            }
            if operation.visits() {
                validate_scope(
                    &directory,
                    &child_path,
                    &planned.children,
                    operation,
                    after,
                    admission.as_deref_mut(),
                )?;
            }
        } else {
            let (file, identity) = open_child_file_for_identity(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            if operation.partial() {
                return Err(invalid(&child_path, "selected ancestor is not a directory"));
            }
            if operation.empty() && file.metadata()?.len() != 0 {
                return Err(invalid(&child_path, "selected file is not empty"));
            }
            if operation.empty()
                && let Some(checker) = admission.as_deref_mut()
            {
                checker.check(&child_path, RetirementEntryKind::File)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
