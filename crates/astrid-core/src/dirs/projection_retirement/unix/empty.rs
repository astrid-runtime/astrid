//! Selected-empty retirement uses the ordinary captured deletion traversal.

use super::super::{RetirementEntryKind, SelectedEntryChecker};
use super::{
    File, FileStat, Path, PathBuf, PlannedEntry, PreparedProjectionRetirement, RetirementHooks,
    RetirementMode, RootBoundary, SFlag, SelectedDirectories, delete_inventory, entries, fstat,
    invalid, io, open_entry, os_error, require_identity,
};

impl PreparedProjectionRetirement {
    /// Retire only selected directory subtrees after complete empty admission.
    ///
    /// Targets are disjoint normal relative directories; absent targets permit
    /// retry. The caller must authorize every selected name and keep durable
    /// recovery intent. Core does not interpret catalog directory markers.
    /// Retained entries are never mutated; this is not whole-home retirement.
    ///
    /// The authorizer receives every selected captured directory and file,
    /// including selected roots, as a borrowed HOME-relative path. All
    /// callbacks finish before the first fence/unlink; errors propagate.
    ///
    /// # Errors
    /// Fails before the first unlink for invalid selections, nonempty admission,
    /// changed identities/inventories, wrong volume/root or unsafe namespace.
    /// Late failures may leave earlier selected empties removed. Keep intent.
    /// Size and namespace checks are point-in-time, not writer exclusion.
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
            &mut RetirementHooks {
                before_unlink: |_: &Path| Ok(()),
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        )
    }

    fn retire_empty_with_hooks(
        self,
        expected_volume: &File,
        selected: &[PathBuf],
        authorize: &mut dyn FnMut(&Path, RetirementEntryKind) -> io::Result<()>,
        hooks: &mut RetirementHooks<
            impl FnMut(&Path) -> io::Result<()>,
            impl FnMut(&File, &Path) -> io::Result<()>,
        >,
    ) -> io::Result<()> {
        let selected = SelectedDirectories::parse(selected)?;
        let mode = selected.mode();
        let expected = fstat(expected_volume).map_err(os_error)?;
        self.require_root()?;
        self.require_volume(Some(&expected))?;
        validate_targets(&self.inventory, &selected, &self.path)?;
        let mut admission = SelectedEntryChecker {
            home: &self.path,
            authorize,
        };
        // Check every selected file before any earlier selected tree can unlink.
        validate_scope(
            &self.directory,
            &self.path,
            &self.boundary,
            &self.inventory,
            mode,
            false,
            Some(&mut admission),
        )?;
        self.require_root()?;
        self.require_volume(Some(&expected))?;
        let RetirementHooks {
            before_unlink,
            sync_directory,
        } = hooks;
        let mut guarded = RetirementHooks {
            before_unlink: |path: &Path| before_unlink(path),
            sync_directory: |directory: &File, path: &Path| {
                self.require_root()?;
                self.require_volume(Some(&expected))?;
                sync_directory(directory, path)?;
                self.require_root()?;
                self.require_volume(Some(&expected))
            },
        };
        delete_inventory(
            &self.directory,
            &self.path,
            &self.boundary,
            &self.inventory,
            true,
            mode,
            &mut guarded,
        )?;
        self.require_root()?;
        self.require_volume(Some(&expected))?;
        validate_scope(
            &self.directory,
            &self.path,
            &self.boundary,
            &self.inventory,
            mode,
            true,
            None,
        )?;
        self.require_root()?;
        self.require_volume(Some(&expected))
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
        let child_path = path.join(name);
        if SFlag::from_bits_truncate(planned.identity.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
            return Err(invalid(
                &child_path,
                "selected path is obstructed by a file",
            ));
        }
        if selection.mode().empty() {
            require_captured_empty(&planned.children, &child_path)?;
        } else {
            validate_targets(&planned.children, selection, &child_path)?;
        }
    }
    Ok(())
}

fn require_captured_empty(inventory: &[PlannedEntry], path: &Path) -> io::Result<()> {
    for entry in inventory {
        let child = path.join(&entry.name);
        if SFlag::from_bits_truncate(entry.identity.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR {
            require_captured_empty(&entry.children, &child)?;
        } else if entry.identity.st_size != 0 {
            return Err(invalid(&child, "selected file was not empty at capture"));
        }
    }
    Ok(())
}

// Revisit retained ancestors and selected subtrees only. Their complete immediate
// inventories and identities still bind every untouched sibling. Unaffected
// descendant trees are not re-walked or claimed immutable against other writers.
pub(super) fn validate_scope(
    directory: &File,
    path: &Path,
    root: &RootBoundary,
    inventory: &[PlannedEntry],
    mode: RetirementMode<'_>,
    after: bool,
    mut admission: Option<&mut SelectedEntryChecker<'_>>,
) -> io::Result<()> {
    let expected = inventory
        .iter()
        .filter(|entry| !(after && mode.child(&entry.name).removes()))
        .collect::<Vec<_>>();
    if !entries(directory)?
        .iter()
        .eq(expected.iter().map(|entry| &entry.name))
    {
        return Err(invalid(path, "selected retirement inventory changed"));
    }
    for planned in expected {
        let child_path = path.join(&planned.name);
        let child = open_entry(directory, &planned.name, &child_path, root)?;
        require_identity(&planned.identity, child.identity(), &child_path)?;
        let operation = mode.child(&planned.name);
        if operation.empty() {
            if child.directory().is_none() {
                require_zero(child.identity(), &child_path)?;
            }
            if let Some(checker) = admission.as_deref_mut() {
                let kind = if child.directory().is_some() {
                    RetirementEntryKind::Directory
                } else {
                    RetirementEntryKind::File
                };
                checker.check(&child_path, kind)?;
            }
        }
        if operation.visits() {
            if let Some(handle) = child.directory() {
                validate_scope(
                    handle,
                    &child_path,
                    root,
                    &planned.children,
                    operation,
                    after,
                    admission.as_deref_mut(),
                )?;
            } else if operation.partial() {
                return Err(invalid(&child_path, "selected ancestor is not a directory"));
            }
        }
    }
    Ok(())
}

pub(super) fn require_zero(stat: &FileStat, path: &Path) -> io::Result<()> {
    if stat.st_size != 0 {
        return Err(invalid(path, "selected file is no longer empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
