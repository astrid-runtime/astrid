//! Captured Windows projection retirement over handle-relative inventory.
//!
//! Revalidate the complete inventory and current survivor identity before the
//! first durability fence or delete, and recheck each identity at deletion.
//! Only root astrid.volume is the survivor; nested names require receipts.
//! Namespace durability uses the shared NTFS directory flush primitive.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use crate::platform_fs::DirectoryIdentity;
use crate::platform_fs::windows::retirement_support::{
    ListedEntry, RetirementRoot, delete_captured_file, delete_empty_captured_directory,
    file_id_identity, list_child_entries, open_child_directory, open_child_directory_for_capture,
    open_child_file_for_delete, open_child_file_for_identity, open_child_file_for_read,
    require_identity,
};

use super::{CANONICAL_VOLUME, SourceChecker};

#[cfg(test)]
mod tests;

struct PlannedEntry {
    name: OsString,
    identity: DirectoryIdentity,
    is_directory: bool,
    children: Vec<PlannedEntry>,
}

/// Captured namespace authority and complete, ephemeral preflight inventory.
///
/// Dropping this plan performs no deletion.
pub struct PreparedProjectionRetirement {
    root: RetirementRoot,
    path: PathBuf,
    inventory: Vec<PlannedEntry>,
    regular_files: Vec<PathBuf>,
}

impl PreparedProjectionRetirement {
    /// Validate every entry and capture names and identities eligible for retirement.
    ///
    /// # Errors
    /// Returns an error for redirects, special entries, invalid identities, denied
    /// access, or a filesystem without NTFS directory-structure durability.
    pub fn prepare(root: &Path) -> io::Result<Self> {
        Self::prepare_with_checker(root, None)
    }

    /// Capture the complete inventory and verify selected regular source files.
    ///
    /// The predicate controls only read access: unselected entries still receive
    /// all inventory, `FileId` and deletion checks. Selected leaves open read-only
    /// relative to their captured parent, without privacy repair or ACL changes.
    /// The canonical volume is never a source. Every callback completes before
    /// this method returns; no entry is deleted. Ordinary [`Self::prepare`]
    /// remains metadata-only.
    ///
    /// # Errors
    /// Returns ordinary preflight errors, selected-source read/verification
    /// failures, or changed source/root bindings. Failure leaves the tree intact.
    pub fn prepare_checked(
        root: &Path,
        mut should_check: impl FnMut(&Path) -> bool,
        mut check: impl FnMut(&Path, &mut File) -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::prepare_with_checker(
            root,
            Some(SourceChecker {
                select: &mut should_check,
                verify: &mut check,
            }),
        )
    }

    fn prepare_with_checker(
        root: &Path,
        mut checker: Option<SourceChecker<'_>>,
    ) -> io::Result<Self> {
        let root_handle = RetirementRoot::open(root)?;
        let mut regular_files = Vec::new();
        let inventory = capture(
            root_handle.file(),
            root,
            Path::new(""),
            &mut regular_files,
            &mut checker,
        )?;
        let prepared = Self {
            root: root_handle,
            path: root.to_owned(),
            inventory,
            regular_files,
        };
        if checker.is_some() {
            prepared.require_root()?;
        }
        Ok(prepared)
    }

    /// Regular projection files relative to the captured root, excluding root `astrid.volume`.
    pub fn regular_files(&self) -> impl Iterator<Item = &Path> {
        self.regular_files.iter().map(PathBuf::as_path)
    }

    /// Remove only captured entries, retaining the engine-held canonical volume.
    ///
    /// # Errors
    /// Returns an error if any captured identity or inventory changed, deletion
    /// fails, or the namespace cannot be made durable. Recovery authority remains
    /// with the volume when retirement stops partway through.
    pub fn retire(self, expected_volume: &File) -> io::Result<()> {
        let expected = file_id_identity(expected_volume)?;
        self.retire_with_hooks(Some(expected), &mut |_path: &Path| Ok(()), || {})
    }

    pub(super) fn retire_with_hooks(
        self,
        expected_volume: Option<DirectoryIdentity>,
        before_unlink: &mut impl FnMut(&Path) -> io::Result<()>,
        after_preflight: impl FnOnce(),
    ) -> io::Result<()> {
        self.require_root()?;
        self.require_volume(expected_volume)?;
        after_preflight();
        // Historical stronger contract: revalidate complete inventory + current
        // survivor FileId after storage receipt validation and before first fence.
        validate_inventory(self.root.file(), &self.path, &self.inventory)?;
        self.require_volume_current(expected_volume)?;
        self.root.flush_namespace()?;
        delete_inventory(
            self.root.file(),
            &self.path,
            &self.inventory,
            true,
            before_unlink,
        )?;
        self.require_survivors(expected_volume)?;
        self.root.flush_namespace()?;
        self.require_survivors(expected_volume)
    }

    fn require_root(&self) -> io::Result<()> {
        let confirmation = RetirementRoot::open(&self.path)?;
        require_identity(self.root.identity(), confirmation.identity(), &self.path)
    }

    fn require_volume(&self, expected: Option<DirectoryIdentity>) -> io::Result<()> {
        let planned = self
            .inventory
            .iter()
            .find(|entry| entry.name == OsStr::new(CANONICAL_VOLUME));
        let path = self.path.join(CANONICAL_VOLUME);
        match (expected, planned) {
            (Some(expected), Some(planned)) => {
                if planned.is_directory {
                    return Err(invalid(&path, "canonical volume is a directory"));
                }
                require_identity(expected, planned.identity, &path)
            },
            (Some(_), None) => Err(invalid(&path, "canonical volume is missing")),
            (None, _) => Ok(()),
        }
    }

    fn require_volume_current(&self, expected: Option<DirectoryIdentity>) -> io::Result<()> {
        let Some(expected) = expected else {
            return Ok(());
        };
        let path = self.path.join(CANONICAL_VOLUME);
        let (file, identity) =
            open_child_file_for_identity(self.root.handle(), OsStr::new(CANONICAL_VOLUME))?;
        drop(file);
        require_identity(expected, identity, &path)
    }

    fn require_survivors(&self, expected: Option<DirectoryIdentity>) -> io::Result<()> {
        self.require_root()?;
        let listed = list_child_entries(self.root.file())?;
        if listed
            .iter()
            .any(|entry| entry.name != OsStr::new(CANONICAL_VOLUME))
        {
            return Err(invalid(
                &self.path,
                "projection root retained unexpected survivors",
            ));
        }
        if expected.is_some() {
            if !listed
                .iter()
                .any(|entry| entry.name == OsStr::new(CANONICAL_VOLUME))
            {
                return Err(invalid(
                    &self.path.join(CANONICAL_VOLUME),
                    "canonical volume is missing after retirement",
                ));
            }
            self.require_volume_current(expected)?;
        }
        Ok(())
    }
}

fn capture(
    parent: &File,
    absolute: &Path,
    relative: &Path,
    regular_files: &mut Vec<PathBuf>,
    checker: &mut Option<SourceChecker<'_>>,
) -> io::Result<Vec<PlannedEntry>> {
    let listed = list_child_entries(parent)?;
    let parent = parent.as_raw_handle().cast();

    let mut inventory = Vec::with_capacity(listed.len());
    for entry in listed {
        let child_absolute = absolute.join(&entry.name);
        let child_relative = relative.join(&entry.name);
        let canonical =
            relative.as_os_str().is_empty() && entry.name == OsStr::new(CANONICAL_VOLUME);
        let (is_directory, identity, children) = classify_and_capture(
            parent,
            &entry,
            &child_absolute,
            &child_relative,
            regular_files,
            canonical,
            checker,
        )?;
        if !is_directory && !canonical {
            regular_files.push(child_relative);
        }
        inventory.push(PlannedEntry {
            name: entry.name,
            identity,
            is_directory,
            children,
        });
    }
    Ok(inventory)
}

fn classify_and_capture(
    parent: windows_sys::Win32::Foundation::HANDLE,
    listed: &ListedEntry,
    absolute: &Path,
    relative: &Path,
    regular_files: &mut Vec<PathBuf>,
    canonical: bool,
    checker: &mut Option<SourceChecker<'_>>,
) -> io::Result<(bool, DirectoryIdentity, Vec<PlannedEntry>)> {
    if listed.is_directory {
        if canonical {
            return Err(invalid(absolute, "canonical volume is a directory"));
        }
        let (directory, identity) = open_child_directory_for_capture(parent, &listed.name)?;
        require_identity(listed.identity, identity, absolute)?;
        let children = capture(&directory, absolute, relative, regular_files, checker)?;
        drop(directory);
        Ok((true, identity, children))
    } else {
        let (file, identity) = open_child_file_for_identity(parent, &listed.name)?;
        require_identity(listed.identity, identity, absolute)?;
        if !canonical
            && let Some(checker) = checker
            && (checker.select)(relative)
        {
            let (mut source, opened) = open_child_file_for_read(parent, &listed.name)?;
            require_identity(identity, opened, absolute)?;
            (checker.verify)(relative, &mut source)?;
            require_identity(identity, file_id_identity(&source)?, absolute)?;
            let (confirmation, current) = open_child_file_for_identity(parent, &listed.name)?;
            require_identity(identity, current, absolute)?;
            drop(confirmation);
        }
        drop(file);
        Ok((false, identity, Vec::new()))
    }
}

fn validate_inventory(parent: &File, path: &Path, inventory: &[PlannedEntry]) -> io::Result<()> {
    let current = list_child_entries(parent)?;
    let parent = parent.as_raw_handle().cast();
    if !current
        .iter()
        .map(|entry| entry.name.as_os_str())
        .eq(inventory.iter().map(|entry| entry.name.as_os_str()))
    {
        return Err(invalid(
            path,
            "projection inventory changed after preflight",
        ));
    }
    for (listed, planned) in current.iter().zip(inventory) {
        if listed.identity != planned.identity || listed.is_directory != planned.is_directory {
            return Err(invalid(
                &path.join(&planned.name),
                "projection entry identity changed after preflight",
            ));
        }
        let child_path = path.join(&planned.name);
        if planned.is_directory {
            let (directory, identity) = open_child_directory_for_capture(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            validate_inventory(&directory, &child_path, &planned.children)?;
            drop(directory);
        } else {
            let (file, identity) = open_child_file_for_identity(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            drop(file);
        }
    }
    Ok(())
}

fn delete_inventory(
    parent: &File,
    path: &Path,
    inventory: &[PlannedEntry],
    is_root: bool,
    before_unlink: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let names = list_child_entries(parent)?;
    let parent = parent.as_raw_handle().cast();
    if !names
        .iter()
        .map(|entry| entry.name.as_os_str())
        .eq(inventory.iter().map(|entry| entry.name.as_os_str()))
    {
        return Err(invalid(
            path,
            "projection inventory changed after preflight",
        ));
    }

    for planned in inventory {
        let child_path = path.join(&planned.name);
        if is_root && planned.name == OsStr::new(CANONICAL_VOLUME) {
            let (file, identity) = open_child_file_for_identity(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            drop(file);
            continue;
        }
        if planned.is_directory {
            let (directory, identity) = open_child_directory(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            delete_inventory(
                &directory,
                &child_path,
                &planned.children,
                false,
                before_unlink,
            )?;
            before_unlink(&child_path)?;
            let still = file_id_identity(&directory)?;
            require_identity(planned.identity, still, &child_path)?;
            delete_empty_captured_directory(directory)?;
        } else {
            let (file, identity) = open_child_file_for_delete(parent, &planned.name)?;
            require_identity(planned.identity, identity, &child_path)?;
            before_unlink(&child_path)?;
            delete_captured_file(file)?;
        }
    }
    Ok(())
}

pub(super) fn retire(root: &Path) -> io::Result<()> {
    let plan = PreparedProjectionRetirement::prepare(root)?;
    let volume_path = root.join(CANONICAL_VOLUME);
    match File::open(&volume_path) {
        Ok(volume) => plan.retire(&volume),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            plan.retire_with_hooks(None, &mut |_| Ok(()), || {})
        },
        Err(error) => Err(error),
    }
}

#[cfg(test)]
pub(super) fn retire_with_hook(path: &Path, after_preflight: impl FnOnce()) -> io::Result<()> {
    let plan = PreparedProjectionRetirement::prepare(path)?;
    let volume_path = path.join(CANONICAL_VOLUME);
    match File::open(&volume_path) {
        Ok(volume) => {
            let expected = file_id_identity(&volume)?;
            plan.retire_with_hooks(Some(expected), &mut |_| Ok(()), after_preflight)
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            plan.retire_with_hooks(None, &mut |_| Ok(()), after_preflight)
        },
        Err(error) => Err(error),
    }
}

fn invalid(path: &Path, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{message}: {}", path.display()),
    )
}
