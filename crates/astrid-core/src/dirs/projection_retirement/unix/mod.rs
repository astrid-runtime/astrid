//! One no-follow root walk, then descriptor-relative preflight and retirement.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};

use super::CANONICAL_VOLUME;

#[cfg(test)]
mod barrier_tests;
#[cfg(all(test, target_os = "linux"))]
mod mount_tests;

struct RootBoundary {
    identity: FileStat,
    #[cfg(target_os = "linux")]
    mount: crate::platform_fs::MountId,
}

struct PlannedEntry {
    name: OsString,
    identity: FileStat,
    children: Vec<PlannedEntry>,
}

/// Captured namespace authority and complete, ephemeral preflight inventory.
///
/// Only the root descriptor is retained. Entries are reopened without following
/// redirects and must retain their captured identity before they can be removed.
/// Dropping this plan performs no deletion.
pub struct PreparedProjectionRetirement {
    directory: File,
    path: PathBuf,
    boundary: RootBoundary,
    inventory: Vec<PlannedEntry>,
    regular_files: Vec<PathBuf>,
}

impl PreparedProjectionRetirement {
    /// Validate every entry and capture the names and identities eligible for retirement.
    ///
    /// # Errors
    /// Returns an error for redirected, special, inaccessible, or cross-mount entries.
    pub fn prepare(root: &Path) -> io::Result<Self> {
        let directory = crate::platform_fs::open_existing_directory_no_follow(root)?;
        let boundary = RootBoundary {
            identity: fstat(&directory).map_err(os_error)?,
            #[cfg(target_os = "linux")]
            mount: crate::platform_fs::MountId::of(&directory)?,
        };
        let mut regular_files = Vec::new();
        let inventory = capture(
            &directory,
            root,
            Path::new(""),
            &boundary,
            &mut regular_files,
        )?;
        Ok(Self {
            directory,
            path: root.to_owned(),
            boundary,
            inventory,
            regular_files,
        })
    }

    /// Regular projection files relative to the captured root, excluding `astrid.volume`.
    /// Callers must validate these against their durable receipt before retiring.
    pub fn regular_files(&self) -> impl Iterator<Item = &Path> {
        self.regular_files.iter().map(PathBuf::as_path)
    }

    /// Remove only captured entries, retaining the actual engine-held canonical volume.
    ///
    /// # Errors
    /// Returns an error if the expected volume, root binding, inventory, or any
    /// captured identity changes, or removal or the root durability barrier fails.
    /// After any error the caller must retain its durable retirement receipt.
    pub fn retire(self, expected_volume: &File) -> io::Result<()> {
        let expected = fstat(expected_volume).map_err(os_error)?;
        self.retire_with_hooks(
            Some(&expected),
            &mut RetirementHooks {
                before_unlink: |_: &Path| Ok(()),
                sync_directory: |directory: &File, _: &Path| directory.sync_all(),
            },
        )
    }

    fn require_root(&self) -> io::Result<()> {
        let confirmation = crate::platform_fs::open_existing_directory_no_follow(&self.path)?;
        require_identity(
            &self.boundary.identity,
            &fstat(&confirmation).map_err(os_error)?,
            &self.path,
        )?;
        #[cfg(target_os = "linux")]
        self.boundary
            .mount
            .require_same(&confirmation, &self.path)?;
        Ok(())
    }

    fn require_volume(&self, expected: Option<&FileStat>) -> io::Result<()> {
        let planned = self
            .inventory
            .iter()
            .find(|entry| entry.name == OsStr::new(CANONICAL_VOLUME));
        let path = self.path.join(CANONICAL_VOLUME);
        if let Some(expected) = expected {
            let planned = planned.ok_or_else(|| invalid(&path, "canonical volume is missing"))?;
            require_identity(expected, &planned.identity, &path)?;
        }
        if let Some(planned) = planned {
            let current = open_entry(
                &self.directory,
                OsStr::new(CANONICAL_VOLUME),
                &path,
                &self.boundary,
            )?;
            require_identity(&planned.identity, current.identity(), &path)?;
        }
        Ok(())
    }

    fn require_survivors(&self, expected: Option<&FileStat>) -> io::Result<()> {
        self.require_root()?;
        self.require_volume(expected)?;
        let names = entries(&self.directory)?;
        let planned_volume = self
            .inventory
            .iter()
            .find(|entry| entry.name == OsStr::new(CANONICAL_VOLUME));
        if names.len() != usize::from(planned_volume.is_some())
            || names
                .iter()
                .any(|name| name != OsStr::new(CANONICAL_VOLUME))
        {
            return Err(invalid(&self.path, "projection contains unretired entries"));
        }
        Ok(())
    }

    fn retire_with_hooks(
        self,
        expected: Option<&FileStat>,
        hooks: &mut RetirementHooks<
            impl FnMut(&Path) -> io::Result<()>,
            impl FnMut(&File, &Path) -> io::Result<()>,
        >,
    ) -> io::Result<()> {
        self.require_root()?;
        self.require_volume(expected)?;
        delete_inventory(
            &self.directory,
            &self.path,
            &self.boundary,
            &self.inventory,
            true,
            hooks,
        )?;
        self.require_survivors(expected)?;
        // Removed descendants need no independent barrier: the retained durable
        // volume remains recovery authority until the root namespace is committed.
        (hooks.sync_directory)(&self.directory, &self.path)?;
        self.require_survivors(expected)
    }
}

// Directories carry traversal authority. Linux regular leaves retain an
// O_PATH handle for mount/identity checks without requesting content access.
enum Entry {
    Directory {
        handle: File,
        identity: FileStat,
    },
    File {
        identity: FileStat,
        #[cfg(target_os = "linux")]
        _handle: File,
    },
}

impl Entry {
    fn identity(&self) -> &FileStat {
        match self {
            Self::Directory { identity, .. } | Self::File { identity, .. } => identity,
        }
    }

    fn directory(&self) -> Option<&File> {
        match self {
            Self::Directory { handle, .. } => Some(handle),
            Self::File { .. } => None,
        }
    }
}

pub(super) fn retire(root: &Path) -> io::Result<()> {
    retire_with_hook(root, || Ok(()))
}

pub(super) fn retire_with_hook(
    root: &Path,
    before_delete: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    retire_with_hooks(root, before_delete, |_| Ok(()))
}

struct RetirementHooks<U, S> {
    before_unlink: U,
    sync_directory: S,
}

fn retire_with_hooks(
    root: &Path,
    before_delete: impl FnOnce() -> io::Result<()>,
    before_unlink: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    retire_with_io_hooks(root, before_delete, before_unlink, |directory, _| {
        directory.sync_all()
    })
}

fn retire_with_io_hooks(
    root: &Path,
    before_delete: impl FnOnce() -> io::Result<()>,
    before_unlink: impl FnMut(&Path) -> io::Result<()>,
    sync_directory: impl FnMut(&File, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let plan = PreparedProjectionRetirement::prepare(root)?;
    before_delete()?;
    plan.retire_with_hooks(
        None,
        &mut RetirementHooks {
            before_unlink,
            sync_directory,
        },
    )
}

fn capture(
    directory: &File,
    path: &Path,
    relative: &Path,
    root: &RootBoundary,
    regular_files: &mut Vec<PathBuf>,
) -> io::Result<Vec<PlannedEntry>> {
    let mut inventory = Vec::new();
    for name in entries(directory)? {
        let child_path = path.join(&name);
        let child_relative = relative.join(&name);
        let child = open_entry(directory, &name, &child_path, root)?;
        let canonical = relative.as_os_str().is_empty() && name == OsStr::new(CANONICAL_VOLUME);
        if canonical && child.directory().is_some() {
            return Err(invalid(
                &child_path,
                "canonical volume is not a regular file",
            ));
        }
        let children = if let Some(handle) = child.directory() {
            capture(handle, &child_path, &child_relative, root, regular_files)?
        } else {
            if !canonical {
                regular_files.push(child_relative);
            }
            Vec::new()
        };
        inventory.push(PlannedEntry {
            name,
            identity: *child.identity(),
            children,
        });
    }
    Ok(inventory)
}

fn delete_inventory(
    directory: &File,
    path: &Path,
    root: &RootBoundary,
    inventory: &[PlannedEntry],
    is_root: bool,
    hooks: &mut RetirementHooks<
        impl FnMut(&Path) -> io::Result<()>,
        impl FnMut(&File, &Path) -> io::Result<()>,
    >,
) -> io::Result<()> {
    // A listing only confirms the captured plan; it never grants deletion
    // authority to newly observed names. Missing captured names fail closed too.
    let names = entries(directory)?;
    if !names.iter().eq(inventory.iter().map(|entry| &entry.name)) {
        return Err(invalid(
            path,
            "projection inventory changed after preflight",
        ));
    }
    for planned in inventory {
        let name = &planned.name;
        let child_path = path.join(name);
        let child = open_entry(directory, name, &child_path, root)?;
        require_identity(&planned.identity, child.identity(), &child_path)?;
        if is_root && name == OsStr::new(CANONICAL_VOLUME) {
            continue;
        }
        if let Some(child_directory) = child.directory() {
            delete_inventory(
                child_directory,
                &child_path,
                root,
                &planned.children,
                false,
                hooks,
            )?;
        }
        (hooks.before_unlink)(&child_path)?;
        #[cfg(feature = "test-support")]
        super::replay::before_unlink(&child_path)?;
        // Do not unlink a different object that replaced the opened entry
        // while its contents were being walked. unlinkat never follows a
        // last-component redirect, even if replacement wins after this check.
        let current =
            fstatat(directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(os_error)?;
        require_identity(&planned.identity, &current, &child_path)?;
        check_boundary(&child_path, root, &current)?;
        #[cfg(target_os = "linux")]
        let _mount_confirmation = {
            // Bind mounts can preserve dev/ino/type while replacing a name.
            let confirmation = open_entry(directory, name, &child_path, root)?;
            require_identity(&planned.identity, confirmation.identity(), &child_path)?;
            confirmation
        };
        let flags = if child.directory().is_some() {
            UnlinkatFlags::RemoveDir
        } else {
            UnlinkatFlags::NoRemoveDir
        };
        unlinkat(directory, name.as_os_str(), flags).map_err(os_error)?;
        if is_root && child.directory().is_some() {
            // Preserve the existing root barrier after each top-level directory.
            (hooks.sync_directory)(directory, path)?;
        }
    }
    Ok(())
}

fn open_entry(parent: &File, name: &OsStr, path: &Path, root: &RootBoundary) -> io::Result<Entry> {
    let before = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(os_error)?;
    check_boundary(path, root, &before)?;
    match SFlag::from_bits_truncate(before.st_mode) & SFlag::S_IFMT {
        SFlag::S_IFDIR => {
            let (handle, identity) = open_checked(
                parent,
                name,
                path,
                root,
                &before,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NONBLOCK,
            )?;
            Ok(Entry::Directory { handle, identity })
        },
        SFlag::S_IFREG => {
            #[cfg(target_os = "linux")]
            {
                let (handle, identity) =
                    open_checked(parent, name, path, root, &before, OFlag::O_PATH)?;
                Ok(Entry::File {
                    identity,
                    _handle: handle,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Cleanup needs namespace authority, not leaf content access.
                // A fresh no-follow identity check still precedes unlinkat.
                Ok(Entry::File { identity: before })
            }
        },
        _ => Err(invalid(
            path,
            "projection contains a redirect or special entry",
        )),
    }
}

fn open_checked(
    parent: &File,
    name: &OsStr,
    path: &Path,
    root: &RootBoundary,
    before: &FileStat,
    flags: OFlag,
) -> io::Result<(File, FileStat)> {
    let flags = flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let child = File::from(openat(parent, name, flags, Mode::empty()).map_err(os_error)?);
    let after = fstat(&child).map_err(os_error)?;
    require_identity(before, &after, path)?;
    check_boundary(path, root, &after)?;
    #[cfg(target_os = "linux")]
    root.mount.require_same(&child, path)?;
    Ok((child, after))
}

fn entries(directory: &File) -> io::Result<Vec<OsString>> {
    // A fresh relative open gives this listing its own directory offset;
    // dup/try_clone would share offsets with the retained descriptor.
    let mut reader = nix::dir::Dir::openat(
        directory,
        Path::new("."),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(os_error)?;
    let mut names = Vec::new();
    for entry in reader.iter() {
        let entry = entry.map_err(os_error)?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
    }
    names.sort();
    Ok(names)
}

fn check_boundary(path: &Path, root: &RootBoundary, entry: &FileStat) -> io::Result<()> {
    if entry.st_dev != root.identity.st_dev {
        return Err(invalid(path, "projection crosses a filesystem boundary"));
    }
    Ok(())
}

fn require_identity(expected: &FileStat, actual: &FileStat, path: &Path) -> io::Result<()> {
    if expected.st_dev != actual.st_dev
        || expected.st_ino != actual.st_ino
        || (expected.st_mode & SFlag::S_IFMT.bits()) != (actual.st_mode & SFlag::S_IFMT.bits())
    {
        return Err(invalid(path, "projection entry changed identity or type"));
    }
    Ok(())
}

fn invalid(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{detail}: {}", path.display()),
    )
}

fn os_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
