//! One no-follow root walk, then descriptor-relative preflight and retirement.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};

use super::CANONICAL_VOLUME;

#[cfg(target_os = "linux")]
mod mount;
#[cfg(all(test, target_os = "linux"))]
mod mount_tests;

struct RootBoundary {
    identity: FileStat,
    #[cfg(target_os = "linux")]
    mount: mount::MountId,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Traversal {
    Preflight,
    Delete,
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

fn retire_with_hooks(
    root: &Path,
    before_delete: impl FnOnce() -> io::Result<()>,
    mut before_unlink: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let directory = crate::platform_fs::open_existing_directory_no_follow(root)?;
    let boundary = RootBoundary {
        identity: fstat(&directory).map_err(os_error)?,
        #[cfg(target_os = "linux")]
        mount: mount::MountId::of(&directory)?,
    };
    walk(
        &directory,
        root,
        &boundary,
        Traversal::Preflight,
        true,
        &mut before_unlink,
    )?;
    before_delete()?;
    // Reconfirm the ambient binding once before mutation. Descendants are
    // subsequently opened relative to this retained authority, never through
    // a potentially replaced absolute ancestor chain.
    let confirmation = crate::platform_fs::open_existing_directory_no_follow(root)?;
    require_identity(
        &boundary.identity,
        &fstat(&confirmation).map_err(os_error)?,
        root,
    )?;
    #[cfg(target_os = "linux")]
    boundary.mount.require_same(&confirmation, root)?;
    walk(
        &directory,
        root,
        &boundary,
        Traversal::Delete,
        true,
        &mut before_unlink,
    )
}

fn walk(
    directory: &File,
    path: &Path,
    root: &RootBoundary,
    traversal: Traversal,
    is_root: bool,
    before_unlink: &mut impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    for name in entries(directory)? {
        let child_path = path.join(&name);
        let child = open_entry(directory, &name, &child_path, root)?;
        // Validate the canonical survivor too, including special files and
        // redirects. Only its deletion is excluded.
        if is_root && name == OsStr::new(CANONICAL_VOLUME) {
            if child.directory().is_some() {
                return Err(invalid(
                    &child_path,
                    "canonical volume is not a regular file",
                ));
            }
            continue;
        }
        if let Some(child_directory) = child.directory() {
            walk(
                child_directory,
                &child_path,
                root,
                traversal,
                false,
                before_unlink,
            )?;
        }
        if traversal == Traversal::Delete {
            before_unlink(&child_path)?;
            // Do not unlink a different object that replaced the opened entry
            // while its contents were being walked. unlinkat never follows a
            // last-component redirect, even if replacement wins after this check.
            let current = fstatat(directory, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(os_error)?;
            require_identity(child.identity(), &current, &child_path)?;
            check_boundary(&child_path, root, &current)?;
            #[cfg(target_os = "linux")]
            let _mount_confirmation = {
                // A bind mount can preserve dev/ino/type while changing the
                // mounted object behind this name during the subtree walk.
                let confirmation = open_entry(directory, &name, &child_path, root)?;
                require_identity(child.identity(), confirmation.identity(), &child_path)?;
                confirmation
            };
            let flags = if child.directory().is_some() {
                UnlinkatFlags::RemoveDir
            } else {
                UnlinkatFlags::NoRemoveDir
            };
            unlinkat(directory, name.as_os_str(), flags).map_err(os_error)?;
            if is_root && child.directory().is_some() {
                // The former per-subtree retirement also flushed its parent
                // after every top-level directory removal, before proceeding
                // to later siblings. Keep that barrier as well as the final one.
                directory.sync_all()?;
            }
        }
    }
    if traversal == Traversal::Delete {
        // Preserve every existing directory barrier: flush child removals
        // before the caller removes this directory, and flush the root last.
        directory.sync_all()?;
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
