//! Retirement authority stays with opened directories, never reconstructed paths.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::Path;

use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};

#[path = "mount.rs"]
mod mount;
use mount::MountBoundary;

const CANONICAL_VOLUME: &str = "astrid.volume";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryIdentity {
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    kind: EntryKind,
}

impl EntryIdentity {
    fn read(stat: &FileStat) -> io::Result<Self> {
        let kind = match SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT {
            SFlag::S_IFREG => EntryKind::File,
            SFlag::S_IFDIR => EntryKind::Directory,
            _ => return Err(invalid("projection contains a redirect or special entry")),
        };
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            kind,
        })
    }
}

/// Directories need readable handles for enumeration and durability. Regular
/// files need only identity: Linux `O_PATH` also supplies their mount identity
/// without requiring read access to projection or canonical-volume contents.
enum Child {
    Directory(File),
    File {
        #[cfg(target_os = "linux")]
        path_fd: File,
    },
}

/// This inventory lasts only for this retirement. It captures every identity
/// before the first unlink, so a late invalid entry cannot cause partial cleanup.
struct InventoryEntry {
    name: OsString,
    identity: EntryIdentity,
    children: Vec<Self>,
}

pub(super) fn retire(path: &Path) -> io::Result<()> {
    retire_after_preflight(path, || {})
}

fn retire_after_preflight(path: &Path, after_preflight: impl FnOnce()) -> io::Result<()> {
    let root = crate::platform_fs::open_existing_directory_no_follow(path)?;
    let boundary = MountBoundary::new(&root)?;
    let entries = inventory(&root, &boundary, true)?;
    after_preflight();
    // Recheck the complete captured tree before committing any deletion. This
    // also detects canonical-volume replacement at the preflight boundary.
    validate_inventory(&root, &entries, &boundary)?;
    retire_entries(&root, &entries, &boundary, true)?;
    validate_survivor(&root, &entries, &boundary)?;
    root.sync_all()
}

fn inventory(
    parent: &File,
    boundary: &MountBoundary,
    root: bool,
) -> io::Result<Vec<InventoryEntry>> {
    let mut entries = Vec::new();
    for name in names(parent)? {
        let identity = entry_identity(parent, &name)?;
        if root && name == OsStr::new(CANONICAL_VOLUME) && identity.kind != EntryKind::File {
            return Err(invalid("canonical volume is not a regular file"));
        }
        let child = open_checked(parent, &name, identity, boundary)?;
        let children = match &child {
            Child::Directory(directory) => inventory(directory, boundary, false)?,
            Child::File { .. } => Vec::new(),
        };
        entries.push(InventoryEntry {
            name,
            identity,
            children,
        });
    }
    Ok(entries)
}

fn validate_inventory(
    parent: &File,
    entries: &[InventoryEntry],
    boundary: &MountBoundary,
) -> io::Result<()> {
    let current = names(parent)?;
    if !current
        .iter()
        .map(OsString::as_os_str)
        .eq(entries.iter().map(|entry| entry.name.as_os_str()))
    {
        return Err(invalid("projection entries changed after preflight"));
    }
    for entry in entries {
        let child = open_checked(parent, &entry.name, entry.identity, boundary)?;
        if let Child::Directory(directory) = &child {
            validate_inventory(directory, &entry.children, boundary)?;
        }
    }
    Ok(())
}

fn retire_entries(
    parent: &File,
    entries: &[InventoryEntry],
    boundary: &MountBoundary,
    root: bool,
) -> io::Result<()> {
    for entry in entries {
        let child = open_checked(parent, &entry.name, entry.identity, boundary)?;
        if root && entry.name == OsStr::new(CANONICAL_VOLUME) {
            continue;
        }
        let flags = match &child {
            Child::Directory(directory) => {
                retire_entries(directory, &entry.children, boundary, false)?;
                // Preserve the legacy durability order: sync the directory's
                // removals before unlinking the directory from its parent.
                directory.sync_all()?;
                UnlinkatFlags::RemoveDir
            },
            Child::File { .. } => UnlinkatFlags::NoRemoveDir,
        };
        // Compare the live parent entry and any held child immediately before
        // unlinkat. No path lookup can redirect deletion to another tree.
        check_identity(parent, &entry.name, &child, entry.identity, boundary)?;
        unlinkat(parent, entry.name.as_os_str(), flags).map_err(nix_error)?;
        if root && entry.identity.kind == EntryKind::Directory {
            // Legacy top-level tree retirement also fenced the containing
            // root after each directory removal, including before a later error.
            parent.sync_all()?;
        }
    }
    Ok(())
}

fn validate_survivor(
    root: &File,
    entries: &[InventoryEntry],
    boundary: &MountBoundary,
) -> io::Result<()> {
    let survivor = entries
        .iter()
        .find(|entry| entry.name == OsStr::new(CANONICAL_VOLUME));
    let current = names(root)?;
    match survivor {
        Some(entry) if current.len() == 1 && current[0] == entry.name => {
            drop(open_checked(root, &entry.name, entry.identity, boundary)?);
            Ok(())
        },
        None if current.is_empty() => Ok(()),
        _ => Err(invalid("projection changed during retirement")),
    }
}

fn names(parent: &File) -> io::Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStrExt as _;

    // openat(".") creates an independent enumeration offset; dup would share
    // the held directory's offset and could silently omit entries on a retry.
    let mut directory =
        Dir::openat(parent, ".", directory_flags(), Mode::empty()).map_err(nix_error)?;
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(nix_error)?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
    }
    names.sort();
    Ok(names)
}

fn entry_identity(parent: &File, name: &OsStr) -> io::Result<EntryIdentity> {
    let stat = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(nix_error)?;
    EntryIdentity::read(&stat)
}

fn open_checked(
    parent: &File,
    name: &OsStr,
    identity: EntryIdentity,
    boundary: &MountBoundary,
) -> io::Result<Child> {
    let child = match identity.kind {
        EntryKind::Directory => Child::Directory(File::from(
            openat(parent, name, directory_flags(), Mode::empty()).map_err(nix_error)?,
        )),
        EntryKind::File => {
            #[cfg(target_os = "linux")]
            {
                let flags = OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
                Child::File {
                    path_fd: File::from(
                        openat(parent, name, flags, Mode::empty()).map_err(nix_error)?,
                    ),
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                Child::File {}
            }
        },
    };
    check_identity(parent, name, &child, identity, boundary)?;
    Ok(child)
}

fn check_identity(
    parent: &File,
    name: &OsStr,
    child: &Child,
    expected: EntryIdentity,
    boundary: &MountBoundary,
) -> io::Result<()> {
    match child {
        Child::Directory(directory) => check_opened_identity(directory, expected, boundary)?,
        Child::File {
            #[cfg(target_os = "linux")]
            path_fd,
        } => {
            #[cfg(target_os = "linux")]
            check_opened_identity(path_fd, expected, boundary)?;
        },
    }
    let current = entry_identity(parent, name)?;
    if current != expected {
        return Err(invalid("projection entry identity changed after preflight"));
    }
    boundary.validate_device(current.device)
}

fn check_opened_identity(
    child: &File,
    expected: EntryIdentity,
    boundary: &MountBoundary,
) -> io::Result<()> {
    if EntryIdentity::read(&fstat(child).map_err(nix_error)?)? != expected {
        return Err(invalid("projection entry identity changed after preflight"));
    }
    boundary.validate(child)
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK | OFlag::O_DIRECTORY
}

fn nix_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
