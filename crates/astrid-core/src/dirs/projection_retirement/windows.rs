//! Retirement authority stays with opened directories, never reconstructed paths.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;

use crate::platform_fs::windows_projection::{
    EntryKind, FileIdentity, OpenedDirectory, OpenedFile, is_canonical_volume_name,
    windows_names_equal,
};

#[cfg(test)]
type BeforeDisposition = Box<dyn FnMut(&OsStr)>;

#[cfg(test)]
thread_local! {
    static BEFORE_DISPOSITION: std::cell::RefCell<Option<BeforeDisposition>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn before_disposition(name: &OsStr) {
    BEFORE_DISPOSITION.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(name);
        }
    });
}

struct InventoryEntry {
    name: OsString,
    identity: FileIdentity,
    kind: EntryKind,
    children: Vec<Self>,
}

enum Child {
    Directory(OpenedDirectory),
    File(OpenedFile),
}

pub(super) fn retire(path: &Path) -> io::Result<()> {
    retire_after_preflight(path, || {})
}

fn retire_after_preflight(path: &Path, after_preflight: impl FnOnce()) -> io::Result<()> {
    let root = OpenedDirectory::open_existing(path)?;
    let entries = inventory(&root, true)?;
    after_preflight();
    // Recheck the complete captured tree before committing any deletion. This
    // also detects canonical-volume replacement at the preflight boundary.
    validate_inventory(&root, &entries)?;
    prove_flush(&root, &entries, true)?;
    let retirement =
        retire_entries(&root, &entries, true).and_then(|()| validate_survivor(&root, &entries));
    finish_retirement(retirement, root.sync_all())
}

fn finish_retirement(retirement: io::Result<()>, flush: io::Result<()>) -> io::Result<()> {
    // The flush has already been attempted. Preserve the first failure,
    // including its OS code and source, if both operations failed.
    retirement.and(flush)
}

fn prove_flush(parent: &OpenedDirectory, entries: &[InventoryEntry], root: bool) -> io::Result<()> {
    if root {
        parent.sync_all()?;
    }
    for entry in entries {
        if root && is_canonical_volume_name(&entry.name)? {
            continue;
        }
        if entry.kind != EntryKind::Directory {
            continue;
        }
        let Child::Directory(directory) =
            open_checked(parent, &entry.name, entry.identity, entry.kind, true)?
        else {
            return Err(invalid("projection entry identity changed after preflight"));
        };
        prove_flush(&directory, &entry.children, false)?;
        directory.sync_all()?;
    }
    Ok(())
}

fn inventory(parent: &OpenedDirectory, root: bool) -> io::Result<Vec<InventoryEntry>> {
    let mut entries = Vec::new();
    let mut seen_canonical = false;
    for listed in parent.list()? {
        if root {
            note_canonical_volume(&listed.name, listed.kind, &mut seen_canonical)?;
        }
        let child = open_checked(parent, &listed.name, listed.identity, listed.kind, false)?;
        let children = match &child {
            Child::Directory(directory) => inventory(directory, false)?,
            Child::File(_) => Vec::new(),
        };
        entries.push(InventoryEntry {
            name: listed.name,
            identity: listed.identity,
            kind: listed.kind,
            children,
        });
    }
    Ok(entries)
}

fn note_canonical_volume(name: &OsStr, kind: EntryKind, seen: &mut bool) -> io::Result<()> {
    if !is_canonical_volume_name(name)? {
        return Ok(());
    }
    if kind != EntryKind::File {
        return Err(invalid("canonical volume is not a regular file"));
    }
    if *seen {
        return Err(invalid(
            "projection contains colliding canonical volume names",
        ));
    }
    *seen = true;
    Ok(())
}

fn validate_inventory(parent: &OpenedDirectory, entries: &[InventoryEntry]) -> io::Result<()> {
    let current = parent.list()?;
    if !current
        .iter()
        .map(|entry| entry.name.as_os_str())
        .eq(entries.iter().map(|entry| entry.name.as_os_str()))
    {
        return Err(invalid("projection entries changed after preflight"));
    }
    for (listed, entry) in current.iter().zip(entries) {
        if listed.identity != entry.identity || listed.kind != entry.kind {
            return Err(invalid("projection entry identity changed after preflight"));
        }
        let child = open_checked(parent, &entry.name, entry.identity, entry.kind, false)?;
        if let Child::Directory(directory) = &child {
            validate_inventory(directory, &entry.children)?;
        }
    }
    Ok(())
}

fn retire_entries(
    parent: &OpenedDirectory,
    entries: &[InventoryEntry],
    root: bool,
) -> io::Result<()> {
    for entry in entries {
        let delete = !(root && is_canonical_volume_name(&entry.name)?);
        let child = open_checked(parent, &entry.name, entry.identity, entry.kind, delete)?;
        if !delete {
            continue;
        }
        match child {
            Child::Directory(directory) => {
                retire_entries(&directory, &entry.children, false)?;
                directory.sync_all()?;
                check_current_entry(parent, &entry.name, entry.identity, entry.kind)?;
                #[cfg(test)]
                before_disposition(&entry.name);
                directory.delete()?;
                if root {
                    parent.sync_all()?;
                }
            },
            Child::File(file) => {
                check_current_entry(parent, &entry.name, entry.identity, entry.kind)?;
                #[cfg(test)]
                before_disposition(&entry.name);
                file.delete()?;
            },
        }
    }
    Ok(())
}

fn validate_survivor(root: &OpenedDirectory, entries: &[InventoryEntry]) -> io::Result<()> {
    let mut survivor = None;
    for entry in entries {
        if is_canonical_volume_name(&entry.name)? {
            if survivor.is_some() {
                return Err(invalid(
                    "projection contains colliding canonical volume names",
                ));
            }
            survivor = Some(entry);
        }
    }
    let current = root.list()?;
    match survivor {
        Some(entry) if current.len() == 1 => {
            if !windows_names_equal(&current[0].name, &entry.name)? {
                return Err(invalid("projection changed during retirement"));
            }
            drop(open_checked(
                root,
                &entry.name,
                entry.identity,
                entry.kind,
                false,
            )?);
            Ok(())
        },
        None if current.is_empty() => Ok(()),
        _ => Err(invalid("projection changed during retirement")),
    }
}

fn open_checked(
    parent: &OpenedDirectory,
    name: &OsStr,
    identity: FileIdentity,
    kind: EntryKind,
    delete: bool,
) -> io::Result<Child> {
    let child = match kind {
        EntryKind::Directory => Child::Directory(parent.open_directory(name, delete)?),
        EntryKind::File => Child::File(parent.open_file(name, delete)?),
    };
    check_identity(parent, name, &child, identity, kind)?;
    Ok(child)
}

fn check_identity(
    parent: &OpenedDirectory,
    name: &OsStr,
    child: &Child,
    expected: FileIdentity,
    kind: EntryKind,
) -> io::Result<()> {
    let opened = match child {
        Child::Directory(directory) => directory.identity()?,
        Child::File(file) => file.identity()?,
    };
    if opened != expected {
        return Err(invalid("projection entry identity changed after preflight"));
    }
    check_current_entry(parent, name, expected, kind)
}

fn check_current_entry(
    parent: &OpenedDirectory,
    name: &OsStr,
    expected: FileIdentity,
    kind: EntryKind,
) -> io::Result<()> {
    let opened = match kind {
        EntryKind::Directory => parent.open_directory(name, false)?.identity()?,
        EntryKind::File => parent.open_file(name, false)?.identity()?,
    };
    if opened != expected {
        return Err(invalid("projection entry identity changed after preflight"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
