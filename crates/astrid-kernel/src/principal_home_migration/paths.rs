//! Receipt/path helpers for principal-home migration.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_storage::{FilesystemError, FilesystemPath};

use super::{MAX_RELATIVE_PATH_BYTES, RECEIPT_PAGE_MARKER, RECEIPT_PREFIX, RECEIPT_SUFFIX};

pub(super) fn page_path_in(directory: &Path, uid: PrincipalUid, page: u64) -> PathBuf {
    directory.join(format!(
        "{RECEIPT_PREFIX}{uid}{RECEIPT_PAGE_MARKER}{page}{RECEIPT_SUFFIX}"
    ))
}

pub(super) fn receipt_path_for_display(uid: PrincipalUid) -> PathBuf {
    PathBuf::from(format!("{RECEIPT_PREFIX}{uid}{RECEIPT_SUFFIX}"))
}

pub(super) fn source_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Resolve a legacy source directory whose alias was renamed after its
/// migration receipt was written. Receipts remain authoritative even after
/// an identity is retired; the caller compares the result with any current
/// alias binding and fails closed on reuse.
pub(super) fn receipt_uid_for_alias(
    home: &AstridHome,
    alias: &PrincipalId,
) -> io::Result<Option<PrincipalUid>> {
    let directory = home.migrations_dir();
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut found = None;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(uid_text) = name
            .strip_prefix(RECEIPT_PREFIX)
            .and_then(|name| name.strip_suffix(RECEIPT_SUFFIX))
        else {
            continue;
        };
        if uid_text.contains(RECEIPT_PAGE_MARKER) {
            continue;
        }
        let Ok(uid) = uid_text.parse::<PrincipalUid>() else {
            return Err(invalid_source(&path, "receipt UID is not canonical"));
        };
        let Some(receipt) = super::read_receipt(&path)? else {
            continue;
        };
        if receipt.uid != uid || &receipt.alias != alias {
            continue;
        }
        if found.replace(uid).is_some_and(|existing| existing != uid) {
            return Err(conflict_path(
                &path,
                "multiple live migration receipts claim the same alias",
            ));
        }
    }
    Ok(found)
}

pub(super) fn append_relative(base: &Path, name: &std::ffi::OsStr) -> io::Result<PathBuf> {
    if name.to_str().is_none() {
        return Err(invalid_source(base, "entry name is not UTF-8"));
    }
    Ok(base.join(name))
}

pub(super) fn logical_relative(path: &Path) -> io::Result<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_source(
            path,
            "legacy relative path is not canonical",
        ));
    }
    let text = path
        .to_str()
        .ok_or_else(|| invalid_source(path, "legacy relative path is not UTF-8"))?
        .replace('\\', "/");
    if text.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(invalid_source(path, "legacy relative path is too long"));
    }
    FilesystemPath::new(text.clone()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy path {text:?} is not a canonical filesystem path: {error}"),
        )
    })?;
    Ok(text)
}

pub(super) fn destination_name(relative: &str) -> String {
    format!("home/{relative}")
}

pub(super) fn is_dedicated_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    match components.as_slice() {
        [".config", "env", ..] => true,
        [".config", name] => matches!(*name, "profile.toml" | "distro.lock" | "distro.init.lock"),
        [".local", name, ..] => {
            matches!(
                *name,
                "capsules" | "audit" | "tmp" | "kv" | "tokens" | "log"
            )
        },
        _ => false,
    }
}

pub(super) fn storage_error(error: &FilesystemError) -> io::Error {
    io::Error::other(format!(
        "authoritative home migration storage error: {error}"
    ))
}

pub(super) fn invalid_source(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("legacy principal-home source {}: {detail}", path.display()),
    )
}

pub(super) fn conflict_path(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "principal-home migration conflict at {}: {detail}",
            path.display()
        ),
    )
}

pub(super) fn conflict_fs(path: &FilesystemPath, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "principal-home migration conflict at {}: {detail}",
            path.as_str()
        ),
    )
}
