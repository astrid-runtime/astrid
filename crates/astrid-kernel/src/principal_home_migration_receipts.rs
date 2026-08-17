//! Durable page and receipt records for ordinary principal-home migration.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use serde::{Deserialize, Serialize};

use super::migration_paths::{invalid_source, page_path_in};
use super::{
    MAX_RECEIPT_INDEX_BYTES, MAX_RECEIPT_PAGE_BYTES, PAGE_ENTRY_LIMIT, RECEIPT_PAGE_MARKER,
    RECEIPT_PREFIX, RECEIPT_SCHEMA, RECEIPT_SUFFIX,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationReceipt {
    pub(super) schema: u32,
    pub(super) uid: PrincipalUid,
    pub(super) alias: astrid_core::PrincipalId,
    pub(super) inventory_digest: String,
    pub(super) entry_count: u64,
    pub(super) bytes: u64,
    pub(super) page_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationPage {
    pub(super) schema: u32,
    pub(super) uid: PrincipalUid,
    pub(super) page: u64,
    pub(super) entries: Vec<MigrationEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MigrationEntry {
    pub(super) source: String,
    pub(super) destination: String,
    pub(super) kind: EntryKind,
    pub(super) bytes: u64,
    pub(super) digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum EntryKind {
    Directory,
    File,
}

pub(super) struct PageWriter {
    directory: PathBuf,
    uid: PrincipalUid,
    page: u64,
    entries: Vec<MigrationEntry>,
}

impl PageWriter {
    pub(super) fn new(home: &AstridHome, uid: PrincipalUid) -> Self {
        Self {
            directory: home.migrations_dir().clone(),
            uid,
            page: 0,
            entries: Vec::with_capacity(PAGE_ENTRY_LIMIT),
        }
    }

    pub(super) fn push(&mut self, entry: MigrationEntry) -> io::Result<()> {
        self.entries.push(entry);
        if self.entries.len() >= PAGE_ENTRY_LIMIT {
            self.flush_page()?;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<u64> {
        self.flush_page()?;
        Ok(self.page)
    }

    fn flush_page(&mut self) -> io::Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let page = MigrationPage {
            schema: RECEIPT_SCHEMA,
            uid: self.uid,
            page: self.page,
            entries: std::mem::take(&mut self.entries),
        };
        let bytes = canonical_json(&page)?;
        if bytes.len() > MAX_RECEIPT_PAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("principal-home migration page exceeds {MAX_RECEIPT_PAGE_BYTES} bytes"),
            ));
        }
        astrid_core::platform_fs::atomic_write_private_file(
            &page_path_in(&self.directory, self.uid, self.page),
            &bytes,
        )?;
        self.page = self
            .page
            .checked_add(1)
            .ok_or_else(|| io::Error::other("migration page count overflow"))?;
        Ok(())
    }
}

pub(super) fn validate_receipt_pages(
    home: &AstridHome,
    uid: PrincipalUid,
    receipt: &MigrationReceipt,
) -> io::Result<()> {
    // Do not trust the receipt's unbounded `entry_count` for allocation. A
    // tampered but canonical receipt can advertise `u64::MAX` while carrying
    // no pages; validating the bounded pages must fail closed without an
    // attacker-controlled allocation.
    let mut count = 0_u64;
    for page_number in 0..receipt.page_count {
        let page = read_page(home, uid, page_number)?;
        count = count
            .checked_add(u64::try_from(page.entries.len()).map_err(|_| {
                invalid_source(&receipt_path(home, uid), "receipt entry count is too large")
            })?)
            .ok_or_else(|| {
                invalid_source(&receipt_path(home, uid), "receipt entry count overflow")
            })?;
        if count > receipt.entry_count {
            return Err(invalid_source(
                &receipt_path(home, uid),
                "receipt entry count exceeds its index",
            ));
        }
    }
    if count != receipt.entry_count {
        return Err(invalid_source(
            &receipt_path(home, uid),
            "receipt entry count does not match its pages",
        ));
    }
    Ok(())
}

pub(super) fn read_receipt(path: &Path) -> io::Result<Option<MigrationReceipt>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(invalid_source(path, "receipt is not a regular file"))
        },
        Ok(_) => {
            astrid_core::platform_fs::validate_private_file(path)?;
            let bytes = fs::read(path)?;
            if bytes.len() > MAX_RECEIPT_INDEX_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "principal-home migration receipt exceeds {MAX_RECEIPT_INDEX_BYTES} bytes"
                    ),
                ));
            }
            let receipt: MigrationReceipt = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid principal-home migration receipt: {error}"),
                )
            })?;
            if receipt.page_count > receipt.entry_count
                || (receipt.entry_count == 0 && receipt.page_count != 0)
            {
                return Err(invalid_source(path, "receipt page count is not canonical"));
            }
            let canonical = canonical_json(&receipt)?;
            if bytes != canonical {
                return Err(invalid_source(path, "receipt is not canonical JSON"));
            }
            Ok(Some(receipt))
        },
    }
}

pub(super) fn write_receipt(path: &Path, receipt: &MigrationReceipt) -> io::Result<()> {
    let bytes = canonical_json(receipt)?;
    if bytes.len() > MAX_RECEIPT_INDEX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("principal-home migration receipt exceeds {MAX_RECEIPT_INDEX_BYTES} bytes"),
        ));
    }
    astrid_core::platform_fs::atomic_write_private_file(path, &bytes)
}

pub(super) fn read_page(
    home: &AstridHome,
    uid: PrincipalUid,
    page: u64,
) -> io::Result<MigrationPage> {
    let path = page_path(home, uid, page);
    match fs::symlink_metadata(&path) {
        Err(error) => Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(invalid_source(&path, "receipt page is not a regular file"))
        },
        Ok(_) => {
            astrid_core::platform_fs::validate_private_file(&path)?;
            let bytes = fs::read(&path)?;
            if bytes.len() > MAX_RECEIPT_PAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("principal-home migration page exceeds {MAX_RECEIPT_PAGE_BYTES} bytes"),
                ));
            }
            let page: MigrationPage = serde_json::from_slice(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid principal-home migration page: {error}"),
                )
            })?;
            if page.schema != RECEIPT_SCHEMA || page.uid != uid || page.page != page_number(&path)?
            {
                return Err(invalid_source(
                    &path,
                    "receipt page identity is not canonical",
                ));
            }
            if page.entries.len() > PAGE_ENTRY_LIMIT {
                return Err(invalid_source(&path, "receipt page has too many entries"));
            }
            let canonical = canonical_json(&page)?;
            if bytes != canonical {
                return Err(invalid_source(&path, "receipt page is not canonical JSON"));
            }
            Ok(page)
        },
    }
}

fn page_number(path: &Path) -> io::Result<u64> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_source(path, "receipt page name is not UTF-8"))?;
    let uid_and_page = name
        .strip_prefix(RECEIPT_PREFIX)
        .and_then(|name| name.strip_suffix(RECEIPT_SUFFIX))
        .ok_or_else(|| invalid_source(path, "receipt page name is not canonical"))?;
    let (_, number) = uid_and_page
        .rsplit_once(RECEIPT_PAGE_MARKER)
        .ok_or_else(|| invalid_source(path, "receipt page name is not canonical"))?;
    number.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid receipt page number: {error}"),
        )
    })
}

pub(super) fn remove_stale_pages(home: &AstridHome, uid: PrincipalUid) -> io::Result<()> {
    let directory = home.migrations_dir();
    let prefix = format!("{RECEIPT_PREFIX}{uid}{RECEIPT_PAGE_MARKER}");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(RECEIPT_SUFFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(invalid_source(
                &path,
                "stale receipt page is not a regular file",
            ));
        }
        astrid_core::platform_fs::validate_private_file(&path)?;
        fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn receipt_path(home: &AstridHome, uid: PrincipalUid) -> PathBuf {
    home.migrations_dir()
        .join(format!("{RECEIPT_PREFIX}{uid}{RECEIPT_SUFFIX}"))
}

pub(super) fn page_path(home: &AstridHome, uid: PrincipalUid, page: u64) -> PathBuf {
    page_path_in(&home.migrations_dir(), uid, page)
}
