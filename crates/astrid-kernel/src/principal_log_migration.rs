//! Receipt-bound migration of released per-principal operational logs.
//!
//! Capsule logs are deliberately native operational state rather than
//! `home://` content.  Releases before the UID-scoped log layout placed them
//! below a mutable principal alias, however, so upgrade must move that source
//! without allowing an alias reuse or a concurrent writer to redirect bytes.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use astrid_storage::PrincipalDirectory;
use serde::{Deserialize, Serialize};

const RECEIPT_SCHEMA: u32 = 1;
const RECEIPT_PREFIX: &str = "principal-logs-";
const RECEIPT_SUFFIX: &str = ".json";
const MAX_ENTRIES: u64 = 100_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogReceipt {
    schema: u32,
    uid: PrincipalUid,
    alias: PrincipalId,
    source_digest: String,
    destination_digest: String,
    entries: u64,
    bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogEntry {
    relative: String,
    bytes: u64,
    digest: String,
}

/// Move every admitted principal's released `.local/log` tree into the
/// immutable UID log projection. A missing source is a no-op; an existing
/// receipt is verified and only then used to retire its exact source tree.
///
/// # Errors
///
/// Returns an error for redirected or special entries, source mutation,
/// destination conflicts, size-limit violations, or a receipt mismatch.
pub(crate) fn migrate_legacy_principal_logs(
    home: &AstridHome,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, uid) in directory.bindings() {
        let source = home.principal_home(&alias).log_dir();
        if !exists(&source)? {
            continue;
        }
        migrate_one(home, &alias, uid, &source)?;
    }
    Ok(())
}

/// Return a deterministic proof of one UID's canonical import receipt.
///
/// The migration verifies every destination byte before publishing this
/// receipt. Runtime logs are appendable operational state, so later proof
/// checks bind the immutable receipt rather than re-hashing the live log tree.
///
/// # Errors
///
/// Returns an error when the receipt exists but is malformed or belongs to a
/// different UID.
pub(crate) fn legacy_log_destination_proof(
    home: &AstridHome,
    uid: PrincipalUid,
) -> io::Result<String> {
    let path = receipt_path(home, uid);
    let Some(bytes) = read_receipt_bytes(&path)? else {
        return Ok("absent".to_owned());
    };
    let receipt: LogReceipt = decode_receipt(&bytes, &path)?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy log receipt identity mismatch: {}", path.display()),
        ));
    }
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

fn migrate_one(
    home: &AstridHome,
    alias: &PrincipalId,
    uid: PrincipalUid,
    source: &Path,
) -> io::Result<()> {
    let receipt_path = receipt_path(home, uid);
    if let Some(bytes) = read_receipt_bytes(&receipt_path)? {
        let receipt: LogReceipt = decode_receipt(&bytes, &receipt_path)?;
        if receipt.schema != RECEIPT_SCHEMA || receipt.uid != uid || receipt.alias != *alias {
            return Err(conflict(
                &receipt_path,
                "receipt identity differs from source binding",
            ));
        }
        verify_destination(home, uid, &receipt)?;
        retire_source(source, &receipt)?;
        return Ok(());
    }

    let source_device = device_id(&fs::symlink_metadata(source)?);
    let destination = destination_root(home, uid);
    ensure_same_device(home, source_device)?;
    let entries = inventory(source, source_device)?;
    let source_digest = digest_entries(&entries);
    preflight_destination(&destination, &entries)?;
    let destination_digest = if entries.is_empty() {
        digest_entries(&entries)
    } else {
        astrid_core::platform_fs::ensure_private_directory(&destination)?;
        for entry in &entries {
            copy_entry(source, &destination, entry, source_device)?;
        }
        verify_entries(&destination, &entries)?
    };
    let reread = inventory(source, source_device)?;
    if reread != entries {
        return Err(conflict(
            source,
            "legacy log source changed before retirement",
        ));
    }
    let receipt = LogReceipt {
        schema: RECEIPT_SCHEMA,
        uid,
        alias: alias.clone(),
        source_digest,
        destination_digest,
        entries: u64::try_from(entries.len())
            .map_err(|_| io::Error::other("legacy log entry count overflow"))?,
        bytes: entries.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.bytes)
                .ok_or_else(|| io::Error::other("legacy log byte count overflow"))
        })?,
    };
    let bytes = canonical_json(&receipt)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path, &bytes)?;
    retire_source(source, &receipt)
}

fn inventory(source: &Path, source_device: u64) -> io::Result<Vec<LogEntry>> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid(source, "legacy log root is not a directory"));
    }
    astrid_core::platform_fs::ensure_private_directory_tree(source)?;
    astrid_core::platform_fs::verify_no_redirects(source)?;
    let mut entries = Vec::new();
    let mut total = 0_u64;
    walk_inventory(source, source, source_device, &mut entries, &mut total)?;
    Ok(entries)
}

fn walk_inventory(
    root: &Path,
    current: &Path,
    source_device: u64,
    entries: &mut Vec<LogEntry>,
    total: &mut u64,
) -> io::Result<()> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || device_id(&metadata) != source_device
            || (!metadata.is_dir() && !metadata.is_file())
        {
            return Err(invalid(
                &path,
                "redirected, cross-device, or special log entry",
            ));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative.is_empty()
            || relative.len() > MAX_PATH_BYTES
            || Path::new(&relative)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(invalid(&path, "non-canonical relative log path"));
        }
        if metadata.is_dir() {
            walk_inventory(root, &path, source_device, entries, total)?;
            continue;
        }
        let (bytes, digest) = digest_file(&path, source_device)?;
        *total = total
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("legacy log byte count overflow"))?;
        if *total > MAX_BYTES {
            return Err(invalid(
                root,
                "legacy log tree exceeds migration byte limit",
            ));
        }
        entries.push(LogEntry {
            relative,
            bytes,
            digest,
        });
        if u64::try_from(entries.len())
            .ok()
            .is_some_and(|count| count > MAX_ENTRIES)
        {
            return Err(invalid(
                root,
                "legacy log tree exceeds migration entry limit",
            ));
        }
    }
    Ok(())
}

fn preflight_destination(destination: &Path, entries: &[LogEntry]) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid(destination, "destination log root is redirected"));
        }
        astrid_core::platform_fs::verify_no_redirects(destination)?;
    }
    for entry in entries {
        let path = destination.join(&entry.relative);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(conflict(&path, "destination entry type differs"));
            }
            let (bytes, digest) = digest_file(&path, device_id(&metadata))?;
            if bytes != entry.bytes || digest != entry.digest {
                return Err(conflict(&path, "destination bytes differ"));
            }
        }
    }
    Ok(())
}

fn copy_entry(
    source_root: &Path,
    destination_root: &Path,
    entry: &LogEntry,
    source_device: u64,
) -> io::Result<()> {
    let source = source_root.join(&entry.relative);
    let destination = destination_root.join(&entry.relative);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(conflict(
                &destination,
                "destination entry is redirected or not a file",
            ));
        }
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        astrid_core::platform_fs::ensure_private_directory(parent)?;
    }
    let metadata = fs::symlink_metadata(&source)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || device_id(&metadata) != source_device
    {
        return Err(invalid(&source, "source changed before log copy"));
    }
    let temporary = destination.with_extension(format!("tmp.{}", uuid::Uuid::new_v4().simple()));
    let mut input = open_nofollow(&source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io::Error::other)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| io::Error::other("log read overflow"))?)
            .ok_or_else(|| io::Error::other("log byte count overflow"))?;
    }
    output.sync_all()?;
    if bytes != entry.bytes || hasher.finalize().to_hex().as_str() != entry.digest {
        let _ = fs::remove_file(&temporary);
        return Err(conflict(&source, "source changed during log copy"));
    }
    fs::rename(&temporary, &destination)?;
    astrid_core::platform_fs::restrict_private_file(&destination)?;
    Ok(())
}

fn verify_entries(destination: &Path, entries: &[LogEntry]) -> io::Result<String> {
    for entry in entries {
        let path = destination.join(&entry.relative);
        let (bytes, digest) = digest_file(&path, device_id(&fs::symlink_metadata(&path)?))?;
        if bytes != entry.bytes || digest != entry.digest {
            return Err(conflict(&path, "destination read-back differs"));
        }
    }
    Ok(digest_entries(entries))
}

fn retire_source(source: &Path, receipt: &LogReceipt) -> io::Result<()> {
    let entries = inventory(source, device_id(&fs::symlink_metadata(source)?))?;
    let expected_count = usize::try_from(receipt.entries)
        .map_err(|_| invalid(source, "receipt entry count is too large"))?;
    if entries.len() != expected_count || digest_entries(&entries) != receipt.source_digest {
        return Err(conflict(
            source,
            "legacy log source changed before retirement",
        ));
    }
    let mut paths = entries
        .iter()
        .map(|entry| source.join(&entry.relative))
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(invalid(&path, "legacy log entry changed type"));
        }
        fs::remove_file(&path)?;
        sync_parent(&path)?;
    }
    remove_empty_directories(source)?;
    Ok(())
}

fn remove_empty_directories(root: &Path) -> io::Result<()> {
    let mut children = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(conflict(&path, "unretired legacy log entry remains"));
        }
        remove_empty_directories(&path)?;
    }
    if fs::read_dir(root)?.next().is_none() {
        fs::remove_dir(root)?;
        sync_parent(root)?;
    }
    Ok(())
}

fn verify_destination(
    home: &AstridHome,
    uid: PrincipalUid,
    receipt: &LogReceipt,
) -> io::Result<()> {
    let destination = destination_root(home, uid);
    if !destination.is_dir() {
        if receipt.entries == 0 && !exists(&destination)? {
            return Ok(());
        }
        return Err(conflict(&destination, "log destination is missing"));
    }
    let entries = inventory(
        &destination,
        device_id(&fs::symlink_metadata(&destination)?),
    )?;
    let bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .ok_or_else(|| io::Error::other("log destination byte count overflow"))
    })?;
    if entries.len() != usize::try_from(receipt.entries).unwrap_or(usize::MAX)
        || bytes != receipt.bytes
        || digest_entries(&entries) != receipt.destination_digest
    {
        return Err(conflict(&destination, "log destination receipt mismatch"));
    }
    Ok(())
}

fn digest_entries(entries: &[LogEntry]) -> String {
    let mut hasher = blake3::Hasher::new();
    for entry in entries {
        hasher.update(entry.relative.as_bytes());
        hasher.update(&entry.bytes.to_le_bytes());
        hasher.update(entry.digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn destination_root(home: &AstridHome, uid: PrincipalUid) -> PathBuf {
    home.log_dir().join("principals").join(uid.to_string())
}

fn receipt_path(home: &AstridHome, uid: PrincipalUid) -> PathBuf {
    home.migrations_dir()
        .join(format!("{RECEIPT_PREFIX}{uid}{RECEIPT_SUFFIX}"))
}

fn read_receipt_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(invalid(path, "legacy log receipt is not a regular file"));
        }
        astrid_core::platform_fs::verify_no_redirects(path)?;
        astrid_core::platform_fs::validate_private_file(path)?;
        if metadata.len() > MAX_RECEIPT_BYTES {
            return Err(invalid(path, "legacy log receipt exceeds size limit"));
        }
    }
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn decode_receipt(bytes: &[u8], path: &Path) -> io::Result<LogReceipt> {
    let receipt: LogReceipt = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode legacy log receipt {}: {error}", path.display()),
        )
    })?;
    if canonical_json(&receipt)? != bytes {
        return Err(invalid(path, "legacy log receipt is not canonical JSON"));
    }
    Ok(receipt)
}

fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}

fn digest_file(path: &Path, expected_device: u64) -> io::Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || device_id(&metadata) != expected_device
    {
        return Err(invalid(path, "not a regular same-device log file"));
    }
    astrid_core::platform_fs::validate_private_file(path)?;
    let mut file = open_nofollow(path)?;
    let before = metadata.len();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| io::Error::other("log read overflow"))?)
            .ok_or_else(|| io::Error::other("log byte count overflow"))?;
    }
    if before != bytes || fs::symlink_metadata(path)?.len() != before {
        return Err(conflict(path, "log file changed during read"));
    }
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    options.open(path)
}

fn ensure_same_device(home: &AstridHome, source_device: u64) -> io::Result<()> {
    let root = home.log_dir();
    let existing = root
        .parent()
        .and_then(|parent| fs::symlink_metadata(parent).ok())
        .or_else(|| fs::symlink_metadata(home.root()).ok())
        .ok_or_else(|| invalid(&root, "cannot resolve log destination device"))?;
    if device_id(&existing) != source_device {
        return Err(invalid(&root, "log migration crosses a device boundary"));
    }
    Ok(())
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn device_id(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

// Windows retirement uses write-through platform helpers; retain the common
// fallible signature for the cross-platform migration flow.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn invalid(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("legacy log {}: {detail}", path.display()),
    )
}

fn conflict(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("legacy log conflict at {}: {detail}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_logs_to_uid_projection_and_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("astrid"));
        let principal = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([0x91; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let source = home.principal_home(&principal).log_dir();
        astrid_core::platform_fs::ensure_private_directory(&source).unwrap();
        let source_file = source.join("capsule").join("2026-01-01.log");
        astrid_core::platform_fs::ensure_private_directory(source_file.parent().unwrap()).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(&source_file, b"legacy log\n").unwrap();

        migrate_legacy_principal_logs(&home, &directory).unwrap();
        let destination = destination_root(&home, uid).join("capsule/2026-01-01.log");
        assert_eq!(fs::read(&destination).unwrap(), b"legacy log\n");
        assert!(!source.exists());
        assert_ne!(legacy_log_destination_proof(&home, uid).unwrap(), "absent");
        migrate_legacy_principal_logs(&home, &directory).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"legacy log\n");
    }

    #[test]
    fn empty_log_source_gets_a_receipt_without_a_destination_root() {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("astrid"));
        let principal = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([0x93; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let source = home.principal_home(&principal).log_dir();
        astrid_core::platform_fs::ensure_private_directory(&source).unwrap();

        migrate_legacy_principal_logs(&home, &directory).unwrap();
        assert!(!source.exists());
        assert!(!destination_root(&home, uid).exists());
        assert!(
            legacy_log_destination_proof(&home, uid)
                .unwrap()
                .starts_with("blake3:")
        );
        migrate_legacy_principal_logs(&home, &directory).unwrap();
    }

    #[test]
    fn live_log_growth_does_not_invalidate_the_import_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("astrid"));
        let principal = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([0x95; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let source = home.principal_home(&principal).log_dir();
        astrid_core::platform_fs::ensure_private_directory(&source).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(
            &source.join("capsule.log"),
            b"legacy log\n",
        )
        .unwrap();

        migrate_legacy_principal_logs(&home, &directory).unwrap();
        let proof = legacy_log_destination_proof(&home, uid).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(
            &destination_root(&home, uid).join("current-runtime.log"),
            b"current runtime log\n",
        )
        .unwrap();

        assert_eq!(legacy_log_destination_proof(&home, uid).unwrap(), proof);
    }

    #[test]
    fn tampered_log_receipt_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("astrid"));
        let principal = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([0x94; 32]);
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let source = home.principal_home(&principal).log_dir();
        astrid_core::platform_fs::ensure_private_directory(&source).unwrap();

        migrate_legacy_principal_logs(&home, &directory).unwrap();
        let receipt = receipt_path(&home, uid);
        let mut bytes = fs::read(&receipt).unwrap();
        bytes.push(b' ');
        astrid_core::platform_fs::atomic_write_private_file(&receipt, &bytes).unwrap();
        assert!(legacy_log_destination_proof(&home, uid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_redirected_log_entries() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("astrid"));
        let principal = PrincipalId::new("alice").unwrap();
        let directory = PrincipalDirectory::default();
        directory
            .register(principal.clone(), PrincipalUid::from_bytes([0x92; 32]))
            .unwrap();
        let source = home.principal_home(&principal).log_dir();
        astrid_core::platform_fs::ensure_private_directory(&source).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.log"), source.join("secret.log"))
            .unwrap();
        assert!(migrate_legacy_principal_logs(&home, &directory).is_err());
    }
}
