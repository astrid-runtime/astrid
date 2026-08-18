//! Migration of released per-principal distro provenance.
//!
//! `Distro.lock` used to live below a mutable principal alias.  The runtime
//! authority is now the UID-scoped `principal_control_kv(uid, "distro")`
//! projection; this module performs the one-way import and records a
//! receipt before retiring the exact legacy file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_core::kernel_api::{DistroCapsuleProvenance, DistroProvenance};
use astrid_core::principal::PrincipalId;
use astrid_storage::{PrincipalDirectory, RuntimePrincipalStore};
use serde::{Deserialize, Serialize};

const RECEIPT_SCHEMA: u32 = 1;
const RECEIPT_PREFIX: &str = "principal-distro-lock-";
const INIT_RECEIPT_PREFIX: &str = "principal-distro-init-lock-";
const RECEIPT_SUFFIX: &str = ".json";
const KEY: &str = "provenance";
const MAX_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_CAPSULES: usize = 4096;
const MAX_ID_BYTES: usize = 256;
const MAX_SOURCE_FIELD_BYTES: usize = 4096;

/// Receipt-compatible identity for a legacy distro source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistroSourceIdentity {
    pub(crate) digest: String,
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
    pub(crate) present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    uid: PrincipalUid,
    alias: PrincipalId,
    source_digest: String,
    source_bytes: u64,
    destination_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LegacyLock {
    schema_version: u32,
    distro: LegacyDistro,
    #[serde(default, rename = "capsule")]
    capsules: Vec<LegacyCapsule>,
    #[serde(default)]
    manifest_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LegacyDistro {
    id: String,
    version: String,
    resolved_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LegacyCapsule {
    name: String,
    version: String,
    source: String,
    hash: String,
    #[serde(default)]
    resolved_ref: Option<String>,
}

/// Import every released `Distro.lock` and retire each exact source file.
pub(crate) async fn migrate_legacy_distro_locks(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, uid) in directory.bindings() {
        migrate_one(home, store, &alias, uid).await?;
    }
    Ok(())
}

/// Snapshot one alias-bound distro lock without following redirects.
pub(crate) fn legacy_distro_source_snapshot(
    home: &AstridHome,
    alias: &PrincipalId,
) -> io::Result<DistroSourceIdentity> {
    snapshot_file(&distro_path(home, alias))
}

/// Snapshot one alias-bound disposable init lock using the same digest that
/// its verified-discard receipt records.
pub(crate) fn legacy_distro_init_source_snapshot(
    home: &AstridHome,
    alias: &PrincipalId,
) -> io::Result<DistroSourceIdentity> {
    snapshot_file(&init_path(home, alias))
}

/// Return the receipt digest for an imported distro lock, or `absent`.
pub(crate) fn legacy_distro_destination_proof(
    home: &AstridHome,
    uid: PrincipalUid,
) -> io::Result<String> {
    let path = receipt_path(home, uid);
    let Some(bytes) = read_bounded(&path, MAX_RECEIPT_BYTES)? else {
        return Ok("absent".to_owned());
    };
    let receipt = decode_receipt(&bytes, &path)?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.uid != uid {
        return Err(invalid(&path, "distro receipt identity mismatch"));
    }
    if canonical_json(&receipt)? != bytes {
        return Err(invalid(&path, "distro receipt is not canonical JSON"));
    }
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

/// Return the source-bound discard receipt for a released init lock.
pub(crate) fn legacy_distro_init_destination_proof(
    home: &AstridHome,
    uid: PrincipalUid,
) -> io::Result<String> {
    let path = init_receipt_path(home, uid);
    let Some(bytes) = read_bounded(&path, MAX_RECEIPT_BYTES)? else {
        return Ok("absent".to_owned());
    };
    let receipt: InitReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(&path, &format!("decode distro init receipt: {error}")))?;
    if receipt.schema != RECEIPT_SCHEMA || receipt.uid != uid {
        return Err(invalid(&path, "distro init receipt identity mismatch"));
    }
    if canonical_json(&receipt)? != bytes {
        return Err(invalid(&path, "distro init receipt is not canonical JSON"));
    }
    Ok(format!(
        "verified-discard-v1:source-digest={}",
        receipt.source_digest
    ))
}

/// Retire released `.config/distro.init.lock` files after recording an exact
/// source-bound discard receipt.
pub(crate) fn retire_legacy_distro_init_locks(
    home: &AstridHome,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, uid) in directory.bindings() {
        let source = init_path(home, &alias);
        let Some((digest, bytes)) = read_digest(&source)? else {
            continue;
        };
        let receipt = InitReceipt {
            schema: RECEIPT_SCHEMA,
            uid,
            alias: alias.clone(),
            source_digest: digest,
            source_bytes: bytes,
        };
        let receipt_path = init_receipt_path(home, uid);
        let encoded = canonical_json(&receipt)?;
        if let Some(existing) = read_bounded(&receipt_path, MAX_RECEIPT_BYTES)? {
            if existing != encoded {
                return Err(conflict(&receipt_path, "distro init receipt differs"));
            }
        } else {
            astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
            astrid_core::platform_fs::atomic_write_private_file(&receipt_path, &encoded)?;
        }
        let reread =
            read_digest(&source)?.ok_or_else(|| conflict(&source, "source disappeared"))?;
        if reread != (receipt.source_digest.clone(), receipt.source_bytes) {
            return Err(conflict(
                &source,
                "distro init source changed before discard",
            ));
        }
        fs::remove_file(&source)?;
        sync_parent(&source)?;
    }
    Ok(())
}

async fn migrate_one(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    alias: &PrincipalId,
    uid: PrincipalUid,
) -> io::Result<()> {
    let receipt_path = receipt_path(home, uid);
    if let Some(bytes) = read_bounded(&receipt_path, MAX_RECEIPT_BYTES)? {
        let receipt = decode_receipt(&bytes, &receipt_path)?;
        if receipt.schema != RECEIPT_SCHEMA || receipt.uid != uid || receipt.alias != *alias {
            return Err(conflict(
                &receipt_path,
                "distro receipt does not match source",
            ));
        }
        if canonical_json(&receipt)? != bytes {
            return Err(invalid(
                &receipt_path,
                "distro receipt is not canonical JSON",
            ));
        }
        let source = distro_path(home, alias);
        if let Some((source_digest, source_bytes)) = read_digest(&source)? {
            if receipt.source_digest != source_digest || receipt.source_bytes != source_bytes {
                return Err(conflict(
                    &receipt_path,
                    "distro receipt does not match source",
                ));
            }
            verify_destination(store, uid, &receipt.destination_digest).await?;
            return retire_source(&source, &receipt.source_digest, receipt.source_bytes);
        }
        verify_destination(store, uid, &receipt.destination_digest).await?;
        return Ok(());
    }
    let source = distro_path(home, alias);
    let Some((source_digest, source_bytes)) = read_digest(&source)? else {
        return Ok(());
    };
    let bytes = read_bounded(&source, MAX_SOURCE_BYTES)?
        .ok_or_else(|| invalid(&source, "distro source disappeared"))?;
    let reread =
        read_digest(&source)?.ok_or_else(|| invalid(&source, "distro source disappeared"))?;
    if reread != (source_digest.clone(), source_bytes) {
        return Err(conflict(&source, "distro source changed before import"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| invalid(&source, &format!("Distro.lock is not UTF-8: {error}")))?;
    let lock: LegacyLock = toml::from_str(text)
        .map_err(|error| invalid(&source, &format!("decode Distro.lock: {error}")))?;
    let provenance = convert_lock(lock)?;
    let encoded = serde_json::to_vec(&provenance).map_err(io::Error::other)?;
    let max_source_bytes = usize::try_from(MAX_SOURCE_BYTES)
        .map_err(|_| io::Error::other("distro source size does not fit this platform"))?;
    if encoded.len() > max_source_bytes {
        return Err(invalid(&source, "distro provenance exceeds size limit"));
    }
    let scoped = store
        .principal_control_kv(uid, "distro")
        .map_err(io::Error::other)?;
    let existing = scoped.get(KEY).await.map_err(io::Error::other)?;
    if let Some(current) = existing {
        if current != encoded {
            return Err(conflict(
                &source,
                "distro provenance conflicts with control KV",
            ));
        }
    } else if !scoped
        .compare_and_swap(KEY, None, encoded.clone())
        .await
        .map_err(io::Error::other)?
    {
        return Err(conflict(&source, "distro provenance CAS raced"));
    }
    let reread = scoped
        .get(KEY)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("distro provenance disappeared after write"))?;
    if reread != encoded {
        return Err(conflict(&source, "distro provenance read-back differs"));
    }
    let destination_digest = format!("blake3:{}", blake3::hash(&encoded).to_hex());
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA,
        uid,
        alias: alias.clone(),
        source_digest,
        source_bytes,
        destination_digest,
    };
    let receipt_bytes = canonical_json(&receipt)?;
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(&receipt_path, &receipt_bytes)?;
    retire_source(&source, &receipt.source_digest, receipt.source_bytes)
}

async fn verify_destination(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    expected_digest: &str,
) -> io::Result<()> {
    let scoped = store
        .principal_control_kv(uid, "distro")
        .map_err(io::Error::other)?;
    let bytes = scoped
        .get(KEY)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("distro provenance is missing after receipt"))?;
    let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    if actual != expected_digest {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "distro provenance receipt read-back differs",
        ));
    }
    Ok(())
}

fn convert_lock(lock: LegacyLock) -> io::Result<DistroProvenance> {
    let provenance = DistroProvenance {
        schema_version: lock.schema_version,
        distro_id: lock.distro.id,
        distro_version: lock.distro.version,
        resolved_at: lock.distro.resolved_at,
        capsules: lock
            .capsules
            .into_iter()
            .map(|capsule| DistroCapsuleProvenance {
                name: capsule.name,
                version: capsule.version,
                source: capsule.source,
                hash: capsule.hash,
                resolved_ref: capsule.resolved_ref,
            })
            .collect(),
        manifest_hash: lock.manifest_hash,
    };
    validate(&provenance)?;
    Ok(provenance)
}

fn validate(lock: &DistroProvenance) -> io::Result<()> {
    if lock.schema_version == 0 {
        return Err(invalid(Path::new("Distro.lock"), "schema version is zero"));
    }
    identifier(&lock.distro_id, "distro id")?;
    nonempty(&lock.distro_version, "distro version", MAX_ID_BYTES)?;
    nonempty(&lock.resolved_at, "resolved_at", MAX_ID_BYTES)?;
    if lock.capsules.len() > MAX_CAPSULES {
        return Err(invalid(Path::new("Distro.lock"), "too many capsules"));
    }
    if let Some(hash) = &lock.manifest_hash {
        digest(hash, "manifest hash")?;
    }
    let mut names = std::collections::BTreeSet::new();
    for capsule in &lock.capsules {
        identifier(&capsule.name, "capsule name")?;
        nonempty(&capsule.version, "capsule version", MAX_ID_BYTES)?;
        nonempty(&capsule.source, "capsule source", MAX_SOURCE_FIELD_BYTES)?;
        digest(&capsule.hash, "capsule hash")?;
        if let Some(reference) = &capsule.resolved_ref {
            nonempty(reference, "capsule resolved ref", MAX_ID_BYTES)?;
        }
        if !names.insert(&capsule.name) {
            return Err(invalid(Path::new("Distro.lock"), "duplicate capsule"));
        }
    }
    Ok(())
}

fn identifier(value: &str, field: &str) -> io::Result<()> {
    nonempty(value, field, MAX_ID_BYTES)?;
    if value.bytes().enumerate().any(|(index, byte)| {
        !(byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || (index > 0 && byte == b'_'))
    }) || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(invalid(
            Path::new("Distro.lock"),
            "non-canonical identifier",
        ));
    }
    Ok(())
}

fn nonempty(value: &str, field: &str, max: usize) -> io::Result<()> {
    if value.is_empty() || value.len() > max || value.bytes().any(|byte| byte == 0) {
        return Err(invalid(
            Path::new("Distro.lock"),
            &format!("invalid {field}"),
        ));
    }
    Ok(())
}

fn digest(value: &str, field: &str) -> io::Result<()> {
    if value.len() != 71
        || !value.starts_with("blake3:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            Path::new("Distro.lock"),
            &format!("invalid {field}"),
        ));
    }
    Ok(())
}

fn retire_source(path: &Path, expected_digest: &str, expected_bytes: u64) -> io::Result<()> {
    let actual = read_digest(path)?.ok_or_else(|| conflict(path, "source disappeared"))?;
    if actual != (expected_digest.to_owned(), expected_bytes) {
        return Err(conflict(path, "distro source changed before retirement"));
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

fn snapshot_file(path: &Path) -> io::Result<DistroSourceIdentity> {
    let Some((digest, bytes)) = read_digest(path)? else {
        return Ok(DistroSourceIdentity {
            digest: "absent".to_owned(),
            entries: 0,
            bytes: 0,
            present: false,
        });
    };
    Ok(DistroSourceIdentity {
        digest,
        entries: 1,
        bytes,
        present: true,
    })
}

fn read_digest(path: &Path) -> io::Result<Option<(String, u64)>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(path, "source is not a regular file"));
    }
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(invalid(path, "source exceeds size limit"));
    }
    if let Some(parent) = path.parent() {
        astrid_core::platform_fs::validate_private_directory(parent)?;
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    astrid_core::platform_fs::validate_private_file(path)?;
    let mut file = open_nofollow(path)?;
    let before = metadata.len();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| io::Error::other("read overflow"))?)
            .ok_or_else(|| io::Error::other("source byte count overflow"))?;
    }
    if bytes != before || fs::symlink_metadata(path)?.len() != before {
        return Err(conflict(path, "source changed while being read"));
    }
    Ok(Some((
        format!("blake3:{}", hasher.finalize().to_hex()),
        bytes,
    )))
}

fn read_bounded(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let Some((_, bytes)) = read_digest(path)? else {
        return Ok(None);
    };
    if bytes > max {
        return Err(invalid(path, "file exceeds size limit"));
    }
    let mut file = open_nofollow(path)?;
    let mut output = Vec::with_capacity(
        usize::try_from(bytes)
            .map_err(|_| io::Error::other("source does not fit this platform"))?,
    );
    file.read_to_end(&mut output)?;
    if u64::try_from(output.len()).ok() != Some(bytes) {
        return Err(conflict(path, "source changed while being read"));
    }
    Ok(Some(output))
}

fn decode_receipt(bytes: &[u8], path: &Path) -> io::Result<Receipt> {
    serde_json::from_slice(bytes)
        .map_err(|error| invalid(path, &format!("decode receipt: {error}")))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitReceipt {
    schema: u32,
    uid: PrincipalUid,
    alias: PrincipalId,
    source_digest: String,
    source_bytes: u64,
}

fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(io::Error::other)
}

fn distro_path(home: &AstridHome, alias: &PrincipalId) -> PathBuf {
    home.principal_home(alias).config_dir().join("distro.lock")
}

fn init_path(home: &AstridHome, alias: &PrincipalId) -> PathBuf {
    home.principal_home(alias)
        .config_dir()
        .join("distro.init.lock")
}

fn receipt_path(home: &AstridHome, uid: PrincipalUid) -> PathBuf {
    home.migrations_dir()
        .join(format!("{RECEIPT_PREFIX}{uid}{RECEIPT_SUFFIX}"))
}

fn init_receipt_path(home: &AstridHome, uid: PrincipalUid) -> PathBuf {
    home.migrations_dir()
        .join(format!("{INIT_RECEIPT_PREFIX}{uid}{RECEIPT_SUFFIX}"))
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

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn invalid(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("legacy distro {}: {detail}", path.display()),
    )
}

fn conflict(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("legacy distro conflict at {}: {detail}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_text() -> &'static str {
        "schema-version = 1\n\n[distro]\nid = \"example\"\nversion = \"1.0.0\"\nresolved-at = \"2026-01-01T00:00:00Z\"\n"
    }

    #[test]
    fn source_snapshot_counts_only_the_private_lock() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path().join("astrid"));
        let alias = PrincipalId::new("alice").unwrap();
        let path = distro_path(&home, &alias);
        astrid_core::platform_fs::ensure_private_directory(path.parent().unwrap()).unwrap();
        astrid_core::platform_fs::atomic_write_private_file(&path, lock_text().as_bytes()).unwrap();
        let snapshot = legacy_distro_source_snapshot(&home, &alias).unwrap();
        assert!(snapshot.present);
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.bytes, lock_text().len() as u64);
    }

    #[cfg(unix)]
    #[test]
    fn source_snapshot_rejects_redirects_and_non_private_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path().join("astrid"));
        let alias = PrincipalId::new("alice").unwrap();
        let path = distro_path(&home, &alias);
        astrid_core::platform_fs::ensure_private_directory(path.parent().unwrap()).unwrap();
        symlink(outside.path().join("lock"), &path).unwrap();
        assert!(legacy_distro_source_snapshot(&home, &alias).is_err());

        let _ = fs::remove_file(&path);
        fs::write(&path, lock_text()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(legacy_distro_source_snapshot(&home, &alias).is_err());
    }

    #[test]
    fn lock_validation_rejects_bad_hash_and_duplicate_capsules() {
        let mut lock = convert_lock(LegacyLock {
            schema_version: 1,
            distro: LegacyDistro {
                id: "example".into(),
                version: "1.0.0".into(),
                resolved_at: "2026-01-01T00:00:00Z".into(),
            },
            capsules: Vec::new(),
            manifest_hash: None,
        })
        .unwrap();
        lock.manifest_hash = Some("blake3:BAD".into());
        assert!(validate(&lock).is_err());
    }
}
