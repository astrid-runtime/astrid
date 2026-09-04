//! Capsule-install adapter for the durable Astrid package registry.
//!
//! This module is the boundary between the installer's manifest/authority
//! types and storage's opaque fixed-file package schema. Native directories
//! are treated as input or disposable materialization only. The durable
//! registry receives a deterministic `.capsule` archive, exact `meta.json`
//! bytes, and an exact serialized authority receipt before an install is
//! reported successful.

use std::fs::{self, File, Metadata, ReadDir};
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use astrid_build::artifact::{self, ArtifactVerification};
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_storage::{
    CapsuleInstallExpectation, CapsulePackage, CapsulePackageSnapshot, RuntimePrincipalStore,
    StateOwner,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};

use crate::authority::InstalledAuthority;
use crate::meta::CapsuleMeta;

/// One verified durable capsule generation.
///
/// The archive, metadata, and authority bytes are captured from one
/// `CapsuleRegistry` snapshot. The parsed values are derived from those bytes;
/// no native materialization path participates in authority or discovery.
#[derive(Clone, Debug)]
pub struct VerifiedDurableCapsulePackage {
    id: String,
    snapshot: CapsulePackageSnapshot,
    manifest: CapsuleManifest,
    manifest_bytes: Vec<u8>,
    archive_files: std::collections::BTreeMap<String, Vec<u8>>,
    archive_directories: std::collections::BTreeSet<String>,
    metadata: CapsuleMeta,
    metadata_bytes: Vec<u8>,
    authority: InstalledAuthority,
}

impl VerifiedDurableCapsulePackage {
    /// Return the canonical capsule identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the immutable registry generation used for verification.
    #[must_use]
    pub const fn snapshot(&self) -> &CapsulePackageSnapshot {
        &self.snapshot
    }

    /// Return the validated manifest parsed from the durable archive.
    #[must_use]
    pub const fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    /// Return the exact manifest bytes from the durable archive.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Return the validated install metadata from the durable package.
    #[must_use]
    pub const fn metadata(&self) -> &CapsuleMeta {
        &self.metadata
    }

    /// Return the validated authority receipt from the durable package.
    #[must_use]
    pub const fn authority(&self) -> &InstalledAuthority {
        &self.authority
    }

    /// Return the canonical archive bytes for direct reader-based loading.
    #[must_use]
    pub fn archive(&self) -> &[u8] {
        &self.snapshot.package().archive
    }

    /// Return one verified WIT blob by its metadata-relative path.
    #[must_use]
    pub fn wit_file(&self, relative: &str) -> Option<&[u8]> {
        self.archive_files
            .get(&format!("wit/{relative}"))
            .map(Vec::as_slice)
    }

    /// Return one verified file from the durable archive.
    #[must_use]
    pub fn archive_file(&self, relative: &str) -> Option<&[u8]> {
        self.archive_files.get(relative).map(Vec::as_slice)
    }

    /// Iterate every verified archive member without exposing internal storage.
    pub fn archive_entries(&self) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        self.archive_files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// Iterate authenticated archive directory names without exposing storage.
    pub fn archive_directories(&self) -> impl Iterator<Item = &str> + '_ {
        self.archive_directories.iter().map(String::as_str)
    }

    /// Return the exact durable metadata bytes.
    #[must_use]
    pub fn metadata_bytes(&self) -> &[u8] {
        &self.metadata_bytes
    }

    /// Return all verified WIT blobs as `(relative_path, bytes)` pairs.
    #[must_use]
    pub fn wit_files(&self) -> Vec<(String, Vec<u8>)> {
        self.archive_files
            .iter()
            .filter_map(|(path, bytes)| {
                path.strip_prefix("wit/")
                    .map(|relative| (relative.to_owned(), bytes.clone()))
            })
            .collect()
    }
}

/// Read and verify one UID-owned durable package from one immutable registry
/// snapshot. A missing package returns `Ok(None)`; malformed, tampered, or
/// internally inconsistent package bytes fail closed.
pub fn read_verified_durable_package(
    store: &RuntimePrincipalStore,
    uid: astrid_core::identity::PrincipalUid,
    id: &str,
) -> anyhow::Result<Option<VerifiedDurableCapsulePackage>> {
    let owner = StateOwner::Principal(uid);
    read_verified_durable_package_for_owner(store, &owner, id)
}

/// Read and verify one durable package for an arbitrary storage owner.
///
/// System and Fleet callers use this form; principal-facing callers should
/// prefer [`read_verified_durable_package`], which takes an immutable UID.
pub fn read_verified_durable_package_for_owner(
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    id: &str,
) -> anyhow::Result<Option<VerifiedDurableCapsulePackage>> {
    let registry = store.capsules();
    let Some(snapshot) = registry.get_snapshot(owner, id)? else {
        return Ok(None);
    };
    let package = snapshot.package();
    let verification = artifact::verify_archive_bytes(&package.archive)
        .with_context(|| format!("verify durable capsule archive {id}"))?;
    let inventory = read_archive_files(&package.archive)?;
    let ArchiveInventory { files, directories } = inventory;
    let manifest_bytes = files
        .get("Capsule.toml")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("durable capsule {id} is missing Capsule.toml"))?;
    let manifest_text = String::from_utf8(manifest_bytes.clone())
        .with_context(|| format!("durable capsule {id} manifest is not UTF-8"))?;
    let manifest: CapsuleManifest = toml::from_str(&manifest_text)
        .with_context(|| format!("decode durable capsule {id} manifest"))?;
    let metadata: CapsuleMeta = serde_json::from_slice(&package.metadata)
        .with_context(|| format!("decode durable capsule {id} metadata"))?;
    let authority: InstalledAuthority = serde_json::from_slice(&package.authority)
        .with_context(|| format!("decode durable capsule {id} authority"))?;
    let metadata_bytes = package.metadata.clone();
    verify_package_identity(
        id,
        &manifest,
        &metadata,
        &authority,
        &manifest_bytes,
        &verification,
        &files,
    )?;
    verify_wit_files(id, &metadata, &files)?;
    Ok(Some(VerifiedDurableCapsulePackage {
        id: id.to_owned(),
        snapshot,
        manifest,
        manifest_bytes,
        archive_files: files,
        archive_directories: directories,
        metadata,
        metadata_bytes,
        authority,
    }))
}

fn verify_wit_files(
    id: &str,
    metadata: &CapsuleMeta,
    files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    let mut expected = std::collections::BTreeSet::new();
    for (relative, pin) in &metadata.wit_files {
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("durable capsule {id} has unsafe WIT metadata path {relative}");
        }
        let key = format!("wit/{relative}");
        let Some(bytes) = files.get(&key) else {
            bail!("durable capsule {id} is missing WIT file {relative}");
        };
        if !is_hex_digest(pin) || blake3::hash(bytes).to_hex().as_str() != pin {
            bail!("durable capsule {id} WIT digest mismatch for {relative}");
        }
        expected.insert(key);
    }
    for key in files.keys().filter(|key| key.starts_with("wit/")) {
        if Path::new(key)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wit"))
            && !expected.contains(key)
        {
            bail!("durable capsule {id} has an unpinned WIT file {key}");
        }
    }
    Ok(())
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn verify_package_identity(
    id: &str,
    manifest: &CapsuleManifest,
    metadata: &CapsuleMeta,
    authority: &InstalledAuthority,
    manifest_bytes: &[u8],
    verification: &ArtifactVerification,
    archive_files: &std::collections::BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    if authority.schema_version != 1 {
        bail!(
            "durable capsule {id} has unsupported authority schema {}",
            authority.schema_version
        );
    }
    if authority.capsule_id != id || manifest.package.name != id {
        bail!("durable capsule {id} identity differs across archive and authority");
    }
    if authority.version != manifest.package.version || metadata.version != authority.version {
        bail!("durable capsule {id} version differs across package records");
    }
    let manifest_digest = crate::authority::digest_manifest(manifest_bytes);
    if authority.manifest_digest != manifest_digest {
        bail!("durable capsule {id} manifest digest differs from authority receipt");
    }
    if authority.content_digest != verification.content_digest() {
        bail!("durable capsule {id} content digest differs from authority receipt");
    }
    let expected_imports = crate::wit::version_map_to_strings(&manifest.imports, |definition| {
        definition.version.to_string()
    });
    if metadata.imports != expected_imports {
        bail!("durable capsule {id} imports differ between metadata and archive");
    }
    let expected_exports = crate::wit::version_map_to_strings(&manifest.exports, |definition| {
        definition.version.to_string()
    });
    if metadata.exports != expected_exports {
        bail!("durable capsule {id} exports differ between metadata and archive");
    }
    if authority.wasm_hash_pinned && metadata.wasm_hash != authority.approved_wasm_hash {
        bail!("durable capsule {id} metadata executable hash differs from authority receipt");
    }
    if let Some(component) = manifest.components.first() {
        let Some(relative) = component.path.to_str() else {
            bail!("durable capsule {id} component path is not UTF-8");
        };
        let Some(bytes) = archive_files.get(relative) else {
            bail!("durable capsule {id} component is missing from its archive");
        };
        if Path::new(relative)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
        {
            let archive_hash = blake3::hash(bytes).to_hex().to_string();
            if authority.wasm_hash_pinned
                && authority.approved_wasm_hash.as_deref() != Some(archive_hash.as_str())
            {
                bail!("durable capsule {id} WASM hash differs between authority and archive");
            }
            if metadata.wasm_hash.as_deref() != Some(archive_hash.as_str()) {
                bail!("durable capsule {id} WASM hash differs between metadata and archive");
            }
        } else if metadata.wasm_hash.is_some() {
            bail!("durable capsule {id} metadata names a hash for a non-WASM component");
        }
    } else if metadata.wasm_hash.is_some() {
        bail!("durable capsule {id} metadata names a component absent from its archive");
    }
    let mut effective_capabilities = manifest.capabilities.clone();
    for component in &manifest.components {
        if let Some(capabilities) = &component.capabilities {
            effective_capabilities.merge_from(capabilities);
        }
    }
    if !effective_capabilities
        .expansions_from(&authority.approved_capabilities)
        .is_empty()
    {
        bail!("durable capsule {id} manifest exceeds its authority receipt");
    }
    match verification {
        ArtifactVerification::Signed(provenance) => {
            let signer = provenance.signer.to_string();
            let signature = provenance.signature.to_string();
            if authority.signer.as_deref() != Some(signer.as_str())
                || authority.signature.as_deref() != Some(signature.as_str())
            {
                bail!("durable capsule {id} provenance differs from authority receipt");
            }
        },
        ArtifactVerification::Unsigned { .. } => {
            if authority.signer.is_some() || authority.signature.is_some() {
                bail!("durable capsule {id} authority claims provenance absent from archive");
            }
        },
    }
    Ok(())
}

struct ArchiveInventory {
    files: std::collections::BTreeMap<String, Vec<u8>>,
    directories: std::collections::BTreeSet<String>,
}

fn read_archive_files(archive_bytes: &[u8]) -> anyhow::Result<ArchiveInventory> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = std::collections::BTreeMap::new();
    let mut directories = std::collections::BTreeSet::new();
    for entry in archive.entries().context("read durable capsule archive")? {
        let mut entry = entry.context("read durable capsule archive entry")?;
        let path = entry.path().context("read durable capsule archive path")?;
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            bail!("durable capsule archive contains unsafe path");
        }

        let entry_type = entry.header().entry_type();
        if !entry_type.is_dir() && !entry_type.is_file() {
            bail!("durable capsule archive contains a link or special file");
        }

        let name = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("durable capsule archive path is not UTF-8"))?
            .replace('\\', "/");
        if files.contains_key(&name) || directories.contains(&name) {
            bail!("durable capsule archive contains duplicate path {name}");
        }
        if entry_type.is_dir() {
            if !directories.insert(name) {
                bail!("durable capsule archive contains duplicate directory path");
            }
            continue;
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("read durable capsule archive file {name}"))?;
        files.insert(name, bytes);
    }
    Ok(ArchiveInventory { files, directories })
}

/// Publish one source directory into the target principal's durable registry.
///
/// The source tree is canonicalized to a deterministic gzip/tar archive. The
/// package is committed as one content batch; a failed publication therefore
/// leaves the prior package authoritative. Existing durable content is used as
/// the expected generation for upgrades, so a stale installer receives a
/// conflict instead of silently overwriting a concurrent update.
pub fn publish_directory_package(
    store: &Arc<RuntimePrincipalStore>,
    principal: &PrincipalId,
    source_dir: &Path,
    target_dir: &Path,
    meta: &CapsuleMeta,
    authority: &InstalledAuthority,
) -> anyhow::Result<()> {
    let uid = store
        .principal_directory()
        .uid_for(principal)
        .with_context(|| format!("resolve durable uid for principal {principal}"))?;
    let (manifest_id, manifest_version) = manifest_identity(source_dir)?;
    if authority.capsule_id != manifest_id
        || authority.version != manifest_version
        || meta.version != authority.version
    {
        bail!("capsule metadata/authority does not match source manifest");
    }
    let archive = canonical_capsule_archive(source_dir)?;
    let verification = artifact::verify_archive_bytes(&archive)
        .context("verify canonical durable capsule archive")?;
    let mut durable_authority = authority.clone();
    // Directory approval binds the complete checked source tree, while the
    // durable package intentionally omits build/VCS/cache material. Rebind the
    // receipt to the deterministic package produced by that trusted transform;
    // the manifest/capability/WASM pins remain unchanged and are verified
    // again below before publication succeeds.
    verification
        .content_digest()
        .clone_into(&mut durable_authority.content_digest);
    let metadata = fs::read(target_dir.join("meta.json")).with_context(|| {
        format!(
            "read generated capsule metadata from {}",
            target_dir.display()
        )
    })?;
    let authority = serde_json::to_vec_pretty(&durable_authority)
        .context("serialize installed capsule authority receipt")?;
    let registry = store.capsules();
    let owner = StateOwner::Principal(uid);
    let id = authority_capsule_id(&authority)?;
    let expected = registry
        .get_snapshot(&owner, &id)?
        .map_or(CapsuleInstallExpectation::Absent, |snapshot| {
            CapsuleInstallExpectation::Generation(snapshot.generation())
        });
    let package = CapsulePackage::new(archive, metadata, authority);
    let materialization = tempfile::Builder::new()
        .prefix(".capsule-materialization-")
        .tempdir_in(
            target_dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("capsule target has no parent"))?,
        )
        .context("stage verified durable capsule materialization")?;
    let staged_target = materialization.path().join("package");
    materialize_capsule_package(&package, &staged_target)
        .context("stage verified durable capsule package")?;

    // Storage-backed installs initially assemble a lifecycle workspace that
    // intentionally omits the WASM component. Replace it with the complete
    // verified package before publication so an immediately triggered live
    // reload sees the same bytes that a restart would rematerialize.
    let previous_target = materialization.path().join("previous");
    fs::rename(target_dir, &previous_target)
        .context("stage incomplete capsule install cache for replacement")?;
    if let Err(error) = fs::rename(&staged_target, target_dir) {
        let _ = fs::rename(&previous_target, target_dir);
        return Err(error).context("publish verified capsule materialization");
    }

    registry
        .install(&owner, &id, &package, expected)
        .with_context(|| format!("publish durable capsule package {id} for {principal}"))?;
    read_verified_durable_package(store, uid, &id)?
        .ok_or_else(|| anyhow::anyhow!("durable capsule {id} disappeared after publish"))?;
    Ok(())
}

/// Publish a package when the caller already has canonical bytes.
///
/// This is used by archive migration and by tests that have no source
/// directory to materialize. The caller must provide the immutable principal
/// UID, so alias reuse cannot redirect the package to a different owner.
pub fn publish_package(
    store: &Arc<RuntimePrincipalStore>,
    uid: astrid_core::identity::PrincipalUid,
    id: &str,
    package: &CapsulePackage,
) -> anyhow::Result<()> {
    let owner = StateOwner::Principal(uid);
    let registry = store.capsules();
    let expected = registry
        .get_snapshot(&owner, id)?
        .map_or(CapsuleInstallExpectation::Absent, |snapshot| {
            CapsuleInstallExpectation::Generation(snapshot.generation())
        });
    registry.install(&owner, id, package, expected)?;
    read_verified_durable_package(store, uid, id)?
        .ok_or_else(|| anyhow::anyhow!("durable capsule {id} disappeared after publish"))?;
    Ok(())
}

/// Read authoritative installation metadata for one alias without touching
/// the disposable materialization cache.
pub fn read_durable_meta(
    store: &Arc<RuntimePrincipalStore>,
    principal: &PrincipalId,
    id: &str,
) -> anyhow::Result<Option<CapsuleMeta>> {
    let uid = store
        .principal_directory()
        .uid_for(principal)
        .with_context(|| format!("resolve durable uid for principal {principal}"))?;
    Ok(read_verified_durable_package(store, uid, id)?.map(|package| package.metadata().clone()))
}

/// Materialize a verified durable package into a fresh disposable directory.
///
/// This helper is for loaders whose current host ABI still accepts a path. It
/// never establishes authority: callers must retain the package snapshot and
/// digest, and the destination must be a new cache generation. Archive paths,
/// links, special files, duplicate entries, and symlinked parents are rejected
/// before any bytes are written. Exact metadata and authority sidecars are
/// restored from the package bytes, not trusted from the archive.
pub fn materialize_capsule_package(
    package: &CapsulePackage,
    destination: &Path,
) -> anyhow::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("capsule materialization destination is not a directory")
        },
        Ok(_) => bail!("capsule materialization destination already exists"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", destination.display()));
        },
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create materialization parent {}", parent.display()))?;
    }
    fs::create_dir(destination)
        .with_context(|| format!("create materialization {}", destination.display()))?;
    let decoder = flate2::read::GzDecoder::new(Cursor::new(&package.archive));
    let mut archive = tar::Archive::new(decoder);
    let mut names = std::collections::BTreeSet::new();
    for entry in archive.entries().context("read durable capsule archive")? {
        let mut entry = entry.context("read durable capsule archive entry")?;
        let path = entry.path().context("read durable capsule archive path")?;
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            bail!("durable capsule archive contains unsafe path");
        }
        let relative = path.to_path_buf();
        if !names.insert(relative.clone()) {
            bail!("durable capsule archive contains duplicate path");
        }
        let output = destination.join(&relative);
        if entry.header().entry_type().is_symlink()
            || entry.header().entry_type().is_hard_link()
            || entry.header().entry_type().is_block_special()
            || entry.header().entry_type().is_character_special()
            || entry.header().entry_type().is_fifo()
        {
            bail!("durable capsule archive contains a link or special file");
        }
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&output)
                .with_context(|| format!("create materialized directory {}", output.display()))?;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!("durable capsule archive contains an unsupported entry");
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create materialized parent {}", parent.display()))?;
            reject_symlink_ancestors(destination, parent)?;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .context("read durable capsule archive file")?;
        fs::write(&output, bytes)
            .with_context(|| format!("write materialized file {}", output.display()))?;
    }
    fs::write(destination.join("meta.json"), &package.metadata)
        .context("write materialized capsule metadata")?;
    fs::write(destination.join("authority.json"), &package.authority)
        .context("write materialized capsule authority")?;
    Ok(())
}

fn reject_symlink_ancestors(root: &Path, path: &Path) -> anyhow::Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("materialization path escaped destination"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!("materialization parent is a symlink: {}", current.display());
        }
    }
    Ok(())
}

mod leftover;
mod migration;

pub use leftover::retire_unmatched_legacy_authority_receipts;
pub use migration::{
    LegacyCapsuleAuthorityReceipt, LegacyCapsuleMigrationReport, LegacyEnvSecretImportStatus,
    legacy_capsule_authority_status, legacy_env_secret_import_status, migrate_all_native_capsules,
    migrate_all_native_capsules_with_report, migrate_native_capsules,
    migrate_native_capsules_with_report,
};

fn canonical_legacy_archive(
    home: &astrid_core::dirs::AstridHome,
    target: &Path,
    meta: &CapsuleMeta,
    manifest: &astrid_capsule::manifest::CapsuleManifest,
) -> anyhow::Result<Vec<u8>> {
    let staging = tempfile::tempdir().context("stage legacy capsule for migration")?;
    copy_legacy_tree(target, staging.path())?;
    if let Some(component) = manifest.components.first() {
        let component_path = component.path.clone();
        if component_path.is_absolute()
            || component_path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            bail!("legacy capsule component path is not relative");
        }
        let Some(hash) = meta.wasm_hash.as_deref() else {
            bail!("legacy capsule metadata has no WASM hash");
        };
        let wasm = home.bin_dir().join(format!("{hash}.wasm"));
        let destination = staging.path().join(component_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&wasm, &destination).with_context(|| {
            format!("restore content-addressed WASM blob for {}", wasm.display())
        })?;
    }
    for (relative, hash) in &meta.wit_files {
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::RootDir
                )
            })
        {
            bail!(
                "legacy capsule WIT path is not relative: {}",
                relative.display()
            );
        }
        let source = home.wit_store_dir().join(format!("{hash}.wit"));
        let destination = staging.path().join("wit").join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&source, &destination)
            .with_context(|| format!("restore content-addressed WIT blob {hash}"))?;
    }
    canonical_capsule_archive(staging.path())
}

fn copy_legacy_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination)?;
    for (path, metadata) in read_dir_sorted(source)? {
        let relative = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("legacy capsule entry has no name"))?;
        let destination = destination.join(relative);
        if metadata.file_type().is_symlink() {
            bail!("legacy capsule contains symlink {}", path.display());
        }
        if metadata.is_dir() {
            copy_legacy_tree(&path, &destination)?;
        } else if metadata.is_file() {
            let name = path.file_name().and_then(|name| name.to_str());
            if matches!(name, Some("meta.json" | "authority.json" | ".env.json")) {
                continue;
            }
            fs::copy(path, destination)?;
        } else {
            bail!("legacy capsule contains special file {}", path.display());
        }
    }
    Ok(())
}

fn manifest_identity(source_dir: &Path) -> anyhow::Result<(String, String)> {
    let manifest = fs::read_to_string(source_dir.join("Capsule.toml"))
        .with_context(|| format!("read capsule manifest from {}", source_dir.display()))?;
    let value: toml::Value = toml::from_str(&manifest).context("parse capsule manifest")?;
    let id = value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Capsule.toml has no package.name"))?;
    let version = value
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Capsule.toml has no package.version"))?;
    Ok((id.to_owned(), version.to_owned()))
}

fn authority_capsule_id(authority: &[u8]) -> anyhow::Result<String> {
    let authority: InstalledAuthority =
        serde_json::from_slice(authority).context("decode authority receipt for package id")?;
    if authority.capsule_id.is_empty() {
        bail!("authority receipt has an empty capsule id");
    }
    Ok(authority.capsule_id)
}

/// Build a deterministic gzip/tar package from a checked directory.
pub fn canonical_capsule_archive(source_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let mut entries = Vec::new();
    collect_entries(source_dir, source_dir, &mut entries)?;
    if !entries
        .iter()
        .any(|(path, _)| path == Path::new("Capsule.toml"))
    {
        bail!("capsule source has no Capsule.toml");
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let output = Vec::new();
    let encoder = GzEncoder::new(output, Compression::default());
    let mut builder = Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);
    for (relative, metadata) in entries {
        append_entry(&mut builder, source_dir, &relative, &metadata)?;
    }
    let encoder = builder
        .into_inner()
        .context("finish canonical capsule tar stream")?;
    encoder
        .finish()
        .context("finish canonical capsule gzip stream")
}

fn collect_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(PathBuf, Metadata)>,
) -> anyhow::Result<()> {
    let mut children = read_dir_sorted(current)?;
    for (name, metadata) in children.drain(..) {
        let relative = name
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("capsule path escaped source root"))?
            .to_path_buf();
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let resolved = fs::canonicalize(&name).with_context(|| {
                format!("canonicalize capsule source symlink {}", relative.display())
            })?;
            let canonical_root = fs::canonicalize(root)
                .with_context(|| format!("canonicalize capsule source root {}", root.display()))?;
            if !resolved.starts_with(&canonical_root) {
                bail!(
                    "capsule source symlink {} resolves outside source root",
                    relative.display()
                );
            }
            let resolved_metadata = fs::metadata(&resolved).with_context(|| {
                format!("stat capsule source symlink target {}", relative.display())
            })?;
            if !resolved_metadata.is_file() {
                bail!(
                    "capsule source symlink {} does not resolve to a regular file",
                    relative.display()
                );
            }
            // File links are materialized as regular archive entries. This
            // preserves npm's node_modules/.bin links without ever storing a
            // redirect in the durable package.
            entries.push((relative, resolved_metadata));
            continue;
        }
        if file_type.is_dir() {
            if relative.file_name().and_then(|name| name.to_str()) == Some(".git")
                || relative.file_name().and_then(|name| name.to_str()) == Some("target")
            {
                continue;
            }
            // Directory entries are included so empty directories survive
            // archive round-trips; their descendants are sorted recursively.
            entries.push((relative.clone(), metadata));
            collect_entries(root, &name, entries)?;
        } else if file_type.is_file() {
            let name = relative.file_name().and_then(|name| name.to_str());
            if matches!(
                name,
                Some("meta.json" | "authority.json" | ".env" | ".env.json")
            ) {
                continue;
            }
            entries.push((relative, metadata));
        } else {
            bail!(
                "capsule source contains unsupported special file {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn read_dir_sorted(path: &Path) -> anyhow::Result<Vec<(PathBuf, Metadata)>> {
    let mut children = Vec::new();
    let entries: ReadDir = fs::read_dir(path)
        .with_context(|| format!("read capsule source directory {}", path.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read child of {}", path.display()))?;
        let name = entry.path();
        let metadata = fs::symlink_metadata(&name)
            .with_context(|| format!("inspect capsule source entry {}", name.display()))?;
        children.push((name, metadata));
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(children)
}

fn append_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    root: &Path,
    relative: &Path,
    metadata: &Metadata,
) -> anyhow::Result<()> {
    let path = relative
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("capsule path is not valid UTF-8"))?;
    if path.starts_with('/') || path.split('/').any(|part| part == ".." || part.is_empty()) {
        bail!("capsule path is not canonical: {path}");
    }
    let mut header = Header::new_gnu();
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_mode(if metadata.is_dir() { 0o755 } else { 0o644 });
    if metadata.is_dir() {
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, path, io::empty())
            .with_context(|| format!("append capsule directory {path}"))?;
    } else {
        let mut file =
            File::open(root.join(relative)).with_context(|| format!("open capsule file {path}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("read capsule file {path}"))?;
        if bytes.len() as u64 != metadata.len() {
            bail!("capsule source changed while archiving {path}");
        }
        header.set_entry_type(EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(&bytes))
            .with_context(|| format!("append capsule file {path}"))?;
        // Ensure the source was not swapped while it was read. The archive is
        // only authoritative after a caller has separately verified its
        // digest/receipt; this check turns a common TOCTOU into a hard error.
        let mut second = File::open(root.join(relative))?;
        let mut second_bytes = Vec::new();
        second.read_to_end(&mut second_bytes)?;
        if second_bytes != bytes {
            bail!("capsule source changed while archiving {path}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn canonical_archive_rejects_symlink_and_special_entries() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("Capsule.toml"),
            b"[package]\nname='demo'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            let outside = tempdir().unwrap();
            fs::write(outside.path().join("outside"), b"outside").unwrap();
            std::os::unix::fs::symlink(outside.path().join("outside"), root.path().join("link"))
                .unwrap();
        }
        #[cfg(unix)]
        assert!(canonical_capsule_archive(root.path()).is_err());
    }

    #[test]
    fn canonical_archive_is_stable_for_directory_order() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        for root in [first.path(), second.path()] {
            fs::write(root.join("Capsule.toml"), b"[package]\nname='demo'\n").unwrap();
            fs::create_dir(root.join("assets")).unwrap();
            fs::write(root.join("assets/z"), b"z").unwrap();
            fs::write(root.join("assets/a"), b"a").unwrap();
        }
        assert_eq!(
            canonical_capsule_archive(first.path()).unwrap(),
            canonical_capsule_archive(second.path()).unwrap()
        );
    }

    #[test]
    fn materialize_round_trip_restores_exact_receipts_and_rejects_reuse() {
        let source = tempdir().unwrap();
        fs::write(
            source.path().join("Capsule.toml"),
            b"[package]\nname='demo'\n",
        )
        .unwrap();
        fs::create_dir(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/file"), b"bytes").unwrap();
        let package = CapsulePackage::new(
            canonical_capsule_archive(source.path()).unwrap(),
            br#"{"version":"1"}"#.to_vec(),
            br#"{"capsule_id":"demo"}"#.to_vec(),
        );
        let cache_root = tempdir().unwrap();
        let destination = cache_root.path().join("materialized");
        materialize_capsule_package(&package, &destination).unwrap();
        assert_eq!(fs::read(destination.join("nested/file")).unwrap(), b"bytes");
        assert_eq!(
            fs::read(destination.join("meta.json")).unwrap(),
            package.metadata
        );
        assert_eq!(
            fs::read(destination.join("authority.json")).unwrap(),
            package.authority
        );
        assert!(materialize_capsule_package(&package, &destination).is_err());
    }
}

#[cfg(test)]
mod durable_metadata_tests;
