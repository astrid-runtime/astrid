//! One authoritative verification path for staged and durable package bytes.

use anyhow::Context;
use astrid_build::artifact;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_storage::CapsulePackage;

use crate::authority::InstalledAuthority;
use crate::meta::CapsuleMeta;

use super::{ArchiveInventory, read_archive_files, verify_package_identity, verify_wit_files};

pub(super) struct VerifiedPackageContents {
    pub(super) manifest: CapsuleManifest,
    pub(super) manifest_bytes: Vec<u8>,
    pub(super) files: std::collections::BTreeMap<String, Vec<u8>>,
    pub(super) directories: std::collections::BTreeSet<String>,
    pub(super) metadata: CapsuleMeta,
    pub(super) authority: InstalledAuthority,
}

/// Verify every authoritative package field before registry publication or use.
pub(super) fn verify_package_contents(
    id: &str,
    package: &CapsulePackage,
) -> anyhow::Result<VerifiedPackageContents> {
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
    Ok(VerifiedPackageContents {
        manifest,
        manifest_bytes,
        files,
        directories,
        metadata,
        authority,
    })
}
