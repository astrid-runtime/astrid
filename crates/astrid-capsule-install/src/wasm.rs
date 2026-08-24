//! Publish the capsule's WASM binary into the system-owned `bin/` catalog.
//!
//! The runtime always loads a capsule's executable from `bin/<hash>.wasm`
//! (see `astrid_capsule::engine::wasm::resolve_content_addressed_wasm`).
//! Install reads the WASM from the **source** path, BLAKE3-hashes it,
//! and publishes it to the packed catalog when a runtime store is bound.
//! Workspace-only installs retain a native compatibility cache.

use std::io::Cursor;
use std::path::Path;

use anyhow::Context;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;
use astrid_storage::{ContentIngest, ContentName, RuntimePrincipalStore, StateOwner};

/// Output of [`content_address_wasm`]: the content hash and bytes (so the
/// caller can hand them to lifecycle hooks without re-reading from disk).
pub struct WasmAddressed {
    /// BLAKE3 hex hash, also the basename of the catalog name in `bin/`.
    pub hash: String,
    /// Raw WASM bytes — passed to lifecycle hooks below.
    pub bytes: Vec<u8>,
}

/// Hash the WASM binary referenced by `manifest.components[0]` against
/// the **source** directory and publish it under `bin/<hash>.wasm`.
///
/// A storage-backed install publishes the executable through the system-owned
/// packed content catalog. Workspace-only installs retain the native
/// content-addressed file as a compatibility cache because they do not have a
/// durable runtime store bound to them.
///
/// Returns `Ok(None)` for non-WASM capsules (no components, or a
/// component path that doesn't resolve to a `.wasm` file). Catalog writes
/// are content-addressed: identical bytes converge on one entry.
pub fn content_address_wasm(
    home: &AstridHome,
    source_dir: &Path,
    manifest: &CapsuleManifest,
    storage: Option<&RuntimePrincipalStore>,
) -> anyhow::Result<Option<WasmAddressed>> {
    let Some(component) = manifest.components.first() else {
        return Ok(None);
    };

    let wasm_path = if component.path.is_absolute() {
        component.path.clone()
    } else {
        source_dir.join(&component.path)
    };

    if !wasm_path.exists() || wasm_path.extension().and_then(|e| e.to_str()) != Some("wasm") {
        return Ok(None);
    }

    let bytes = std::fs::read(&wasm_path)
        .with_context(|| format!("failed to read WASM binary: {}", wasm_path.display()))?;

    let hash = blake3::hash(&bytes).to_hex().to_string();
    if let Some(storage) = storage {
        let name = ContentName::new(format!("bin/{hash}.wasm"))
            .context("construct system WASM catalog name")?;
        storage
            .content()
            .put_streaming_batch(
                &StateOwner::System,
                [ContentIngest::new(name, Cursor::new(bytes.clone()))],
            )
            .map_err(|error| anyhow::anyhow!(error))
            .context("publish WASM into the system content catalog")?;
    } else {
        let bin_dir = home.bin_dir();
        std::fs::create_dir_all(&bin_dir)?;

        let store_path = bin_dir.join(format!("{hash}.wasm"));
        if !store_path.exists() {
            // Atomic temp-and-rename so a concurrent installer racing on
            // identical bytes never observes a half-written file.
            // A UUID-suffixed temp name is essential — `process::id()`
            // alone would collide between sibling tokio tasks in the
            // same daemon (gateway processes admin requests in parallel
            // after the bus-direct refactor).
            let tmp = bin_dir.join(format!("{hash}.tmp.{}", uuid::Uuid::new_v4().simple()));
            std::fs::write(&tmp, &bytes)
                .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
            match std::fs::rename(&tmp, &store_path) {
                Ok(()) => {},
                Err(_) if store_path.exists() => {
                    let _ = std::fs::remove_file(&tmp);
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e).with_context(|| {
                        format!("failed to rename temp file to {}", store_path.display())
                    });
                },
            }
        }
    }

    Ok(Some(WasmAddressed { hash, bytes }))
}

/// Read one verified executable from the system-owned content catalog.
pub(crate) fn read_catalog_wasm(
    storage: &RuntimePrincipalStore,
    hash: &str,
) -> anyhow::Result<Vec<u8>> {
    let name = ContentName::new(format!("bin/{hash}.wasm"))
        .context("construct system WASM catalog name")?;
    let descriptor = storage
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| anyhow::anyhow!(error))
        .context("describe WASM in system catalog")?
        .ok_or_else(|| anyhow::anyhow!("WASM catalog entry is missing: bin/{hash}.wasm"))?;
    storage
        .content()
        .read_range(&StateOwner::System, &name, 0, descriptor.logical_bytes())
        .map_err(|error| anyhow::anyhow!(error))
        .context("read WASM from system catalog")?
        .ok_or_else(|| anyhow::anyhow!("WASM catalog entry has no readable bytes: bin/{hash}.wasm"))
}

pub(crate) fn catalog_wasm_hash(
    storage: &RuntimePrincipalStore,
    expected: &str,
) -> anyhow::Result<String> {
    let actual = blake3::hash(&read_catalog_wasm(storage, expected)?)
        .to_hex()
        .to_string();
    anyhow::ensure!(
        actual == expected,
        "installed WASM integrity check failed: expected BLAKE3 {expected}, got {actual}"
    );
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capsule::discovery::load_manifest;
    use astrid_storage::{KvQuotaResolver, open_runtime_principal_store};
    use std::sync::Arc;

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    #[tokio::test]
    async fn storage_install_publishes_wasm_to_system_catalog() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        home.ensure().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            source_dir.path().join("Capsule.toml"),
            "[package]\nname = \"catalog-test\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n",
        )
        .unwrap();
        let bytes = wat::parse_str("(component)").unwrap();
        std::fs::write(source_dir.path().join("main.wasm"), &bytes).unwrap();
        let manifest = load_manifest(&source_dir.path().join("Capsule.toml")).unwrap();
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();

        let addressed = content_address_wasm(&home, source_dir.path(), &manifest, Some(&store))
            .unwrap()
            .unwrap();
        let name = ContentName::new(format!("bin/{}.wasm", addressed.hash)).unwrap();
        let descriptor = store
            .content()
            .describe(&StateOwner::System, &name)
            .unwrap()
            .expect("system catalog entry");
        let catalog_bytes = store
            .content()
            .read_range(&StateOwner::System, &name, 0, descriptor.logical_bytes())
            .unwrap()
            .expect("system catalog bytes");

        assert_eq!(catalog_bytes, bytes);
        assert!(
            !home
                .bin_dir()
                .join(format!("{}.wasm", addressed.hash))
                .exists()
        );
    }
}
