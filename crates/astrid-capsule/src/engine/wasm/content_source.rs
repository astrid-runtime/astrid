//! WASM executable source resolution for native and packed runtimes.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Source selected for one verified WASM load.
pub(super) enum WasmSource {
    /// Bytes reconstructed from the authoritative packed catalog.
    Bytes(Vec<u8>),
    /// Compatibility path used when no packed catalog entry is available.
    Path(PathBuf),
}

/// Read the expected executable hash from an installed capsule metadata file.
pub(super) fn read_expected_hash(capsule_dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(capsule_dir.join("meta.json")).ok()?;
    let meta: Value = serde_json::from_str(&content).ok()?;
    meta.get("wasm_hash")?.as_str().map(ToOwned::to_owned)
}

/// Resolve the host compatibility copy of a content-addressed executable.
pub(super) fn host_path(hash: Option<&str>) -> Option<PathBuf> {
    let hash = hash?;
    let home = astrid_core::dirs::AstridHome::resolve().ok()?;
    let wasm_path = home.bin_dir().join(format!("{hash}.wasm"));
    wasm_path.exists().then_some(wasm_path)
}

/// Reconstruct a content-addressed executable from the system-owned catalog.
#[cfg(not(target_family = "wasm"))]
pub(super) fn catalog_bytes(
    store: Option<&astrid_storage::RuntimePrincipalStore>,
    hash: Option<&str>,
) -> Option<Vec<u8>> {
    let store = store?;
    let hash = hash?;
    let name = astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).ok()?;
    let content = store.content();
    let descriptor = content
        .describe(&astrid_storage::StateOwner::System, &name)
        .ok()??;
    content
        .read_range(
            &astrid_storage::StateOwner::System,
            &name,
            0,
            descriptor.logical_bytes(),
        )
        .ok()?
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use astrid_core::dirs::AstridHome;

    fn unlimited_quota() -> Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> {
        Arc::new(|owner: &astrid_storage::StateOwner| {
            Ok(match owner {
                astrid_storage::StateOwner::System => None,
                astrid_storage::StateOwner::Principal(_) | astrid_storage::StateOwner::Fleet(_) => {
                    Some(u64::MAX)
                },
            })
        })
    }

    #[tokio::test]
    async fn catalog_bytes_reconstructs_system_bin_entry() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let bytes = b"\0asm\x01\0\0\0catalog-source".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let name = astrid_storage::ContentName::new(format!("bin/{hash}.wasm")).unwrap();
        store
            .content()
            .put(&astrid_storage::StateOwner::System, &name, &bytes)
            .unwrap();

        assert_eq!(catalog_bytes(Some(&store), Some(&hash)), Some(bytes));
        assert_eq!(catalog_bytes(Some(&store), Some("missing")), None);
    }
}
