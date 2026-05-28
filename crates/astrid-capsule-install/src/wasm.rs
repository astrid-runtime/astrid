//! Content-address the capsule's WASM binary into the shared `bin/` store.
//!
//! The runtime always loads a capsule's executable from `bin/<hash>.wasm`
//! (see `astrid_capsule::engine::wasm::resolve_content_addressed_wasm`).
//! Install reads the WASM from the **source** path, BLAKE3-hashes it,
//! and writes it to the content-addressed store. The per-capsule
//! directory never contains a `.wasm` file — it's a manifest+env
//! pointer package, not the executable itself.

use std::path::{Path, PathBuf};

use anyhow::Context;
use astrid_capsule::manifest::CapsuleManifest;
use astrid_core::dirs::AstridHome;

/// Output of [`content_address_wasm`]: where the WASM ended up in the
/// content store, plus the bytes it contained (so the caller can hand
/// them to lifecycle hooks without re-reading from disk).
pub struct WasmAddressed {
    /// BLAKE3 hex hash, also the basename of the file in `bin/`.
    pub hash: String,
    /// Full path of `bin/<hash>.wasm`.
    pub store_path: PathBuf,
    /// Raw WASM bytes — passed to lifecycle hooks below.
    pub bytes: Vec<u8>,
}

/// Hash the WASM binary referenced by `manifest.components[0]` against
/// the **source** directory and write it to `home.bin_dir()/<hash>.wasm`.
///
/// Returns `Ok(None)` for non-WASM capsules (no components, or a
/// component path that doesn't resolve to a `.wasm` file). The blob
/// store is append-only: a second install of identical bytes is a
/// no-op (atomic temp-and-rename so concurrent writers converge).
pub fn content_address_wasm(
    home: &AstridHome,
    source_dir: &Path,
    manifest: &CapsuleManifest,
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

    Ok(Some(WasmAddressed {
        hash,
        store_path,
        bytes,
    }))
}
