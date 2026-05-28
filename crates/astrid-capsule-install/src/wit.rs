//! Content-address WIT files into the shared `wit/` store.
//!
//! Read-only with respect to the source: we hash files in
//! `source_dir/wit/` and write the BLAKE3-keyed blobs to
//! `home.wit_dir()`. The source tree is **never** modified — that
//! mattered when source and target were the same directory (the old
//! CLI install staged everything in `target_dir`), but matters even
//! more now because the kernel-side handler may be installing from
//! a path the operator handed in (a checkout, an unpacked archive)
//! that we have no business mutating.
//!
//! The store is append-only from the installer's perspective. Blobs
//! are never deleted on uninstall, only by an explicit admin GC.
//! This lets a historic capsule state be reconstructed as long as
//! the blobs it referenced still exist.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;

/// Content-address all `.wit` files under `source_dir/wit/`
/// (recursively) into the system-wide BLAKE3 store at
/// `home.wit_dir()`. Returns a map of relative path under `wit/` →
/// BLAKE3 hex. Returns an empty map (not an error) when the source
/// has no `wit/` directory.
pub fn content_address_wit(
    home: &AstridHome,
    source_dir: &Path,
) -> anyhow::Result<HashMap<String, String>> {
    let wit_source = source_dir.join("wit");
    let mut hashes = HashMap::new();

    if !wit_source.is_dir() {
        return Ok(hashes);
    }

    let wit_store = home.wit_dir();
    std::fs::create_dir_all(&wit_store)?;

    content_address_wit_recursive(&wit_source, &wit_source, &wit_store, &mut hashes)?;

    Ok(hashes)
}

fn content_address_wit_recursive(
    wit_root: &Path,
    current: &Path,
    wit_store: &Path,
    hashes: &mut HashMap<String, String>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("failed to read {}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            content_address_wit_recursive(wit_root, &path, wit_store, hashes)?;
            continue;
        }

        if !file_type.is_file() || path.extension().and_then(|e| e.to_str()) != Some("wit") {
            continue;
        }

        // 1 MB cap — keeps a hostile or accidental gigabyte .wit from
        // either blowing memory or filling the content store.
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if metadata.len() > 1024 * 1024 {
            bail!(
                "WIT file {} exceeds 1MB size limit ({})",
                path.display(),
                metadata.len(),
            );
        }

        let rel_path = path
            .strip_prefix(wit_root)
            .with_context(|| {
                format!(
                    "WIT path {} not under wit root {}",
                    path.display(),
                    wit_root.display()
                )
            })?
            .to_string_lossy()
            .into_owned();

        let content =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

        let hash = blake3::hash(&content).to_hex().to_string();
        let dest = wit_store.join(format!("{hash}.wit"));

        // Atomic temp-and-rename — concurrent writers on identical
        // bytes converge harmlessly.
        if !dest.exists() {
            // UUID, not process::id() — sibling tokio tasks in the
            // same daemon share a pid and would race on the same
            // temp name.
            let tmp = wit_store.join(format!("{hash}.tmp.{}", uuid::Uuid::new_v4().simple()));
            std::fs::write(&tmp, &content)
                .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
            match std::fs::rename(&tmp, &dest) {
                Ok(()) => {},
                Err(_) if dest.exists() => {
                    let _ = std::fs::remove_file(&tmp);
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e).with_context(|| {
                        format!("failed to rename temp file to {}", dest.display())
                    });
                },
            }
        }

        hashes.insert(rel_path, hash);
    }

    Ok(())
}

/// Convert a nested namespace→interface→T map to namespace→interface→String
/// by extracting the version via the provided closure.
pub(crate) fn version_map_to_strings<T>(
    map: &HashMap<String, HashMap<String, T>>,
    version_fn: impl Fn(&T) -> String,
) -> HashMap<String, HashMap<String, String>> {
    map.iter()
        .map(|(ns, ifaces)| {
            let inner = ifaces
                .iter()
                .map(|(name, def)| (name.clone(), version_fn(def)))
                .collect();
            (ns.clone(), inner)
        })
        .collect()
}
