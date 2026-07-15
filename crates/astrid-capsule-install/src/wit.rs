//! Content-address WIT files into the shared `wit/store/` blob store.
//!
//! Read-only with respect to the source: we hash files in
//! `source_dir/wit/` and write the BLAKE3-keyed blobs to
//! `home.wit_store_dir()` (`~/.astrid/wit/store/<hash>.wit`). The store
//! is a dedicated subdirectory so it never collides with the daemon's
//! canonical named copies at the top of `wit/` (e.g.
//! `wit/astrid-contracts.wit`). The source tree is **never** modified —
//! that mattered when source and target were the same directory (the
//! old CLI install staged everything in `target_dir`), but matters even
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
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

/// Content-address all `.wit` files under `source_dir/wit/`
/// (recursively) into the system-wide BLAKE3 store at
/// `home.wit_store_dir()`. Returns a map of relative path under `wit/` →
/// BLAKE3 hex. Returns an empty map (not an error) when the source
/// has no `wit/` directory.
///
/// Pin computation (reading the source and hashing it) is fatal — a
/// source that can't be read is a broken capsule tree. Blob **retention**
/// is best-effort: if the store can't be written, the pins are still
/// recorded (they're the `meta.json` record) and only a warning is logged,
/// so an unwritable store never breaks an otherwise-valid install.
pub fn content_address_wit(
    home: &AstridHome,
    source_dir: &Path,
) -> anyhow::Result<HashMap<String, String>> {
    let wit_source = source_dir.join("wit");
    let mut hashes = HashMap::new();

    if !wit_source.is_dir() {
        return Ok(hashes);
    }

    // Best-effort store directory creation. Computing pins only needs to
    // read the source; persisting the blobs is the retention layer, which
    // must never break an otherwise-valid install. If the store dir
    // can't be created, we still hash and record the pins — the bytes
    // just aren't retained this pass (re-attempted on the next install).
    let wit_store = home.wit_store_dir();
    let store_ready = match std::fs::create_dir_all(&wit_store) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                path = %wit_store.display(),
                error = %e,
                "failed to create WIT blob store; pins recorded but bytes not retained this install"
            );
            false
        },
    };

    content_address_wit_recursive(
        &wit_source,
        &wit_source,
        &wit_store,
        store_ready,
        &mut hashes,
    )?;

    Ok(hashes)
}

fn content_address_wit_recursive(
    wit_root: &Path,
    current: &Path,
    wit_store: &Path,
    store_ready: bool,
    hashes: &mut HashMap<String, String>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("failed to read {}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            content_address_wit_recursive(wit_root, &path, wit_store, store_ready, hashes)?;
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

        // Record the pin unconditionally — this is the meta.json record.
        // Blob persistence below is best-effort retention layered on top.
        hashes.insert(rel_path, hash.clone());
        if store_ready {
            persist_wit_blob(wit_store, &hash, &content);
        }
    }

    Ok(())
}

/// Best-effort atomic write of one content-addressed WIT blob to the
/// store. A failure is logged and swallowed: the pin is already recorded,
/// and retention must never break the install.
fn persist_wit_blob(wit_store: &Path, hash: &str, content: &[u8]) {
    let dest = wit_store.join(format!("{hash}.wit"));
    // Dedup by content — a blob already present is byte-identical (same
    // BLAKE3), so there's nothing to do.
    if dest.exists() {
        return;
    }
    // UUID, not process::id() — sibling tokio tasks in the same daemon
    // share a pid and would race on the same temp name.
    let tmp = wit_store.join(format!("{hash}.tmp.{}", uuid::Uuid::new_v4().simple()));
    if let Err(e) = std::fs::write(&tmp, content) {
        // Clean up the partial temp so a failed write doesn't leak an orphan
        // into wit/store/ (mirrors the rename-failure path below).
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            path = %tmp.display(),
            error = %e,
            "failed to write WIT blob temp; pin recorded but bytes not retained"
        );
        return;
    }
    match std::fs::rename(&tmp, &dest) {
        Ok(()) => {},
        // A concurrent writer already landed identical bytes — harmless.
        Err(_) if dest.exists() => {
            let _ = std::fs::remove_file(&tmp);
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!(
                path = %dest.display(),
                error = %e,
                "failed to persist WIT blob; pin recorded but bytes not retained"
            );
        },
    }
}

/// Materialize the content-addressed WIT blobs into `principal`'s
/// `home://wit/` directory so the introspection tools (`list_interfaces`
/// / `read_interface` in the system capsule) can read them.
///
/// Those tools read `home://wit/<basename>`, which resolves to
/// `<principal_home>/wit/<basename>`. The content-addressed blob store at
/// [`AstridHome::wit_store_dir`] is BLAKE3-keyed and lives outside any VFS
/// scheme a capsule can reach (its `fs_read` grant is `home://` only),
/// so the store alone leaves those tools with an empty directory. This
/// mirrors a readable, human-named copy into the principal's home.
///
/// `principal` names the mirror's home target: the WIT lands under
/// `home.principal_home(principal)/wit`. The caller passes
/// [`crate::paths::install_principal`] — the same id used for the home-scoped
/// install paths — so introspection tools resolve the mirror under the home
/// they read from. For a workspace install, `principal` names the mirror home,
/// not necessarily the capsule's project-state directory.
///
/// `wit_files` is the name→hash map returned by [`content_address_wit`]:
/// keys are paths relative to the source `wit/` directory (e.g.
/// `deps/astrid-contracts/astrid-contracts.wit`), values are BLAKE3
/// hex. Bytes are read back from the store at
/// `home.wit_store_dir()/{hash}.wit` — they were just written there, so
/// no source round-trip is needed.
///
/// Files are named by the **basename** of the key: `read_interface`
/// rejects any name containing `/`, so nested paths must be flattened.
/// Idempotent: a basename already present with byte-identical content is
/// skipped; one present with different content is overwritten
/// (last-writer-wins). Collisions are acceptable for introspection
/// tooling — the common shared files (`astrid-contracts.wit`,
/// `capsule.wit`) are byte-identical across capsules by construction
/// (same hash), so overwrite is a no-op for them.
pub fn materialize_wit_mirror<S: std::hash::BuildHasher>(
    home: &AstridHome,
    principal: &PrincipalId,
    wit_files: &HashMap<String, String, S>,
) -> anyhow::Result<()> {
    if wit_files.is_empty() {
        return Ok(());
    }

    let wit_store = home.wit_store_dir();
    let mirror_dir = home.principal_home(principal).root().join("wit");
    std::fs::create_dir_all(&mirror_dir)
        .with_context(|| format!("failed to create WIT mirror dir {}", mirror_dir.display()))?;

    // Iterate in a stable order. `wit_files` is a HashMap, so raw iteration
    // order is nondeterministic; in the (rare, documented) basename-collision
    // case that would make the last-writer-wins winner depend on hash order.
    // Sort by relative path so the outcome is reproducible across runs.
    let mut entries: Vec<(&String, &String)> = wit_files.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    for (rel_path, hash) in entries {
        let Some(basename) = Path::new(rel_path).file_name() else {
            continue;
        };

        let blob = wit_store.join(format!("{hash}.wit"));
        let content = std::fs::read(&blob)
            .with_context(|| format!("failed to read WIT blob {}", blob.display()))?;

        let dest = mirror_dir.join(basename);

        // Skip if already byte-identical — keeps re-installs idempotent
        // and avoids churning the file when nothing changed.
        if let Ok(existing) = std::fs::read(&dest)
            && existing == content
        {
            continue;
        }

        // Atomic temp-and-rename so a concurrent reader never sees a
        // half-written file. UUID temp name — sibling tokio tasks in
        // the daemon share a pid and would race on a pid-based name.
        let tmp = mirror_dir.join(format!(
            "{}.tmp.{}",
            basename.to_string_lossy(),
            uuid::Uuid::new_v4().simple()
        ));
        if let Err(e) = std::fs::write(&tmp, &content) {
            // Clean up the partial temp so a failed write doesn't leak an
            // orphan into the mirror dir (mirrors the rename-failure path).
            let _ = std::fs::remove_file(&tmp);
            return Err(e)
                .with_context(|| format!("failed to write WIT mirror temp {}", tmp.display()));
        }
        if let Err(e) = std::fs::rename(&tmp, &dest) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e)
                .with_context(|| format!("failed to rename WIT mirror to {}", dest.display()));
        }
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
