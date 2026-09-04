//! CLI-side retirement of the volume-backed running projection.

use std::sync::Arc;

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;

#[expect(
    clippy::unnecessary_wraps,
    reason = "the quota hook requires the storage projection's Result shape"
)]
fn unbounded(owner: &astrid_storage::StateOwner) -> astrid_storage::StorageResult<Option<u64>> {
    let _ = owner;
    Ok(None)
}

/// Reopen the stopped volume, publish the final projection, and retire hosts.
pub(super) async fn pack_stopped_projection() -> Result<()> {
    let home =
        AstridHome::resolve().context("shutdown stage durable_projection_home_resolution")?;
    pack_stopped_projection_for_home(&home).await
}

/// Pack and retire one explicit isolated home during tests and stop handling.
pub(super) async fn pack_stopped_projection_for_home(home: &AstridHome) -> Result<()> {
    if !home
        .storage_volume_path()
        .try_exists()
        .context("shutdown stage durable_media_probe")?
    {
        return Ok(());
    }

    let quota: Arc<dyn astrid_storage::KvQuotaResolver<astrid_storage::StateOwner>> =
        Arc::new(unbounded);
    let store = astrid_storage::principal_state::open_runtime_principal_store_for_pack(home, quota)
        .await
        .context("shutdown stage durable_projection_open")?;
    store
        .pack_and_retire_runtime_projection(home)
        .context("shutdown stage durable_projection_pack")?;
    retire_stopped_projection(home)
}

/// Remove durable projections after the CLI-only post-exit pack.
///
/// The canonical media file is the only survivor.
pub(super) fn retire_stopped_projection(home: &AstridHome) -> Result<()> {
    let root = home.root();
    if !root
        .try_exists()
        .context("shutdown stage durable_root_probe")?
    {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(root)
        .with_context(|| format!("shutdown stage durable_root_read: {}", root.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("shutdown stage durable_root_entry")?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if entry.file_name() == std::ffi::OsStr::new("astrid.volume") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "shutdown stage durable_projection_probe: {}",
                path.display()
            )
        })?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "shutdown stage durable_projection_boundary: {} is redirected",
            path.display()
        );
        if metadata.is_dir() {
            astrid_core::dirs::retire_legacy_source_tree(&path).with_context(|| {
                format!(
                    "shutdown stage durable_projection_cleanup: {}",
                    path.display()
                )
            })?;
        } else if metadata.is_file() {
            std::fs::remove_file(&path).with_context(|| {
                format!(
                    "shutdown stage durable_projection_cleanup: {}",
                    path.display()
                )
            })?;
        } else {
            anyhow::bail!(
                "shutdown stage durable_projection_boundary: {} is not a regular file or directory",
                path.display()
            );
        }
    }
    Ok(())
}
