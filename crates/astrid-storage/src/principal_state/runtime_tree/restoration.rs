//! Restore a volume-authoritative host projection before publishing readiness.

use std::path::PathBuf;

use astrid_core::platform_fs::PrivateFileProjection;

use super::{
    AstridHome, RuntimePrincipalStore, StateOwner, StorageResult, confined_projection_path,
    ingest_runtime_key, is_excluded, is_retired_legacy_projection, is_staging_generation,
    projection, seed_layout_version, transition_retiring_projection, tree_error, tree_io_error,
};
use crate::principal_state::{NativePrincipalContentStore, rebind_staging_generation};

pub(super) fn restore_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
) -> StorageResult<()> {
    restore_with_sync(home, store, content, || Ok(()))
}

fn restore_with_sync(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
    mut after_sync: impl FnMut() -> StorageResult<()>,
) -> StorageResult<()> {
    let layout_version = home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?;
    if layout_version.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        return Ok(());
    }
    ingest_runtime_key(home, store)?;
    seed_layout_version(home, store)?;
    let mut entries = content
        .list(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("list volume projection: {error}")))?;
    // Make subsequent interrupted restores structurally recognizable before
    // materializing other volume-owned directories or configuration files.
    entries.sort_by_key(|entry| entry.name().as_str() != "etc/layout-version");
    for entry in &entries {
        let name = entry.name().as_str();
        if is_excluded(name) || is_retired_legacy_projection(home, name) {
            continue;
        }
        confined_projection_path(home.root(), name.strip_suffix('/').unwrap_or(name))?;
    }
    let writer = PrivateFileProjection::open(home.root())
        .map_err(|error| tree_error(home.root(), format!("open projection writer: {error}")))?;
    let mut written = Vec::new();
    let result = (|| -> StorageResult<()> {
        for entry in entries {
            let name = entry.name().as_str();
            if is_excluded(name) || is_retired_legacy_projection(home, name) {
                continue;
            }
            if let Some(directory) = name.strip_suffix('/') {
                projection::restore_directory(
                    &writer,
                    home.root(),
                    directory,
                    entry.logical_bytes(),
                )?;
                continue;
            }
            let Some(bytes) = content
                .read(&StateOwner::System, entry.name())
                .map_err(|error| {
                    tree_error(home.root(), format!("read projection {name}: {error}"))
                })?
            else {
                continue;
            };
            let path = confined_projection_path(home.root(), name)?;
            let relative = path.strip_prefix(home.root()).map_err(|error| {
                tree_error(&path, format!("projection escaped its root: {error}"))
            })?;
            let previous = writer
                .snapshot(relative)
                .map_err(|error| tree_error(&path, format!("snapshot projection: {error}")))?;
            written.push((relative.to_path_buf(), previous));
            writer
                .write(relative, &bytes)
                .map_err(|error| tree_error(home.root(), format!("restore {name}: {error}")))?;
            if is_staging_generation(name) {
                let path = confined_projection_path(home.root(), name)?;
                rebind_staging_generation(&path)?;
            }
        }
        writer.sync().map_err(|error| {
            tree_error(home.root(), format!("fence restored projection: {error}"))
        })?;
        after_sync()
    })();
    if let Err(error) = result {
        let mut rollback_errors = rollback_projection_files(&writer, written);
        // Fence rollback too. Readiness and ACTIVE publication must not succeed
        // after a failed terminal barrier, even if a retry fence succeeds.
        let rollback_sync = writer
            .sync()
            .map_err(|error| tree_error(home.root(), format!("fence projection rollback: {error}")))
            .and_then(|()| after_sync());
        if let Err(sync_error) = rollback_sync {
            rollback_errors.push(sync_error.to_string());
        }
        if !rollback_errors.is_empty() {
            let retirement = match transition_retiring_projection(home, store) {
                Ok(()) => "durable RETIRING receipt recorded".to_owned(),
                Err(retirement) => format!("failed to force RETIRING receipt: {retirement}"),
            };
            return Err(tree_error(
                home.root(),
                format!(
                    "restore failed: {error}; rollback failures: {rollback_errors:?}; {retirement}"
                ),
            ));
        }
        return Err(error);
    }
    Ok(())
}

pub(super) fn rollback_projection_files(
    writer: &PrivateFileProjection,
    written: Vec<(PathBuf, Option<Vec<u8>>)>,
) -> Vec<String> {
    written
        .into_iter()
        .rev()
        .filter_map(|(name, previous)| {
            let rollback = match previous {
                Some(bytes) => writer.write(&name, &bytes),
                None => writer.remove(&name),
            };
            rollback
                .err()
                .map(|error| format!("{}: {error}", name.display()))
        })
        .collect()
}

#[cfg(test)]
#[path = "restoration_tests.rs"]
mod tests;
