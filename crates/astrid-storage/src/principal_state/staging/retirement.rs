//! Crash-safe retirement of already-published staged generations.

use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::recovery::{retired_generation_name, sealed_generation_name};
use super::{StageKey, connection};
use crate::error::StorageResult;
use crate::principal_state::native_io::{create_private_file, rename_private_entry};

/// Make one completed generation permanently non-publishable.
///
/// An already-missing source is fenced by publishing an empty retired marker;
/// the write-through transition orders that absence before journal drainage.
pub(super) fn establish(generations: &Path, key: StageKey) -> StorageResult<PathBuf> {
    let sealed = generations.join(sealed_generation_name(key.sequence, key.id));
    let retired = generations.join(retired_generation_name(key.sequence, key.id));
    match (
        std::fs::symlink_metadata(&sealed),
        std::fs::symlink_metadata(&retired),
    ) {
        (Ok(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            rename_private_entry(&sealed, &retired)?;
            Ok(retired)
        },
        (Err(error), Ok(metadata)) if error.kind() == std::io::ErrorKind::NotFound => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(connection(format!(
                    "retired staged generation {} is redirected or not a regular file",
                    retired.display()
                )));
            }
            Ok(retired)
        },
        (Err(source_error), Err(retired_error))
            if source_error.kind() == std::io::ErrorKind::NotFound
                && retired_error.kind() == std::io::ErrorKind::NotFound =>
        {
            create_marker(generations, key)?;
            Ok(retired)
        },
        (Ok(_), Ok(_)) => Err(connection(format!(
            "staged generation {} has both sealed and retired names",
            key.id
        ))),
        (Err(error), _) => Err(connection(format!(
            "inspect staged generation {}: {error}",
            sealed.display()
        ))),
        (_, Err(error)) => Err(connection(format!(
            "inspect retired staged generation {}: {error}",
            retired.display()
        ))),
    }
}

pub(super) fn create_marker(generations: &Path, key: StageKey) -> StorageResult<()> {
    let retired = generations.join(retired_generation_name(key.sequence, key.id));
    let temporary = generations.join(format!(
        "{}.{}.tmp",
        retired_generation_name(key.sequence, key.id),
        Uuid::new_v4()
    ));
    let file = create_private_file(&temporary)?;
    let result = file
        .sync_all()
        .map_err(|error| connection(format!("flush retirement marker: {error}")))
        .and_then(|()| rename_private_entry(&temporary, &retired));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(super) fn remove(path: &Path) -> StorageResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(connection(format!(
            "remove staged generation {}: {error}",
            path.display()
        ))),
    }
}
