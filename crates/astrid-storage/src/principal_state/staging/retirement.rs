//! Crash-safe retirement of already-published staged generations.

use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::recovery::{retired_generation_name, sealed_generation_name};
use super::{StageKey, connection};
use crate::error::StorageResult;
use crate::principal_state::native_io::{
    PrivateDirectory, create_private_file, private_file_identity, rename_private_entry,
};

/// Make one completed generation non-publishable below a retained capability.
pub(super) fn establish_in(directory: &PrivateDirectory, key: StageKey) -> StorageResult<()> {
    let sealed = PathBuf::from(sealed_generation_name(key.sequence, key.id));
    let retired = PathBuf::from(retired_generation_name(key.sequence, key.id));
    match (directory.contains(&sealed)?, directory.contains(&retired)?) {
        (true, false) => {
            let source = directory.open_file(&sealed)?;
            directory.rename_with_identity(&sealed, &retired, private_file_identity(&source)?)
        },
        (false, true) => directory.open_file(&retired).map(|_| ()),
        (false, false) => create_marker_in(directory, key),
        (true, true) => Err(connection(format!(
            "staged generation {} has both sealed and retired names",
            key.id
        ))),
    }
}

fn create_marker_in(directory: &PrivateDirectory, key: StageKey) -> StorageResult<()> {
    let retired = PathBuf::from(retired_generation_name(key.sequence, key.id));
    let temporary = PathBuf::from(format!(
        "{}.{}.tmp",
        retired_generation_name(key.sequence, key.id),
        Uuid::new_v4()
    ));
    let file = directory.create_file(&temporary)?;
    let identity = private_file_identity(&file)?;
    let result = file
        .sync_all()
        .map_err(|error| connection(format!("flush retirement marker: {error}")))
        .and_then(|()| directory.rename_with_identity(&temporary, &retired, identity));
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

pub(super) fn remove_in(directory: &PrivateDirectory, key: StageKey) -> StorageResult<()> {
    directory.remove_file(Path::new(&retired_generation_name(key.sequence, key.id)))
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
