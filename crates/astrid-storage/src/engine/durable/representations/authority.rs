//! Capability-relative access to representation authority files.

use std::fs::File;
use std::path::Path;

use cap_std::fs::{Dir, OpenOptions};

use super::contiguous::{configure_no_follow, sync_directory, validate_opened_regular};
use crate::engine::durable::{DurableError, io_error};

pub(super) fn open_file(directory: &Dir, name: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_no_follow(&mut options);
    let file = directory
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|source| io_error("open representation file capability", source))?;
    validate_opened_regular(&file)
        .map_err(|source| io_error("validate opened representation file", source))?;
    Ok(file)
}

pub(super) fn create_file(directory: &Dir, name: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    directory
        .open_with(name, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|source| io_error("create representation file capability", source))
}

pub(super) fn quarantine_entry(parent: &Dir, name: &str, stem: &str) -> Result<(), DurableError> {
    match parent.symlink_metadata(name) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error("inspect representation quarantine entry", source)),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(DurableError::InvalidRepresentationState(
                "representation quarantine entry is redirected",
            ));
        },
        Ok(_) => {},
    }
    for ordinal in 0_u32..=u32::MAX {
        let quarantine = format!("{stem}.{ordinal:08x}");
        if parent.symlink_metadata(&quarantine).is_ok() {
            continue;
        }
        parent
            .rename(name, parent, &quarantine)
            .map_err(|source| io_error("quarantine incomplete representation entry", source))?;
        sync_directory(parent)
            .map_err(|source| io_error("flush representation quarantine parent", source))?;
        return Ok(());
    }
    Err(DurableError::InvalidRepresentationState(
        "representation quarantine namespace is exhausted",
    ))
}
