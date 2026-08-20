//! Contiguous-file ingest for owner-named content on volume media.
//!
//! File payloads become `ContiguousFile` blobs. Catalog names still publish
//! through one principal-root transaction. Chunk DAG identity is preserved;
//! chunk frames are not stored.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::content::{ChunkingProfile, ContentName};
use crate::content_dag::VerifiedContent;
use crate::error::{StorageError, StorageResult};

use super::{RuntimePrincipalStore, StateOwner};

/// One sealed regular file ready for contiguous publication.
pub struct ContiguousFileIngest {
    name: ContentName,
    path: std::path::PathBuf,
    logical_bytes: u64,
}

impl ContiguousFileIngest {
    /// Bind a source path to one catalog name.
    #[must_use]
    pub fn new(name: ContentName, path: impl Into<std::path::PathBuf>, logical_bytes: u64) -> Self {
        Self {
            name,
            path: path.into(),
            logical_bytes,
        }
    }
}

impl RuntimePrincipalStore {
    /// Publish several files as contiguous physical payloads, then one catalog CAS.
    ///
    /// Identical source bytes share one blob identity. Structural File and
    /// `ChunkTree` records remain in the object arena; raw chunk frames do not.
    ///
    /// # Errors
    ///
    /// Returns a storage error if preparation, blob installation, or catalog
    /// publication fails. A failed batch does not publish a partial catalog.
    pub fn put_contiguous_files(
        &self,
        owner: StateOwner,
        files: impl IntoIterator<Item = ContiguousFileIngest>,
    ) -> StorageResult<()> {
        let mut entries = Vec::new();
        let mut objects_inserted = 0_u64;
        for file in files {
            let published = ingest_one(&self.engine, &file)?;
            objects_inserted = objects_inserted.checked_add(published.1).ok_or_else(|| {
                StorageError::Internal("contiguous object count overflow".to_owned())
            })?;
            entries.push((file.name, published.0));
        }
        if entries.is_empty() {
            return Ok(());
        }
        self.content
            .publish_verified_batch(&owner, entries, objects_inserted)
            .map_err(|error| {
                StorageError::Internal(format!("publish contiguous catalog batch: {error}"))
            })?;
        Ok(())
    }
}

fn ingest_one(
    engine: &super::RuntimeEngine,
    file: &ContiguousFileIngest,
) -> StorageResult<(VerifiedContent, u64)> {
    let path = Path::new(&file.path);
    let mut source = File::open(path).map_err(|error| {
        StorageError::Connection(format!(
            "open contiguous source {}: {error}",
            path.display()
        ))
    })?;
    let prepared = engine
        .prepare_contiguous_file(ChunkingProfile::ASTRID_V1, file.logical_bytes, &mut source)
        .map_err(|error| {
            StorageError::Connection(format!(
                "prepare contiguous file {}: {error}",
                path.display()
            ))
        })?;
    source.seek(SeekFrom::Start(0)).map_err(|error| {
        StorageError::Connection(format!(
            "rewind contiguous source {}: {error}",
            path.display()
        ))
    })?;
    let published = engine
        .publish_contiguous_from_file(prepared, &source)
        .map_err(|error| {
            StorageError::Connection(format!(
                "publish contiguous blob {}: {error}",
                path.display()
            ))
        })?;
    Ok((published.verified_content(), published.objects_inserted()))
}
