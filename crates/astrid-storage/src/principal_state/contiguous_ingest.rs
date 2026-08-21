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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ContentName;
    use crate::{KvQuotaResolver, open_runtime_principal_store};
    use astrid_core::PrincipalUid;
    use astrid_core::dirs::AstridHome;
    use std::sync::Arc;

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    #[tokio::test]
    async fn packed_volume_reopens_contiguous_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x44; 32]));
        let source = directory.path().join("note.bin");
        let bytes = vec![0x42_u8; 4096];
        std::fs::write(&source, &bytes).unwrap();
        store
            .put_contiguous_files(
                owner,
                [ContiguousFileIngest::new(
                    ContentName::new("note.bin").unwrap(),
                    source,
                    u64::try_from(bytes.len()).unwrap(),
                )],
            )
            .unwrap();
        store.engine.close().unwrap();
        drop(store);
        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("reopen packed volume");
        let filesystem = crate::AstridFilesystem::new(reopened.content(), owner);
        assert_eq!(
            filesystem
                .read(&crate::FilesystemPath::new("note.bin").unwrap(), 0, 4)
                .unwrap(),
            &bytes[..4]
        );
    }

    async fn packed_home(bytes: &[u8]) -> (tempfile::TempDir, AstridHome, StateOwner) {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x44; 32]));
        let source = directory.path().join("note.bin");
        std::fs::write(&source, bytes).unwrap();
        store
            .put_contiguous_files(
                owner,
                [ContiguousFileIngest::new(
                    ContentName::new("note.bin").unwrap(),
                    source,
                    u64::try_from(bytes.len()).unwrap(),
                )],
            )
            .unwrap();
        store.engine.close().unwrap();
        drop(store);
        (directory, home, owner)
    }

    #[tokio::test]
    async fn contiguous_volume_blob_is_one_payload_record_and_shared() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x44; 32]));
        let bytes = vec![0x5A_u8; 256 * 1024];
        let first = directory.path().join("one.bin");
        let second = directory.path().join("two.bin");
        std::fs::write(&first, &bytes).unwrap();
        std::fs::write(&second, &bytes).unwrap();
        store
            .put_contiguous_files(
                owner,
                [ContiguousFileIngest::new(
                    ContentName::new("one.bin").unwrap(),
                    first,
                    u64::try_from(bytes.len()).unwrap(),
                )],
            )
            .unwrap();
        let volume_path = home.storage_volume_path();
        let after_first = std::fs::metadata(&volume_path).unwrap().len();
        store
            .put_contiguous_files(
                owner,
                [ContiguousFileIngest::new(
                    ContentName::new("two.bin").unwrap(),
                    second,
                    u64::try_from(bytes.len()).unwrap(),
                )],
            )
            .unwrap();
        let after_second = std::fs::metadata(&volume_path).unwrap().len();
        assert!(
            after_second.saturating_sub(after_first) < u64::try_from(bytes.len()).unwrap(),
            "identical second file recopied payload: {after_first} -> {after_second}"
        );
        store.engine.close().unwrap();
        drop(store);
        let payload_writes = crate::volume::write_record_payloads(&volume_path)
            .unwrap()
            .into_iter()
            .filter(|(name, len)| {
                *len == u64::try_from(bytes.len()).unwrap()
                    && name.contains("representations/blobs/loose")
                    && std::path::Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("blob"))
            })
            .count();
        assert_eq!(
            payload_writes, 1,
            "blob payload was shredded into journal writes"
        );
        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("reopen packed volume");
        let filesystem = crate::AstridFilesystem::new(reopened.content(), owner);
        assert_eq!(
            filesystem
                .read(
                    &crate::FilesystemPath::new("one.bin").unwrap(),
                    0,
                    u64::try_from(bytes.len()).unwrap(),
                )
                .unwrap(),
            bytes
        );
        assert_eq!(
            filesystem
                .read(
                    &crate::FilesystemPath::new("two.bin").unwrap(),
                    0,
                    u64::try_from(bytes.len()).unwrap(),
                )
                .unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn packed_volume_rejects_a_lengthened_blob_region() {
        let bytes = vec![0x42_u8; 4096];
        let (_directory, home, _owner) = packed_home(&bytes).await;
        let volume = crate::volume::HostedFileVolume::open(home.storage_volume_path()).unwrap();
        let regions = crate::volume::AstridVolume::list_regions(
            volume.as_ref(),
            "representations/blobs/loose",
        )
        .unwrap();
        let blob = regions
            .iter()
            .find(|region| {
                std::path::Path::new(region.as_str())
                    .extension()
                    .is_some_and(|ext| ext == "blob")
            })
            .expect("blob region")
            .clone();
        let len = crate::volume::AstridVolume::region_len(volume.as_ref(), &blob).unwrap();
        crate::volume::AstridVolume::set_region_len(volume.as_ref(), &blob, len + 1).unwrap();
        crate::volume::AstridVolume::write_region_at(volume.as_ref(), &blob, len, &[0xff]).unwrap();
        drop(volume);
        let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
            panic!("trailing blob bytes must fail closed");
        };
        assert!(
            error.to_string().contains("contiguous blob length"),
            "{error}"
        );
    }
}
