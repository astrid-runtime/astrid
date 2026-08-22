//! Contiguous-file ingest for owner-named content on volume media.
//!
//! File payloads become `ContiguousFile` blobs. Catalog names still publish
//! through one principal-root transaction. Chunk DAG identity is preserved;
//! chunk frames are not stored.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::content::{ChunkingProfile, ContentName};
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
        let mut names = Vec::new();
        let mut prepared = Vec::new();
        let mut objects_inserted = 0_u64;
        for file in files {
            let item = prepare_installed_blob(&self.engine, &file)?;
            objects_inserted = objects_inserted
                .checked_add(item.objects_inserted())
                .ok_or_else(|| {
                    StorageError::Internal("contiguous object count overflow".to_owned())
                })?;
            names.push(file.name);
            prepared.push(item);
        }
        if prepared.is_empty() {
            return Ok(());
        }
        let published = self
            .engine
            .publish_installed_contiguous_batch(prepared)
            .map_err(|error| {
                StorageError::Connection(format!("publish contiguous batch: {error}"))
            })?;
        let entries = names
            .into_iter()
            .zip(published)
            .map(|(name, item)| (name, item.verified_content()))
            .collect::<Vec<_>>();
        self.content
            .publish_verified_batch(&owner, entries, objects_inserted)
            .map_err(|error| {
                StorageError::Internal(format!("publish contiguous catalog batch: {error}"))
            })?;
        Ok(())
    }
}

fn prepare_installed_blob(
    engine: &super::RuntimeEngine,
    file: &ContiguousFileIngest,
) -> StorageResult<crate::engine::PreparedContiguousFile> {
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
    engine
        .install_prepared_contiguous_blob(&prepared, &source)
        .map_err(|error| {
            StorageError::Connection(format!(
                "install contiguous blob {}: {error}",
                path.display()
            ))
        })?;
    Ok(prepared)
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

    #[tokio::test]
    async fn volume_flush_does_not_journal_a_full_index_snapshot_per_file() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        home.ensure().unwrap();
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let owner = StateOwner::Principal(PrincipalUid::from_bytes([0x51; 32]));
        let unique_dir = directory.path().join("unique");
        std::fs::create_dir(&unique_dir).unwrap();
        let file_count = 512_usize;
        let mut files = Vec::with_capacity(file_count);
        let mut unique_bytes = 0_u64;
        for index in 0..file_count {
            let mut bytes = vec![0xA5_u8; 256];
            bytes[0] = u8::try_from(index % 256).unwrap();
            bytes[1] = u8::try_from(index / 256).unwrap();
            let path = unique_dir.join(format!("{index:04}.bin"));
            std::fs::write(&path, &bytes).unwrap();
            unique_bytes += u64::try_from(bytes.len()).unwrap();
            files.push(ContiguousFileIngest::new(
                ContentName::new(format!("u/{index:04}.bin")).unwrap(),
                path,
                u64::try_from(bytes.len()).unwrap(),
            ));
        }
        store.put_contiguous_files(owner, files).unwrap();
        store.engine.close().unwrap();
        drop(store);
        let volume_path = home.storage_volume_path();
        let volume_len = std::fs::metadata(&volume_path).unwrap().len();
        let mut index_payload = 0_u64;
        let mut index_writes = 0_u32;
        let mut metadata_writes = 0_u32;
        let mut blob_payload = 0_u64;
        let mut buckets = std::collections::BTreeMap::<String, (u32, u64)>::new();
        for (name, len) in crate::volume::write_record_payloads(&volume_path).unwrap() {
            let bucket = if name == "objects.index" {
                index_payload += len;
                index_writes += 1;
                name
            } else if name.ends_with("metadata.arena") {
                metadata_writes += 1;
                "metadata.arena".to_owned()
            } else if name.contains("representations/blobs/loose")
                && std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("blob"))
            {
                blob_payload += len;
                "blob.payload".to_owned()
            } else if name.contains("blobs/loose")
                && std::path::Path::new(&name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("meta"))
            {
                "blob.meta".to_owned()
            } else {
                name.rsplit_once('/')
                    .map_or(name.clone(), |(_, tail)| tail.to_owned())
            };
            let entry = buckets.entry(bucket).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += len;
        }
        let census = buckets
            .iter()
            .map(|(name, (count, bytes))| format!("{bytes} n={count} {name}"))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(blob_payload, unique_bytes, "{census}");
        assert!(
            index_payload < unique_bytes.saturating_add(2 * 1024 * 1024),
            "objects.index journaled {index_payload} bytes across {index_writes} writes; {census}"
        );
        assert!(
            index_writes <= 16,
            "objects.index snapshot-per-file still journaled {index_writes} writes; {census}"
        );
        assert!(
            metadata_writes <= 16,
            "metadata.arena snapshot-per-file still journaled {metadata_writes} writes; {census}"
        );
        assert!(
            volume_len <= unique_bytes.saturating_add(8 * 1024 * 1024),
            "volume {volume_len} unique {unique_bytes}; {census}"
        );
    }
}
