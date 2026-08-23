//! Home-file ingest for owner-named content on volume media.
//!
//! New files use the same canonical streaming arena path as capsule content.
//! Legacy contiguous-file metadata is rejected during representation recovery;
//! new home imports never create loose blob regions.

use std::fs::File;

use crate::content::{ContentIngest, ContentName};
use crate::error::{StorageError, StorageResult};

use super::{RuntimePrincipalStore, StateOwner};

/// One sealed regular file ready for packed home publication.
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
    /// Publish several files through the canonical packed content path.
    ///
    /// Files are chunked into `Chunk`/`ChunkTree`/`File` records in the shared
    /// object arena, then all names publish under one principal-root CAS and
    /// durability boundary. Legacy loose representations are not a readable
    /// home-content format and fail closed during recovery.
    ///
    /// # Errors
    ///
    /// Returns a storage error if source validation or catalog
    /// publication fails. A failed batch does not publish a partial catalog.
    pub fn put_contiguous_files(
        &self,
        owner: StateOwner,
        files: impl IntoIterator<Item = ContiguousFileIngest>,
    ) -> StorageResult<()> {
        let mut ingests = Vec::new();
        for file in files {
            let source = open_home_source(&file)?;
            ingests.push(ContentIngest::new(file.name, source));
        }
        if ingests.is_empty() {
            return Ok(());
        }
        self.content
            .put_streaming_batch(&owner, ingests)
            .map_err(|error| {
                StorageError::Internal(format!("publish packed home batch: {error}"))
            })?;
        Ok(())
    }
}

fn open_home_source(file: &ContiguousFileIngest) -> StorageResult<File> {
    let source = File::open(&file.path).map_err(|error| {
        StorageError::Connection(format!("open home source {}: {error}", file.path.display()))
    })?;
    let actual_bytes = source
        .metadata()
        .map_err(|error| {
            StorageError::Connection(format!("stat home source {}: {error}", file.path.display()))
        })?
        .len();
    if actual_bytes != file.logical_bytes {
        return Err(StorageError::Connection(format!(
            "home source {} changed length (expected {}, found {})",
            file.path.display(),
            file.logical_bytes,
            actual_bytes
        )));
    }
    Ok(source)
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
    async fn packed_volume_reopens_home_payloads() {
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

    #[tokio::test]
    async fn packed_home_deduplicates_repeated_chunks_without_loose_regions() {
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
        let copy_directory = tempfile::tempdir().unwrap();
        let copy_home = AstridHome::from_path(copy_directory.path());
        copy_home.ensure().unwrap();
        std::fs::copy(&volume_path, copy_home.storage_volume_path()).unwrap();

        store.engine.close().unwrap();
        drop(store);
        let volume = crate::volume::HostedFileVolume::open(&volume_path).unwrap();
        assert!(
            crate::volume::AstridVolume::list_regions(
                volume.as_ref(),
                "representations/blobs/loose"
            )
            .unwrap()
            .is_empty(),
            "new home ingest created a loose representation"
        );
        drop(volume);

        let reopened = open_runtime_principal_store(&copy_home, unlimited_quota())
            .await
            .expect("reopen packed volume copied before source close");
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
        let mut logical_bytes = 0_u64;
        for index in 0..file_count {
            let mut bytes = vec![0xA5_u8; 256];
            bytes[0] = u8::try_from(index % 256).unwrap();
            bytes[1] = u8::try_from(index / 256).unwrap();
            let path = unique_dir.join(format!("{index:04}.bin"));
            std::fs::write(&path, &bytes).unwrap();
            logical_bytes += u64::try_from(bytes.len()).unwrap();
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
        let mut loose_payload = 0_u64;
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
                loose_payload += len;
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
        assert_eq!(
            loose_payload, 0,
            "new home ingest wrote loose payloads; {census}"
        );
        assert!(
            index_payload < logical_bytes.saturating_add(2 * 1024 * 1024),
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
            volume_len <= logical_bytes.saturating_add(8 * 1024 * 1024),
            "volume {volume_len} logical {logical_bytes}; {census}"
        );
    }
}
