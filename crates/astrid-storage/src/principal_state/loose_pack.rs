//! Convert recovered ASTVOL1 `LooseBlob` homes into packed arena frames.
//!
//! Volume media stays a projection. Named payloads are republished through
//! the same `put_streaming_batch` path as new home imports. Chunk objects that
//! still exist only as `LooseBlob` are then admitted into arena `DirectCanonical`
//! frames. Identical catalog names do not skip that admission: bulk ingest
//! treats an unchanged file id as a no-op commit and would otherwise leave
//! chunks off the `DirectCanonical` catalogue. Leftover loose regions are
//! retired only after a volume flush (`AstridVolume::sync` / `Operation::Commit`).

use std::collections::BTreeSet;
use std::io::Cursor;

use crate::content::{ContentIngest, PrincipalContentError};
use crate::engine::DurableError;
use crate::error::{StorageError, StorageResult};
use crate::storage_model::{ObjectId, ObjectRecord};

use super::RuntimePrincipalStore;

/// Republish batches stay under compaction headroom
/// (`COMPACTION_HEADROOM_BYTES`) so a later compact still has arena-copy
/// space. This is a conversion working-set ceiling, not operator cache policy.
const PACK_CONVERT_BATCH_BYTES: u64 = 32 * 1024 * 1024;

impl RuntimePrincipalStore {
    /// Pack any remaining `LooseBlob` home payloads into `DirectCanonical` frames.
    ///
    /// Idempotent: stores with an empty contiguous index return immediately
    /// after retiring leftover volume blob regions. Unnamed blobs that are not
    /// in the catalog fail closed and are not deleted.
    pub(crate) fn pack_contiguous_home_payloads(&self) -> StorageResult<()> {
        if !self
            .engine
            .has_contiguous_payloads()
            .map_err(|error| map_engine(&error))?
        {
            self.engine
                .retire_packed_contiguous_payloads()
                .map_err(|error| map_engine(&error))?;
            return Ok(());
        }
        self.republish_named_contiguous_payloads()?;
        self.admit_named_contiguous_payloads()?;
        self.engine.flush().map_err(|error| map_engine(&error))?;
        self.engine
            .require_contiguous_payloads_in_arena()
            .map_err(|error| map_engine(&error))?;
        self.engine
            .retire_packed_contiguous_payloads()
            .map_err(|error| map_engine(&error))?;
        Ok(())
    }

    fn republish_named_contiguous_payloads(&self) -> StorageResult<()> {
        let owners = self.engine.roots().map_err(|error| map_engine(&error))?;
        for (owner, _) in owners {
            self.republish_owner_payloads(&owner)?;
        }
        Ok(())
    }

    fn republish_owner_payloads(&self, owner: &super::StateOwner) -> StorageResult<()> {
        let entries = self
            .content
            .list(owner)
            .map_err(|error| map_content(&error))?;
        let mut batch = Vec::new();
        let mut batch_bytes = 0_u64;
        for entry in entries {
            let bytes = self
                .content
                .read(owner, entry.name())
                .map_err(|error| map_content(&error))?
                .ok_or_else(|| {
                    StorageError::Internal(format!(
                        "pack contiguous home payloads: catalog name {} disappeared",
                        entry.name().as_str()
                    ))
                })?;
            let logical = u64::try_from(bytes.len()).map_err(|_| {
                StorageError::Internal(
                    "pack contiguous home payloads: source length overflow".to_owned(),
                )
            })?;
            if logical != entry.logical_bytes() {
                return Err(StorageError::Internal(format!(
                    "pack contiguous home payloads: {} length changed (catalog {}, read {logical})",
                    entry.name().as_str(),
                    entry.logical_bytes()
                )));
            }
            if !batch.is_empty()
                && batch_bytes
                    .checked_add(logical)
                    .is_some_and(|total| total > PACK_CONVERT_BATCH_BYTES)
            {
                self.flush_pack_batch(owner, &mut batch, &mut batch_bytes)?;
            }
            batch_bytes = batch_bytes.saturating_add(logical);
            batch.push(ContentIngest::new(entry.name().clone(), Cursor::new(bytes)));
        }
        if !batch.is_empty() {
            self.flush_pack_batch(owner, &mut batch, &mut batch_bytes)?;
        }
        Ok(())
    }

    fn flush_pack_batch(
        &self,
        owner: &super::StateOwner,
        batch: &mut Vec<ContentIngest<Cursor<Vec<u8>>>>,
        batch_bytes: &mut u64,
    ) -> StorageResult<()> {
        let ingests = std::mem::take(batch);
        *batch_bytes = 0;
        self.content
            .put_streaming_batch(owner, ingests)
            .map_err(|error| map_content(&error))?;
        Ok(())
    }

    fn admit_named_contiguous_payloads(&self) -> StorageResult<()> {
        let missing = self
            .engine
            .contiguous_ids_missing_from_arena()
            .map_err(|error| map_engine(&error))?;
        if missing.is_empty() {
            return Ok(());
        }
        let named = self.named_object_ids()?;
        let mut batch = Vec::new();
        let mut batch_bytes = 0_u64;
        for id in missing {
            if !named.contains(&id) {
                return Err(StorageError::Internal(
                    "pack contiguous home payloads: invalid representation state: unnamed loose payload not in catalog"
                        .to_owned(),
                ));
            }
            let record = self
                .engine
                .object(id)
                .map_err(|error| map_engine(&error))?
                .ok_or_else(|| {
                    StorageError::Internal(
                        "pack contiguous home payloads: named loose payload disappeared".to_owned(),
                    )
                })?;
            let logical = u64::try_from(record.canonical_bytes().len()).map_err(|_| {
                StorageError::Internal(
                    "pack contiguous home payloads: chunk length overflow".to_owned(),
                )
            })?;
            if !batch.is_empty()
                && batch_bytes
                    .checked_add(logical)
                    .is_some_and(|total| total > PACK_CONVERT_BATCH_BYTES)
            {
                self.flush_admit_batch(&mut batch, &mut batch_bytes)?;
            }
            batch_bytes = batch_bytes.saturating_add(logical);
            batch.push(record);
        }
        self.flush_admit_batch(&mut batch, &mut batch_bytes)
    }

    fn flush_admit_batch(
        &self,
        batch: &mut Vec<ObjectRecord>,
        batch_bytes: &mut u64,
    ) -> StorageResult<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let records = std::mem::take(batch);
        *batch_bytes = 0;
        self.engine
            .stage_objects(records)
            .map_err(|error| map_engine(&error))?;
        Ok(())
    }

    fn named_object_ids(&self) -> StorageResult<BTreeSet<ObjectId>> {
        let mut named = BTreeSet::new();
        for (owner, _) in self.engine.roots().map_err(|error| map_engine(&error))? {
            for entry in self
                .content
                .list(&owner)
                .map_err(|error| map_content(&error))?
            {
                self.collect_owned(entry.file(), &mut named)?;
            }
        }
        Ok(named)
    }

    fn collect_owned(&self, id: ObjectId, named: &mut BTreeSet<ObjectId>) -> StorageResult<()> {
        if !named.insert(id) {
            return Ok(());
        }
        let Some(record) = self.engine.object(id).map_err(|error| map_engine(&error))? else {
            return Err(StorageError::Internal(
                "pack contiguous home payloads: catalog object disappeared".to_owned(),
            ));
        };
        for child in record.owning_references() {
            self.collect_owned(child, named)?;
        }
        Ok(())
    }
}

fn map_engine(error: &DurableError) -> StorageError {
    StorageError::Internal(format!("pack contiguous home payloads: {error}"))
}

fn map_content(error: &PrincipalContentError) -> StorageError {
    StorageError::Internal(format!("pack contiguous home payloads: {error}"))
}
