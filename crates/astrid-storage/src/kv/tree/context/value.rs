//! Versioned spilled KV values backed by canonical content DAGs.
//!
//! Small values retain the original representation. Values larger than the
//! pinned content profile's maximum chunk use a version-five KV value wrapper
//! owning one canonical file DAG. Reuse, reachability and admission remain in
//! the same root transaction; no side keys or separate publications are used.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::node::{decode_value, value_record};
use super::{
    INLINE_VALUE_MAX, KvProjectionEngine, ObjectClass, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, ReferenceKind, StorageError, StorageResult, TreeContext, ValueSlot,
    arithmetic_overflow, invalid, map_engine,
};
use crate::content_dag::{
    ChunkingProfile, ContentSource, build_content, open_content, read_opened_content,
};
use crate::storage_model::{ObjectFormatVersion, ObjectIdentity, ReferenceLabel};

// These are immutable encoding rules, not operator memory limits. They pin
// identities and the canonical representation chosen for the same KV bytes.
const CHUNKED_VALUE_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(5) {
    Some(version) => version,
    None => unreachable!(),
};
const CONTENT_LABEL: &[u8] = b"content";
const PROFILE: ChunkingProfile = ChunkingProfile::ASTRID_V1;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    pub(super) fn make_value(&mut self, bytes: Cow<'_, [u8]>) -> StorageResult<ValueSlot> {
        if bytes.len() <= INLINE_VALUE_MAX {
            return Ok(ValueSlot::Inline(bytes.into_owned()));
        }
        let length = u64::try_from(bytes.len()).map_err(|_| arithmetic_overflow())?;
        let object = if length > u64::from(PROFILE.maximum_bytes()) {
            self.make_chunked_value(&bytes, length)?
        } else {
            self.insert(value_record(bytes.into_owned())?)?
        };
        Ok(ValueSlot::Spilled { object, length })
    }

    fn make_chunked_value(&mut self, bytes: &[u8], length: u64) -> StorageResult<ObjectId> {
        let built = build_content(self, PROFILE, bytes).map_err(|error| {
            StorageError::Serialization(format!("build chunked KV value: {error}"))
        })?;
        let file = built.descriptor().file();
        for (_, record) in built.into_records() {
            self.insert(record)?;
        }
        let wrapper = ObjectRecord::new(
            ObjectKind::KvLeaf,
            CHUNKED_VALUE_VERSION,
            length.to_le_bytes().to_vec(),
            vec![ObjectReference::owns(
                ReferenceLabel::new(CONTENT_LABEL.to_vec()),
                file,
            )],
            0,
            ObjectClass::Data,
        )
        .map_err(|error| map_engine(&error.into()))?;
        self.insert(wrapper)
    }

    pub(in crate::kv::tree) fn value_bytes(&self, value: &ValueSlot) -> StorageResult<Vec<u8>> {
        match value {
            ValueSlot::Inline(bytes) => Ok(bytes.clone()),
            ValueSlot::Spilled { object, length } => {
                let record = self.record(*object)?;
                if record.format_version() == CHUNKED_VALUE_VERSION {
                    self.read_chunked_value(*object, *length, &record)
                } else {
                    decode_value(*object, *length, &record)
                }
            },
        }
    }

    fn read_chunked_value(
        &self,
        id: ObjectId,
        length: u64,
        record: &ObjectRecord,
    ) -> StorageResult<Vec<u8>> {
        if record.kind() != ObjectKind::KvLeaf
            || record.class() != ObjectClass::Data
            || record.logical_bytes() != 0
            || record.canonical_bytes() != length.to_le_bytes()
            || record.references().len() != 1
            || length <= u64::from(PROFILE.maximum_bytes())
        {
            return Err(invalid(id, "invalid chunked KV value wrapper"));
        }
        let reference = &record.references()[0];
        if reference.kind() != ReferenceKind::Owns || reference.label().as_bytes() != CONTENT_LABEL
        {
            return Err(invalid(id, "invalid chunked KV content reference"));
        }
        let opened = open_content(self, reference.target()).map_err(|error| {
            StorageError::Serialization(format!("open chunked KV value {id:?}: {error}"))
        })?;
        // Validate the declared size before content reconstruction allocates.
        if opened.descriptor().logical_bytes() != length || opened.descriptor().profile() != PROFILE
        {
            return Err(invalid(id, "chunked KV descriptor disagrees with wrapper"));
        }
        read_opened_content(self, opened).map_err(|error| {
            StorageError::Serialization(format!("read chunked KV value {id:?}: {error}"))
        })
    }
}

impl<P: Ord, E: KvProjectionEngine<P>> ObjectIdentity for TreeContext<'_, P, E> {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.engine.identify_kv_object(record)
    }
}

impl<P: Ord, E: KvProjectionEngine<P>> ContentSource for TreeContext<'_, P, E> {
    type Error = StorageError;

    fn load_content_object(&self, id: ObjectId) -> StorageResult<Option<ObjectRecord>> {
        #[cfg(test)]
        self.content_loads
            .set(self.content_loads.get().strict_add(1));
        self.record(id).map(Some)
    }

    fn load_shared_content_object(&self, id: ObjectId) -> StorageResult<Option<Arc<ObjectRecord>>> {
        #[cfg(test)]
        self.content_loads
            .set(self.content_loads.get().strict_add(1));
        if let Some(record) = self.records.get(&id) {
            return Ok(Some(Arc::new(record.clone())));
        }
        self.engine
            .load_shared_kv_object_for(self.principal, id)
            .map_err(|error| map_engine(&error))?
            .map(Some)
            .ok_or_else(|| map_engine(&crate::storage_model::ModelError::MissingObject(id).into()))
    }

    fn load_shared_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> StorageResult<Vec<Option<Arc<ObjectRecord>>>> {
        #[cfg(test)]
        self.content_loads
            .set(self.content_loads.get().strict_add(ids.len()));
        let mut local = BTreeMap::new();
        let mut results: Vec<_> = ids
            .iter()
            .map(|id| {
                self.records.get(id).map(|record| {
                    Arc::clone(local.entry(*id).or_insert_with(|| Arc::new(record.clone())))
                })
            })
            .collect();
        let missing: Vec<_> = ids
            .iter()
            .copied()
            .enumerate()
            .filter(|(index, _)| results[*index].is_none())
            .collect();
        if missing.is_empty() {
            return Ok(results);
        }
        let unresolved: Vec<_> = missing.iter().map(|(_, id)| *id).collect();
        let loaded = self
            .engine
            .load_shared_kv_objects_for(self.principal, &unresolved)
            .map_err(|error| map_engine(&error))?;
        if loaded.len() != missing.len() {
            return Err(StorageError::Internal(
                "KV content batch length mismatch".to_owned(),
            ));
        }
        for ((index, id), record) in missing.into_iter().zip(loaded) {
            results[index] = Some(record.ok_or_else(|| {
                map_engine(&crate::storage_model::ModelError::MissingObject(id).into())
            })?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests;
