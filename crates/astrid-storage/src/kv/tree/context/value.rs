//! Versioned spilled KV values backed by canonical content DAGs.
//!
//! Small values retain the original representation. Values larger than the
//! pinned content profile's maximum chunk use a version-five KV value wrapper
//! owning one canonical file DAG. Reuse, reachability and admission remain in
//! the same root transaction; no side keys or separate publications are used.

use std::borrow::Cow;
use std::sync::Arc;

use super::super::node::{spilled_opaque_payload, value_record};
use super::{
    INLINE_VALUE_MAX, KvProjectionEngine, ObjectId, ObjectRecord, StorageError, StorageResult,
    TreeContext, ValueSlot, arithmetic_overflow, invalid, map_engine,
};
use crate::content_dag::{
    ChunkingProfile, ContentSource, OpenedContent, build_content, open_content,
    read_opened_content, validate_opened_content,
};
use crate::storage_model::{ModelError, ObjectFormatVersion, ObjectIdentity};
#[cfg(test)]
use crate::storage_model::{
    ObjectClass, ObjectKind, ObjectReference, ReferenceKind, ReferenceLabel,
};

// These are immutable encoding rules, not operator memory limits. They pin
// identities and the canonical representation chosen for the same KV bytes.
const CHUNKED_VALUE_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(5) {
    Some(version) => version,
    None => unreachable!(),
};

#[cfg(test)]
const CONTENT_LABEL: &[u8] = &super::super::spill_record::CONTENT;
const PROFILE: ChunkingProfile = ChunkingProfile::ASTRID_V1;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    pub(super) fn make_value<'b>(
        &mut self,
        bytes: impl Into<Cow<'b, [u8]>>,
    ) -> StorageResult<ValueSlot> {
        let bytes = bytes.into();
        if bytes.len() <= INLINE_VALUE_MAX {
            return Ok(ValueSlot::Inline(bytes.into_owned()));
        }
        let length = u64::try_from(bytes.len()).map_err(|_| arithmetic_overflow())?;
        let object = self.spill_value(bytes, length)?;
        Ok(ValueSlot::Spilled { object, length })
    }

    pub(super) fn spill_value(
        &mut self,
        bytes: Cow<'_, [u8]>,
        length: u64,
    ) -> StorageResult<ObjectId> {
        if length > u64::from(PROFILE.maximum_bytes()) {
            self.make_chunked_value(&bytes, length)
        } else {
            self.insert(value_record(bytes.into_owned()))
        }
    }

    fn make_chunked_value(&mut self, bytes: &[u8], length: u64) -> StorageResult<ObjectId> {
        let built = build_content(self, PROFILE, bytes).map_err(|error| {
            StorageError::Serialization(format!("build chunked KV value: {error}"))
        })?;
        let file = built.descriptor().file();
        // The builder used this same context's engine identity and returns
        // unchanged owned records. A captured session binds these exact IDs to
        // the consuming engine; untrusted and foreign commits rehash them.
        for (object, record) in built.into_records() {
            self.stage_identified_record(object, record)?;
        }
        let wrapper = super::super::spill_record::wrapper(CHUNKED_VALUE_VERSION, file, length);
        self.insert(wrapper)
    }

    pub(in crate::kv::tree) fn value_bytes(&self, value: &ValueSlot) -> StorageResult<Vec<u8>> {
        self.resolve_slot(value, |id, length, record| {
            self.read_chunked_value(id, length, record)
        })
    }

    pub(in crate::kv::tree) fn resolve_slot(
        &self,
        value: &ValueSlot,
        chunk: impl FnOnce(ObjectId, u64, &ObjectRecord) -> StorageResult<Vec<u8>>,
    ) -> StorageResult<Vec<u8>> {
        use super::super::spill_record::{self, ResolveError};
        spill_record::resolve(
            value,
            super::super::FORMAT_VERSION,
            CHUNKED_VALUE_VERSION,
            |id| self.record(id),
            chunk,
        )
        .map_err(|error| match error {
            ResolveError::Source(e) => e,
            ResolveError::Invalid(id) => invalid(id, "invalid spilled KV value"),
        })
    }

    pub(in crate::kv::tree) fn validate_value(&self, value: &ValueSlot) -> StorageResult<()> {
        match value {
            ValueSlot::Inline(_) => Ok(()),
            ValueSlot::Spilled { object, length } => {
                let record = self.record(*object)?;
                if record.format_version() == CHUNKED_VALUE_VERSION {
                    let opened = self.open_chunked_value(*object, *length, &record)?;
                    validate_opened_content(self, opened).map_err(|error| {
                        StorageError::Serialization(format!(
                            "read chunked KV value {object:?}: {error}"
                        ))
                    })
                } else {
                    spilled_opaque_payload(*object, *length, &record).map(|_| ())
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
        let opened = self.open_chunked_value(id, length, record)?;
        read_opened_content(self, opened).map_err(|error| {
            StorageError::Serialization(format!("read chunked KV value {id:?}: {error}"))
        })
    }

    pub(in crate::kv::tree) fn open_chunked_value(
        &self,
        id: ObjectId,
        length: u64,
        record: &ObjectRecord,
    ) -> StorageResult<OpenedContent> {
        use super::super::spill_record::{self, Error};
        let file = spill_record::file(record, length, PROFILE.maximum_bytes()).map_err(
            |error| match error {
                Error::Wrapper => invalid(id, "invalid chunked KV value wrapper"),
                Error::Reference => invalid(id, "invalid chunked KV content reference"),
            },
        )?;
        let opened = open_content(self, file).map_err(|error| {
            StorageError::Serialization(format!("open chunked KV value {id:?}: {error}"))
        })?;
        // Validate the declared size before content reconstruction allocates.
        if opened.descriptor().logical_bytes() != length || opened.descriptor().profile() != PROFILE
        {
            return Err(invalid(id, "chunked KV descriptor disagrees with wrapper"));
        }
        Ok(opened)
    }
}

impl<P: Ord, E: KvProjectionEngine<P>> ObjectIdentity for TreeContext<'_, P, E> {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identify_record(record)
    }
}

impl<P: Ord, E: KvProjectionEngine<P>> ContentSource for TreeContext<'_, P, E> {
    type Error = StorageError;

    fn load_content_object(&self, id: ObjectId) -> StorageResult<Option<ObjectRecord>> {
        self.record(id).map(Some)
    }

    fn load_shared_content_object(&self, id: ObjectId) -> StorageResult<Option<Arc<ObjectRecord>>> {
        if let Some(record) = self.records.get(&id) {
            return Ok(Some(Arc::new(record.clone())));
        }
        self.engine
            .load_shared_kv_object_for(self.principal, id)
            .map_err(|error| map_engine(&error))?
            .map(Some)
            .ok_or_else(|| map_engine(&ModelError::MissingObject(id).into()))
    }

    fn load_shared_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> StorageResult<Vec<Option<Arc<ObjectRecord>>>> {
        // Follow the same source for each element: staged records stay local,
        // and engine misses retain single-read recovery/WAL semantics.
        ids.iter()
            .map(|id| self.load_shared_content_object(*id))
            .collect()
    }
}

#[cfg(test)]
mod tests;
