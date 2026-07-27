//! Error mapping and reference validation for the persistent KV projection.

use astrid_storage_engine::KvProjectionError;
use astrid_storage_model::{ObjectId, ObjectRecord, ReferenceKind, ReferenceLabel};

use crate::error::{StorageError, StorageResult};

pub(super) fn exact_owned_reference(
    id: ObjectId,
    record: &ObjectRecord,
    label: &[u8],
    required: bool,
) -> StorageResult<Option<ObjectId>> {
    match record.reference(&ReferenceLabel::new(label)) {
        Some(reference) if reference.kind() == ReferenceKind::Owns => Ok(Some(reference.target())),
        Some(_) => Err(invalid(id, "KV tree reference is not owning")),
        None if required => Err(invalid(id, "required KV tree reference is missing")),
        None => Ok(None),
    }
}

pub(super) fn map_engine(error: &KvProjectionError) -> StorageError {
    StorageError::Internal(format!("persistent KV tree: {error}"))
}

pub(super) fn invalid(id: ObjectId, detail: &'static str) -> StorageError {
    StorageError::Serialization(format!("invalid persistent KV object {id:?}: {detail}"))
}
