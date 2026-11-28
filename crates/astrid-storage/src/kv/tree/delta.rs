//! Canonical write-ahead projection records over immutable KV checkpoints.

use crate::storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};

use super::node::NodeTotals;
#[cfg(test)]
use super::node::ValueSlot;
use super::overlay::OverlayMap;
use super::validation::validate_composite_key;
use super::{FORMAT_VERSION, ROOT_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::invalid;

const CHECKPOINT: u8 = 0;
const DELTA: u8 = 1;
#[cfg(test)]
use super::delta_mutation::{DELETE, INLINE, SPILLED};
use super::delta_mutation::{DecodeError, EdgeError, ReadError, WriteError};

pub(super) use super::delta_mutation::Mutation;

#[derive(Clone, Debug)]
pub(super) struct Projection {
    pub(super) head: Option<ObjectId>,
    pub(super) tree: Option<ObjectId>,
    pub(super) overlay: OverlayMap,
    pub(super) depth: u64,
    pub(super) delta_bytes: u64,
    pub(super) totals: NodeTotals,
    pub(super) boundary: Option<super::validation::ValidatedCheckpoint>,
}

impl Projection {
    pub(super) fn empty() -> Self {
        Self {
            head: None,
            tree: None,
            overlay: OverlayMap::default(),
            depth: 0,
            delta_bytes: 0,
            totals: NodeTotals::default(),
            boundary: Some(super::validation::ValidatedCheckpoint::empty()),
        }
    }
}

pub(super) use super::delta_chain::Head;

pub(super) fn checkpoint_record(
    tree: Option<ObjectId>,
    totals: NodeTotals,
) -> StorageResult<ObjectRecord> {
    let mut canonical = Vec::with_capacity(17);
    canonical.push(CHECKPOINT);
    canonical.extend_from_slice(&totals.entries.to_le_bytes());
    canonical.extend_from_slice(&totals.quota_bytes.to_le_bytes());
    let references = tree
        .map(|tree| vec![ObjectReference::owns(ROOT_LABEL.to_vec().into(), tree)])
        .unwrap_or_default();
    ObjectRecord::new(
        ObjectKind::NamespaceMap,
        FORMAT_VERSION,
        canonical,
        references,
        totals.logical_bytes,
        ObjectClass::Metadata,
    )
    .map_err(|error| model_error(&error))
}

pub(super) fn delta_record(
    previous: Option<ObjectId>,
    previous_depth: u64,
    previous_delta_bytes: u64,
    mutations: &[Mutation],
    totals: NodeTotals,
) -> StorageResult<ObjectRecord> {
    if mutations.is_empty() || !super::delta_batch::keys_ordered(mutations) {
        return Err(serialization("KV delta keys are not strictly ordered"));
    }
    let depth = previous_depth
        .checked_add(1)
        .ok_or_else(arithmetic_overflow)?;
    let mutation_bytes = mutation_payload_bytes(mutations)?;
    let delta_bytes = previous_delta_bytes
        .checked_add(mutation_bytes)
        .ok_or_else(arithmetic_overflow)?;
    let count = u32::try_from(mutations.len()).map_err(|_| arithmetic_overflow())?;
    let mut canonical = Vec::new();
    canonical.push(DELTA);
    super::delta_header::Header {
        depth,
        delta_bytes,
        entries: totals.entries,
        quota_bytes: totals.quota_bytes,
        count,
    }
    .append(&mut canonical);
    let mut references = super::delta_header::predecessor_edges(previous);
    for (index, mutation) in mutations.iter().enumerate() {
        mutation
            .append(index, &mut canonical, &mut references)
            .map_err(|error| match error {
                WriteError::Overflow => arithmetic_overflow(),
                WriteError::Oversized => serialization("oversized inline KV delta value"),
                WriteError::SmallSpill => serialization("small KV delta value was not inlined"),
            })?;
    }
    references.sort();
    ObjectRecord::new(
        ObjectKind::NamespaceMap,
        FORMAT_VERSION,
        canonical,
        references,
        totals.logical_bytes,
        ObjectClass::Metadata,
    )
    .map_err(|error| model_error(&error))
}

pub(super) fn decode_head(id: ObjectId, record: &ObjectRecord) -> StorageResult<Head> {
    if record.kind() != ObjectKind::NamespaceMap
        || record.format_version() != FORMAT_VERSION
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(id, "invalid KV projection head"));
    }
    let mut cursor = Cursor::new(id, record.canonical_bytes());
    match cursor.u8()? {
        CHECKPOINT => decode_checkpoint(id, record, cursor),
        DELTA => decode_delta(id, record),
        _ => Err(invalid(id, "invalid KV projection head tag")),
    }
}

fn decode_checkpoint(
    id: ObjectId,
    record: &ObjectRecord,
    mut cursor: Cursor<'_>,
) -> StorageResult<Head> {
    let totals = NodeTotals {
        entries: cursor.u64()?,
        logical_bytes: record.logical_bytes(),
        quota_bytes: cursor.u64()?,
    };
    cursor.done()?;
    let tree = match record.reference(&ReferenceLabel::new(ROOT_LABEL)) {
        None if record.references().is_empty() => None,
        Some(reference)
            if reference.kind() == ReferenceKind::Owns && record.references().len() == 1 =>
        {
            Some(reference.target())
        },
        _ => return Err(invalid(id, "invalid KV checkpoint root reference")),
    };
    Ok(Head::Checkpoint { tree, totals })
}

fn decode_delta(id: ObjectId, record: &ObjectRecord) -> StorageResult<Head> {
    use super::delta_recovery::{self, Error};
    let head = delta_recovery::decode(record, |key| validate_composite_key(id, key).err())
        .map_err(|error| match error {
            Error::Truncated => invalid(id, "truncated KV projection head"),
            Error::Count => invalid(id, "KV projection count is too large"),
            Error::Empty => invalid(id, "empty KV delta head"),
            Error::NonOwning => invalid(id, "KV delta predecessor is not owning"),
            Error::Batch(super::delta_batch::Error::Row(error)) => decode_error(id, error),
            Error::Batch(super::delta_batch::Error::Trailing) => {
                invalid(id, "trailing KV projection head bytes")
            },
            Error::Audit(super::delta_batch::AuditError::NonCanonical) => {
                invalid(id, "non-canonical KV delta operations")
            },
            Error::Audit(super::delta_batch::AuditError::Overflow) => arithmetic_overflow(),
            Error::Audit(super::delta_batch::AuditError::References) => {
                invalid(id, "unexpected KV delta reference")
            },
        })?;
    Ok(Head::Delta {
        previous: head.previous,
        depth: head.depth,
        delta_bytes: head.delta_bytes,
        mutations: head.rows,
        totals: head.totals,
    })
}

pub(super) fn mutation_payload_bytes(mutations: &[Mutation]) -> StorageResult<u64> {
    super::delta_batch::measure(mutations)
        .map(|(bytes, _)| bytes)
        .ok_or_else(arithmetic_overflow)
}

fn decode_error(id: ObjectId, error: DecodeError<StorageError>) -> StorageError {
    use super::checkpoint_key_field::KeyError;
    match error {
        DecodeError::Key(KeyError::Field(error))
        | DecodeError::Operation(ReadError::Field(error)) => field_error(id, error),
        DecodeError::Key(KeyError::Length) => invalid(id, "KV projection count is too large"),
        DecodeError::InvalidKey(error) => error,
        DecodeError::Operation(ReadError::Length) => {
            invalid(id, "KV projection length is too large")
        },
        DecodeError::Operation(ReadError::Oversized) => {
            invalid(id, "oversized inline KV delta value")
        },
        DecodeError::Operation(ReadError::SmallSpill) => {
            invalid(id, "small KV delta value was not inlined")
        },
        DecodeError::Operation(ReadError::Tag) => invalid(id, "invalid KV delta operation tag"),
        DecodeError::Edge(EdgeError::Index) => arithmetic_overflow(),
        DecodeError::Edge(EdgeError::Missing) => invalid(id, "spilled KV delta value is missing"),
        DecodeError::Edge(EdgeError::NonOwning) => {
            invalid(id, "spilled KV delta value is not owning")
        },
    }
}

fn field_error(id: ObjectId, error: crate::storage_fields::ReadError) -> StorageError {
    match error {
        crate::storage_fields::ReadError::Overflow(_) => arithmetic_overflow(),
        crate::storage_fields::ReadError::Truncated => invalid(id, "truncated KV projection head"),
    }
}

pub(super) fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("persistent KV projection arithmetic overflow".to_owned())
}

fn serialization(message: &str) -> StorageError {
    StorageError::Serialization(message.to_owned())
}

fn model_error(error: &crate::storage_model::ModelError) -> StorageError {
    StorageError::Serialization(error.to_string())
}

struct Cursor<'a> {
    id: ObjectId,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(id: ObjectId, bytes: &'a [u8]) -> Self {
        Self {
            id,
            bytes,
            offset: 0,
        }
    }

    fn take(&mut self, length: usize) -> StorageResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(arithmetic_overflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid(self.id, "truncated KV projection head"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> StorageResult<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid(self.id, "truncated KV projection integer"))
    }

    fn u8(&mut self) -> StorageResult<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u64(&mut self) -> StorageResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn done(self) -> StorageResult<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid(self.id, "trailing KV projection head bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inline(key: &[u8], value: &[u8]) -> Mutation {
        Mutation {
            key: key.to_vec(),
            value: Some(ValueSlot::Inline(value.to_vec())),
        }
    }

    #[test]
    fn format_four_transition_discriminants_are_stable() {
        assert_eq!(CHECKPOINT, 0);
        assert_eq!(DELTA, 1);
        assert_eq!(DELETE, 0);
        assert_eq!(INLINE, 1);
        assert_eq!(SPILLED, 2);
    }

    fn rewrite(record: &ObjectRecord, bytes: Vec<u8>) -> ObjectRecord {
        ObjectRecord::new(
            record.kind(),
            record.format_version(),
            bytes,
            record.references().to_vec(),
            record.logical_bytes(),
            record.class(),
        )
        .unwrap()
    }

    #[test]
    fn delta_decode_rejects_trailing_bytes() {
        let record = delta_record(
            None,
            0,
            0,
            &[inline(b"n\0a", b"x")],
            NodeTotals {
                entries: 1,
                logical_bytes: 1,
                quota_bytes: 4,
            },
        )
        .unwrap();
        let mut bytes = record.canonical_bytes().to_vec();
        bytes.push(0);

        assert!(decode_head(ObjectId::new([1; 32]), &rewrite(&record, bytes)).is_err());
    }

    #[test]
    fn delta_decode_rejects_unsorted_and_duplicate_keys() {
        let record = delta_record(
            None,
            0,
            0,
            &[inline(b"n\0a", b"x"), inline(b"n\0b", b"y")],
            NodeTotals {
                entries: 2,
                logical_bytes: 2,
                quota_bytes: 8,
            },
        )
        .unwrap();
        let first_key_last = 43;
        let second_key_last = 60;
        let mut descending = record.canonical_bytes().to_vec();
        descending.swap(first_key_last, second_key_last);
        assert!(decode_head(ObjectId::new([2; 32]), &rewrite(&record, descending)).is_err());

        let mut duplicate = record.canonical_bytes().to_vec();
        duplicate[second_key_last] = duplicate[first_key_last];
        assert!(decode_head(ObjectId::new([3; 32]), &rewrite(&record, duplicate)).is_err());
    }

    #[test]
    fn spilled_delta_values_must_have_exact_owning_references() {
        let record = delta_record(
            None,
            0,
            0,
            &[Mutation {
                key: b"n\0a".to_vec(),
                value: Some(ValueSlot::Spilled {
                    object: ObjectId::new([4; 32]),
                    length: 1_025,
                }),
            }],
            NodeTotals {
                entries: 1,
                logical_bytes: 1_025,
                quota_bytes: 1_028,
            },
        )
        .unwrap();
        let without_reference = ObjectRecord::new(
            record.kind(),
            record.format_version(),
            record.canonical_bytes().to_vec(),
            Vec::new(),
            record.logical_bytes(),
            record.class(),
        )
        .unwrap();

        assert!(decode_head(ObjectId::new([5; 32]), &without_reference).is_err());
    }
}
