//! Canonical write-ahead projection records over immutable KV checkpoints.

use crate::storage_model::{ObjectId, ObjectRecord};

use super::node::NodeTotals;
#[cfg(test)]
use super::node::ValueSlot;
use super::overlay::OverlayMap;
use super::validation::validate_composite_key;
use super::{FORMAT_VERSION, ROOT_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::invalid;

#[cfg(test)]
use super::delta_mutation::{DELETE, INLINE, SPILLED};
use super::delta_mutation::{DecodeError, EdgeError, ReadError, WriteError};
#[cfg(test)]
use super::projection_record::CHECKPOINT;
#[cfg(test)]
use super::projection_record::DELTA;

pub(super) use super::delta_mutation::Mutation;

pub(super) type Projection =
    super::memo_projection::Projection<super::validation::ValidatedCheckpoint>;

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

pub(super) fn checkpoint_record(tree: Option<ObjectId>, totals: NodeTotals) -> ObjectRecord {
    super::projection_record::checkpoint(FORMAT_VERSION, ROOT_LABEL, tree, totals)
}

pub(super) fn delta_record(
    previous: Option<ObjectId>,
    previous_depth: u64,
    previous_delta_bytes: u64,
    mutations: &[Mutation],
    totals: NodeTotals,
) -> StorageResult<ObjectRecord> {
    use super::delta_writer::EncodeError;
    super::delta_writer::record(
        FORMAT_VERSION,
        previous,
        previous_depth,
        previous_delta_bytes,
        mutations,
        totals,
    )
    .map_err(|error| match error {
        EncodeError::Keys => serialization("KV delta keys are not strictly ordered"),
        EncodeError::Overflow | EncodeError::Row(WriteError::Overflow) => arithmetic_overflow(),
        EncodeError::Row(WriteError::Oversized) => serialization("oversized inline KV delta value"),
        EncodeError::Row(WriteError::SmallSpill) => {
            serialization("small KV delta value was not inlined")
        },
        EncodeError::References => {
            model_error(&crate::storage_model::ModelError::NonCanonicalReferences)
        },
    })
}

pub(super) fn decode_head(id: ObjectId, record: &ObjectRecord) -> StorageResult<Head> {
    use super::projection_record;
    projection_record::decode(record, FORMAT_VERSION, ROOT_LABEL, |key| {
        validate_composite_key(id, key).err()
    })
    .map_err(|error| projection_error(id, error))
}

pub(super) fn projection_error(
    id: ObjectId,
    error: super::projection_record::Error<StorageError>,
) -> StorageError {
    use super::delta_recovery::Error;
    use super::projection_record::Error as RecordError;
    match error {
        RecordError::Type => invalid(id, "invalid KV projection head"),
        RecordError::Tag => invalid(id, "invalid KV projection head tag"),
        RecordError::Root => invalid(id, "invalid KV checkpoint root reference"),
        RecordError::Truncated => invalid(id, "truncated KV projection head"),
        RecordError::Trailing => invalid(id, "trailing KV projection head bytes"),
        RecordError::Delta(error) => match error {
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
        },
    }
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
