//! Canonical page grammar for the persistent KV B+-tree.

use crate::storage_model::{ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference};

use super::super::tree_error::invalid;
use super::FORMAT_VERSION;
use super::checkpoint_branch::Header;
use super::checkpoint_header::{self, Kind};
use super::checkpoint_reference::{self, Rejection, Relation};
use super::validation::validate_composite_key;
use crate::error::{StorageError, StorageResult};

pub(super) use super::checkpoint_branch::{MAX_TREE_LEVEL, NODE_MAX_ENTRIES};
pub(super) use super::checkpoint_record::NODE_MAX_RETAINED_BYTES;
pub(super) use super::checkpoint_value::{INLINE_VALUE_MAX, ValueSlot};

pub(super) use super::checkpoint_totals::NodeTotals;

impl NodeTotals {
    pub(super) fn add(self, other: Self) -> StorageResult<Self> {
        Ok(Self {
            entries: self
                .entries
                .checked_add(other.entries)
                .ok_or_else(arithmetic_overflow)?,
            logical_bytes: self
                .logical_bytes
                .checked_add(other.logical_bytes)
                .ok_or_else(arithmetic_overflow)?,
            quota_bytes: self
                .quota_bytes
                .checked_add(other.quota_bytes)
                .ok_or_else(arithmetic_overflow)?,
        })
    }
}

pub(super) type LeafEntry = super::checkpoint_leaf::Entry<ValueSlot>;

impl LeafEntry {
    pub(super) fn totals(&self) -> StorageResult<NodeTotals> {
        super::checkpoint_leaf_summary::charge(self).ok_or_else(arithmetic_overflow)
    }
}

pub(super) type ChildPointer = super::checkpoint_range::Child<ObjectId, NodeTotals>;

pub(super) type Node = super::checkpoint_page::Node<ObjectId, NodeTotals, ValueSlot>;

pub(super) type NodeHandle = super::checkpoint_page::Handle<ObjectId, NodeTotals, ValueSlot>;

impl NodeHandle {
    pub(super) fn pointer(&self) -> ChildPointer {
        ChildPointer {
            lower_bound: self.node.minimum_key().to_vec(),
            object: self.object,
            level: self.node.level(),
            totals: self.node.totals(),
        }
    }
}

pub(super) fn value_record(bytes: Vec<u8>) -> ObjectRecord {
    super::spill_record::opaque(FORMAT_VERSION, bytes)
}

pub(super) fn leaf_record(entries: &[LeafEntry]) -> StorageResult<ObjectRecord> {
    use super::checkpoint_value::WriteError;

    if entries.is_empty() || entries.len() > NODE_MAX_ENTRIES {
        return Err(serialization("invalid KV leaf entry count"));
    }
    let totals = leaf_totals(entries)?;
    let mut canonical = Vec::new();
    if !checkpoint_header::append(
        &mut canonical,
        Kind::Leaf,
        Header {
            level: 0,
            count: entries.len(),
            totals,
        },
    ) {
        return Err(arithmetic_overflow());
    }
    let mut references = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if !super::checkpoint_key_field::append(&mut canonical, &entry.key) {
            return Err(arithmetic_overflow());
        }
        super::checkpoint_value::append(&mut canonical, &mut references, index, &entry.value)
            .map_err(|reason| match reason {
                WriteError::Overflow => arithmetic_overflow(),
                WriteError::Oversized => serialization("oversized inline KV value"),
                WriteError::SmallSpill => serialization("small KV value was not inlined"),
            })?;
    }
    ObjectRecord::new(
        ObjectKind::KvLeaf,
        FORMAT_VERSION,
        canonical,
        references,
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| model_error(&error))
}

pub(super) fn branch_record(children: &[ChildPointer]) -> StorageResult<ObjectRecord> {
    if children.len() < 2 || children.len() > NODE_MAX_ENTRIES {
        return Err(serialization("invalid KV branch child count"));
    }
    let child_level = children
        .first()
        .map(|child| child.level)
        .ok_or_else(|| serialization("KV branch has no children"))?;
    if children.iter().any(|child| child.level != child_level) {
        return Err(serialization("KV branch children have mixed levels"));
    }
    let level = child_level
        .checked_add(1)
        .filter(|level| *level <= MAX_TREE_LEVEL)
        .ok_or_else(arithmetic_overflow)?;
    let totals = super::checkpoint_summary::sum(children).ok_or_else(arithmetic_overflow)?;
    let mut canonical = Vec::new();
    if !checkpoint_header::append(
        &mut canonical,
        Kind::Branch,
        Header {
            level,
            count: children.len(),
            totals,
        },
    ) {
        return Err(arithmetic_overflow());
    }
    let mut references = Vec::with_capacity(children.len());
    for (index, child) in children.iter().enumerate() {
        if !super::checkpoint_key_field::append(&mut canonical, &child.lower_bound) {
            return Err(arithmetic_overflow());
        }
        child.totals.append(&mut canonical);
        references.push(ObjectReference::owns(
            checkpoint_reference::label(Relation::Child, index).ok_or_else(arithmetic_overflow)?,
            child.object,
        ));
    }
    ObjectRecord::new(
        ObjectKind::KvBranch,
        FORMAT_VERSION,
        canonical,
        references,
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| model_error(&error))
}

pub(super) fn decode_node(id: ObjectId, record: &ObjectRecord) -> StorageResult<NodeHandle> {
    super::checkpoint_record::read(id, record, FORMAT_VERSION, |k| {
        validate_composite_key(id, k)
    })
    .map_err(|error| decode_error(id, error))
}

pub(super) fn decode_error(
    id: ObjectId,
    error: super::checkpoint_record::ReadError<StorageError>,
) -> StorageError {
    use super::checkpoint_record::{EnvelopeError, ReadError, SizeError};
    match error {
        ReadError::Envelope(EnvelopeError::Header) => {
            invalid(id, "invalid persistent KV page header")
        },
        ReadError::Envelope(EnvelopeError::Kind) => invalid(id, "invalid persistent KV page kind"),
        ReadError::Leaf(e) => leaf_error(id, e),
        ReadError::Branch(e) => branch_error(id, e),
        ReadError::Size(SizeError::Overflow) => {
            model_error(&crate::storage_model::ModelError::ArithmeticOverflow)
        },
        ReadError::Size(SizeError::Oversize) => invalid(id, "oversized persistent KV page"),
    }
}

pub(super) fn spilled_opaque_payload(
    id: ObjectId,
    expected_length: u64,
    record: &ObjectRecord,
) -> StorageResult<&[u8]> {
    super::spill_record::payload(record, FORMAT_VERSION, expected_length)
        .ok_or_else(|| invalid(id, "invalid spilled KV value"))
}

fn leaf_error(
    id: ObjectId,
    reason: super::checkpoint_leaf_record::Error<StorageError>,
) -> StorageError {
    use super::checkpoint_entries::Error;
    use super::checkpoint_key_field::KeyError;
    use super::checkpoint_value::Error as ValueError;

    use super::checkpoint_leaf_record::Error as RecordError;
    use super::checkpoint_leaf_summary::Error as SummaryError;
    match reason {
        RecordError::Prefix(e) => header_error(id, e),
        RecordError::Count => invalid(id, "invalid KV leaf entry count"),
        RecordError::Summary(SummaryError::Overflow) => arithmetic_overflow(),
        RecordError::Summary(SummaryError::NonCanonical) => {
            invalid(id, "non-canonical persistent KV leaf")
        },
        RecordError::Entries(reason) => match reason {
            Error::Key(KeyError::Field(e)) => page_read_error(id, e),
            Error::Key(KeyError::Length) => invalid(id, "persistent KV length is too large"),
            Error::Invalid(e) => e,
            Error::References => invalid(id, "non-canonical persistent KV leaf"),
            Error::Trailing => invalid(id, "trailing persistent KV page bytes"),
            Error::Value(reason) => match reason {
                ValueError::Field(e) => page_read_error(id, e),
                ValueError::Length => invalid(id, "KV value too large"),
                ValueError::Oversized => invalid(id, "oversized inline KV value"),
                ValueError::SmallSpill => invalid(id, "small KV value was not inlined"),
                ValueError::Tag => invalid(id, "invalid KV value storage tag"),
                ValueError::Reference(Rejection::Missing) => {
                    invalid(id, "spilled KV value reference is missing")
                },
                ValueError::Reference(Rejection::IndexOverflow) => arithmetic_overflow(),
                ValueError::Reference(Rejection::Mismatch) => {
                    invalid(id, "invalid spilled KV value reference")
                },
            },
        },
    }
}

fn branch_error(
    id: ObjectId,
    reason: checkpoint_header::RecordError<StorageError>,
) -> StorageError {
    use super::checkpoint_branch::{DecodeError, RowsError};
    use super::checkpoint_child::ChildError;
    use super::checkpoint_key_field::KeyError;
    use super::checkpoint_summary::FinishError;

    match reason {
        checkpoint_header::RecordError::Prefix(e) => header_error(id, e),
        checkpoint_header::RecordError::Body(reason) => match reason {
            DecodeError::Header => invalid(id, "invalid KV branch header"),
            DecodeError::Rows(RowsError::Level) => invalid(id, "invalid KV branch level"),
            DecodeError::Rows(RowsError::Child(reason)) => match reason {
                ChildError::Key(KeyError::Field(e)) | ChildError::Totals(e) => {
                    page_read_error(id, e)
                },
                ChildError::Key(KeyError::Length) => {
                    invalid(id, "persistent KV length is too large")
                },
                ChildError::InvalidKey(e) => e,
                ChildError::Empty => invalid(id, "empty KV branch child"),
                ChildError::Reference(Rejection::IndexOverflow) => arithmetic_overflow(),
                ChildError::Reference(Rejection::Missing | Rejection::Mismatch) => {
                    invalid(id, "invalid KV branch child reference")
                },
            },
            DecodeError::Finish(FinishError::Trailing) => {
                invalid(id, "trailing persistent KV page bytes")
            },
            DecodeError::Finish(FinishError::NonCanonical) => {
                invalid(id, "non-canonical persistent KV branch")
            },
            DecodeError::Finish(FinishError::Overflow) => arithmetic_overflow(),
        },
    }
}

fn leaf_totals(entries: &[LeafEntry]) -> StorageResult<NodeTotals> {
    super::checkpoint_leaf_summary::sum(entries).ok_or_else(arithmetic_overflow)
}

fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("persistent KV tree arithmetic overflow".to_owned())
}

fn serialization(message: &str) -> StorageError {
    StorageError::Serialization(message.to_owned())
}

fn model_error(error: &crate::storage_model::ModelError) -> StorageError {
    StorageError::Serialization(error.to_string())
}

fn page_read_error(id: ObjectId, error: crate::storage_fields::ReadError) -> StorageError {
    match error {
        crate::storage_fields::ReadError::Overflow(_) => arithmetic_overflow(),
        crate::storage_fields::ReadError::Truncated => invalid(id, "truncated persistent KV page"),
    }
}

fn header_error(id: ObjectId, e: checkpoint_header::Error) -> StorageError {
    match e {
        checkpoint_header::Error::Field(error) => page_read_error(id, error),
        checkpoint_header::Error::Magic => invalid(id, "invalid persistent KV page magic"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inline(key: &[u8], value: &[u8]) -> LeafEntry {
        LeafEntry {
            key: key.to_vec(),
            value: ValueSlot::Inline(value.to_vec()),
        }
    }

    #[test]
    fn format_four_page_constants_are_stable() {
        assert_eq!(INLINE_VALUE_MAX, 1_024);
        assert_eq!(NODE_MAX_RETAINED_BYTES, 4_096);
        assert_eq!(NODE_MAX_ENTRIES, 64);
        assert_eq!(MAX_TREE_LEVEL, 16);
        assert_eq!(checkpoint_header::LEAF_MAGIC, b"astrid-kv-bplus-leaf-v1\0");
        assert_eq!(
            checkpoint_header::BRANCH_MAGIC,
            b"astrid-kv-bplus-branch-v1\0"
        );
        assert_eq!(super::super::checkpoint_value::INLINE_VALUE, 0);
        assert_eq!(super::super::checkpoint_value::SPILLED_VALUE, 1);
    }

    #[test]
    fn spilled_reference_uses_leaf_entry_index_after_inline_value() {
        let target = ObjectId::new([9; 32]);
        let entries = vec![
            inline(b"n\0a", b"x"),
            LeafEntry {
                key: b"n\0b".to_vec(),
                value: ValueSlot::Spilled {
                    object: target,
                    length: 2_048,
                },
            },
        ];
        let record = leaf_record(&entries).unwrap();
        assert_eq!(record.references().len(), 1);
        assert_eq!(record.references()[0].label().as_bytes(), b"value/\x00\x01");
        let handle = decode_node(ObjectId::new([1; 32]), &record).unwrap();
        assert!(matches!(handle.node, Node::Leaf(leaf) if leaf.entries == entries));
        assert_eq!(
            checkpoint_reference::label(Relation::Child, 0x1234)
                .unwrap()
                .as_bytes(),
            b"child/\x12\x34"
        );
    }

    #[test]
    fn leaf_decode_rejects_unsorted_and_duplicate_keys() {
        for entries in [
            vec![inline(b"n\0b", b"x"), inline(b"n\0a", b"y")],
            vec![inline(b"n\0a", b"x"), inline(b"n\0a", b"y")],
        ] {
            let record = leaf_record(&entries).unwrap();
            assert!(decode_node(ObjectId::new([1; 32]), &record).is_err());
        }
    }

    #[test]
    fn branch_decode_rejects_unsorted_bounds() {
        let totals = NodeTotals {
            entries: 1,
            logical_bytes: 1,
            quota_bytes: 4,
        };
        let record = branch_record(&[
            ChildPointer {
                lower_bound: b"n\0b".to_vec(),
                object: ObjectId::new([2; 32]),
                level: 0,
                totals,
            },
            ChildPointer {
                lower_bound: b"n\0a".to_vec(),
                object: ObjectId::new([3; 32]),
                level: 0,
                totals,
            },
        ])
        .unwrap();

        assert!(decode_node(ObjectId::new([4; 32]), &record).is_err());
    }

    #[test]
    fn value_storage_form_is_canonical() {
        assert!(
            leaf_record(&[LeafEntry {
                key: b"n\0a".to_vec(),
                value: ValueSlot::Inline(vec![0; INLINE_VALUE_MAX.saturating_add(1)]),
            }])
            .is_err()
        );
        assert!(
            leaf_record(&[LeafEntry {
                key: b"n\0a".to_vec(),
                value: ValueSlot::Spilled {
                    object: ObjectId::new([5; 32]),
                    length: INLINE_VALUE_MAX as u64,
                },
            }])
            .is_err()
        );
    }
}
