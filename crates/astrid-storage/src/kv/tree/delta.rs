//! Canonical write-ahead projection records over immutable KV checkpoints.

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};

use super::node::{INLINE_VALUE_MAX, NodeTotals, ValueSlot};
use super::overlay::OverlayMap;
use super::validation::validate_composite_key;
use super::{FORMAT_VERSION, ROOT_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::invalid;

const CHECKPOINT: u8 = 0;
const DELTA: u8 = 1;
const DELETE: u8 = 0;
const INLINE: u8 = 1;
const SPILLED: u8 = 2;
const PREVIOUS_LABEL: &[u8] = b"previous";
const VALUE_LABEL_PREFIX: &[u8] = b"value/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mutation {
    pub(super) key: Vec<u8>,
    pub(super) value: Option<ValueSlot>,
}

#[derive(Clone, Debug)]
pub(super) struct Projection {
    pub(super) head: Option<ObjectId>,
    pub(super) tree: Option<ObjectId>,
    pub(super) overlay: OverlayMap,
    pub(super) depth: u64,
    pub(super) delta_bytes: u64,
    pub(super) totals: NodeTotals,
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
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Head {
    Checkpoint {
        tree: Option<ObjectId>,
        totals: NodeTotals,
    },
    Delta {
        previous: Option<ObjectId>,
        depth: u64,
        delta_bytes: u64,
        mutations: Vec<Mutation>,
        totals: NodeTotals,
    },
}

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
    if mutations.is_empty() || mutations.windows(2).any(|pair| pair[0].key >= pair[1].key) {
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
    canonical.extend_from_slice(&depth.to_le_bytes());
    canonical.extend_from_slice(&delta_bytes.to_le_bytes());
    canonical.extend_from_slice(&totals.entries.to_le_bytes());
    canonical.extend_from_slice(&totals.quota_bytes.to_le_bytes());
    canonical.extend_from_slice(&count.to_le_bytes());
    let mut references = Vec::new();
    if let Some(previous) = previous {
        references.push(ObjectReference::owns(
            PREVIOUS_LABEL.to_vec().into(),
            previous,
        ));
    }
    for (index, mutation) in mutations.iter().enumerate() {
        let key_length = u32::try_from(mutation.key.len()).map_err(|_| arithmetic_overflow())?;
        canonical.extend_from_slice(&key_length.to_le_bytes());
        canonical.extend_from_slice(&mutation.key);
        match &mutation.value {
            None => canonical.push(DELETE),
            Some(ValueSlot::Inline(value)) => {
                if value.len() > INLINE_VALUE_MAX {
                    return Err(serialization("oversized inline KV delta value"));
                }
                canonical.push(INLINE);
                canonical.extend_from_slice(
                    &u64::try_from(value.len())
                        .map_err(|_| arithmetic_overflow())?
                        .to_le_bytes(),
                );
                canonical.extend_from_slice(value);
            },
            Some(ValueSlot::Spilled { object, length }) => {
                if *length <= INLINE_VALUE_MAX as u64 {
                    return Err(serialization("small KV delta value was not inlined"));
                }
                canonical.push(SPILLED);
                canonical.extend_from_slice(&length.to_le_bytes());
                references.push(ObjectReference::owns(value_label(index)?, *object));
            },
        }
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
        DELTA => decode_delta(id, record, cursor),
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

fn decode_delta(
    id: ObjectId,
    record: &ObjectRecord,
    mut cursor: Cursor<'_>,
) -> StorageResult<Head> {
    let depth = cursor.u64()?;
    let delta_bytes = cursor.u64()?;
    let totals = NodeTotals {
        entries: cursor.u64()?,
        logical_bytes: record.logical_bytes(),
        quota_bytes: cursor.u64()?,
    };
    let count = cursor.u32_usize()?;
    if depth == 0 || count == 0 {
        return Err(invalid(id, "empty KV delta head"));
    }
    let previous = record
        .reference(&ReferenceLabel::new(PREVIOUS_LABEL))
        .map(|reference| {
            if reference.kind() != ReferenceKind::Owns {
                return Err(invalid(id, "KV delta predecessor is not owning"));
            }
            Ok(reference.target())
        })
        .transpose()?;
    let mut mutations = Vec::with_capacity(count);
    for index in 0..count {
        let key_length = cursor.u32_usize()?;
        let key = cursor.take(key_length)?.to_vec();
        validate_composite_key(id, &key)?;
        let value = match cursor.u8()? {
            DELETE => None,
            INLINE => {
                let length = cursor.u64_usize()?;
                if length > INLINE_VALUE_MAX {
                    return Err(invalid(id, "oversized inline KV delta value"));
                }
                Some(ValueSlot::Inline(cursor.take(length)?.to_vec()))
            },
            SPILLED => {
                let length = cursor.u64()?;
                if length <= INLINE_VALUE_MAX as u64 {
                    return Err(invalid(id, "small KV delta value was not inlined"));
                }
                let reference = record
                    .reference(&value_label(index)?)
                    .ok_or_else(|| invalid(id, "spilled KV delta value is missing"))?;
                if reference.kind() != ReferenceKind::Owns {
                    return Err(invalid(id, "spilled KV delta value is not owning"));
                }
                Some(ValueSlot::Spilled {
                    object: reference.target(),
                    length,
                })
            },
            _ => return Err(invalid(id, "invalid KV delta operation tag")),
        };
        mutations.push(Mutation { key, value });
    }
    cursor.done()?;
    if mutations.windows(2).any(|pair| pair[0].key >= pair[1].key)
        || mutation_payload_bytes(&mutations)? > delta_bytes
    {
        return Err(invalid(id, "non-canonical KV delta operations"));
    }
    let expected_references = usize::from(previous.is_some())
        .checked_add(
            mutations
                .iter()
                .filter(|mutation| matches!(mutation.value, Some(ValueSlot::Spilled { .. })))
                .count(),
        )
        .ok_or_else(arithmetic_overflow)?;
    if record.references().len() != expected_references {
        return Err(invalid(id, "unexpected KV delta reference"));
    }
    Ok(Head::Delta {
        previous,
        depth,
        delta_bytes,
        mutations,
        totals,
    })
}

pub(super) fn mutation_payload_bytes(mutations: &[Mutation]) -> StorageResult<u64> {
    mutations.iter().try_fold(0_u64, |total, mutation| {
        let key = u64::try_from(mutation.key.len()).map_err(|_| arithmetic_overflow())?;
        let value = mutation
            .value
            .as_ref()
            .map(ValueSlot::length)
            .transpose()?
            .unwrap_or(0);
        total
            .checked_add(key)
            .and_then(|total| total.checked_add(value))
            .ok_or_else(arithmetic_overflow)
    })
}

fn value_label(index: usize) -> StorageResult<ReferenceLabel> {
    let index = u32::try_from(index).map_err(|_| arithmetic_overflow())?;
    let mut label = Vec::with_capacity(VALUE_LABEL_PREFIX.len().saturating_add(4));
    label.extend_from_slice(VALUE_LABEL_PREFIX);
    label.extend_from_slice(&index.to_be_bytes());
    Ok(ReferenceLabel::new(label))
}

fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("persistent KV projection arithmetic overflow".to_owned())
}

fn serialization(message: &str) -> StorageError {
    StorageError::Serialization(message.to_owned())
}

fn model_error(error: &astrid_storage_model::ModelError) -> StorageError {
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

    fn u32_usize(&mut self) -> StorageResult<usize> {
        usize::try_from(u32::from_le_bytes(self.array()?))
            .map_err(|_| invalid(self.id, "KV projection count is too large"))
    }

    fn u64(&mut self) -> StorageResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn u64_usize(&mut self) -> StorageResult<usize> {
        usize::try_from(self.u64()?)
            .map_err(|_| invalid(self.id, "KV projection length is too large"))
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
