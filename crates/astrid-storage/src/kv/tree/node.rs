//! Canonical page grammar for the persistent KV B+-tree.

use astrid_storage_model::{
    ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, ReferenceLabel,
};

use super::super::tree_error::invalid;
use super::FORMAT_VERSION;
use super::validation::validate_composite_key;
use crate::error::{StorageError, StorageResult};

pub(super) const INLINE_VALUE_MAX: usize = 1_024;
pub(super) const NODE_MAX_RETAINED_BYTES: u64 = 4_096;
pub(super) const NODE_MAX_ENTRIES: usize = 64;
pub(super) const MAX_TREE_LEVEL: u16 = 16;

const LEAF_MAGIC: &[u8] = b"astrid-kv-bplus-leaf-v1\0";
const BRANCH_MAGIC: &[u8] = b"astrid-kv-bplus-branch-v1\0";
const VALUE_LABEL_PREFIX: &[u8] = b"value/";
const CHILD_LABEL_PREFIX: &[u8] = b"child/";
const INLINE_VALUE: u8 = 0;
const SPILLED_VALUE: u8 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct NodeTotals {
    pub(super) entries: u64,
    pub(super) logical_bytes: u64,
    pub(super) quota_bytes: u64,
}

impl NodeTotals {
    fn add(self, other: Self) -> StorageResult<Self> {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ValueSlot {
    Inline(Vec<u8>),
    Spilled { object: ObjectId, length: u64 },
}

impl ValueSlot {
    pub(super) fn length(&self) -> StorageResult<u64> {
        match self {
            Self::Inline(bytes) => u64::try_from(bytes.len()).map_err(|_| arithmetic_overflow()),
            Self::Spilled { length, .. } => Ok(*length),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LeafEntry {
    pub(super) key: Vec<u8>,
    pub(super) value: ValueSlot,
}

impl LeafEntry {
    fn totals(&self) -> StorageResult<NodeTotals> {
        let key = u64::try_from(self.key.len()).map_err(|_| arithmetic_overflow())?;
        let value = self.value.length()?;
        Ok(NodeTotals {
            entries: 1,
            logical_bytes: value,
            quota_bytes: key.checked_add(value).ok_or_else(arithmetic_overflow)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ChildPointer {
    pub(super) lower_bound: Vec<u8>,
    pub(super) object: ObjectId,
    pub(super) level: u16,
    pub(super) totals: NodeTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LeafNode {
    pub(super) entries: Vec<LeafEntry>,
    pub(super) totals: NodeTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BranchNode {
    pub(super) level: u16,
    pub(super) children: Vec<ChildPointer>,
    pub(super) totals: NodeTotals,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Node {
    Leaf(LeafNode),
    Branch(BranchNode),
}

impl Node {
    pub(super) const fn level(&self) -> u16 {
        match self {
            Self::Leaf(_) => 0,
            Self::Branch(branch) => branch.level,
        }
    }

    pub(super) const fn totals(&self) -> NodeTotals {
        match self {
            Self::Leaf(leaf) => leaf.totals,
            Self::Branch(branch) => branch.totals,
        }
    }

    pub(super) fn minimum_key(&self) -> &[u8] {
        match self {
            Self::Leaf(leaf) => leaf
                .entries
                .first()
                .map_or(&[], |entry| entry.key.as_slice()),
            Self::Branch(branch) => branch
                .children
                .first()
                .map_or(&[], |child| child.lower_bound.as_slice()),
        }
    }

    pub(super) fn entry_slots(&self) -> usize {
        match self {
            Self::Leaf(leaf) => leaf.entries.len(),
            Self::Branch(branch) => branch.children.len(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct NodeHandle {
    pub(super) object: ObjectId,
    pub(super) node: Node,
}

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

pub(super) fn value_record(bytes: Vec<u8>) -> StorageResult<ObjectRecord> {
    ObjectRecord::new(
        ObjectKind::KvLeaf,
        FORMAT_VERSION,
        bytes,
        Vec::new(),
        0,
        ObjectClass::Data,
    )
    .map_err(|error| model_error(&error))
}

pub(super) fn leaf_record(entries: &[LeafEntry]) -> StorageResult<ObjectRecord> {
    if entries.is_empty() || entries.len() > NODE_MAX_ENTRIES {
        return Err(serialization("invalid KV leaf entry count"));
    }
    let totals = leaf_totals(entries)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(LEAF_MAGIC);
    push_count(&mut canonical, entries.len())?;
    push_totals(&mut canonical, totals);
    let mut references = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let key_length = u32::try_from(entry.key.len()).map_err(|_| arithmetic_overflow())?;
        canonical.extend_from_slice(&key_length.to_le_bytes());
        canonical.extend_from_slice(&entry.key);
        canonical.extend_from_slice(&entry.value.length()?.to_le_bytes());
        match &entry.value {
            ValueSlot::Inline(value) => {
                if value.len() > INLINE_VALUE_MAX {
                    return Err(serialization("oversized inline KV value"));
                }
                canonical.push(INLINE_VALUE);
                canonical.extend_from_slice(value);
            },
            ValueSlot::Spilled { object, length } => {
                if *length <= u64::try_from(INLINE_VALUE_MAX).unwrap_or(u64::MAX) {
                    return Err(serialization("small KV value was not inlined"));
                }
                canonical.push(SPILLED_VALUE);
                references.push(ObjectReference::owns(
                    indexed_label(VALUE_LABEL_PREFIX, index)?,
                    *object,
                ));
            },
        }
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
    let totals = sum_totals(children.iter().map(|child| child.totals))?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(BRANCH_MAGIC);
    canonical.extend_from_slice(&level.to_le_bytes());
    push_count(&mut canonical, children.len())?;
    push_totals(&mut canonical, totals);
    let mut references = Vec::with_capacity(children.len());
    for (index, child) in children.iter().enumerate() {
        let lower_bound = child.lower_bound.as_slice();
        let key_length = u32::try_from(lower_bound.len()).map_err(|_| arithmetic_overflow())?;
        canonical.extend_from_slice(&key_length.to_le_bytes());
        canonical.extend_from_slice(lower_bound);
        push_totals(&mut canonical, child.totals);
        references.push(ObjectReference::owns(
            indexed_label(CHILD_LABEL_PREFIX, index)?,
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
    if record.format_version() != FORMAT_VERSION
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(id, "invalid persistent KV page header"));
    }
    let node = match record.kind() {
        ObjectKind::KvLeaf => decode_leaf(id, record)?,
        ObjectKind::KvBranch => decode_branch(id, record)?,
        _ => return Err(invalid(id, "invalid persistent KV page kind")),
    };
    let retained_bytes = record
        .retained_bytes()
        .map_err(|error| model_error(&error))?;
    let unsplittable_slots = match &node {
        Node::Leaf(_) => 1,
        Node::Branch(_) => 3,
    };
    if retained_bytes > NODE_MAX_RETAINED_BYTES && node.entry_slots() > unsplittable_slots {
        return Err(invalid(id, "oversized persistent KV page"));
    }
    Ok(NodeHandle { object: id, node })
}

pub(super) fn decode_value(
    id: ObjectId,
    expected_length: u64,
    record: &ObjectRecord,
) -> StorageResult<Vec<u8>> {
    if record.kind() != ObjectKind::KvLeaf
        || record.format_version() != FORMAT_VERSION
        || record.class() != ObjectClass::Data
        || record.logical_bytes() != 0
        || !record.references().is_empty()
        || u64::try_from(record.canonical_bytes().len()).ok() != Some(expected_length)
        || expected_length <= u64::try_from(INLINE_VALUE_MAX).unwrap_or(u64::MAX)
    {
        return Err(invalid(id, "invalid spilled KV value"));
    }
    Ok(record.canonical_bytes().to_vec())
}

fn decode_leaf(id: ObjectId, record: &ObjectRecord) -> StorageResult<Node> {
    let mut cursor = Cursor::new(id, record.canonical_bytes());
    cursor.require(LEAF_MAGIC)?;
    let count = cursor.count()?;
    let totals = cursor.totals()?;
    if count == 0 || count > NODE_MAX_ENTRIES {
        return Err(invalid(id, "invalid KV leaf entry count"));
    }
    let mut entries = Vec::with_capacity(count);
    let mut reference_index = 0_usize;
    for entry_index in 0..count {
        let key_length = cursor.u32_usize()?;
        let key = cursor.take(key_length)?.to_vec();
        validate_composite_key(id, &key)?;
        let value_length = cursor.u64()?;
        let value = match cursor.u8()? {
            INLINE_VALUE => {
                let inline_length =
                    usize::try_from(value_length).map_err(|_| invalid(id, "KV value too large"))?;
                if inline_length > INLINE_VALUE_MAX {
                    return Err(invalid(id, "oversized inline KV value"));
                }
                ValueSlot::Inline(cursor.take(inline_length)?.to_vec())
            },
            SPILLED_VALUE => {
                if value_length <= u64::try_from(INLINE_VALUE_MAX).unwrap_or(u64::MAX) {
                    return Err(invalid(id, "small KV value was not inlined"));
                }
                let reference = record
                    .references()
                    .get(reference_index)
                    .ok_or_else(|| invalid(id, "spilled KV value reference is missing"))?;
                if reference.label() != &indexed_label(VALUE_LABEL_PREFIX, entry_index)?
                    || reference.kind() != ReferenceKind::Owns
                {
                    return Err(invalid(id, "invalid spilled KV value reference"));
                }
                reference_index = reference_index.saturating_add(1);
                ValueSlot::Spilled {
                    object: reference.target(),
                    length: value_length,
                }
            },
            _ => return Err(invalid(id, "invalid KV value storage tag")),
        };
        entries.push(LeafEntry { key, value });
    }
    cursor.done()?;
    if reference_index != record.references().len()
        || entries.windows(2).any(|pair| pair[0].key >= pair[1].key)
        || leaf_totals(&entries)? != totals
    {
        return Err(invalid(id, "non-canonical persistent KV leaf"));
    }
    Ok(Node::Leaf(LeafNode { entries, totals }))
}

fn decode_branch(id: ObjectId, record: &ObjectRecord) -> StorageResult<Node> {
    let mut cursor = Cursor::new(id, record.canonical_bytes());
    cursor.require(BRANCH_MAGIC)?;
    let level = cursor.u16()?;
    let count = cursor.count()?;
    let totals = cursor.totals()?;
    if level == 0
        || level > MAX_TREE_LEVEL
        || !(2..=NODE_MAX_ENTRIES).contains(&count)
        || record.references().len() != count
    {
        return Err(invalid(id, "invalid KV branch header"));
    }
    let child_level = level
        .checked_sub(1)
        .ok_or_else(|| invalid(id, "invalid KV branch level"))?;
    let mut children = Vec::with_capacity(count);
    for index in 0..count {
        let key_length = cursor.u32_usize()?;
        let lower_bound = cursor.take(key_length)?.to_vec();
        validate_composite_key(id, &lower_bound)?;
        let child_totals = cursor.totals()?;
        if child_totals.entries == 0 {
            return Err(invalid(id, "empty KV branch child"));
        }
        let reference = &record.references()[index];
        if reference.label() != &indexed_label(CHILD_LABEL_PREFIX, index)?
            || reference.kind() != ReferenceKind::Owns
        {
            return Err(invalid(id, "invalid KV branch child reference"));
        }
        children.push(ChildPointer {
            lower_bound,
            object: reference.target(),
            level: child_level,
            totals: child_totals,
        });
    }
    cursor.done()?;
    if children
        .windows(2)
        .any(|pair| pair[0].lower_bound >= pair[1].lower_bound)
        || sum_totals(children.iter().map(|child| child.totals))? != totals
    {
        return Err(invalid(id, "non-canonical persistent KV branch"));
    }
    Ok(Node::Branch(BranchNode {
        level,
        children,
        totals,
    }))
}

fn leaf_totals(entries: &[LeafEntry]) -> StorageResult<NodeTotals> {
    sum_totals(
        entries
            .iter()
            .map(LeafEntry::totals)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

fn sum_totals(totals: impl IntoIterator<Item = NodeTotals>) -> StorageResult<NodeTotals> {
    totals
        .into_iter()
        .try_fold(NodeTotals::default(), NodeTotals::add)
}

fn push_totals(bytes: &mut Vec<u8>, totals: NodeTotals) {
    bytes.extend_from_slice(&totals.entries.to_le_bytes());
    bytes.extend_from_slice(&totals.logical_bytes.to_le_bytes());
    bytes.extend_from_slice(&totals.quota_bytes.to_le_bytes());
}

fn push_count(bytes: &mut Vec<u8>, count: usize) -> StorageResult<()> {
    let count = u16::try_from(count).map_err(|_| arithmetic_overflow())?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn indexed_label(prefix: &[u8], index: usize) -> StorageResult<ReferenceLabel> {
    let index = u16::try_from(index).map_err(|_| arithmetic_overflow())?;
    let mut label = Vec::with_capacity(prefix.len().saturating_add(2));
    label.extend_from_slice(prefix);
    label.extend_from_slice(&index.to_be_bytes());
    Ok(ReferenceLabel::new(label))
}

fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("persistent KV tree arithmetic overflow".to_owned())
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
            .ok_or_else(|| invalid(self.id, "truncated persistent KV page"))?;
        self.offset = end;
        Ok(value)
    }

    fn require(&mut self, expected: &[u8]) -> StorageResult<()> {
        if self.take(expected.len())? != expected {
            return Err(invalid(self.id, "invalid persistent KV page magic"));
        }
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> StorageResult<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid(self.id, "truncated persistent KV integer"))
    }

    fn u8(&mut self) -> StorageResult<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> StorageResult<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32_usize(&mut self) -> StorageResult<usize> {
        usize::try_from(u32::from_le_bytes(self.array()?))
            .map_err(|_| invalid(self.id, "persistent KV length is too large"))
    }

    fn u64(&mut self) -> StorageResult<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> StorageResult<usize> {
        Ok(usize::from(self.u16()?))
    }

    fn totals(&mut self) -> StorageResult<NodeTotals> {
        Ok(NodeTotals {
            entries: self.u64()?,
            logical_bytes: self.u64()?,
            quota_bytes: self.u64()?,
        })
    }

    fn done(self) -> StorageResult<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid(self.id, "trailing persistent KV page bytes"));
        }
        Ok(())
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
