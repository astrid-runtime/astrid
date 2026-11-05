//! Full structural and accounting validation for persistent KV B+-trees.

#[cfg(test)]
#[path = "validation/proof_tests.rs"]
mod proof_tests;

use std::collections::BTreeMap;

use crate::engine::KvProjectionEngine;
use crate::storage_model::ObjectId;

use super::context::TreeContext;
use super::node::{ChildPointer, Node, NodeHandle, NodeTotals, ValueSlot};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::invalid;
use crate::kv::{validate_key, validate_namespace};

/// Opaque constant-size certificate that an exact immutable KV checkpoint tree
/// may use certified point-reads.
///
/// Constructed only inside this module after full `validate_tree`, for the empty
/// tree, or by inductive checkpoint derivation from a header that already
/// carried a matching certificate. Owner binding is the carrying
/// [`super::header::TreeHeader`] / principal partition: `projected_get` only
/// skips content-boundary revalidation when the live context principal owns
/// that header and `header.tree` matches this certificate. An empty
/// (`None`-root) certificate never authorizes an opened content DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedCheckpoint {
    root: Option<ObjectId>,
}

impl ValidatedCheckpoint {
    const EMPTY: Self = Self { root: None };

    const fn certified(root: ObjectId) -> Self {
        Self { root: Some(root) }
    }

    /// Empty checkpoint tree certificate. Never authorizes content tokens.
    #[must_use]
    pub(super) const fn empty() -> Self {
        Self::EMPTY
    }

    /// Exact checkpoint tree root covered by this certificate, if any.
    #[must_use]
    pub(crate) const fn root(self) -> Option<ObjectId> {
        self.root
    }

    /// Return whether this certificate names exactly `tree`.
    #[must_use]
    pub(super) fn matches_tree(self, tree: Option<ObjectId>) -> bool {
        self.root == tree
    }

    /// Mint a per-read membership token for a content file retrieved under this
    /// certificate. Empty certificates cannot mint; callers must only invoke
    /// this after a bound leaf traversal found the file in this tree.
    const fn membership_for_retrieved_file(
        self,
        file: ObjectId,
    ) -> Option<CertifiedValueMembership> {
        if self.root.is_none() {
            return None;
        }
        Some(CertifiedValueMembership { file })
    }
}

/// Constant-size per-read proof that one content file was retrieved under a
/// sealed [`ValidatedCheckpoint`] tree traversal.
///
/// Constructed only in this module. The content-DAG bridge accepts this type
/// and checks the opened descriptor's file identity; arbitrary opened DAGs
/// cannot be authorized by presenting a tree certificate alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertifiedValueMembership {
    file: ObjectId,
}

impl CertifiedValueMembership {
    /// Content-DAG file identity bound by the certified retrieval.
    #[must_use]
    pub(crate) const fn file(self) -> ObjectId {
        self.file
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kv) struct TreeValidation {
    certificate: ValidatedCheckpoint,
    pub(in crate::kv) entries: u64,
    pub(in crate::kv) logical_bytes: u64,
    pub(in crate::kv) quota_bytes: u64,
}

impl TreeValidation {
    pub(in crate::kv) const EMPTY: Self = Self {
        certificate: ValidatedCheckpoint::EMPTY,
        entries: 0,
        logical_bytes: 0,
        quota_bytes: 0,
    };

    /// Checkpoint tree root named by the sealed certificate.
    #[must_use]
    pub(in crate::kv) const fn root(self) -> Option<ObjectId> {
        self.certificate.root()
    }

    /// Borrow the sealed certificate carried by this validation result.
    #[must_use]
    pub(super) const fn certificate(self) -> ValidatedCheckpoint {
        self.certificate
    }

    /// Construct accounting around an already-sealed certificate.
    #[must_use]
    pub(super) const fn from_certificate(
        certificate: ValidatedCheckpoint,
        entries: u64,
        logical_bytes: u64,
        quota_bytes: u64,
    ) -> Self {
        Self {
            certificate,
            entries,
            logical_bytes,
            quota_bytes,
        }
    }
}

#[derive(Clone, Debug)]
struct ValidatedNode {
    minimum_key: Vec<u8>,
    maximum_key: Vec<u8>,
    level: u16,
    totals: NodeTotals,
}

pub(super) fn validate_composite_key(id: ObjectId, key: &[u8]) -> StorageResult<()> {
    let Some(separator) = key.iter().position(|byte| *byte == 0) else {
        return Err(invalid(id, "persistent KV key has no namespace separator"));
    };
    if separator == 0
        || separator.saturating_add(1) >= key.len()
        || key[separator.saturating_add(1)..].contains(&0)
    {
        return Err(invalid(id, "persistent KV composite key is non-canonical"));
    }
    let namespace = std::str::from_utf8(&key[..separator])
        .map_err(|_| invalid(id, "persistent KV namespace is not UTF-8"))?;
    let name = std::str::from_utf8(&key[separator.saturating_add(1)..])
        .map_err(|_| invalid(id, "persistent KV key is not UTF-8"))?;
    validate_namespace(namespace)
        .and_then(|()| validate_key(name))
        .map_err(|_| invalid(id, "persistent KV composite key is invalid"))
}

impl<P, E> TreeContext<'_, P, E>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    pub(super) fn validate_tree(
        &mut self,
        root: Option<ObjectId>,
    ) -> StorageResult<TreeValidation> {
        let Some(root) = root else {
            return Ok(TreeValidation::EMPTY);
        };
        let mut marks = BTreeMap::<ObjectId, u8>::new();
        let mut computed = BTreeMap::<ObjectId, ValidatedNode>::new();
        let mut stack = vec![(root, false)];

        while let Some((object, expanded)) = stack.pop() {
            if !expanded {
                match marks.insert(object, 1) {
                    Some(1) => {
                        return Err(invalid(object, "persistent KV tree contains a cycle"));
                    },
                    Some(2) => {
                        return Err(invalid(object, "persistent KV tree reuses a page"));
                    },
                    Some(_) | None => {},
                }
                let handle = self.node(object)?;
                stack.push((object, true));
                if let Node::Branch(branch) = handle.node {
                    for child in branch.children.iter().rev() {
                        stack.push((child.object, false));
                    }
                }
                continue;
            }

            let handle = self.node(object)?;
            let validated = self.validate_page(&handle, &mut computed)?;
            computed.insert(object, validated);
            marks.insert(object, 2);
        }

        let validated = computed
            .remove(&root)
            .ok_or_else(|| invalid(root, "persistent KV root validation is missing"))?;
        Ok(TreeValidation::from_certificate(
            ValidatedCheckpoint::certified(root),
            validated.totals.entries,
            validated.totals.logical_bytes,
            validated.totals.quota_bytes,
        ))
    }

    /// Pack a new checkpoint tree from a header that already carries a sealed
    /// certificate for its current tree, and mint the successor certificate.
    pub(super) fn build_validated_checkpoint(
        &mut self,
        header: &super::header::TreeHeader<P>,
    ) -> StorageResult<(Option<ObjectId>, TreeValidation)> {
        if self.principal() != &header.owner {
            return Err(StorageError::Serialization(
                "KV checkpoint owner disagrees with the live principal".to_owned(),
            ));
        }
        if !header
            .boundary
            .is_some_and(|certificate| certificate.matches_tree(header.tree))
        {
            return Err(StorageError::Serialization(
                "KV checkpoint requires a sealed certificate for the current tree".to_owned(),
            ));
        }
        let entries = self.checkpoint_entries(header)?;
        let tree = self.build_sorted_slots(entries)?;
        let certificate = tree.map_or(ValidatedCheckpoint::empty(), ValidatedCheckpoint::certified);
        Ok((
            tree,
            TreeValidation::from_certificate(
                certificate,
                header.entries,
                header.logical_bytes,
                header.quota_bytes,
            ),
        ))
    }

    /// Point-read a value under a sealed checkpoint certificate.
    ///
    /// Requires the carrying header's owner to match this context principal and
    /// the certificate to name `header.tree`. Chunked values mint a private
    /// per-read [`CertifiedValueMembership`] after the shared leaf lookup.
    /// Mismatched or empty certificates fall back to fully validating reads.
    pub(super) fn read_certified_tree_value(
        &mut self,
        header: &super::header::TreeHeader<P>,
        key: &[u8],
        certificate: ValidatedCheckpoint,
    ) -> StorageResult<Option<Vec<u8>>> {
        if self.principal() != &header.owner
            || !certificate.matches_tree(header.tree)
            || certificate.root().is_none()
        {
            return self.get(header.tree, key);
        }
        self.get_slot(header.tree, key)?
            .map(|value| self.certified_slot_bytes(&value, certificate))
            .transpose()
    }

    fn certified_slot_bytes(
        &self,
        value: &ValueSlot,
        certificate: ValidatedCheckpoint,
    ) -> StorageResult<Vec<u8>> {
        use super::node::decode_value;
        use crate::content_dag::{
            read_verified_content, verified_content_from_certified_membership,
        };
        match value {
            ValueSlot::Inline(bytes) => Ok(bytes.clone()),
            ValueSlot::Spilled { object, length } => {
                let record = self.record(*object)?;
                if record.format_version() == super::context::value::chunked_value_version() {
                    let opened = self.open_chunked_value(*object, *length, &record)?;
                    let membership = certificate
                        .membership_for_retrieved_file(opened.descriptor().file())
                        .ok_or_else(|| {
                            invalid(
                                *object,
                                "chunked KV value lacks a matching tree certificate",
                            )
                        })?;
                    let verified = verified_content_from_certified_membership(opened, membership)
                        .ok_or_else(|| {
                        invalid(
                            *object,
                            "chunked KV value membership disagrees with opened content",
                        )
                    })?;
                    read_verified_content(self, verified).map_err(|error| {
                        StorageError::Serialization(format!(
                            "read chunked KV value {object:?}: {error}"
                        ))
                    })
                } else {
                    decode_value(*object, *length, &record)
                }
            },
        }
    }

    fn validate_page(
        &mut self,
        handle: &NodeHandle,
        computed: &mut BTreeMap<ObjectId, ValidatedNode>,
    ) -> StorageResult<ValidatedNode> {
        match &handle.node {
            Node::Leaf(leaf) => {
                for entry in &leaf.entries {
                    self.value_bytes(&entry.value)?;
                }
                Ok(ValidatedNode {
                    minimum_key: leaf
                        .entries
                        .first()
                        .map(|entry| entry.key.clone())
                        .ok_or_else(|| invalid(handle.object, "persistent KV leaf is empty"))?,
                    maximum_key: leaf
                        .entries
                        .last()
                        .map(|entry| entry.key.clone())
                        .ok_or_else(|| invalid(handle.object, "persistent KV leaf is empty"))?,
                    level: 0,
                    totals: leaf.totals,
                })
            },
            Node::Branch(branch) => {
                let mut children = Vec::with_capacity(branch.children.len());
                for pointer in &branch.children {
                    children.push(take_validated_child(handle.object, pointer, computed)?);
                }
                for (index, (pointer, child)) in branch.children.iter().zip(&children).enumerate() {
                    if pointer.lower_bound != child.minimum_key
                        || pointer.level != child.level
                        || pointer.totals != child.totals
                        || child.level.checked_add(1) != Some(branch.level)
                    {
                        return Err(invalid(
                            handle.object,
                            "persistent KV child summary disagrees",
                        ));
                    }
                    if let Some(previous) = index
                        .checked_sub(1)
                        .and_then(|previous| children.get(previous))
                        && previous.maximum_key >= child.minimum_key
                    {
                        return Err(invalid(handle.object, "persistent KV child ranges overlap"));
                    }
                }
                let totals = children.iter().try_fold(
                    NodeTotals::default(),
                    |total, child| -> StorageResult<NodeTotals> {
                        Ok(NodeTotals {
                            entries: total.entries.checked_add(child.totals.entries).ok_or_else(
                                || invalid(handle.object, "persistent KV entry total overflow"),
                            )?,
                            logical_bytes: total
                                .logical_bytes
                                .checked_add(child.totals.logical_bytes)
                                .ok_or_else(|| {
                                    invalid(handle.object, "persistent KV logical total overflow")
                                })?,
                            quota_bytes: total
                                .quota_bytes
                                .checked_add(child.totals.quota_bytes)
                                .ok_or_else(|| {
                                    invalid(handle.object, "persistent KV quota total overflow")
                                })?,
                        })
                    },
                )?;
                if totals != branch.totals {
                    return Err(invalid(
                        handle.object,
                        "persistent KV branch totals disagree",
                    ));
                }
                Ok(ValidatedNode {
                    minimum_key: children
                        .first()
                        .map(|child| child.minimum_key.clone())
                        .ok_or_else(|| invalid(handle.object, "persistent KV branch is empty"))?,
                    maximum_key: children
                        .last()
                        .map(|child| child.maximum_key.clone())
                        .ok_or_else(|| invalid(handle.object, "persistent KV branch is empty"))?,
                    level: branch.level,
                    totals,
                })
            },
        }
    }
}

fn take_validated_child(
    parent: ObjectId,
    pointer: &ChildPointer,
    computed: &mut BTreeMap<ObjectId, ValidatedNode>,
) -> StorageResult<ValidatedNode> {
    computed
        .remove(&pointer.object)
        .ok_or_else(|| invalid(parent, "persistent KV child validation is missing"))
}

#[cfg(test)]
mod tests {
    use crate::engine::{CommitOutcome, KvProjectionError, RootSnapshot, RootTransaction};
    use crate::storage_model::{ObjectRecord, RootState};

    use super::*;
    use crate::kv::tree::node::{LeafEntry, ValueSlot, branch_record, decode_node, leaf_record};

    #[derive(Default)]
    struct FixtureEngine {
        objects: BTreeMap<ObjectId, ObjectRecord>,
    }

    impl KvProjectionEngine<String> for FixtureEngine {
        fn identify_kv_object(&self, _record: &ObjectRecord) -> ObjectId {
            ObjectId::new([0; 32])
        }

        fn current_kv_root(
            &self,
            _principal: &String,
        ) -> Result<Option<RootState>, KvProjectionError> {
            Ok(None)
        }

        fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
            Ok(self.objects.get(&id).cloned())
        }

        fn snapshot_kv_root(
            &self,
            _principal: &String,
        ) -> Result<Option<RootSnapshot>, KvProjectionError> {
            Ok(None)
        }

        fn commit_kv_root(
            &self,
            _transaction: RootTransaction<String>,
        ) -> Result<CommitOutcome, KvProjectionError> {
            Err(KvProjectionError::Engine(
                "validation fixture cannot commit".to_owned(),
            ))
        }

        fn flush_kv(&self) -> Result<(), KvProjectionError> {
            Ok(())
        }
    }

    fn leaf(key: &[u8], value: &[u8]) -> ObjectRecord {
        leaf_record(&[LeafEntry {
            key: key.to_vec(),
            value: ValueSlot::Inline(value.to_vec()),
        }])
        .unwrap()
    }

    fn pointer(id: ObjectId, record: &ObjectRecord) -> ChildPointer {
        decode_node(id, record).unwrap().pointer()
    }

    #[test]
    fn full_validation_rejects_a_forged_child_summary() {
        let left_id = ObjectId::new([1; 32]);
        let right_id = ObjectId::new([2; 32]);
        let root_id = ObjectId::new([3; 32]);
        let left = leaf(b"n\0a", b"left");
        let right = leaf(b"n\0b", b"right");
        let mut right_pointer = pointer(right_id, &right);
        right_pointer.totals.logical_bytes = right_pointer.totals.logical_bytes.saturating_add(1);
        let root = branch_record(&[pointer(left_id, &left), right_pointer]).unwrap();
        let engine = FixtureEngine {
            objects: BTreeMap::from([(left_id, left), (right_id, right), (root_id, root)]),
        };
        let principal = "alice".to_owned();

        let error = TreeContext::<String, _>::new(&engine, &principal)
            .validate_tree(Some(root_id))
            .unwrap_err();
        assert!(
            error.to_string().contains("child summary disagrees"),
            "{error}"
        );
    }

    #[test]
    fn full_validation_rejects_page_reuse() {
        let leaf_id = ObjectId::new([4; 32]);
        let root_id = ObjectId::new([5; 32]);
        let leaf = leaf(b"n\0a", b"value");
        let first = pointer(leaf_id, &leaf);
        let mut second = first.clone();
        second.lower_bound = b"n\0b".to_vec();
        let root = branch_record(&[first, second]).unwrap();
        let engine = FixtureEngine {
            objects: BTreeMap::from([(leaf_id, leaf), (root_id, root)]),
        };
        let principal = "alice".to_owned();

        let error = TreeContext::<String, _>::new(&engine, &principal)
            .validate_tree(Some(root_id))
            .unwrap_err();
        assert!(error.to_string().contains("reuses a page"), "{error}");
    }

    #[test]
    fn full_validation_rejects_cycles_before_following_them() {
        let root_id = ObjectId::new([6; 32]);
        let leaf_id = ObjectId::new([7; 32]);
        let leaf = leaf(b"n\0b", b"value");
        let root = branch_record(&[
            ChildPointer {
                lower_bound: b"n\0a".to_vec(),
                object: root_id,
                level: 0,
                totals: NodeTotals {
                    entries: 1,
                    logical_bytes: 1,
                    quota_bytes: 4,
                },
            },
            pointer(leaf_id, &leaf),
        ])
        .unwrap();
        let engine = FixtureEngine {
            objects: BTreeMap::from([(root_id, root), (leaf_id, leaf)]),
        };
        let principal = "alice".to_owned();

        let error = TreeContext::<String, _>::new(&engine, &principal)
            .validate_tree(Some(root_id))
            .unwrap_err();
        assert!(error.to_string().contains("contains a cycle"), "{error}");
    }
}
