//! Full structural and accounting validation for persistent KV B+-trees.

use std::collections::BTreeMap;

use crate::engine::KvProjectionEngine;
use crate::storage_model::ObjectId;

use super::context::TreeContext;
use super::node::{ChildPointer, Node, NodeHandle, NodeTotals};
use crate::error::StorageResult;
use crate::kv::tree_error::invalid;
use crate::kv::{validate_key, validate_namespace};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kv) struct TreeValidation {
    pub(in crate::kv) root: Option<ObjectId>,
    pub(in crate::kv) entries: u64,
    pub(in crate::kv) logical_bytes: u64,
    pub(in crate::kv) quota_bytes: u64,
}

impl TreeValidation {
    pub(in crate::kv) const EMPTY: Self = Self {
        root: None,
        entries: 0,
        logical_bytes: 0,
        quota_bytes: 0,
    };
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
        Ok(TreeValidation {
            root: Some(root),
            entries: validated.totals.entries,
            logical_bytes: validated.totals.logical_bytes,
            quota_bytes: validated.totals.quota_bytes,
        })
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
