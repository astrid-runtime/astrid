//! Full structural and accounting validation for persistent KV trees.

use std::collections::BTreeMap;

use astrid_storage_engine::KvProjectionEngine;
use astrid_storage_model::ObjectId;

use super::{TreeContext, TreeNode};
use crate::error::StorageResult;
use crate::kv::tree_error::invalid;
use crate::kv::{validate_key, validate_namespace};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kv) struct TreeValidation {
    pub(in crate::kv) root: Option<ObjectId>,
    pub(in crate::kv) logical_bytes: u64,
    pub(in crate::kv) quota_bytes: u64,
}

impl TreeValidation {
    pub(in crate::kv) const EMPTY: Self = Self {
        root: None,
        logical_bytes: 0,
        quota_bytes: 0,
    };
}

#[derive(Clone, Debug)]
struct ValidatedNode {
    minimum_key: Vec<u8>,
    maximum_key: Vec<u8>,
    height: u32,
    logical_total: u64,
    quota_total: u64,
}

fn validated_child(
    parent: ObjectId,
    child: Option<ObjectId>,
    missing: &'static str,
    computed: &mut BTreeMap<ObjectId, ValidatedNode>,
) -> StorageResult<Option<ValidatedNode>> {
    child
        .map(|id| computed.remove(&id).ok_or_else(|| invalid(parent, missing)))
        .transpose()
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

        while let Some((id, expanded)) = stack.pop() {
            if !expanded {
                match marks.insert(id, 1) {
                    Some(1) => return Err(invalid(id, "persistent KV tree contains a cycle")),
                    Some(2) => {
                        return Err(invalid(id, "persistent KV tree reuses a branch"));
                    },
                    Some(_) | None => {},
                }
                let node = self.node(id)?;
                stack.push((id, true));
                if let Some(right) = node.right {
                    stack.push((right, false));
                }
                if let Some(left) = node.left {
                    stack.push((left, false));
                }
                continue;
            }

            let node = self.node(id)?;
            let validated = self.validate_node(id, &node, &mut computed)?;
            computed.insert(id, validated);
            marks.insert(id, 2);
        }

        let validated = computed
            .remove(&root)
            .ok_or_else(|| invalid(root, "persistent KV root validation is missing"))?;
        Ok(TreeValidation {
            root: Some(root),
            logical_bytes: validated.logical_total,
            quota_bytes: validated.quota_total,
        })
    }

    fn validate_node(
        &mut self,
        id: ObjectId,
        node: &TreeNode,
        computed: &mut BTreeMap<ObjectId, ValidatedNode>,
    ) -> StorageResult<ValidatedNode> {
        self.value_bytes(id, node)?;
        let left = validated_child(
            id,
            node.left,
            "KV left child validation is missing",
            computed,
        )?;
        let right = validated_child(
            id,
            node.right,
            "KV right child validation is missing",
            computed,
        )?;
        if left
            .as_ref()
            .is_some_and(|child| child.maximum_key >= node.key)
            || right
                .as_ref()
                .is_some_and(|child| child.minimum_key <= node.key)
        {
            return Err(invalid(id, "persistent KV tree key order is invalid"));
        }

        let left_height = left.as_ref().map_or(0, |child| child.height);
        let right_height = right.as_ref().map_or(0, |child| child.height);
        let height = left_height
            .max(right_height)
            .checked_add(1)
            .ok_or_else(|| invalid(id, "persistent KV tree height overflow"))?;
        if node.height != height || left_height.abs_diff(right_height) > 1 {
            return Err(invalid(id, "persistent KV tree is not canonical AVL"));
        }
        let logical_total = left
            .as_ref()
            .map_or(0, |child| child.logical_total)
            .checked_add(node.value_len)
            .and_then(|total| {
                total.checked_add(right.as_ref().map_or(0, |child| child.logical_total))
            })
            .ok_or_else(|| invalid(id, "persistent KV tree logical total overflow"))?;
        let key_len = u64::try_from(node.key.len())
            .map_err(|_| invalid(id, "persistent KV tree key length overflow"))?;
        let quota_total = left
            .as_ref()
            .map_or(0, |child| child.quota_total)
            .checked_add(node.value_len)
            .and_then(|total| total.checked_add(key_len))
            .and_then(|total| {
                total.checked_add(right.as_ref().map_or(0, |child| child.quota_total))
            })
            .ok_or_else(|| invalid(id, "persistent KV tree quota total overflow"))?;
        if node.logical_total != logical_total || node.quota_total != quota_total {
            return Err(invalid(id, "persistent KV tree node totals disagree"));
        }

        let minimum_key = left.map_or_else(|| node.key.clone(), |child| child.minimum_key);
        let maximum_key = right.map_or_else(|| node.key.clone(), |child| child.maximum_key);
        Ok(ValidatedNode {
            minimum_key,
            maximum_key,
            height,
            logical_total,
            quota_total,
        })
    }
}
