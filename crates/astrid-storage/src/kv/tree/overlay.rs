//! Process-local persistent map for resolved KV deltas.
//!
//! Nodes are immutable and reference-counted, so each published projection
//! reuses the previous projection and copies only one balanced search path.

use std::cmp::Ordering;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub(super) struct OverlayMap {
    root: Option<Arc<Node>>,
}

#[derive(Debug)]
struct Node {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
    height: u32,
}

impl OverlayMap {
    pub(super) fn get(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        let mut cursor = self.root.as_deref();
        while let Some(node) = cursor {
            match key.cmp(node.key.as_slice()) {
                Ordering::Less => cursor = node.left.as_deref(),
                Ordering::Greater => cursor = node.right.as_deref(),
                Ordering::Equal => return Some(&node.value),
            }
        }
        None
    }

    pub(super) fn insert(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        self.root = Some(insert(self.root.take(), key, value));
    }

    pub(super) fn range(&self, start: &[u8], end: &[u8]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut entries = Vec::new();
        collect_range(self.root.as_deref(), start, end, &mut entries);
        entries
    }

    pub(super) fn all(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut entries = Vec::new();
        collect_all(self.root.as_deref(), &mut entries);
        entries
    }
}

fn collect_all(node: Option<&Node>, entries: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>) {
    let Some(node) = node else {
        return;
    };
    collect_all(node.left.as_deref(), entries);
    entries.push((node.key.clone(), node.value.clone()));
    collect_all(node.right.as_deref(), entries);
}

fn insert(root: Option<Arc<Node>>, key: Vec<u8>, value: Option<Vec<u8>>) -> Arc<Node> {
    let Some(node) = root else {
        return make_node(key, value, None, None);
    };
    let rebuilt = match key.as_slice().cmp(node.key.as_slice()) {
        Ordering::Less => make_node(
            node.key.clone(),
            node.value.clone(),
            Some(insert(node.left.clone(), key, value)),
            node.right.clone(),
        ),
        Ordering::Greater => make_node(
            node.key.clone(),
            node.value.clone(),
            node.left.clone(),
            Some(insert(node.right.clone(), key, value)),
        ),
        Ordering::Equal => make_node(key, value, node.left.clone(), node.right.clone()),
    };
    rebalance(rebuilt)
}

fn make_node(
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    left: Option<Arc<Node>>,
    right: Option<Arc<Node>>,
) -> Arc<Node> {
    Arc::new(Node {
        key,
        value,
        height: height(left.as_ref())
            .max(height(right.as_ref()))
            .saturating_add(1),
        left,
        right,
    })
}

fn rebalance(node: Arc<Node>) -> Arc<Node> {
    let balance = i64::from(height(node.left.as_ref()))
        .saturating_sub(i64::from(height(node.right.as_ref())));
    if balance > 1 {
        let Some(left) = node.left.as_ref() else {
            return node;
        };
        let node = if height(left.left.as_ref()) < height(left.right.as_ref()) {
            make_node(
                node.key.clone(),
                node.value.clone(),
                Some(rotate_left(left)),
                node.right.clone(),
            )
        } else {
            node
        };
        return rotate_right(&node);
    }
    if balance < -1 {
        let Some(right) = node.right.as_ref() else {
            return node;
        };
        let node = if height(right.right.as_ref()) < height(right.left.as_ref()) {
            make_node(
                node.key.clone(),
                node.value.clone(),
                node.left.clone(),
                Some(rotate_right(right)),
            )
        } else {
            node
        };
        return rotate_left(&node);
    }
    node
}

fn rotate_left(node: &Arc<Node>) -> Arc<Node> {
    let Some(right) = node.right.as_ref() else {
        return Arc::clone(node);
    };
    let left = make_node(
        node.key.clone(),
        node.value.clone(),
        node.left.clone(),
        right.left.clone(),
    );
    make_node(
        right.key.clone(),
        right.value.clone(),
        Some(left),
        right.right.clone(),
    )
}

fn rotate_right(node: &Arc<Node>) -> Arc<Node> {
    let Some(left) = node.left.as_ref() else {
        return Arc::clone(node);
    };
    let right = make_node(
        node.key.clone(),
        node.value.clone(),
        left.right.clone(),
        node.right.clone(),
    );
    make_node(
        left.key.clone(),
        left.value.clone(),
        left.left.clone(),
        Some(right),
    )
}

fn height(node: Option<&Arc<Node>>) -> u32 {
    node.map_or(0, |node| node.height)
}

fn collect_range(
    node: Option<&Node>,
    start: &[u8],
    end: &[u8],
    entries: &mut Vec<(Vec<u8>, Option<Vec<u8>>)>,
) {
    let Some(node) = node else {
        return;
    };
    if node.key.as_slice() >= start {
        collect_range(node.left.as_deref(), start, end, entries);
    }
    if node.key.as_slice() >= start && node.key.as_slice() < end {
        entries.push((node.key.clone(), node.value.clone()));
    }
    if node.key.as_slice() < end {
        collect_range(node.right.as_deref(), start, end, entries);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::OverlayMap;

    #[test]
    fn persistent_overlay_matches_an_ordered_map_under_replacement() {
        let mut overlay = OverlayMap::default();
        let mut expected = BTreeMap::<Vec<u8>, Option<Vec<u8>>>::new();
        let mut seed = 0x4f56_4552_4c41_5931_u64;
        for step in 0..2_048_u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let key = format!("n\0{:04}", seed % 257).into_bytes();
            let value = (seed & 3 != 0).then(|| seed.to_le_bytes().to_vec());
            let prior = overlay.clone();
            let expected_before = expected
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            overlay.insert(key.clone(), value.clone());
            expected.insert(key.clone(), value.clone());
            assert_eq!(overlay.get(&key), Some(&value), "step {step}");
            assert_eq!(prior.all(), expected_before, "step {step}");
            assert_eq!(
                overlay.all(),
                expected
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>()
            );
        }
    }
}
