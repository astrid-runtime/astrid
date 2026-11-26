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

use crate::kv::encoding;
mod traversal;
use traversal::{Entry, Node};

impl OverlayMap {
    pub(super) fn get(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        traversal::lookup(self.root.as_ref(), key)
    }

    pub(super) fn insert(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        self.root = Some(insert(self.root.take(), Arc::new(Entry { key, value })));
    }

    pub(super) fn range<'a>(
        &'a self,
        start: &'a [u8],
        end: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)> + 'a {
        let mut cursor = self.root.as_deref();
        let mut stack = Vec::new();
        std::iter::from_fn(move || {
            while let Some(node) = cursor {
                if crate::kv::encoding::bytewise_less(&node.entry.key, start) {
                    cursor = node.right.as_deref();
                } else {
                    stack.push(node);
                    cursor = node.left.as_deref();
                }
            }
            let node = stack.pop()?;
            if !crate::kv::encoding::bytewise_less(&node.entry.key, end) {
                cursor = None;
                stack.clear();
                return None;
            }
            cursor = node.right.as_deref();
            Some((node.entry.key.as_slice(), node.entry.value.as_deref()))
        })
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
    entries.push((node.entry.key.clone(), node.entry.value.clone()));
    collect_all(node.right.as_deref(), entries);
}

fn insert(root: Option<Arc<Node>>, entry: Arc<Entry>) -> Arc<Node> {
    let Some(node) = root else {
        return make_node(entry, None, None);
    };
    let rebuilt = match encoding::bytewise_cmp(&entry.key, &node.entry.key) {
        Ordering::Less => make_node(
            Arc::clone(&node.entry),
            Some(insert(node.left.clone(), entry)),
            node.right.clone(),
        ),
        Ordering::Greater => make_node(
            Arc::clone(&node.entry),
            node.left.clone(),
            Some(insert(node.right.clone(), entry)),
        ),
        Ordering::Equal => make_node(entry, node.left.clone(), node.right.clone()),
    };
    rebalance(rebuilt)
}

fn make_node(entry: Arc<Entry>, left: Option<Arc<Node>>, right: Option<Arc<Node>>) -> Arc<Node> {
    Arc::new(Node {
        entry,
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
                Arc::clone(&node.entry),
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
                Arc::clone(&node.entry),
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
        Arc::clone(&node.entry),
        node.left.clone(),
        right.left.clone(),
    );
    make_node(Arc::clone(&right.entry), Some(left), right.right.clone())
}

fn rotate_right(node: &Arc<Node>) -> Arc<Node> {
    let Some(left) = node.left.as_ref() else {
        return Arc::clone(node);
    };
    let right = make_node(
        Arc::clone(&node.entry),
        left.right.clone(),
        node.right.clone(),
    );
    make_node(Arc::clone(&left.entry), left.left.clone(), Some(right))
}

fn height(node: Option<&Arc<Node>>) -> u32 {
    node.map_or(0, |node| node.height)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

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
    #[test]
    fn unrelated_overlay_insert_reuses_existing_payload_allocation() {
        let mut overlay = OverlayMap::default();
        overlay.insert(b"a".to_vec(), Some(vec![0x41; 512 * 1024]));
        let snapshot = overlay.clone();
        let before = snapshot.get(b"a").unwrap().as_ref().unwrap();
        overlay.insert(b"b".to_vec(), Some(vec![0x42; 8]));
        let after = overlay.get(b"a").unwrap().as_ref().unwrap();
        assert_eq!(before, after);
        assert_eq!(
            before.as_ptr(),
            after.as_ptr(),
            "inserting another key deep-copied an unchanged overlay payload"
        );
    }

    #[test]
    fn every_rotation_preserves_existing_payloads_and_snapshots() {
        for keys in [[3_u8, 2, 1], [1, 2, 3], [3, 1, 2], [1, 3, 2]] {
            let mut overlay = OverlayMap::default();
            for key in keys {
                let snapshot = overlay.clone();
                let before = snapshot.all();
                overlay.insert(vec![key], Some(vec![key; 64 * 1024]));
                for (existing, value) in before {
                    assert_eq!(snapshot.get(&existing), Some(&value));
                    let previous = snapshot.get(&existing).unwrap().as_ref().unwrap();
                    let current = overlay.get(&existing).unwrap().as_ref().unwrap();
                    assert_eq!(previous.as_ptr(), current.as_ptr());
                }
            }
            let snapshot = overlay.clone();
            overlay.insert(vec![2], None);
            assert_eq!(overlay.get(&[2]), Some(&None));
            assert_eq!(
                snapshot.get(&[2]).unwrap().as_ref().unwrap(),
                &vec![2; 64 * 1024]
            );
            let range = overlay
                .range(&[1], &[3])
                .map(|(key, value)| (key.to_vec(), value.map(<[u8]>::to_vec)))
                .collect::<Vec<_>>();
            assert_eq!(range.len(), 2);
            assert_eq!(range[0].0, vec![1]);
            assert_eq!(range[1], (vec![2], None));
        }
    }

    #[test]
    fn replaced_entry_releases_after_its_last_snapshot() {
        let mut overlay = OverlayMap::default();
        overlay.insert(b"a".to_vec(), Some(vec![0x41; 512 * 1024]));
        let weak = Arc::downgrade(&overlay.root.as_ref().unwrap().entry);
        let snapshot = overlay.clone();
        overlay.insert(b"b".to_vec(), Some(vec![0x42; 8]));
        assert!(Arc::ptr_eq(
            &weak.upgrade().unwrap(),
            &overlay.root.as_ref().unwrap().entry,
        ));
        overlay.insert(b"a".to_vec(), Some(vec![0x43; 8]));
        assert!(weak.upgrade().is_some());
        drop(snapshot);
        assert!(weak.upgrade().is_none());
        assert_eq!(overlay.get(b"a"), Some(&Some(vec![0x43; 8])));
    }
}
