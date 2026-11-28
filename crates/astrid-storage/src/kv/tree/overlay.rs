//! Process-local persistent map for resolved KV deltas.
//!
//! Nodes are immutable and reference-counted, so each published projection
//! reuses the previous projection and copies only one balanced search path.

mod snapshot;
pub(super) use snapshot::OverlayMap;

use super::{
    ObjectId, checkpoint_totals, checkpoint_value, delta_mutation, delta_totals, key_projection,
    mutation_replay, replay_values,
};
use crate::kv::encoding;
pub(super) mod batch;
mod range;
mod traversal;
mod update;
use traversal::Node;

impl OverlayMap {
    pub(super) fn get(&self, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        traversal::lookup(self.root.as_ref(), key)
    }

    pub(super) fn insert(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        update::put(&mut self.root, key, value);
    }

    pub(super) fn stage<E>(
        &mut self,
        key: Vec<u8>,
        replacement: Option<Vec<u8>>,
        encode: impl FnOnce(&Vec<u8>) -> Result<checkpoint_value::ValueSlot, E>,
    ) -> Result<delta_mutation::Mutation, E> {
        update::stage(&mut self.root, key, replacement, encode)
    }

    pub(super) fn range<'a>(
        &'a self,
        start: &'a [u8],
        end: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], Option<&'a [u8]>)> + 'a {
        let mut cursor = range::Range::new(self.root.as_ref(), start, end);
        std::iter::from_fn(move || {
            let entry = cursor.next_entry()?;
            Some((entry.key.as_slice(), entry.value.as_deref()))
        })
    }

    pub(super) fn project_presence(
        &self,
        keys: &mut std::collections::BTreeMap<Vec<u8>, bool>,
        start: &[u8],
        end: &[u8],
    ) {
        range::apply_presence(self.root.as_ref(), start, end, keys);
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
    fn range_and_presence_match_the_same_snapshot_at_every_boundary() {
        let mut overlay = OverlayMap::default();
        let mut expected = BTreeMap::new();
        for key in [7, 3, 11, 1, 5, 9, 13, 2, 10] {
            let value = (key % 3 != 0).then(|| vec![key]);
            overlay.insert(vec![key], value.clone());
            expected.insert(vec![key], value);
        }
        let checkpoint: BTreeMap<_, _> = (0..16).step_by(2).map(|key| (vec![key], true)).collect();
        for start in 0..=15 {
            for end in 0..=15 {
                let selected: Vec<_> = expected
                    .iter()
                    .filter(|(key, _)| start <= key[0] && key[0] < end)
                    .map(|(key, value)| (key.as_slice(), value.as_deref()))
                    .collect();
                assert_eq!(
                    overlay.range(&[start], &[end]).collect::<Vec<_>>(),
                    selected
                );
                let mut projected = checkpoint.clone();
                overlay.project_presence(&mut projected, &[start], &[end]);
                let mut expected_presence = checkpoint.clone();
                for (key, value) in selected {
                    expected_presence.insert(key.to_vec(), value.is_some());
                }
                assert_eq!(projected, expected_presence);
            }
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
