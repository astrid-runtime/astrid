use std::collections::BTreeMap;

use super::OverlayMap;

fn measured(node: Option<&super::Node>) -> usize {
    node.map_or(0, |node| {
        std::mem::size_of::<super::Node>()
            .saturating_add(std::mem::size_of::<[usize; 2]>())
            .saturating_add(node.key.capacity())
            .saturating_add(std::mem::size_of::<Option<Vec<u8>>>())
            .saturating_add(std::mem::size_of::<[usize; 2]>())
            .saturating_add(node.value.as_ref().as_ref().map_or(0, Vec::capacity))
            .saturating_add(measured(node.left.as_deref()))
            .saturating_add(measured(node.right.as_deref()))
    })
}

#[test]
fn subtree_charge_includes_spare_capacity_and_survives_rotations_and_sharing() {
    let mut overlay = OverlayMap::default();
    for index in 0..128_u8 {
        let mut key = Vec::with_capacity(128);
        key.push(index);
        let mut value = Vec::with_capacity(1024);
        value.push(index);
        overlay.insert(key, Some(value));
        assert_eq!(overlay.retained_bytes(), measured(overlay.root.as_deref()));
    }
    let prior = overlay.clone();
    let before = prior.retained_bytes();
    for index in (0..128_u8).rev() {
        overlay.insert(vec![index], None);
        assert_eq!(overlay.retained_bytes(), measured(overlay.root.as_deref()));
    }
    assert_eq!(prior.retained_bytes(), before);
    assert!(before > overlay.retained_bytes());
    assert_eq!(OverlayMap::default().retained_bytes(), 0);
}

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
fn untouched_payload_storage_is_shared_across_paths_rotations_and_snapshots() {
    let mut overlay = OverlayMap::default();
    let payload = vec![0x5a; 1024 * 1024];
    overlay.insert(b"b".to_vec(), Some(payload));
    let mut snapshots = vec![overlay.clone()];
    let pointer = overlay.get(b"b").unwrap().as_ref().unwrap().as_ptr();
    for index in 0..128_u8 {
        overlay.insert(format!("z{index:03}").into_bytes(), Some(vec![index]));
        snapshots.push(overlay.clone());
    }
    for snapshot in &snapshots {
        let value = snapshot.get(b"b").unwrap().as_ref().unwrap();
        assert_eq!(
            value.as_ptr(),
            pointer,
            "an unchanged payload was deep-copied"
        );
        assert!(value.iter().all(|byte| *byte == 0x5a));
    }
    let mut owned = overlay.range(b"b", b"c");
    assert_eq!(owned.len(), 1);
    owned[0].1.as_mut().unwrap().fill(0);
    assert!(
        overlay
            .get(b"b")
            .unwrap()
            .as_ref()
            .unwrap()
            .iter()
            .all(|byte| *byte == 0x5a)
    );
    overlay.insert(b"b".to_vec(), None);
    assert_eq!(overlay.get(b"b"), Some(&None));
    assert!(snapshots.iter().all(|map| map.get(b"b").unwrap().is_some()));
    overlay.insert(b"b".to_vec(), Some(vec![7]));
    assert_eq!(overlay.get(b"b"), Some(&Some(vec![7])));
    assert_eq!(
        snapshots[0].all(),
        vec![(b"b".to_vec(), Some(vec![0x5a; 1024 * 1024]))]
    );
}

#[test]
fn copied_ancestors_keep_payload_capacity_and_conservative_snapshot_charge() {
    let mut overlay = OverlayMap::default();
    let mut value = Vec::with_capacity(1024 * 1024);
    value.push(42);
    let capacity = value.capacity();
    overlay.insert(b"b".to_vec(), Some(value));
    let prior = overlay.clone();
    overlay.insert(b"a".to_vec(), Some(vec![1]));
    for snapshot in [&prior, &overlay] {
        assert_eq!(
            snapshot.get(b"b").unwrap().as_ref().unwrap().capacity(),
            capacity
        );
        assert!(snapshot.retained_bytes() >= capacity);
    }
}
