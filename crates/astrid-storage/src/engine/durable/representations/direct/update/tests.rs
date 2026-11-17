use std::sync::Arc;

use super::super::tests::empty_store;
use super::*;
use crate::volume::{AstridVolume, HostedFileVolume};

#[test]
fn failed_observation_does_not_promote_new_node_closures() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("observe.volume")).unwrap();
    let mut store = empty_store(&volume);
    let old_nodes = store
        .representations
        .nodes()
        .keys()
        .chain(store.placement_entries.nodes().keys())
        .chain(store.profiles.nodes().keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let direct = store
        .describe_direct(
            ObjectId::new([42; 32]),
            &[42; 16],
            ArenaLocation {
                offset: 42,
                payload_len: 16,
                checksum: [42; 32],
            },
        )
        .unwrap();
    let active = store.active;
    let result = store.append_direct_update_with(&[direct], |_, _| {
        Err::<(), _>(DurableError::InvalidRepresentationState(
            "observation failed",
        ))
    });
    assert!(matches!(
        result,
        Err(DurableError::InvalidRepresentationState(
            "observation failed"
        ))
    ));
    assert_eq!(store.active, active);
    assert!(store.complete_map_subtrees.is_subset(&old_nodes));
}

#[test]
fn successful_rebase_retains_closed_root_proofs() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("rebase.volume")).unwrap();
    let mut store = empty_store(&volume);
    let direct = store
        .describe_direct(
            ObjectId::new([42; 32]),
            &[42; 16],
            ArenaLocation {
                offset: 42,
                payload_len: 16,
                checksum: [42; 32],
            },
        )
        .unwrap();
    store.rebase_all_direct(&[direct]).unwrap();
    for root in [store.representations.root(), store.placement_entries.root()] {
        let root = root.unwrap();
        assert!(store.complete_map_subtrees.contains(&root));
        assert!(!store.persisted_map_nodes.contains(&root));
    }
}

#[test]
fn rebase_releases_superseded_complete_memo_entries() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("rebase-capacity.volume")).unwrap();
    let mut store = empty_store(&volume);
    let mut survivor = None;
    for sequence in 0_u64..256 {
        let bytes = sequence.to_le_bytes();
        let direct = store
            .describe_direct(
                ObjectId::new(*blake3::hash(&bytes).as_bytes()),
                &bytes,
                ArenaLocation {
                    offset: sequence * 100,
                    payload_len: 8,
                    checksum: [3; 32],
                },
            )
            .unwrap();
        let update = store
            .append_direct_update(std::slice::from_ref(&direct))
            .unwrap()
            .unwrap();
        store.publish_direct_update(update).unwrap();
        survivor = Some(direct);
    }
    let survivor = survivor.unwrap();
    let highwater = store.complete_map_subtrees.len();
    assert!(
        highwater > 32,
        "grown complete memo must contain historical node identities"
    );
    store.rebase_all_direct(&[survivor]).unwrap();
    assert!(
        store.complete_map_subtrees.len() < highwater,
        "rebase collection must release superseded complete memo entries"
    );
    let resident: BTreeSet<_> = store
        .profiles
        .nodes()
        .keys()
        .chain(store.representations.nodes().keys())
        .chain(store.placement_entries.nodes().keys())
        .copied()
        .collect();
    assert_eq!(store.complete_map_subtrees, resident);
    assert!(
        store
            .complete_map_subtrees
            .iter()
            .all(|id| !store.persisted_map_nodes.contains(id))
    );
    for root in [store.representations.root(), store.placement_entries.root()] {
        let root = root.unwrap();
        assert!(store.complete_map_subtrees.contains(&root));
        assert!(!store.persisted_map_nodes.contains(&root));
    }
}
