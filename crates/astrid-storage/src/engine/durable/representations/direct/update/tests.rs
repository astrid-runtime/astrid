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
