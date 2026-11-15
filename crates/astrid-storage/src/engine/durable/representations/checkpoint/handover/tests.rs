use crate::storage_model::{ObjectId, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode};

use super::super::super::{ArenaLocation, RepresentationStore};
use super::super::adoption_tests::primed_volume;

#[test]
fn handover_requires_exact_live_reverse_even_when_authority_roots_match() {
    let (_directory, volume, mut live, limits) = primed_volume();
    let prepared = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    live.verify_checkpoint_tip(&prepared).unwrap();
    live.reverse.clear();
    assert!(live.verify_checkpoint_tip(&prepared).is_err());
    assert_eq!(live.active, prepared.active);
}

#[test]
fn handover_rejects_a_foreign_live_body_under_the_prepared_root_identity() {
    let (_directory, volume, mut live, limits) = primed_volume();
    let prepared = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    let root = prepared.representations.root().unwrap();
    assert!(live.representations.replace_arena_node_for_fault(
        root,
        PhysicalMapNode::leaf(
            PhysicalMapDomain::Representation,
            PhysicalMapKey::new([0x71; 32]),
            vec![9],
        ),
    ));
    assert!(live.verify_checkpoint_tip(&prepared).is_err());
}

#[test]
fn handover_compares_unreachable_aliases_in_every_live_arena() {
    for equal in [false, true] {
        let (_directory, volume, mut live, limits) = primed_volume();
        let prepared = RepresentationStore::open_volume(&volume, limits)
            .unwrap()
            .unwrap();
        let root = prepared.representations.root().unwrap();
        let alias = if equal {
            prepared.representations.nodes()[&root].clone()
        } else {
            PhysicalMapNode::leaf(
                PhysicalMapDomain::Profile,
                PhysicalMapKey::new([0x71; 32]),
                vec![9],
            )
        };
        assert!(
            live.profiles
                .insert_unreachable_adversarial_node(root, alias)
        );
        assert_eq!(live.verify_checkpoint_tip(&prepared).is_ok(), equal);
    }
}

#[test]
fn handover_rejects_a_writer_that_advanced_after_the_worker_finished() {
    let (_directory, volume, mut live, limits) = primed_volume();
    let prepared = RepresentationStore::open_volume(&volume, limits)
        .unwrap()
        .unwrap();
    let object = live
        .describe_direct(
            ObjectId::new([0x52; 32]),
            &[4; 64],
            ArenaLocation {
                offset: 5000,
                payload_len: 64,
                checksum: [8; 32],
            },
        )
        .unwrap();
    let update = live.append_direct_update(&[object]).unwrap().unwrap();
    live.publish_direct_update(update).unwrap();
    assert!(live.verify_checkpoint_tip(&prepared).is_err());
}
