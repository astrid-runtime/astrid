use super::super::{ArenaLocation, RepresentationStore};
use super::*;
use crate::engine::RecoveryLimits;
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

fn assert_bounded(store: &RepresentationStore, count: usize) {
    assert_eq!(store.reverse.len(), count);
    assert!(
        store.reverse.resident_capacity_bytes() as u64
            <= store.persisted_map_nodes.budget().bytes().get() / 4
    );
    assert_eq!(store.direct_arena_locations().unwrap().len(), count);
}

#[test]
fn direct_publication_rebase_and_recovery_keep_all_reverse_entries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inline.volume");
    let volume: Arc<dyn AstridVolume> = HostedFileVolume::open(&path).unwrap();
    let limits = RecoveryLimits::process_addressable();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        limits,
        ObjectId::new([1; 32]),
        [],
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap();
    let objects = (0..128_u64)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_le_bytes());
            store
                .describe_direct(
                    ObjectId::new(bytes),
                    &index.to_le_bytes(),
                    ArenaLocation {
                        offset: index.strict_mul(8),
                        payload_len: 8,
                        checksum: [3; 32],
                    },
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let update = store.append_direct_update(&objects).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
    assert_bounded(&store, objects.len());
    store.rebase_all_direct(&objects).unwrap();
    assert_bounded(&store, objects.len());
    let active = store.active;
    let expected = store.reverse.snapshot().unwrap();
    store.checkpoint_volume(&volume, limits).unwrap();
    drop(store);
    std::fs::copy(&path, directory.path().join("reopened.volume")).unwrap();
    let reopened: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("reopened.volume")).unwrap();
    let mut recovered = RepresentationStore::open_volume(
        &reopened,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_bounded(&recovered, objects.len());
    assert_eq!(recovered.active, active);
    assert_eq!(recovered.reverse.snapshot().unwrap(), expected);
    for object in &objects {
        assert!(recovered.contains_direct(object.object).unwrap());
    }
    let before = recovered.active;
    recovered
        .reverse
        .set_memory(
            super::super::LocationIndexMemoryBudget::new(std::num::NonZeroU64::new(80).unwrap())
                .unwrap(),
        )
        .unwrap();
    recovered.reverse.truncate_test_run();
    assert!(recovered.checkpoint_volume(&reopened, limits).is_err());
    assert_eq!(recovered.active, before);
    drop(recovered);
    let repaired = RepresentationStore::open_volume(
        &reopened,
        limits,
        super::super::LocationIndexMemoryBudget::default(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(repaired.active, before);
    assert_eq!(repaired.reverse.snapshot().unwrap(), expected);
}
