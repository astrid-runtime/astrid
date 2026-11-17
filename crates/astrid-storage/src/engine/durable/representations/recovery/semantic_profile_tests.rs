//! Observe profile decoding in the actual complete semantic validation pass.

use super::*;
use crate::engine::durable::ArenaLocation;
use crate::engine::durable::representations::RepresentationStore;
use crate::storage_model::physical::count_identified_profile_decodes_during;
use crate::volume::{AstridVolume, HostedFileVolume};
use std::sync::Arc;

#[test]
fn complete_semantic_validation_decodes_shared_direct_profile_once() {
    let directory = tempfile::tempdir().unwrap();
    let volume: Arc<dyn AstridVolume> =
        HostedFileVolume::open(directory.path().join("profiles.volume")).unwrap();
    let mut store = RepresentationStore::activate_volume(
        &volume,
        RecoveryLimits::process_addressable(),
        ObjectId::new([1; 32]),
        [],
    )
    .unwrap();
    let objects: Vec<_> = (0_u32..256)
        .map(|ordinal| {
            store
                .describe_direct(
                    ObjectId::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    &ordinal.to_le_bytes().repeat(16),
                    ArenaLocation {
                        offset: u64::from(ordinal) * 512,
                        payload_len: 64,
                        checksum: [9; 32],
                    },
                )
                .unwrap()
        })
        .collect();
    let update = store.append_direct_update(&objects).unwrap().unwrap();
    store.publish_direct_update(update).unwrap();
    let (result, decodes) = count_identified_profile_decodes_during(|| {
        validate_representations::<false>(
            store.profiles.as_canonical(),
            store.representations.as_canonical(),
            store.placement_entries.as_canonical(),
            store.direct_profile,
        )
    });
    let validated = result.unwrap();
    assert_eq!(validated.reverse, store.reverse);
    assert_eq!(validated.reverse.len(), 256);
    assert_eq!(
        decodes, 1,
        "immutable shared profile is checked once per complete pass"
    );
}
