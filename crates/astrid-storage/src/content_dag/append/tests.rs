use std::{cell::Cell, collections::BTreeMap, convert::Infallible};

use super::*;
use crate::content_dag::{
    ChunkingProfile, build_content, read_content,
    tests::{TestIdentity, deterministic_bytes},
};
use crate::storage_model::{ObjectId, ObjectKind};

struct Source {
    records: BTreeMap<ObjectId, ObjectRecord>,
    payload_loads: Cell<usize>,
}

impl ContentSource for Source {
    type Error = Infallible;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        let record = self.records.get(&id);
        if record.is_some_and(|record| record.kind() == ObjectKind::Chunk) {
            self.payload_loads
                .set(self.payload_loads.get().strict_add(1));
        }
        Ok(record.cloned())
    }
}

#[test]
fn append_matches_full_builder_across_small_file_threshold_and_tree_levels() {
    let profile = ChunkingProfile::ASTRID_V1;
    let max = profile.maximum_bytes() as usize;
    let bytes = deterministic_bytes(12 * 1024 * 1024);
    for split in [0, 1, max - 1, max, max + 1, max * 2 + 7, 10 * 1024 * 1024] {
        for added in [0, 1, 8193, max, max + 1] {
            let old = build_content(&TestIdentity, profile, &bytes[..split]).unwrap();
            let mut source = Source {
                records: old.records().iter().cloned().collect(),
                payload_loads: Cell::new(0),
            };
            let append = append_verified_content(
                &TestIdentity,
                &source,
                old.verified_content(),
                &bytes[split..split + added],
            )
            .unwrap();
            let expected = build_content(&TestIdentity, profile, &bytes[..split + added]).unwrap();
            assert_eq!(
                append.verified,
                expected.verified_content(),
                "{split}+{added}"
            );
            assert_eq!(
                source.payload_loads.get(),
                usize::from(split != 0),
                "{split}+{added}"
            );
            for record in append.records {
                source
                    .records
                    .insert(TestIdentity.identify(&record), record);
            }
            assert_eq!(
                read_content(&source, append.verified.descriptor().file()).unwrap(),
                &bytes[..split + added]
            );
        }
    }
}

#[test]
fn fragmented_append_preserves_canonical_identity_for_repetitive_and_random_data() {
    for bytes in [vec![0_u8; 1024 * 1024], deterministic_bytes(1024 * 1024)] {
        let old = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &[]).unwrap();
        let mut verified = old.verified_content();
        let mut source = Source {
            records: old.records().iter().cloned().collect(),
            payload_loads: Cell::new(0),
        };
        let mut length = 0;
        for fragment in bytes.chunks(7919) {
            let append =
                append_verified_content(&TestIdentity, &source, verified, fragment).unwrap();
            length += fragment.len();
            assert_eq!(
                append.verified,
                build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, &bytes[..length])
                    .unwrap()
                    .verified_content()
            );
            verified = append.verified;
            for record in append.records {
                source
                    .records
                    .insert(TestIdentity.identify(&record), record);
            }
        }
    }
}

#[test]
fn missing_tail_fails_instead_of_publishing_truncated_content() {
    let old = build_content(&TestIdentity, ChunkingProfile::ASTRID_V1, b"old").unwrap();
    let mut source = Source {
        records: old.records().iter().cloned().collect(),
        payload_loads: Cell::new(0),
    };
    source.records.remove(
        &old.verified_content()
            .opened_content()
            .content_root()
            .unwrap(),
    );
    assert!(
        append_verified_content(&TestIdentity, &source, old.verified_content(), b"new").is_err()
    );
}

#[test]
fn append_preserves_seeded_and_legacy_odd_profiles() {
    let bytes = deterministic_bytes(128 * 1024);
    for profile in [
        ChunkingProfile::fastcdc_v2020(64, 256, 1024, 42).unwrap(),
        ChunkingProfile::fastcdc_v2020(65, 256, 1025, 42).unwrap(),
    ] {
        for split in [1, 1023, 1024, 1025, 1026, 8191, 65_537] {
            let old = build_content(&TestIdentity, profile, &bytes[..split]).unwrap();
            let source = Source {
                records: old.records().iter().cloned().collect(),
                payload_loads: Cell::new(0),
            };
            for added in [0, 1, 2, 65, 1024, 8193] {
                let delta = append_verified_content(
                    &TestIdentity,
                    &source,
                    old.verified_content(),
                    &bytes[split..split + added],
                )
                .unwrap();
                assert_eq!(
                    delta.verified,
                    build_content(&TestIdentity, profile, &bytes[..split + added])
                        .unwrap()
                        .verified_content(),
                    "{profile:?}: {split}+{added}"
                );
            }
        }
    }
}
