//! Canonical decode identity must equal the original encode-and-hash grammar.

use alloc::vec;
use core::cell::Cell;

use super::*;
use crate::storage_model::{BlobId, ObjectId};

struct ObservedIdentity {
    profile_hashes: Cell<usize>,
}

impl PhysicalIdentity for ObservedIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        if context == "astrid-representation-profile-v1\0" {
            self.profile_hashes
                .set(self.profile_hashes.get().strict_add(1));
        }
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }
}

fn profile(kind: ProfileKind) -> RepresentationProfile {
    RepresentationProfile::new_builtin(
        kind,
        ReconstructionBounds::new(4, 8, 1024, 4096, 1000, 4096, 1000).unwrap(),
        ObjectId::new([0x17; 32]),
    )
    .unwrap()
}

fn record(profile: RepresentationProfileId, recipe: Recipe) -> RepresentationRecord {
    let evidence =
        (!matches!(&recipe, Recipe::DirectCanonical { .. })).then_some(ObjectId::new([0x47; 32]));
    RepresentationRecord::new(
        profile,
        Coverage::exact(ObjectId::new([0x27; 32]), 64).unwrap(),
        recipe,
        64,
        64,
        evidence,
    )
    .unwrap()
}

#[test]
fn checked_byte_identity_matches_encode_and_hash_for_profile_and_record() {
    for kind in [ProfileKind::DirectCanonical, ProfileKind::PackedCanonical] {
        let original = profile(kind);
        let identity = ObservedIdentity {
            profile_hashes: Cell::new(0),
        };
        let bytes = original.encode().unwrap();
        let decoded = IdentifiedProfile::decode(&identity, &bytes).unwrap();
        assert_eq!(decoded.profile(), &original);
        assert_eq!(decoded.identity(), original.identify(&identity).unwrap());
        let recipe = if kind == ProfileKind::DirectCanonical {
            Recipe::DirectCanonical {
                blob: BlobId::new([0x37; 32]),
            }
        } else {
            Recipe::PackedSlice {
                blob: BlobId::new([0x37; 32]),
                offset: 3,
                length: 64,
            }
        };
        let original_record = record(decoded.identity(), recipe);
        let bytes = original_record.encode().unwrap();
        let (decoded_record, id) =
            RepresentationRecord::decode_and_identify(&identity, &bytes).unwrap();
        assert_eq!(decoded_record, original_record);
        assert_eq!(id, original_record.identify(&identity).unwrap());
        decoded_record
            .validate_against_identified_profile(&decoded)
            .unwrap();
    }
}

#[test]
fn shared_profile_validation_does_not_reencode_and_hash_profile_per_record() {
    let identity = ObservedIdentity {
        profile_hashes: Cell::new(0),
    };
    let bytes = profile(ProfileKind::DirectCanonical).encode().unwrap();
    let decoded = IdentifiedProfile::decode(&identity, &bytes).unwrap();
    assert_eq!(identity.profile_hashes.get(), 1);
    for value in 0_u8..128 {
        let record = record(
            decoded.identity(),
            Recipe::DirectCanonical {
                blob: BlobId::new([value; 32]),
            },
        );
        record
            .validate_against_identified_profile(&decoded)
            .unwrap();
    }
    assert_eq!(
        identity.profile_hashes.get(),
        1,
        "immutable decoded profile is identified once"
    );
}

#[test]
fn checked_profile_validation_retains_identity_recipe_and_output_rejections() {
    let identity = ObservedIdentity {
        profile_hashes: Cell::new(0),
    };
    let original = profile(ProfileKind::DirectCanonical);
    let decoded = IdentifiedProfile::decode(&identity, &original.encode().unwrap()).unwrap();
    let wrong_identity = record(
        RepresentationProfileId::new([0x45; 32]),
        Recipe::DirectCanonical {
            blob: BlobId::new([1; 32]),
        },
    );
    let wrong_recipe = record(
        decoded.identity(),
        Recipe::PackedSlice {
            blob: BlobId::new([1; 32]),
            offset: 0,
            length: 64,
        },
    );
    let wrong_bound = RepresentationRecord::new(
        decoded.identity(),
        Coverage::exact(ObjectId::new([2; 32]), 8192).unwrap(),
        Recipe::DirectCanonical {
            blob: BlobId::new([3; 32]),
        },
        8192,
        8192,
        None,
    )
    .unwrap();
    for record in [wrong_identity, wrong_recipe, wrong_bound] {
        let old = record
            .validate_against_profile(&identity, &original)
            .unwrap_err();
        let checked = record
            .validate_against_identified_profile(&decoded)
            .unwrap_err();
        assert_eq!(old, checked);
    }
}

#[test]
fn decode_identity_preserves_canonical_and_trailing_byte_checks() {
    let identity = ObservedIdentity {
        profile_hashes: Cell::new(0),
    };
    let mut bytes = profile(ProfileKind::DirectCanonical).encode().unwrap();
    bytes.extend([0]);
    assert!(IdentifiedProfile::decode(&identity, &bytes).is_err());
    assert_eq!(
        identity.profile_hashes.get(),
        0,
        "invalid profile is not identified"
    );
    let record = record(
        RepresentationProfileId::new([0x45; 32]),
        Recipe::DirectCanonical {
            blob: BlobId::new([1; 32]),
        },
    );
    let mut bytes = record.encode().unwrap();
    bytes.extend(vec![0]);
    assert!(RepresentationRecord::decode_and_identify(&identity, &bytes).is_err());
}
