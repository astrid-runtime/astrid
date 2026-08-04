//! Canonical physical representation model tests.

extern crate std;

use alloc::{string::String, vec};
use std::format;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::{BlobId, InvocationId, ObjectId};

use super::{
    CanonicalChunkingProfile, Coverage, Dependency, PhysicalIdentity, PhysicalModelError,
    ProfileDependency, ProfileKind, Recipe, ReconstructionBounds, RepresentationProfile,
    RepresentationProfileId, RepresentationRecord, RepresentationRecordId,
};

#[derive(Clone, Copy)]
struct Blake3PhysicalIdentity;

impl PhysicalIdentity for Blake3PhysicalIdentity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }
}

fn object(value: u8) -> ObjectId {
    ObjectId::new([value; 32])
}

fn blob(value: u8) -> BlobId {
    BlobId::new([value; 32])
}

fn bounds() -> ReconstructionBounds {
    ReconstructionBounds::new(
        8,
        32,
        8 * 1024 * 1024,
        16 * 1024 * 1024,
        1_000_000,
        32 * 1024 * 1024,
        5_000_000,
    )
    .unwrap()
}

fn direct_profile() -> RepresentationProfile {
    RepresentationProfile::new_builtin(ProfileKind::DirectCanonical, bounds(), object(1)).unwrap()
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().checked_mul(2).unwrap_or(bytes.len()));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

const PROFILE_HEX: &str = "010000000000000000000000000001000000000000000001000100200000000101010101010101010101010101010101010101010101010101010101010101010008000000200000000000800000000000000000010000000040420f00000000000000000200000000404b4c000000000001000100200000000101010101010101010101010101010101010101010101010101010101010101";
const PROFILE_ID_HEX: &str = "59c09924b3b07212c4bc103535cfbbe10deee31d1b157d21538b177595235804";
const BLOB_ID_HEX: &str = "7cd5487139ce9f70b5f679a47b4eba03d3b703d498a72edc0a825163d36c9e7a";
const BLOB_BYTES_HEX: &str =
    "41737472696420706879736963616c20726570726573656e746174696f6e20766563746f72";
const RECORD_HEX: &str = "0100010002002000000059c09924b3b07212c4bc103535cfbbe10deee31d1b157d21538b177595235804000100010020000000020202020202020202020202020202020202020202020202020202020202020200020000000000000001000200200000007cd5487139ce9f70b5f679a47b4eba03d3b703d498a72edc0a825163d36c9e7a02000000000000000101000200200000007cd5487139ce9f70b5f679a47b4eba03d3b703d498a72edc0a825163d36c9e7a03010002002000000059c09924b3b07212c4bc103535cfbbe10deee31d1b157d21538b1775952358040002000000000000000200000000000000";
const RECORD_ID_HEX: &str = "27f6e8261c0dfbb649bf84cc3b44ed98ae128d6dab3d1c05cb310543d97681e2";

#[test]
fn reconstruction_bounds_reject_every_zero_field() {
    assert!(matches!(
        ReconstructionBounds::new(0, 1, 1, 1, 1, 1, 1),
        Err(PhysicalModelError::ZeroReconstructionBound(_))
    ));
    assert!(matches!(
        ReconstructionBounds::new(1, 0, 1, 1, 1, 1, 1),
        Err(PhysicalModelError::ZeroReconstructionBound(_))
    ));
    let valid = [1_u64; 5];
    for index in 0..valid.len() {
        let mut values = valid;
        values[index] = 0;
        assert!(matches!(
            ReconstructionBounds::new(1, 1, values[0], values[1], values[2], values[3], values[4],),
            Err(PhysicalModelError::ZeroReconstructionBound(_))
        ));
    }
}

#[test]
fn builtin_profile_round_trips_and_rejects_transform_fields() {
    let profile = direct_profile();
    let encoded = profile.encode().unwrap();
    assert_eq!(RepresentationProfile::decode(&encoded).unwrap(), profile);

    let mut unknown_kind = encoded.clone();
    unknown_kind[2] = u8::MAX;
    assert_eq!(
        RepresentationProfile::decode(&unknown_kind),
        Err(PhysicalModelError::UnknownTag("profile-kind", u8::MAX))
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        RepresentationProfile::decode(&trailing),
        Err(PhysicalModelError::TrailingBytes)
    );
}

#[test]
fn transform_profile_dependencies_are_canonical_and_complete() {
    let profile = RepresentationProfile::new_transform(
        object(4),
        object(5),
        object(6),
        vec![9, 8, 7],
        vec![
            ProfileDependency::PhysicalBlob(blob(9)),
            ProfileDependency::LogicalObject(object(4)),
            ProfileDependency::PhysicalBlob(blob(9)),
        ],
        bounds(),
        object(7),
    );
    assert!(
        profile
            .immutable_dependencies()
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(
        RepresentationProfile::decode(&profile.encode().unwrap()).unwrap(),
        profile
    );
}

#[test]
fn dependency_order_is_pinned_to_wire_tags_then_digest_bytes() {
    let mut profile_dependencies = vec![
        ProfileDependency::PhysicalBlob(blob(0)),
        ProfileDependency::LogicalObject(object(2)),
        ProfileDependency::LogicalObject(object(1)),
    ];
    profile_dependencies.sort_unstable();
    assert_eq!(
        profile_dependencies,
        [
            ProfileDependency::LogicalObject(object(1)),
            ProfileDependency::LogicalObject(object(2)),
            ProfileDependency::PhysicalBlob(blob(0)),
        ]
    );

    let mut dependencies = [
        Dependency::Evidence(object(0)),
        Dependency::Invocation(InvocationId::new(object(0))),
        Dependency::Profile(RepresentationProfileId::new([0; 32])),
        Dependency::Representation(RepresentationRecordId::new([0; 32])),
        Dependency::PhysicalBlob(blob(0)),
        Dependency::LogicalObject(object(0)),
    ];
    dependencies.sort_unstable();
    assert!(matches!(dependencies[0], Dependency::LogicalObject(_)));
    assert!(matches!(dependencies[1], Dependency::PhysicalBlob(_)));
    assert!(matches!(dependencies[2], Dependency::Representation(_)));
    assert!(matches!(dependencies[3], Dependency::Profile(_)));
    assert!(matches!(dependencies[4], Dependency::Invocation(_)));
    assert!(matches!(dependencies[5], Dependency::Evidence(_)));
}

#[test]
fn blob_identity_binds_profile_length_and_bytes() {
    let first_profile = direct_profile().identify(&Blake3PhysicalIdentity).unwrap();
    let second_profile =
        RepresentationProfile::new_builtin(ProfileKind::PackedCanonical, bounds(), object(1))
            .unwrap()
            .identify(&Blake3PhysicalIdentity)
            .unwrap();
    let bytes = b"same encoded bytes";
    let first = BlobId::identify(&Blake3PhysicalIdentity, first_profile, bytes).unwrap();
    let second = BlobId::identify(&Blake3PhysicalIdentity, second_profile, bytes).unwrap();
    let extended = BlobId::identify(
        &Blake3PhysicalIdentity,
        first_profile,
        b"same encoded bytes\0",
    )
    .unwrap();
    assert_ne!(first, second);
    assert_ne!(first, extended);
}

#[test]
fn representation_derives_the_only_valid_dependency_set() {
    let profile = direct_profile();
    let profile_id = profile.identify(&Blake3PhysicalIdentity).unwrap();
    let record = RepresentationRecord::new(
        profile_id,
        Coverage::exact(object(2), 512).unwrap(),
        Recipe::DirectCanonical { blob: blob(3) },
        512,
        512,
        None,
    )
    .unwrap();
    assert_eq!(
        record.dependencies(),
        &[
            Dependency::PhysicalBlob(blob(3)),
            Dependency::Profile(profile_id),
        ]
    );
    record
        .validate_against_profile(&Blake3PhysicalIdentity, &profile)
        .unwrap();
    let encoded = record.encode().unwrap();
    assert_eq!(RepresentationRecord::decode(&encoded).unwrap(), record);

    let mut reordered = encoded;
    let (prefix, second) = reordered.split_at_mut(181);
    prefix[140..181].swap_with_slice(&mut second[..41]);
    assert_eq!(
        RepresentationRecord::decode(&reordered),
        Err(PhysicalModelError::NonCanonicalCollection(
            "representation dependency"
        ))
    );
}

#[test]
fn alternate_and_generated_recipes_require_exact_evidence() {
    let profile_id = direct_profile().identify(&Blake3PhysicalIdentity).unwrap();
    let exact = Coverage::exact(object(2), 64).unwrap();
    assert!(matches!(
        RepresentationRecord::new(
            profile_id,
            exact.clone(),
            Recipe::PackedSlice {
                blob: blob(3),
                offset: 0,
                length: 64,
            },
            64,
            64,
            None,
        ),
        Err(PhysicalModelError::InvalidRecipe(_))
    ));
    assert!(matches!(
        RepresentationRecord::new(
            profile_id,
            exact,
            Recipe::Generated {
                invocation: InvocationId::new(object(8)),
                output_ordinal: 0,
                evidence: object(9),
            },
            64,
            64,
            Some(object(10)),
        ),
        Err(PhysicalModelError::InvalidRecipe(_))
    ));
}

fn assert_record_round_trip(
    profile: &RepresentationProfile,
    coverage: Coverage,
    recipe: Recipe,
    output_bytes: u64,
    verification_evidence: Option<ObjectId>,
) {
    let profile_id = profile.identify(&Blake3PhysicalIdentity).unwrap();
    let record = RepresentationRecord::new(
        profile_id,
        coverage,
        recipe,
        output_bytes,
        output_bytes.checked_mul(2).unwrap(),
        verification_evidence,
    )
    .unwrap();
    record
        .validate_against_profile(&Blake3PhysicalIdentity, profile)
        .unwrap();
    assert_eq!(
        RepresentationRecord::decode(&record.encode().unwrap()).unwrap(),
        record
    );
}

#[test]
fn built_in_recipe_families_round_trip_under_their_only_compatible_profiles() {
    let evidence = object(20);
    let exact = Coverage::exact(object(2), 64).unwrap();
    let packed =
        RepresentationProfile::new_builtin(ProfileKind::PackedCanonical, bounds(), object(1))
            .unwrap();
    let contiguous =
        RepresentationProfile::new_builtin(ProfileKind::ContiguousFile, bounds(), object(1))
            .unwrap();
    assert_record_round_trip(
        &direct_profile(),
        exact.clone(),
        Recipe::DirectCanonical { blob: blob(8) },
        64,
        None,
    );
    assert_record_round_trip(
        &packed,
        exact,
        Recipe::PackedSlice {
            blob: blob(9),
            offset: 1024,
            length: 64,
        },
        64,
        Some(evidence),
    );
    assert_record_round_trip(
        &contiguous,
        Coverage::canonical_file_chunks(
            object(10),
            Some(object(11)),
            300_000,
            2,
            CanonicalChunkingProfile::ASTRID_V1,
        )
        .unwrap(),
        Recipe::ContiguousFile { blob: blob(12) },
        128,
        Some(evidence),
    );
}

#[test]
fn transform_recipe_families_round_trip_under_the_transform_profile() {
    let evidence = object(20);
    let exact = Coverage::exact(object(2), 64).unwrap();
    let transform = RepresentationProfile::new_transform(
        object(4),
        object(5),
        object(6),
        vec![1, 2, 3],
        vec![ProfileDependency::PhysicalBlob(blob(7))],
        bounds(),
        object(1),
    );
    for recipe in [
        Recipe::Compressed {
            blob: blob(13),
            dictionary: Some(blob(7)),
        },
        Recipe::Delta {
            patch: blob(14),
            base: object(15),
        },
        Recipe::Generated {
            invocation: InvocationId::new(object(16)),
            output_ordinal: 3,
            evidence,
        },
    ] {
        assert_record_round_trip(&transform, exact.clone(), recipe, 64, Some(evidence));
    }

    let direct = direct_profile();
    let profile_id = direct.identify(&Blake3PhysicalIdentity).unwrap();
    let incompatible = RepresentationRecord::new(
        profile_id,
        exact,
        Recipe::Compressed {
            blob: blob(13),
            dictionary: None,
        },
        64,
        64,
        Some(evidence),
    )
    .unwrap();
    assert!(matches!(
        incompatible.validate_against_profile(&Blake3PhysicalIdentity, &direct),
        Err(PhysicalModelError::InvalidRecipe(_))
    ));
}

#[test]
fn packed_slice_rejects_length_mismatch_and_overflow() {
    let profile_id = direct_profile().identify(&Blake3PhysicalIdentity).unwrap();
    let exact = Coverage::exact(object(2), 64).unwrap();
    for (offset, length) in [(0, 63), (u64::MAX, 64)] {
        assert!(matches!(
            RepresentationRecord::new(
                profile_id,
                exact.clone(),
                Recipe::PackedSlice {
                    blob: blob(3),
                    offset,
                    length,
                },
                64,
                64,
                Some(object(4)),
            ),
            Err(PhysicalModelError::InvalidRecipe(_))
        ));
    }
}

#[test]
fn canonical_file_coverage_rejects_impossible_shapes() {
    let profile = CanonicalChunkingProfile::ASTRID_V1;
    assert!(Coverage::canonical_file_chunks(object(1), None, 0, 0, profile).is_ok());
    assert!(matches!(
        Coverage::canonical_file_chunks(object(1), Some(object(2)), 0, 1, profile),
        Err(PhysicalModelError::InvalidCoverage(_))
    ));
    assert!(matches!(
        Coverage::canonical_file_chunks(object(1), Some(object(2)), 1024, 2, profile),
        Err(PhysicalModelError::InvalidCoverage(_))
    ));
}

#[test]
fn format_one_golden_vectors_are_frozen_and_shared_with_the_second_reader() {
    let profile = direct_profile();
    let profile_bytes = profile.encode().unwrap();
    let profile_id = profile.identify(&Blake3PhysicalIdentity).unwrap();
    let encoded_blob = b"Astrid physical representation vector";
    let blob_id = BlobId::identify(&Blake3PhysicalIdentity, profile_id, encoded_blob).unwrap();
    let record = RepresentationRecord::new(
        profile_id,
        Coverage::exact(object(2), 512).unwrap(),
        Recipe::DirectCanonical { blob: blob_id },
        512,
        512,
        None,
    )
    .unwrap();
    let record_bytes = record.encode().unwrap();
    let record_id = record.identify(&Blake3PhysicalIdentity).unwrap();
    assert_eq!(to_hex(&profile_bytes), PROFILE_HEX);
    assert_eq!(to_hex(profile_id.as_bytes()), PROFILE_ID_HEX);
    assert_eq!(to_hex(blob_id.as_bytes()), BLOB_ID_HEX);
    assert_eq!(to_hex(encoded_blob), BLOB_BYTES_HEX);
    assert_eq!(to_hex(&record_bytes), RECORD_HEX);
    assert_eq!(to_hex(record_id.as_bytes()), RECORD_ID_HEX);

    let expected_fixture = format!(
        concat!(
            "{{\n",
            "  \"profile\": {{\n",
            "    \"id\": \"1:2:32:{}\",\n",
            "    \"canonical_hex\": \"{}\"\n",
            "  }},\n",
            "  \"blob\": {{\n",
            "    \"id\": \"1:2:32:{}\",\n",
            "    \"profile\": \"1:2:32:{}\",\n",
            "    \"encoded_hex\": \"{}\"\n",
            "  }},\n",
            "  \"representation\": {{\n",
            "    \"id\": \"1:2:32:{}\",\n",
            "    \"canonical_hex\": \"{}\"\n",
            "  }}\n",
            "}}\n",
        ),
        PROFILE_ID_HEX,
        PROFILE_HEX,
        BLOB_ID_HEX,
        PROFILE_ID_HEX,
        BLOB_BYTES_HEX,
        RECORD_ID_HEX,
        RECORD_HEX,
    );
    assert_eq!(
        include_str!("../../../../scripts/fixtures/runatal-physical-v1.json"),
        expected_fixture
    );

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg(repository.join("scripts/runatal_v1_physical.py"))
        .arg(repository.join("scripts/fixtures/runatal-physical-v1.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent physical reader failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded = String::from_utf8(output.stdout).unwrap();
    assert!(decoded.contains(PROFILE_ID_HEX));
    assert!(decoded.contains(BLOB_ID_HEX));
    assert!(decoded.contains(RECORD_ID_HEX));
}

#[test]
fn independent_reader_rejects_profile_tampering() {
    let fixture = include_str!("../../../../scripts/fixtures/runatal-physical-v1.json");
    let tampered = fixture.replacen(
        &format!("0100{}", &PROFILE_HEX[4..]),
        &format!("0101{}", &PROFILE_HEX[4..]),
        1,
    );
    assert_ne!(tampered, fixture);
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(tampered.as_bytes()).unwrap();
    file.flush().unwrap();

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg(repository.join("scripts/runatal_v1_physical.py"))
        .arg(file.path())
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "independent physical reader accepted a mutated profile"
    );
}
