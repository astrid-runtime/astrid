//! Canonical validation must not retain a second complete payload set.
#![cfg(not(target_family = "wasm"))]

use astrid_storage::storage_model::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey,
};

#[path = "../src/allocation_test_support.rs"]
mod allocation_test_support;
use allocation_test_support::peak_during;

struct Identity;
impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key(context);
        hash.update(material);
        *hash.finalize().as_bytes()
    }
}

fn validate_without_retaining_input_payloads(dense: bool) {
    let count = 128_usize;
    let value_bytes = 64 * 1024_usize;
    let entries = (0..count)
        .map(|index| {
            (
                PhysicalMapKey::new(*blake3::hash(&index.to_le_bytes()).as_bytes()),
                vec![0x5a; value_bytes],
            )
        })
        .collect();
    let map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, entries)
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries)
    }
    .unwrap();
    let (result, peak) = peak_during(|| {
        CanonicalPhysicalMap::validate_root(
            &Identity,
            PhysicalMapDomain::Placement,
            map.root(),
            map.nodes(),
        )
    });
    assert_eq!(result.unwrap(), u64::try_from(count).unwrap());
    // Room for transient node encoding, traversal sets and allocator rounding;
    // a second full input payload set alone exceeds this bound eightfold.
    assert!(
        peak < count * value_bytes / 8,
        "validation retained {peak} temporary bytes"
    );
}

#[test]
fn legacy_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(false);
}

#[test]
fn dense_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(true);
}

fn build_lookup_fixture(dense: bool, count: usize) -> (CanonicalPhysicalMap, Vec<PhysicalMapKey>) {
    let keys = (0..count)
        .map(|index| PhysicalMapKey::new(*blake3::hash(&index.to_le_bytes()).as_bytes()))
        .collect::<Vec<_>>();
    let entries = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                *key,
                u64::try_from(index)
                    .expect("fixture index fits u64")
                    .to_le_bytes()
                    .to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, entries)
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries)
    }
    .expect("fixture map");
    (map, keys)
}

fn assert_get_hit_miss_zero_alloc(dense: bool) {
    let (map, keys) = build_lookup_fixture(dense, 64);
    let miss = PhysicalMapKey::new(*blake3::hash(b"missing-lookup-key").as_bytes());
    assert!(!keys.contains(&miss));

    let (hit, hit_peak) = peak_during(|| map.get(keys[0]));
    assert_eq!(hit, Some(0_u64.to_le_bytes().as_slice()));
    assert_eq!(
        hit_peak,
        0,
        "hit lookup allocated {hit_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );

    let middle_index = keys.len() / 2;
    let (middle, middle_peak) = peak_during(|| map.get(keys[middle_index]));
    assert_eq!(
        middle,
        Some(
            u64::try_from(middle_index)
                .expect("fixture index fits u64")
                .to_le_bytes()
                .as_slice(),
        )
    );
    assert_eq!(
        middle_peak,
        0,
        "interior hit lookup allocated {middle_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );

    let (missed, miss_peak) = peak_during(|| map.get(miss));
    assert_eq!(missed, None);
    assert_eq!(
        miss_peak,
        0,
        "miss lookup allocated {miss_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );
}

#[test]
fn legacy_physical_map_get_hit_and_miss_are_zero_alloc() {
    assert_get_hit_miss_zero_alloc(false);
}

#[test]
fn dense_physical_map_get_hit_and_miss_are_zero_alloc() {
    assert_get_hit_miss_zero_alloc(true);
}

// Public recovery must validate authenticated records without duplicating
// every rooted payload for each successive graph-validation stage.
#[derive(Clone, Copy)]
struct RecoveryIdentity;

impl astrid_storage::storage_model::ObjectIdentity for RecoveryIdentity {
    fn identify(
        &self,
        record: &astrid_storage::storage_model::ObjectRecord,
    ) -> astrid_storage::storage_model::ObjectId {
        let mut hash = blake3::Hasher::new_derive_key("astrid recovery allocation regression");
        hash.update(&record.kind().code().to_le_bytes());
        hash.update(&record.format_version().get().to_le_bytes());
        hash.update(record.canonical_bytes());
        hash.update(&record.logical_bytes().to_le_bytes());
        hash.update(&[record.class().code()]);
        for reference in record.references() {
            hash.update(&reference.label().as_bytes().len().to_le_bytes());
            hash.update(reference.label().as_bytes());
            hash.update(reference.target().as_bytes());
            hash.update(&[reference.kind().code()]);
        }
        astrid_storage::storage_model::ObjectId::new(*hash.finalize().as_bytes())
    }
}

impl astrid_storage::engine::PersistentObjectIdentity for RecoveryIdentity {
    fn scheme(&self) -> astrid_storage::engine::IdentityScheme {
        astrid_storage::engine::IdentityScheme::new(u16::MAX, 1).unwrap()
    }
}

struct PrincipalCodec;
impl astrid_storage::engine::PrincipalCodec<u64> for PrincipalCodec {
    fn encode(&self, principal: &u64) -> Vec<u8> {
        principal.to_le_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<u64> {
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }
}

#[derive(Clone, Copy)]
enum RecoveryMedium {
    Native,
    Volume,
}

impl RecoveryMedium {
    fn open(
        self,
        path: &std::path::Path,
    ) -> astrid_storage::engine::DurableEngine<u64, RecoveryIdentity, PrincipalCodec> {
        use astrid_storage::engine::{
            DurableEngine, DurableEnginePolicy, GroupCommitPolicy, ObjectCacheConfig,
            RecoveryLimits, RecoveryRetryPolicy,
        };
        match self {
            Self::Native => DurableEngine::open_with_object_cache(
                path,
                RecoveryIdentity,
                PrincipalCodec,
                RecoveryLimits::process_addressable(),
                ObjectCacheConfig::disabled(),
            ),
            Self::Volume => DurableEngine::open_volume(
                astrid_storage::volume::HostedFileVolume::open(path.join("store.astrid")).unwrap(),
                RecoveryIdentity,
                PrincipalCodec,
                RecoveryLimits::process_addressable(),
                DurableEnginePolicy::new(
                    GroupCommitPolicy::default(),
                    RecoveryRetryPolicy::default(),
                    ObjectCacheConfig::disabled(),
                ),
            ),
        }
        .unwrap()
    }
}

fn assert_rooted_recovery_moves_authenticated_payloads(medium: RecoveryMedium) {
    use astrid_storage::engine::RootTransaction;
    use astrid_storage::storage_model::{
        ObjectClass, ObjectFormatVersion, ObjectIdentity, ObjectKind, ObjectRecord,
        ObjectReference, ReferenceLabel,
    };

    const COUNT: u8 = 32;
    const PAYLOAD_BYTES: usize = 1024 * 1024;
    let directory = tempfile::tempdir().unwrap();
    let open = || medium.open(directory.path());
    let writer = open();
    let mut records = Vec::new();
    let mut references = Vec::new();
    let chunk = |index| {
        ObjectRecord::new(
            ObjectKind::Chunk,
            ObjectFormatVersion::V1,
            vec![index; PAYLOAD_BYTES],
            Vec::new(),
            PAYLOAD_BYTES as u64,
            ObjectClass::Data,
        )
        .unwrap()
    };
    for index in 0..COUNT {
        let record = chunk(index);
        let id = RecoveryIdentity.identify(&record);
        references.push(ObjectReference::owns(ReferenceLabel::new(vec![index]), id));
        records.push((id, record));
    }
    let commit = ObjectRecord::new(
        ObjectKind::Commit,
        ObjectFormatVersion::V1,
        b"root".to_vec(),
        references,
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    let commit_id = RecoveryIdentity.identify(&commit);
    records.push((commit_id, commit));
    let root = writer
        .commit(RootTransaction::new(7, None, commit_id, records))
        .unwrap()
        .root();
    // Two principals share one complete closure; preserve their independent
    // historical generations instead of replacing them with model generations.
    let shared = writer
        .commit(RootTransaction::new(9, None, commit_id, Vec::new()))
        .unwrap()
        .root();
    let updated = writer
        .commit(RootTransaction::new(7, Some(root), commit_id, Vec::new()))
        .unwrap()
        .root();
    writer.close().unwrap();
    drop(writer);

    let (recovered, peak) = peak_during(open);
    println!("root recovery peak requested allocation: {peak} bytes");
    assert_eq!(recovered.root(&7).unwrap(), Some(updated));
    assert_eq!(recovered.root(&9).unwrap(), Some(shared));
    assert_eq!(recovered.object_count().unwrap(), usize::from(COUNT) + 1);
    for index in 0..COUNT {
        let expected = chunk(index);
        let id = RecoveryIdentity.identify(&expected);
        assert_eq!(recovered.object(id).unwrap(), Some(expected));
    }
    recovered.close().unwrap();
    // One authenticated payload corpus plus coalesced read scratch and graph
    // metadata fits below two corpora. The former three simultaneous payload
    // owners exceed this bound before any allocator-specific RSS behavior.
    assert!(
        peak < usize::from(COUNT).strict_mul(PAYLOAD_BYTES).strict_mul(2),
        "root recovery requested {peak} peak bytes"
    );
}

#[test]
fn rooted_recovery_moves_authenticated_payloads_without_cloning() {
    assert_rooted_recovery_moves_authenticated_payloads(RecoveryMedium::Native);
}

#[test]
fn rooted_volume_recovery_moves_authenticated_payloads_without_cloning() {
    assert_rooted_recovery_moves_authenticated_payloads(RecoveryMedium::Volume);
}
