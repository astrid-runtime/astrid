use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;

use super::PrincipalKvAdapter;
use crate::engine::{
    DurableEngine, KvProjectionEngine, ObjectCacheConfig, PrincipalCodec, RecoveryLimits,
};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::storage_model::{ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord};

#[derive(Clone, Copy)]
struct Utf8Codec;

impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, principal: &String) -> Vec<u8> {
        principal.as_bytes().to_vec()
    }

    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

type Engine = DurableEngine<String, Blake3ObjectIdentityV1, Utf8Codec>;

fn open(path: &Path, cache: bool) -> Engine {
    let config = if cache {
        ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap())
    } else {
        ObjectCacheConfig::disabled()
    };
    DurableEngine::open_with_object_cache(
        path,
        Blake3ObjectIdentityV1,
        Utf8Codec,
        RecoveryLimits::new(1024 * 1024).unwrap(),
        config,
    )
    .unwrap()
}

fn record() -> ObjectRecord {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        b"content-side quota validation".to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap()
}

fn corrupt_last_frame(path: &Path) {
    let mut arena = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("objects.arena"))
        .unwrap();
    arena.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    arena.read_exact(&mut byte).unwrap();
    arena.seek(SeekFrom::End(-1)).unwrap();
    arena.write_all(&[byte[0] ^ 0xff]).unwrap();
    arena.sync_all().unwrap();
}

#[test]
fn adapter_shares_verified_records_and_charges_each_actual_owner() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path(), true);
    let expected = record();
    let (id, _) = engine.persist_standalone_object(&expected).unwrap();
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    let adapter = PrincipalKvAdapter::new(&engine);
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let carol = "carol".to_owned();

    let first = adapter
        .load_shared_kv_object_for(&alice, id)
        .unwrap()
        .unwrap();
    let repeated = adapter
        .load_shared_kv_object_for(&alice, id)
        .unwrap()
        .unwrap();
    let shared = adapter
        .load_shared_kv_object_for(&bob, id)
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), &expected);
    assert!(Arc::ptr_eq(&first, &repeated));
    assert!(Arc::ptr_eq(&first, &shared));
    assert_eq!(
        adapter.load_kv_object_for(&carol, id).unwrap(),
        Some(expected)
    );

    let stats = engine.object_cache_stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 3);
    assert_eq!(stats.insertions, 1);
    assert_eq!(stats.resident_objects, 1);
    assert_eq!(stats.resident_associations, 3);
    assert!(stats.resident_association_bytes > 0);
    for owner in [&alice, &bob, &carol] {
        assert_eq!(
            engine.object_cache_principal_charge(owner),
            stats.resident_record_bytes,
            "adapter must preserve the actual cache-accounting owner"
        );
    }
    engine.close().unwrap();
    assert!(adapter.load_kv_object_for(&alice, id).is_err());
    assert!(adapter.load_shared_kv_object_for(&alice, id).is_err());
}

#[test]
fn adapter_disabled_cache_preserves_bytes_and_missing_objects_without_retention() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path(), false);
    let expected = record();
    let (id, _) = engine.persist_standalone_object(&expected).unwrap();
    let owner = "alice".to_owned();
    let adapter = PrincipalKvAdapter::new(&engine);
    let first = adapter
        .load_shared_kv_object_for(&owner, id)
        .unwrap()
        .unwrap();
    let second = adapter
        .load_shared_kv_object_for(&owner, id)
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), &expected);
    assert_eq!(second.as_ref(), &expected);
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(
        adapter.load_kv_object_for(&owner, id).unwrap(),
        Some(expected)
    );
    let missing = ObjectId::new([0xa5; 32]);
    assert_ne!(missing, id);
    assert!(
        adapter
            .load_kv_object_for(&owner, missing)
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .load_shared_kv_object_for(&owner, missing)
            .unwrap()
            .is_none()
    );
    let stats = engine.object_cache_stats();
    assert_eq!(stats.resident_objects, 0);
    assert_eq!(stats.resident_bytes, 0);
    assert_eq!(engine.object_cache_principal_charge(&owner), 0);
}

#[test]
fn adapter_cold_reads_reject_corrupt_frames_with_or_without_cache() {
    for cache in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let engine = open(directory.path(), cache);
        let (id, _) = engine.persist_standalone_object(&record()).unwrap();
        assert_eq!(engine.object_cache_stats().resident_objects, 0);
        corrupt_last_frame(directory.path());

        let adapter = PrincipalKvAdapter::new(&engine);
        let owner = "alice".to_owned();
        assert!(adapter.load_shared_kv_object_for(&owner, id).is_err());
        assert!(adapter.load_kv_object_for(&owner, id).is_err());
        assert_eq!(engine.object_cache_stats().resident_objects, 0);
        assert_eq!(engine.object_cache_principal_charge(&owner), 0);
    }
}

#[test]
fn adapter_retirement_handoff_cannot_reuse_old_cached_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path(), true);
    let (id, _) = engine.persist_standalone_object(&record()).unwrap();
    let owner = "alice".to_owned();
    let old_adapter = PrincipalKvAdapter::new(&engine);
    let held = old_adapter
        .load_shared_kv_object_for(&owner, id)
        .unwrap()
        .unwrap();
    assert_eq!(engine.object_cache_stats().resident_objects, 1);

    let transferred = engine.handoff_for_retirement().unwrap();
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    assert_eq!(transferred.object_cache_stats().resident_objects, 0);
    assert!(old_adapter.load_shared_kv_object_for(&owner, id).is_err());
    assert!(old_adapter.load_kv_object_for(&owner, id).is_err());
    corrupt_last_frame(directory.path());

    let fresh_adapter = PrincipalKvAdapter::new(&transferred);
    assert_eq!(held.as_ref(), &record());
    assert!(fresh_adapter.load_shared_kv_object_for(&owner, id).is_err());
    assert!(fresh_adapter.load_kv_object_for(&owner, id).is_err());
    assert_eq!(transferred.object_cache_stats().resident_objects, 0);
}
