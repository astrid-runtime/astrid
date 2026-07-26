use std::sync::Arc;

use astrid_storage_engine::InMemoryEngine;
use astrid_storage_model::{ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind};

use super::{ContentName, PrincipalContentError, PrincipalContentStore};
use crate::kv::{KvStore, TreeKvStore};

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid content store tests v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hasher.update(&(record.references().len() as u128).to_le_bytes());
        for reference in record.references() {
            hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[match reference.kind() {
                ReferenceKind::Owns => 0,
                ReferenceKind::Evidence => 1,
                ReferenceKind::Lineage => 2,
                ReferenceKind::Derived => 3,
            }]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

type Engine = InMemoryEngine<String, TestIdentity>;

fn bytes(length: usize) -> Vec<u8> {
    let mut state = 0x8f3f_73b5_cf1c_9ade_u64;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            (state >> 29).to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn named_content_round_trips_lists_ranges_and_deletes() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("models/site.bin").unwrap();
    let value = bytes(2 * 1024 * 1024);
    let outcome = store.put(&owner, &name, &value).unwrap();
    assert!(outcome.objects_inserted() > 3);
    assert_eq!(store.read(&owner, &name).unwrap(), Some(value.clone()));
    assert_eq!(
        store.read_range(&owner, &name, 999_000, 12_345).unwrap(),
        Some(value[999_000..1_011_345].to_vec())
    );
    assert_eq!(
        store.list(&owner).unwrap(),
        vec![super::ContentEntry::new(
            name.clone(),
            outcome.descriptor().file(),
            value.len() as u64,
        )]
    );
    assert!(store.delete(&owner, &name).unwrap());
    assert!(!store.delete(&owner, &name).unwrap());
    assert_eq!(store.read(&owner, &name).unwrap(), None);
}

#[test]
fn principals_and_aliases_share_physical_objects_but_not_logical_usage() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let value = bytes(4 * 1024 * 1024);
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    let first = store
        .put(&alice, &ContentName::new("first").unwrap(), &value)
        .unwrap();
    let second = store
        .put(&bob, &ContentName::new("copy").unwrap(), &value)
        .unwrap();
    assert_eq!(first.descriptor().file(), second.descriptor().file());
    assert!(
        second.objects_inserted() < first.objects_inserted() / 4,
        "second principal inserted {} objects after first inserted {}",
        second.objects_inserted(),
        first.objects_inserted()
    );

    store
        .put(&alice, &ContentName::new("alias").unwrap(), &value)
        .unwrap();
    assert_eq!(
        engine.principal_usage(&alice).unwrap().logical_bytes,
        (value.len() as u64) * 2
    );
    assert_eq!(
        engine.principal_usage(&bob).unwrap().logical_bytes,
        value.len() as u64
    );
}

#[test]
fn aliases_cannot_turn_deduplication_into_free_quota() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(150_u64)));
    let store = PrincipalContentStore::from_engine_with_quota(engine, quota);
    let owner = "alice".to_owned();
    let value = vec![7_u8; 100];
    store
        .put(&owner, &ContentName::new("one").unwrap(), &value)
        .unwrap();
    assert!(matches!(
        store.put(&owner, &ContentName::new("two").unwrap(), &value),
        Err(PrincipalContentError::QuotaExceeded {
            used: 206,
            limit: 150
        })
    ));
}

#[tokio::test]
async fn kv_and_content_share_one_principal_quota_and_root() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(128_u64)));
    let content = PrincipalContentStore::from_engine_with_quota(Arc::clone(&engine), quota.clone());
    let kv = TreeKvStore::<String, TestIdentity, _, _>::from_engine_with_quota(
        Arc::clone(&engine),
        |namespace: &str| Ok(namespace.to_owned()),
        quota,
    );
    kv.set("alice", "key", vec![1_u8; 64]).await.unwrap();
    assert!(matches!(
        content.put(
            &"alice".to_owned(),
            &ContentName::new("blob").unwrap(),
            &[2_u8; 64]
        ),
        Err(PrincipalContentError::QuotaExceeded { .. })
    ));

    content
        .put(
            &"alice".to_owned(),
            &ContentName::new("small").unwrap(),
            &[3_u8; 16],
        )
        .unwrap();
    assert_eq!(kv.get("alice", "key").await.unwrap(), Some(vec![1_u8; 64]));
    assert_eq!(
        content
            .read(&"alice".to_owned(), &ContentName::new("small").unwrap())
            .unwrap(),
        Some(vec![3_u8; 16])
    );
}

#[tokio::test]
async fn kv_growth_accounts_for_existing_content() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let quota = Arc::new(|_: &String| Ok(Some(128_u64)));
    let content = PrincipalContentStore::from_engine_with_quota(Arc::clone(&engine), quota.clone());
    let kv = TreeKvStore::<String, TestIdentity, _, _>::from_engine_with_quota(
        engine,
        |namespace: &str| Ok(namespace.to_owned()),
        quota,
    );
    content
        .put(
            &"alice".to_owned(),
            &ContentName::new("blob").unwrap(),
            &[3_u8; 64],
        )
        .unwrap();
    assert!(kv.set("alice", "key", vec![1_u8; 64]).await.is_err());
    assert_eq!(
        content
            .read(&"alice".to_owned(), &ContentName::new("blob").unwrap())
            .unwrap(),
        Some(vec![3_u8; 64])
    );
}

#[test]
fn concurrent_catalog_updates_retry_the_shared_root_cas() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = Arc::new(PrincipalContentStore::from_engine(engine));
    let mut workers = Vec::new();
    for index in 0..8 {
        let store = Arc::clone(&store);
        workers.push(std::thread::spawn(move || {
            store
                .put(
                    &"alice".to_owned(),
                    &ContentName::new(format!("blob-{index}")).unwrap(),
                    &bytes(128 * 1024 + index),
                )
                .unwrap();
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(store.list(&"alice".to_owned()).unwrap().len(), 8);
}
