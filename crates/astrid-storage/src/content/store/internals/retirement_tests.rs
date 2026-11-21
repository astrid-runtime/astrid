//! A reader/writer admitted before purge must not restore its catalog memo.
use super::*;
use crate::engine::InMemoryEngine;
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_state::Blake3ObjectIdentityV1;
use std::sync::Arc;

type Engine = InMemoryEngine<String, Blake3ObjectIdentityV1>;
type Store =
    TreeKvStore<String, Blake3ObjectIdentityV1, fn(&str) -> crate::StorageResult<String>, Engine>;

fn fixture() -> (Store, PrincipalContentStore<String, Engine>) {
    fn resolve(namespace: &str) -> crate::StorageResult<String> {
        crate::kv::validate_namespace(namespace)?;
        Ok(namespace.to_owned())
    }
    let engine = Arc::new(Engine::new(Blake3ObjectIdentityV1));
    let content = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let store = Store::from_engine_with_quota_and_content_validation(
        engine,
        resolve,
        Arc::new(|_: &String| Ok(None)),
        Arc::clone(&content.validated_kv),
        Arc::clone(&content.validated_catalogs),
    );
    (store, content)
}

#[tokio::test]
async fn delayed_content_commit_completion_cannot_republish_after_purge() {
    let (kv, content) = fixture();
    let owner = "retiring".to_owned();
    kv.set(&owner, "key", b"private".to_vec()).await.unwrap();
    let name = ContentName::new("retained").unwrap();
    content.put(&owner, &name, b"non-KV").unwrap();
    let epoch = content.validated_kv.memo_epoch();
    let header = content.header(&owner).unwrap();
    let root = header.root.unwrap();
    // Model the exact gap between successful commit and finish_catalog_commit.
    assert_eq!(kv.clear_owner(&owner).unwrap(), 1);
    assert!(content.validated_catalogs.lock().is_empty());
    content.finish_catalog_commit(&owner, header.as_ref().clone(), root, epoch);
    assert!(content.validated_catalogs.lock().is_empty());
    assert_eq!(
        content.read(&owner, &name).unwrap(),
        Some(b"non-KV".to_vec())
    );
}

#[tokio::test]
async fn historical_content_decode_does_not_republish_after_purge() {
    let (kv, content) = fixture();
    let owner = "retiring".to_owned();
    kv.set(&owner, "key", b"private".to_vec()).await.unwrap();
    let name = ContentName::new("retained").unwrap();
    content.put(&owner, &name, b"non-KV").unwrap();
    let root = content.engine.current_root(&owner).unwrap();
    assert_eq!(kv.clear_owner(&owner).unwrap(), 1);
    // A fresh ticket alone must not let a historical root refill the map.
    let header = content
        .decode_header(&owner, root, content.validated_kv.memo_epoch())
        .unwrap();
    assert_eq!(header.root, root);
    assert!(header.catalog.is_some());
    assert!(content.validated_catalogs.lock().is_empty());
}

#[tokio::test]
async fn no_op_purge_also_rejects_pre_purge_content_publishers() {
    let (kv, content) = fixture();
    let owner = "retiring".to_owned();
    let name = ContentName::new("retained").unwrap();
    content.put(&owner, &name, b"non-KV").unwrap();
    let epoch = content.validated_kv.memo_epoch();
    let header = content.header(&owner).unwrap();
    let root = header.root.unwrap();
    assert_eq!(kv.clear_owner(&owner).unwrap(), 0);
    assert_eq!(content.engine.current_root(&owner).unwrap(), Some(root));
    content.finish_catalog_commit(&owner, header.as_ref().clone(), root, epoch);
    content.decode_header(&owner, Some(root), epoch).unwrap();
    assert!(content.validated_catalogs.lock().is_empty());
    // Fresh authorized work remains cacheable after retirement cleanup.
    content
        .decode_header(&owner, Some(root), content.validated_kv.memo_epoch())
        .unwrap();
    assert!(content.validated_catalogs.lock().contains_key(&owner));
}
