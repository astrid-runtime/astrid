//! A custom backend's specialized snapshot must survive the visitor default.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::{KvEntry, KvStore};
use crate::StorageResult;

struct SnapshotBackend;

#[async_trait]
impl KvStore for SnapshotBackend {
    async fn get(&self, _: &str, _: &str) -> StorageResult<Option<Vec<u8>>> {
        Ok(Some(b"later point read".to_vec()))
    }
    async fn set(&self, _: &str, _: &str, _: Vec<u8>) -> StorageResult<()> {
        unreachable!("snapshot regression does not mutate")
    }
    async fn delete(&self, _: &str, _: &str) -> StorageResult<bool> {
        unreachable!("snapshot regression does not mutate")
    }
    async fn exists(&self, _: &str, _: &str) -> StorageResult<bool> {
        Ok(true)
    }
    async fn list_keys(&self, _: &str) -> StorageResult<Vec<String>> {
        Ok(vec!["link/a".to_owned()])
    }
    async fn list_entries_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<KvEntry>> {
        assert_eq!(prefix, "link/");
        Ok(vec![KvEntry {
            namespace: namespace.to_owned(),
            key: "link/a".to_owned(),
            value: b"captured snapshot".to_vec(),
        }])
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: &str,
        _: Option<&[u8]>,
        _: Vec<u8>,
    ) -> StorageResult<bool> {
        unreachable!("snapshot regression does not mutate")
    }
    async fn clear_namespace(&self, _: &str) -> StorageResult<u64> {
        unreachable!("snapshot regression does not mutate")
    }
}

#[tokio::test]
async fn default_prefix_visitor_preserves_specialized_entry_snapshot() {
    let result = Arc::new(Mutex::new(Vec::new()));
    let collected = result.clone();
    SnapshotBackend
        .visit_entries_with_prefix(
            "test",
            "link/",
            Box::new(move |namespace, key, value| {
                collected.lock().unwrap().push((
                    namespace.to_owned(),
                    key.to_owned(),
                    value.to_vec(),
                ));
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        *result.lock().unwrap(),
        vec![(
            "test".to_owned(),
            "link/a".to_owned(),
            b"captured snapshot".to_vec()
        )]
    );
}
