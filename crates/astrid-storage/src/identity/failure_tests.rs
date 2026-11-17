use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;

use super::*;
use crate::{KvStore, MemoryKvStore, StorageError, StorageResult};

#[derive(Debug, Default)]
struct FailingSetKv {
    inner: MemoryKvStore,
    reject_sets: AtomicBool,
    reject_prefix_reads: AtomicBool,
    link_gets: AtomicUsize,
    prefix_reads: AtomicUsize,
    relink_after_scan: std::sync::Mutex<Option<(String, Vec<u8>)>>,
    scan_override: std::sync::Mutex<Option<Vec<crate::kv::KvEntry>>>,
}

#[async_trait]
impl KvStore for FailingSetKv {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        if key.starts_with("link/") {
            self.link_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(namespace, key).await
    }

    async fn list_entries_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<crate::kv::KvEntry>> {
        self.prefix_reads.fetch_add(1, Ordering::SeqCst);
        if self.reject_prefix_reads.load(Ordering::SeqCst) {
            return Err(StorageError::Internal(
                "injected prefix read failure".to_owned(),
            ));
        }
        if let Some(entries) = self.scan_override.lock().unwrap().take() {
            return Ok(entries);
        }
        let entries = self
            .inner
            .list_entries_with_prefix(namespace, prefix)
            .await?;
        let replacement = self.relink_after_scan.lock().unwrap().take();
        if let Some((key, value)) = replacement {
            self.inner.set(namespace, &key, value).await?;
        }
        Ok(entries)
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        if self.reject_sets.load(Ordering::SeqCst) {
            return Err(StorageError::Internal("injected set failure".to_owned()));
        }
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

#[tokio::test]
async fn deletion_scans_links_without_point_reading_other_users() {
    let backend = Arc::new(FailingSetKv::default());
    let store =
        KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
    let target = store.create_user(Some("target")).await.unwrap();
    let other = store.create_user(Some("other")).await.unwrap();
    for index in 0..2048 {
        store
            .link(
                "service",
                &index.to_string(),
                if index == 0 { target.id } else { other.id },
                "operator",
            )
            .await
            .unwrap();
    }
    backend.link_gets.store(0, Ordering::SeqCst);
    backend.prefix_reads.store(0, Ordering::SeqCst);

    assert!(store.delete_user(target.id).await.unwrap());
    eprintln!(
        "identity_deletion_scan link_gets={} prefix_reads={}",
        backend.link_gets.load(Ordering::SeqCst),
        backend.prefix_reads.load(Ordering::SeqCst)
    );
    assert_eq!(backend.prefix_reads.load(Ordering::SeqCst), 1);
    assert!(
        backend.link_gets.load(Ordering::SeqCst) <= 1,
        "deletion point-read unrelated frontend links"
    );
    assert!(store.get_user(target.id).await.unwrap().is_none());
    assert!(store.resolve("service", "0").await.unwrap().is_none());
    assert_eq!(
        store.resolve("service", "2047").await.unwrap().unwrap().id,
        other.id
    );
}

#[tokio::test]
async fn failed_link_scan_preserves_the_user_and_links() {
    let backend = Arc::new(FailingSetKv::default());
    let store =
        KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
    let user = store.create_user(Some("target")).await.unwrap();
    store
        .link("service", "target", user.id, "operator")
        .await
        .unwrap();
    backend.reject_prefix_reads.store(true, Ordering::SeqCst);
    assert!(store.delete_user(user.id).await.is_err());
    assert_eq!(store.get_user(user.id).await.unwrap(), Some(user.clone()));
    assert_eq!(
        store
            .resolve("service", "target")
            .await
            .unwrap()
            .unwrap()
            .id,
        user.id
    );
}

#[tokio::test]
async fn deletion_keeps_a_link_reassigned_after_the_prefix_scan() {
    let backend = Arc::new(FailingSetKv::default());
    let store =
        KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
    let target = store.create_user(Some("target")).await.unwrap();
    let other = store.create_user(Some("other")).await.unwrap();
    let mut link = store
        .link("service", "target", target.id, "operator")
        .await
        .unwrap();
    link.astrid_user_id = other.id;
    *backend.relink_after_scan.lock().unwrap() = Some((
        KvIdentityStore::link_key("service", "target"),
        serde_json::to_vec(&link).unwrap(),
    ));

    assert!(store.delete_user(target.id).await.unwrap());
    assert_eq!(
        store
            .resolve("service", "target")
            .await
            .unwrap()
            .unwrap()
            .id,
        other.id
    );
}

#[tokio::test]
async fn invalid_link_scan_entries_preserve_the_user_and_links() {
    for case in ["namespace", "prefix", "json"] {
        let backend = Arc::new(FailingSetKv::default());
        let store =
            KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
        let user = store.create_user(Some("target")).await.unwrap();
        let link = store
            .link("service", "target", user.id, "operator")
            .await
            .unwrap();
        let mut entry = crate::kv::KvEntry {
            namespace: "system:identity".to_owned(),
            key: KvIdentityStore::link_key("service", "target"),
            value: serde_json::to_vec(&link).unwrap(),
        };
        match case {
            "namespace" => entry.namespace = "other".to_owned(),
            "prefix" => entry.key = "user/target".to_owned(),
            "json" => entry.value = b"invalid-json".to_vec(),
            _ => unreachable!(),
        }
        *backend.scan_override.lock().unwrap() = Some(vec![entry]);
        assert!(store.delete_user(user.id).await.is_err(), "{case}");
        assert_eq!(
            store.get_user(user.id).await.unwrap(),
            Some(user.clone()),
            "{case}"
        );
        assert_eq!(
            store
                .resolve("service", "target")
                .await
                .unwrap()
                .unwrap()
                .id,
            user.id,
            "{case}"
        );
    }
}

#[tokio::test]
async fn failed_identity_persistence_restores_the_exact_directory_state() {
    let backend = Arc::new(FailingSetKv::default());
    let bootstrap =
        KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
    let original = PrincipalId::new("Alice").unwrap();
    let renamed = PrincipalId::new("Alice-Renamed").unwrap();
    let user = bootstrap
        .create_principal(original.clone(), [0x11; 32])
        .await
        .unwrap();
    let identity = bootstrap
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let principals = PrincipalDirectory::default();
    principals.register(original.clone(), identity.uid).unwrap();
    let store = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(backend.clone(), "system:identity").unwrap(),
        principals.clone(),
    );

    backend.reject_sets.store(true, Ordering::SeqCst);
    assert!(
        store
            .bind_principal_identity(user.id, original.clone(), [0x22; 32])
            .await
            .is_err()
    );
    assert_eq!(principals.uid_for(&original).unwrap(), identity.uid);

    assert!(
        store
            .bind_principal_identity(user.id, renamed.clone(), [0x22; 32])
            .await
            .is_err()
    );
    assert_eq!(principals.uid_for(&original).unwrap(), identity.uid);
    assert!(principals.uid_for(&renamed).is_err());
}
