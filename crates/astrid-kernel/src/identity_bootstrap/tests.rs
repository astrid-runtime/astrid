//! Causal identity-bootstrap regressions over real KV user-prefix walks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use astrid_core::{AstridUserId, PrincipalId, PrincipalIdentity, PrincipalUid};
use astrid_storage::{
    IdentityStore, KvBatchOutcome, KvIdentityStore, KvMutationBatch, KvStore, MemoryKvStore,
    PrincipalDirectory, ScopedKvStore, StorageResult,
};
use async_trait::async_trait;

use super::bind_identity_store;

const IDENTITY_NAMESPACE: &str = "system:identity";
const USER_PREFIX: &str = "user/";

struct CountingKv {
    inner: Arc<dyn KvStore>,
    user_prefix_lists: AtomicUsize,
    user_record_gets: AtomicUsize,
}

impl CountingKv {
    fn new(inner: Arc<dyn KvStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            user_prefix_lists: AtomicUsize::new(0),
            user_record_gets: AtomicUsize::new(0),
        })
    }

    fn user_prefix_lists(&self) -> usize {
        self.user_prefix_lists.load(Ordering::SeqCst)
    }

    fn user_record_gets(&self) -> usize {
        self.user_record_gets.load(Ordering::SeqCst)
    }

    fn record_list(&self, namespace: &str, prefix: &str) {
        if namespace == IDENTITY_NAMESPACE && prefix == USER_PREFIX {
            self.user_prefix_lists.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_get(&self, namespace: &str, key: &str) {
        if namespace == IDENTITY_NAMESPACE && key.starts_with(USER_PREFIX) {
            self.user_record_gets.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl KvStore for CountingKv {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.record_get(namespace, key);
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
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

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        self.record_list(namespace, prefix);
        self.inner.list_keys_with_prefix(namespace, prefix).await
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

    async fn apply_batch(&self, batch: &KvMutationBatch) -> StorageResult<KvBatchOutcome> {
        self.inner.apply_batch(batch).await
    }

    fn supports_atomic_batch(&self) -> bool {
        self.inner.supports_atomic_batch()
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

fn counting_arc(store: &Arc<CountingKv>) -> Arc<dyn KvStore> {
    Arc::clone(store) as Arc<dyn KvStore>
}

async fn persist_principal(
    kv: &Arc<dyn KvStore>,
    directory: PrincipalDirectory,
    alias: &str,
    key: [u8; 32],
) -> (AstridUserId, PrincipalIdentity) {
    let identity_store = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(Arc::clone(kv), IDENTITY_NAMESPACE).expect("identity scope"),
        directory,
    );
    let user = identity_store
        .create_principal(PrincipalId::new(alias).expect("alias"), key)
        .await
        .expect("create principal");
    let identity = identity_store
        .get_principal_identity(user.id)
        .await
        .expect("read identity")
        .expect("principal identity");
    (user, identity)
}

#[tokio::test]
async fn portable_injected_kv_loads_user_prefix_once() {
    let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let seed_directory = PrincipalDirectory::default();
    let (user, identity) = persist_principal(&backend, seed_directory, "alice", [0x11; 32]).await;

    let counted = CountingKv::new(backend);
    let live = PrincipalDirectory::default();
    bind_identity_store(
        &counting_arc(&counted),
        live.clone(),
        #[cfg(not(target_family = "wasm"))]
        None,
    )
    .await
    .expect("portable identity load");

    assert_eq!(counted.user_prefix_lists(), 1);
    assert_eq!(counted.user_record_gets(), 1);
    assert_eq!(
        live.uid_for(&user.principal).expect("loaded alias"),
        identity.uid
    );
}

#[tokio::test]
async fn portable_injected_kv_rejects_malformed_durable_identity() {
    let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
    let seed_directory = PrincipalDirectory::default();
    let (user, _) = persist_principal(&backend, seed_directory, "bob", [0x22; 32]).await;

    let key = format!("user/{}", user.id);
    let bytes = backend
        .get(IDENTITY_NAMESPACE, &key)
        .await
        .expect("read user")
        .expect("user bytes");
    let mut record: serde_json::Value = serde_json::from_slice(&bytes).expect("user json");
    record["principal_identity"]["uid"] =
        serde_json::Value::String(PrincipalUid::from_bytes([0; 32]).to_string());
    backend
        .set(
            IDENTITY_NAMESPACE,
            &key,
            serde_json::to_vec(&record).expect("corrupt json"),
        )
        .await
        .expect("write corrupt user");

    let counted = CountingKv::new(backend);
    let live = PrincipalDirectory::default();
    let retained = PrincipalId::new("retained").expect("retained");
    let retained_uid = PrincipalUid::from_bytes([0xAB; 32]);
    live.register(retained.clone(), retained_uid)
        .expect("retain live binding");

    let error = bind_identity_store(
        &counting_arc(&counted),
        live.clone(),
        #[cfg(not(target_family = "wasm"))]
        None,
    )
    .await
    .expect_err("malformed identity must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("Failed to load durable principal identities"),
        "unexpected error: {message}"
    );
    assert_eq!(counted.user_prefix_lists(), 1);
    assert!(counted.user_record_gets() >= 1);
    assert_eq!(
        live.uid_for(&retained).expect("retained alias"),
        retained_uid
    );
    assert!(live.uid_for(&user.principal).is_err());
}

#[cfg(not(target_family = "wasm"))]
#[tokio::test(flavor = "multi_thread")]
async fn native_assembled_store_does_not_walk_user_prefix_again() {
    let dir = tempfile::tempdir().expect("temp home");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    home.ensure().expect("ensure home");
    let (_kv, directory, store) = crate::open_test_runtime_kv(&home).await;
    let (user, identity) =
        persist_principal(&store.kv(), directory.clone(), "carol", [0x33; 32]).await;
    assert_eq!(
        directory.uid_for(&user.principal).expect("assembled alias"),
        identity.uid
    );

    let counted = CountingKv::new(store.kv());
    bind_identity_store(&counting_arc(&counted), directory.clone(), Some(&store))
        .await
        .expect("native skip");
    assert_eq!(counted.user_prefix_lists(), 0);
    assert_eq!(counted.user_record_gets(), 0);
    assert_eq!(
        directory.uid_for(&user.principal).expect("kept alias"),
        identity.uid
    );

    let replay = PrincipalDirectory::default();
    bind_identity_store(&counting_arc(&counted), replay.clone(), None)
        .await
        .expect("injected load still walks");
    assert_eq!(counted.user_prefix_lists(), 1);
    assert_eq!(counted.user_record_gets(), 1);
    assert_eq!(
        replay.uid_for(&user.principal).expect("replayed alias"),
        identity.uid
    );
}
