//! Detached, bounded owner state for the two native protection candidates.

use super::{
    CommitOutcome, InMemoryEngine, KvProjectionEngine, KvProjectionError,
    PrincipalProjectionEngine, PrincipalProjectionError, RootSnapshot, RootTransaction,
};
use crate::content::PrincipalContentStore;
use crate::kv::{KvStore, TreeKvStore};
use crate::storage_model::{InsertOutcome, ObjectId, ObjectRecord, RootState};
use crate::{Blake3ObjectIdentityV1, StateOwner, StorageError, StorageResult};
use astrid_core::PrincipalUid;
use std::sync::Arc;

/// Maximum retained bytes in a candidate's captured owner closure.
pub const MAX_NATIVE_SNAPSHOT_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum objects visited while capturing a candidate.
pub const MAX_NATIVE_SNAPSHOT_OBJECTS: usize = 131_072;
/// Private engine shared by both members, never restored over live custody.
pub struct NativePairEngine {
    inner: InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>,
    admitted_bytes: parking_lot::Mutex<u64>,
}

impl NativePairEngine {
    fn charge<'a>(
        &self,
        records: impl IntoIterator<Item = &'a ObjectRecord>,
    ) -> Result<(), String> {
        let mut used = self.admitted_bytes.lock();
        let additional = records
            .into_iter()
            .try_fold(0_u64, |sum, record| {
                sum.checked_add(super::object_record_retained_bytes(record) as u64)
            })
            .ok_or("native candidate allocation overflow")?;
        let next = used
            .checked_add(additional)
            .ok_or("native candidate allocation overflow")?;
        if next > MAX_NATIVE_SNAPSHOT_BYTES.saturating_mul(2) {
            return Err("native candidate cumulative write budget exceeded".into());
        }
        // Conservative: failed/redundant writes are charged too. No history can
        // grow forever merely by overwriting one logically quota-small key.
        *used = next;
        Ok(())
    }
}

impl KvProjectionEngine<StateOwner> for NativePairEngine {
    fn identify_kv_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify_kv_object(record)
    }
    fn current_kv_root(
        &self,
        principal: &StateOwner,
    ) -> Result<Option<RootState>, KvProjectionError> {
        self.inner.current_kv_root(principal)
    }
    fn load_kv_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, KvProjectionError> {
        self.inner.load_kv_object(id)
    }
    fn snapshot_kv_root(
        &self,
        principal: &StateOwner,
    ) -> Result<Option<RootSnapshot>, KvProjectionError> {
        self.inner.snapshot_kv_root(principal)
    }
    fn commit_kv_root(
        &self,
        transaction: RootTransaction<StateOwner>,
    ) -> Result<CommitOutcome, KvProjectionError> {
        self.charge(transaction.records().iter().map(|(_, record)| record))
            .map_err(KvProjectionError::Engine)?;
        self.inner.commit_kv_root(transaction)
    }
    fn flush_kv(&self) -> Result<(), KvProjectionError> {
        Ok(())
    }
}

impl PrincipalProjectionEngine<StateOwner> for NativePairEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify_object(record)
    }
    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
        self.charge([&record])
            .map_err(PrincipalProjectionError::Engine)?;
        self.inner.stage_object(record)
    }
    fn current_root(
        &self,
        owner: &StateOwner,
    ) -> Result<Option<RootState>, PrincipalProjectionError> {
        self.inner.current_root(owner)
    }
    fn load_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, PrincipalProjectionError> {
        self.inner.load_object(id)
    }
    fn commit_root(
        &self,
        transaction: RootTransaction<StateOwner>,
    ) -> Result<CommitOutcome, PrincipalProjectionError> {
        self.charge(transaction.records().iter().map(|(_, record)| record))
            .map_err(PrincipalProjectionError::Engine)?;
        self.inner.commit_root(transaction)
    }
    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}
/// Detached content projection over the same engine as candidate KV.
pub type NativePairContent = PrincipalContentStore<StateOwner, NativePairEngine>;

/// One private owner world, with original identity and separate member namespaces.
pub struct DetachedNativePair {
    engine: Arc<NativePairEngine>,
    kv: Arc<dyn KvStore>,
    content: Arc<NativePairContent>,
    uid: PrincipalUid,
}

impl DetachedNativePair {
    /// Import an already captured closure into a new private engine.
    ///
    /// # Errors
    /// Rejects oversized or invalid closures and invalid owner aliases.
    pub fn from_snapshot(
        uid: PrincipalUid,
        alias: &str,
        snapshot: Option<&RootSnapshot>,
    ) -> StorageResult<Self> {
        if alias.is_empty() || alias.contains(':') {
            return Err(StorageError::InvalidKey(
                "native candidate alias invalid".into(),
            ));
        }
        let engine = Arc::new(NativePairEngine {
            inner: InMemoryEngine::new(Blake3ObjectIdentityV1),
            admitted_bytes: parking_lot::Mutex::new(0),
        });
        let owner = StateOwner::Principal(uid);
        if let Some(snapshot) = snapshot {
            let bytes = snapshot
                .records()
                .iter()
                .try_fold(0_u64, |sum, (_, record)| {
                    sum.checked_add(
                        u64::try_from(super::object_record_retained_bytes(record)).ok()?,
                    )
                })
                .ok_or_else(|| StorageError::Internal("native snapshot size overflow".into()))?;
            if bytes > MAX_NATIVE_SNAPSHOT_BYTES
                || snapshot.records().len() > MAX_NATIVE_SNAPSHOT_OBJECTS
            {
                return Err(StorageError::Internal(
                    "native snapshot limit exceeded".into(),
                ));
            }
            engine
                .charge(snapshot.records().iter().map(|(_, record)| record))
                .map_err(StorageError::Internal)?;
            engine
                .inner
                .import_closure(snapshot.records(), snapshot.root().commit)
                .map_err(|error| {
                    StorageError::Internal(format!("native snapshot import: {error}"))
                })?;
            engine
                .inner
                .compare_and_swap_root(owner, None, snapshot.root().commit)
                .map_err(|error| {
                    StorageError::Internal(format!("native snapshot root: {error}"))
                })?;
        }
        let namespaces = [
            format!("{alias}:capsule:codewall-enforcer"),
            format!("{alias}:capsule:codewall-protocol"),
        ];
        let quota: Arc<dyn crate::kv::KvQuotaResolver<StateOwner>> =
            Arc::new(|_: &StateOwner| Ok(Some(MAX_NATIVE_SNAPSHOT_BYTES)));
        let kv = Arc::new(
            TreeKvStore::<StateOwner, Blake3ObjectIdentityV1, _, _>::from_engine_with_quota(
                Arc::clone(&engine),
                move |namespace: &str| {
                    if namespaces.iter().any(|allowed| allowed == namespace) {
                        Ok(StateOwner::Principal(uid))
                    } else {
                        Err(StorageError::InvalidKey(
                            "native candidate namespace denied".into(),
                        ))
                    }
                },
                Arc::clone(&quota),
            ),
        );
        let content = Arc::new(NativePairContent::from_engine_with_quota(
            Arc::clone(&engine),
            quota,
        ));
        Ok(Self {
            engine,
            kv,
            content,
            uid,
        })
    }

    /// Clone the namespace-confined detached KV backend.
    #[must_use]
    pub fn kv(&self) -> Arc<dyn KvStore> {
        Arc::clone(&self.kv)
    }

    /// Clone the detached logical content provider.
    #[must_use]
    pub fn content(&self) -> Arc<NativePairContent> {
        Arc::clone(&self.content)
    }

    /// Read a frozen host-only principal environment. Never exposed to guests.
    ///
    /// # Errors
    /// Rejects an unsupported member or malformed stored text values.
    pub async fn generation_env(
        &self,
        member: &str,
    ) -> StorageResult<std::collections::HashMap<String, String>> {
        if !matches!(member, "codewall-enforcer" | "codewall-protocol") {
            return Err(StorageError::InvalidKey(
                "native candidate member denied".into(),
            ));
        }
        let ns = crate::env::principal_capsule_namespace(self.uid, member);
        let expected = ns.clone();
        let owner = StateOwner::Principal(self.uid);
        let backend = Arc::new(
            TreeKvStore::<StateOwner, Blake3ObjectIdentityV1, _, _>::from_engine(
                Arc::clone(&self.engine),
                move |namespace: &str| {
                    if namespace == expected {
                        Ok(owner)
                    } else {
                        Err(StorageError::InvalidKey(
                            "native environment namespace denied".into(),
                        ))
                    }
                },
            ),
        );
        crate::env::read_env(&crate::ScopedKvStore::new(backend, ns)?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_candidate_isolated_from_live_state() {
        let uid = astrid_core::PrincipalUid::from_bytes([1; 32]);
        let live = DetachedNativePair::from_snapshot(uid, "alice", None).unwrap();
        let ns = "alice:capsule:codewall-enforcer";
        live.kv()
            .set(ns, "policy/active", b"old".to_vec())
            .await
            .unwrap();
        let snapshot = live
            .engine
            .inner
            .snapshot(&crate::StateOwner::Principal(uid))
            .unwrap();
        let candidate = DetachedNativePair::from_snapshot(uid, "alice", snapshot.as_ref()).unwrap();
        live.kv()
            .set(ns, "policy/active", b"new".to_vec())
            .await
            .unwrap();
        assert_eq!(
            candidate.kv().get(ns, "policy/active").await.unwrap(),
            Some(b"old".to_vec())
        );
        let protocol = "alice:capsule:codewall-protocol";
        candidate
            .kv()
            .set(protocol, "outbox/1", b"private".to_vec())
            .await
            .unwrap();
        assert!(live.kv().get(protocol, "outbox/1").await.unwrap().is_none());
        assert!(
            candidate
                .kv()
                .get("system:control:secret:codewall-protocol", "key")
                .await
                .is_err()
        );
        assert!(
            candidate
                .kv()
                .get("bob:capsule:codewall-enforcer", "policy/active")
                .await
                .is_err()
        );
        let owner = StateOwner::Principal(uid);
        let name = crate::ContentName::new("home/private").unwrap();
        candidate
            .content()
            .put(&owner, &name, b"private content")
            .unwrap();
        assert!(
            live.content()
                .read_range(&owner, &name, 0, 10)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            candidate.content().read_range(&owner, &name, 0, 7).unwrap(),
            Some(b"private".to_vec())
        );
    }

    #[tokio::test]
    async fn native_candidate_budget_rejects_before_private_root_publication() {
        let uid = PrincipalUid::from_bytes([1; 32]);
        let state = DetachedNativePair::from_snapshot(uid, "alice", None).unwrap();
        *state.engine.admitted_bytes.lock() = MAX_NATIVE_SNAPSHOT_BYTES * 2;
        assert!(
            state
                .kv()
                .set("alice:capsule:codewall-protocol", "outbox/1", vec![1])
                .await
                .is_err()
        );
        assert!(
            state
                .engine
                .inner
                .root(&StateOwner::Principal(uid))
                .is_none()
        );
        assert_eq!(state.engine.inner.object_count(), 0);
    }
}
