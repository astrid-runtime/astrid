use std::sync::Arc;

use super::*;
use crate::Blake3ObjectIdentityV1;
use crate::content_dag::{ChunkingProfile, append_verified_content, build_content};
use crate::engine::InMemoryEngine;

#[test]
fn unverified_append_leaves_source_untouched_for_streaming_fallback() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let store = PrincipalContentStore::from_engine(engine);
    let owner = "alice".to_owned();
    let name = ContentName::new("file").unwrap();
    store.put(&owner, &name, b"old").unwrap();
    assert!(!store.try_append(&owner, &name, 3, b"new").unwrap());
    assert_eq!(store.read(&owner, &name).unwrap().unwrap(), b"old");
}

#[test]
fn conditional_append_rejects_changed_file_but_allows_unrelated_catalog_changes() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("file").unwrap();
    let old = build_content(&Blake3ObjectIdentityV1, ChunkingProfile::ASTRID_V1, b"old").unwrap();
    store.put(&owner, &name, b"old").unwrap();
    let delta = append_verified_content(
        &Blake3ObjectIdentityV1,
        &EngineSource::new(engine.as_ref(), &owner),
        old.verified_content(),
        b"new",
    )
    .unwrap();
    store
        .put(&owner, &ContentName::new("unrelated").unwrap(), b"other")
        .unwrap();
    store
        .publish_deferred_expected(
            &owner,
            &name,
            delta.verified,
            &delta.records,
            Some(old.descriptor().file()),
        )
        .unwrap();
    assert_eq!(store.read(&owner, &name).unwrap().unwrap(), b"oldnew");
    // Same-length replacement must also reject: length alone is not identity.
    store.put(&owner, &name, b"NEW").unwrap();
    let root = engine.root(&owner);
    let objects = engine.object_count();
    assert!(matches!(
        store.publish_deferred_expected(
            &owner,
            &name,
            delta.verified,
            &delta.records,
            Some(old.descriptor().file())
        ),
        Err(PrincipalContentError::BatchPreconditionFailed)
    ));
    assert_eq!(engine.root(&owner), root);
    assert_eq!(engine.object_count(), objects);
    assert_eq!(store.read(&owner, &name).unwrap().unwrap(), b"NEW");
}

#[test]
fn quota_rejected_append_admits_no_delta_records_and_preserves_root() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let store = PrincipalContentStore::from_engine_with_quota(
        Arc::clone(&engine),
        Arc::new(|_: &String| Ok(Some(128))),
    );
    let owner = "alice".to_owned();
    let name = ContentName::new("file").unwrap();
    let old = build_content(&Blake3ObjectIdentityV1, ChunkingProfile::ASTRID_V1, b"old").unwrap();
    store.put(&owner, &name, b"old").unwrap();
    let delta = append_verified_content(
        &Blake3ObjectIdentityV1,
        &EngineSource::new(engine.as_ref(), &owner),
        old.verified_content(),
        &[42; 256],
    )
    .unwrap();
    let root = engine.root(&owner);
    let objects = engine.object_count();
    assert!(matches!(
        store.publish_deferred_expected(
            &owner,
            &name,
            delta.verified,
            &delta.records,
            Some(old.descriptor().file())
        ),
        Err(PrincipalContentError::QuotaExceeded { .. })
    ));
    assert_eq!(engine.root(&owner), root);
    assert_eq!(engine.object_count(), objects);
}

struct ConcurrentReplacement {
    inner: Arc<InMemoryEngine<String, Blake3ObjectIdentityV1>>,
    armed: std::sync::atomic::AtomicBool,
}

impl PrincipalProjectionEngine<String> for ConcurrentReplacement {
    fn identify_object(
        &self,
        record: &crate::storage_model::ObjectRecord,
    ) -> crate::storage_model::ObjectId {
        self.inner.identify_object(record)
    }

    fn stage_object(
        &self,
        record: crate::storage_model::ObjectRecord,
    ) -> Result<
        (
            crate::storage_model::ObjectId,
            crate::storage_model::InsertOutcome,
        ),
        crate::engine::PrincipalProjectionError,
    > {
        self.inner.stage_object(record)
    }

    fn current_root(
        &self,
        owner: &String,
    ) -> Result<Option<crate::storage_model::RootState>, crate::engine::PrincipalProjectionError>
    {
        self.inner.current_root(owner)
    }

    fn load_object(
        &self,
        id: crate::storage_model::ObjectId,
    ) -> Result<Option<crate::storage_model::ObjectRecord>, crate::engine::PrincipalProjectionError>
    {
        self.inner.load_object(id)
    }

    fn commit_root(
        &self,
        transaction: crate::engine::RootTransaction<String>,
    ) -> Result<crate::engine::CommitOutcome, crate::engine::PrincipalProjectionError> {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            PrincipalContentStore::from_engine(Arc::clone(&self.inner))
                .put(
                    transaction.principal(),
                    &ContentName::new("file").unwrap(),
                    b"NEW",
                )
                .unwrap();
        }
        self.inner.commit_root(transaction)
    }

    fn flush_projection(&self) -> Result<(), crate::engine::PrincipalProjectionError> {
        Ok(())
    }
}

#[test]
fn append_rechecks_expected_identity_after_root_cas_conflict() {
    let engine = Arc::new(ConcurrentReplacement {
        inner: Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1)),
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let name = ContentName::new("file").unwrap();
    let old = build_content(&Blake3ObjectIdentityV1, ChunkingProfile::ASTRID_V1, b"old").unwrap();
    store.put(&owner, &name, b"old").unwrap();
    let delta = append_verified_content(
        &Blake3ObjectIdentityV1,
        &EngineSource::new(engine.as_ref(), &owner),
        old.verified_content(),
        b"new",
    )
    .unwrap();
    engine
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        store.publish_deferred_expected(
            &owner,
            &name,
            delta.verified,
            &delta.records,
            Some(old.descriptor().file())
        ),
        Err(PrincipalContentError::BatchPreconditionFailed)
    ));
    assert_eq!(store.read(&owner, &name).unwrap().unwrap(), b"NEW");
}
