//! Exercise retained inventory expectations after a real owner-root CAS conflict.
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::content::{
    ContentBatchExpectation, ContentDescriptor, ContentIngest, ContentName,
    PrepareDerivedBatchContent, PrincipalContentError, PrincipalContentStore,
};
use crate::engine::{
    CommitOutcome, InMemoryEngine, PrincipalProjectionEngine, PrincipalProjectionError,
    RootTransaction,
};
use crate::principal_state::{Blake3ObjectIdentityV1, StateOwner};
use crate::storage_model::{InsertOutcome, ObjectId, ObjectRecord, RootState};

type Inner = InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>;

struct InterleavingEngine {
    inner: Arc<Inner>,
    before_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl PrincipalProjectionEngine<StateOwner> for InterleavingEngine {
    fn identify_object(&self, record: &ObjectRecord) -> ObjectId {
        self.inner.identify_object(record)
    }
    fn stage_object(
        &self,
        record: ObjectRecord,
    ) -> Result<(ObjectId, InsertOutcome), PrincipalProjectionError> {
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
        let interleave = self.before_commit.lock().take();
        if let Some(interleave) = interleave {
            interleave();
        }
        self.inner.commit_root(transaction)
    }
    fn flush_projection(&self) -> Result<(), PrincipalProjectionError> {
        Ok(())
    }
}

struct Derived(ContentName);
impl PrepareDerivedBatchContent for Derived {
    fn prepare(
        &mut self,
        _: &BTreeMap<ContentName, ContentDescriptor>,
    ) -> Result<(ContentName, Vec<u8>), PrincipalContentError> {
        Ok((self.0.clone(), b"ACTIVE".to_vec()))
    }
}

#[test]
fn derived_receipt_rechecks_retained_identity_after_cas_conflict() {
    let inner = Arc::new(Inner::new(Blake3ObjectIdentityV1));
    let engine = Arc::new(InterleavingEngine {
        inner: Arc::clone(&inner),
        before_commit: Mutex::new(None),
    });
    let content = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let concurrent = PrincipalContentStore::from_engine(inner);
    let owner = StateOwner::System;
    let retained = ContentName::new("retained").unwrap();
    let control = ContentName::new("control").unwrap();
    let active = ContentName::new("ACTIVE").unwrap();
    content.put(&owner, &retained, b"before").unwrap();
    let expected = content.describe(&owner, &retained).unwrap().unwrap().file();
    let concurrent_name = retained.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent
            .put(&owner, &concurrent_name, b"concurrent")
            .unwrap();
    }));
    let expectation = ContentBatchExpectation::exact([
        (retained.clone(), Some(expected)),
        (control.clone(), None),
        (active.clone(), None),
    ]);
    let error = content
        .replace_streaming_batch_with_expectation(
            &owner,
            [ContentIngest::new(control.clone(), Cursor::new(b"receipt"))],
            &[],
            Some(&mut Derived(active.clone())),
            Some(&expectation),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PrincipalContentError::BatchPreconditionFailed
    ));
    assert_eq!(
        content.read(&owner, &retained).unwrap(),
        Some(b"concurrent".to_vec())
    );
    assert_eq!(content.read(&owner, &control).unwrap(), None);
    assert_eq!(content.read(&owner, &active).unwrap(), None);
}

#[test]
fn empty_source_derived_receipt_rechecks_removal_after_cas_conflict() {
    let inner = Arc::new(Inner::new(Blake3ObjectIdentityV1));
    let engine = Arc::new(InterleavingEngine {
        inner: Arc::clone(&inner),
        before_commit: Mutex::new(None),
    });
    let content = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let concurrent = PrincipalContentStore::from_engine(inner);
    let owner = StateOwner::System;
    let removed = ContentName::new("old-projection").unwrap();
    let active = ContentName::new("ACTIVE").unwrap();
    content.put(&owner, &removed, b"before").unwrap();
    content.put(&owner, &active, b"old receipt").unwrap();
    let expected = content.describe(&owner, &removed).unwrap().unwrap().file();
    let expected_active = content.describe(&owner, &active).unwrap().unwrap().file();
    let concurrent_name = removed.clone();
    *engine.before_commit.lock() = Some(Box::new(move || {
        concurrent
            .put(&owner, &concurrent_name, b"concurrent")
            .unwrap();
    }));
    let expectation = ContentBatchExpectation::exact([
        (removed.clone(), Some(expected)),
        (active.clone(), Some(expected_active)),
    ]);
    let error = content
        .replace_streaming_batch_with_expectation(
            &owner,
            std::iter::empty::<ContentIngest<Cursor<&[u8]>>>(),
            std::slice::from_ref(&removed),
            Some(&mut Derived(active.clone())),
            Some(&expectation),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PrincipalContentError::BatchPreconditionFailed
    ));
    assert_eq!(
        content.read(&owner, &removed).unwrap(),
        Some(b"concurrent".to_vec())
    );
    assert_eq!(
        content.read(&owner, &active).unwrap(),
        Some(b"old receipt".to_vec())
    );
}

#[test]
fn empty_source_without_derivation_remains_an_invalid_streaming_batch() {
    let inner = Arc::new(Inner::new(Blake3ObjectIdentityV1));
    let content = PrincipalContentStore::from_engine(Arc::clone(&inner));
    let owner = StateOwner::System;
    let error = content
        .put_streaming_batch(&owner, std::iter::empty::<ContentIngest<Cursor<&[u8]>>>())
        .unwrap_err();
    assert!(matches!(error, PrincipalContentError::EmptyBatch));
    assert_eq!(inner.current_root(&owner).unwrap(), None);
}

#[test]
fn empty_source_derived_name_cannot_overlap_a_removal() {
    let inner = Arc::new(Inner::new(Blake3ObjectIdentityV1));
    let content = PrincipalContentStore::from_engine(Arc::clone(&inner));
    let owner = StateOwner::System;
    let removed = ContentName::new("old-projection").unwrap();
    content.put(&owner, &removed, b"old").unwrap();
    let before = inner.current_root(&owner).unwrap();
    let error = content
        .replace_streaming_batch_removing_exact(
            &owner,
            std::iter::empty::<ContentIngest<Cursor<&[u8]>>>(),
            std::slice::from_ref(&removed),
            Some(&mut Derived(removed.clone())),
        )
        .unwrap_err();
    assert!(matches!(error, PrincipalContentError::DuplicateBatchName(value) if value == removed));
    assert_eq!(inner.current_root(&owner).unwrap(), before);
    assert_eq!(
        content.read(&owner, &removed).unwrap(),
        Some(b"old".to_vec())
    );
}
