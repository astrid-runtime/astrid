//! A commit digest can remain current across more than one root generation.
use super::{
    ContentName, DECODED_HEADER_CACHE_KEY, PrincipalContentStore, ProjectionCacheEntry,
    RootTransaction,
};
use crate::engine::{DurableEngine, ObjectCacheConfig, RecoveryLimits};
use crate::{Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV2};
use std::{num::NonZeroU64, sync::Arc};

#[test]
fn repeated_commit_at_new_generation_decodes_then_reuses_current_header() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(
        DurableEngine::open_with_object_cache(
            dir.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::new(1024 * 1024).unwrap(),
            ObjectCacheConfig::bounded(NonZeroU64::new(1024 * 1024).unwrap()),
        )
        .unwrap(),
    );
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = StateOwner::System;
    store
        .put(&owner, &ContentName::new("note").unwrap(), b"original")
        .unwrap();
    let first = store.header(&owner).unwrap();
    let previous = first.root.unwrap();
    let current = engine
        .commit(RootTransaction::new(
            owner,
            Some(previous),
            previous.commit,
            Vec::new(),
        ))
        .unwrap()
        .root();
    assert_ne!(current.generation, previous.generation);
    assert_eq!(current.commit, previous.commit);
    assert!(engine.retain_projection_cache(
        &owner,
        current.commit,
        DECODED_HEADER_CACHE_KEY,
        ProjectionCacheEntry::from_shared(first)
    ));
    let before = store.decode_header_invocations();
    let refreshed = store.header(&owner).unwrap();
    assert_eq!(refreshed.root, Some(current));
    assert_eq!(store.decode_header_invocations(), before + 1);
    assert!(Arc::ptr_eq(&refreshed, &store.header(&owner).unwrap()));
    assert_eq!(store.decode_header_invocations(), before + 1);
}
