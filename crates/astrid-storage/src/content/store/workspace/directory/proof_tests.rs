//! Cache admission follows authenticated deltas, including the empty root.
use std::sync::Arc;

use super::tests::{id, owner, prefix, uid};
use super::*;
use crate::engine::{DurableEngine, RecoveryLimits};
use crate::principal_state::{Blake3ObjectIdentityV1, StateOwnerCodecV2};

#[test]
fn hot_workspace_edits_reuse_scalar_proof_and_discard_superseded_roots() {
    let directory = tempfile::tempdir().unwrap();
    let engine = Arc::new(
        DurableEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let branches = WorkspaceBranchStore::new(Arc::new(PrincipalContentStore::from_engine(
        Arc::clone(&engine),
    )));
    let owner = owner();
    for index in 0..24 {
        branches
            .begin_for_uid_at(&owner, uid(index), id(index), prefix())
            .unwrap();
    }
    let before = FULL_DIRECTORY_VALIDATIONS.with(std::cell::Cell::get);
    let name = ContentName::new("hot-file").unwrap();
    for sequence in 0..32_u32 {
        let header = branches.content.header(&owner).unwrap();
        let old = branches.directory_root(&owner, &header).unwrap().unwrap();
        branches
            .write(&owner, id(0), &name, &sequence.to_le_bytes())
            .unwrap();
        assert!(
            engine
                .load_projection_cache(&owner, old.object, PROOF_CACHE_KEY)
                .is_none()
        );
        let header = branches.content.header(&owner).unwrap();
        let next = branches.directory_root(&owner, &header).unwrap().unwrap();
        assert!(
            engine
                .load_projection_cache(&owner, next.object, PROOF_CACHE_KEY)
                .is_some()
        );
    }
    assert_eq!(
        FULL_DIRECTORY_VALIDATIONS.with(std::cell::Cell::get),
        before,
        "hot edits must not full-validate the fleet directory"
    );
    for index in 1..24 {
        branches.drop(&owner, id(index)).unwrap();
    }
    let header = branches.content.header(&owner).unwrap();
    let last = branches.directory_root(&owner, &header).unwrap().unwrap();
    branches.drop(&owner, id(0)).unwrap();
    assert!(
        engine
            .load_projection_cache(&owner, last.object, PROOF_CACHE_KEY)
            .is_none(),
        "dropping the final branch must discard its old scalar proof"
    );
    assert!(
        branches
            .directory_root(&owner, &branches.content.header(&owner).unwrap())
            .unwrap()
            .is_none()
    );
    engine.close().unwrap();
}

#[test]
fn legacy_cleanup_at_exact_quota_does_not_require_index_migration_space() {
    for promote in [false, true] {
        let engine = Arc::new(crate::engine::InMemoryEngine::new(Blake3ObjectIdentityV1));
        let limit = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let current = Arc::clone(&limit);
        let quota: Arc<dyn crate::kv::KvQuotaResolver<_>> =
            Arc::new(move |_: &crate::StateOwner| {
                Ok(Some(current.load(std::sync::atomic::Ordering::Relaxed)))
            });
        let content = Arc::new(PrincipalContentStore::from_engine_with_quota(
            Arc::clone(&engine),
            quota,
        ));
        let owner = owner();
        content
            .put(&owner, &ContentName::new("file").unwrap(), b"retained")
            .unwrap();
        let mut header = content.header(&owner).unwrap().as_ref().clone();
        let record =
            super::super::make_branch_record(id(1), None, header.catalog, header.catalog).unwrap();
        let object = engine.identify_object(&record);
        header.other_quota_bytes = header.catalog.unwrap().summary.quota_bytes;
        header.preserved_state.push(ObjectReference::owns(
            super::super::workspace_ref_label(id(1)),
            object,
        ));
        engine
            .commit(
                content
                    .encode_transaction(owner, header, None, [(object, record)].into())
                    .unwrap(),
            )
            .unwrap();
        let header = content.header(&owner).unwrap();
        limit.store(
            header
                .other_quota_bytes
                .strict_add(header.catalog.unwrap().summary.quota_bytes),
            std::sync::atomic::Ordering::Relaxed,
        );
        let branches = WorkspaceBranchStore::new(Arc::clone(&content));
        if promote {
            branches.promote(&owner, id(1)).unwrap();
        }
        branches.drop(&owner, id(1)).unwrap();
        assert!(branches.list_bindings(&owner).unwrap().is_empty());
        assert_eq!(
            content
                .read(&owner, &ContentName::new("file").unwrap())
                .unwrap(),
            Some(b"retained".to_vec())
        );
        assert_eq!(content.header(&owner).unwrap().other_quota_bytes, 0);
    }
}
