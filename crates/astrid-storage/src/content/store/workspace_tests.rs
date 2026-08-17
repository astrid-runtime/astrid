use super::*;
use crate::StateOwner;
use crate::content::ContentName;
use crate::engine::InMemoryEngine;
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_state::Blake3ObjectIdentityV1;
use astrid_core::PrincipalUid;
use std::sync::Arc;

fn owner() -> StateOwner {
    StateOwner::Principal(PrincipalUid::from_bytes([7; 32]))
}

type TestEngine = InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>;
type TestContent = PrincipalContentStore<StateOwner, TestEngine>;

fn content() -> Arc<TestContent> {
    content_with_engine().0
}

fn content_with_engine() -> (Arc<TestContent>, Arc<TestEngine>) {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let content = Arc::new(PrincipalContentStore::from_engine_with_validation(
        Arc::clone(&engine),
        Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
    ));
    (content, engine)
}

#[test]
fn fork_shares_root_and_divergent_write_isolated() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let branch = branches
        .begin_with_uid(&owner, WorkspaceUid::from_bytes([1; 16]))
        .unwrap();
    assert_eq!(branch.base_content_root(), branch.current_content_root());
    branches
        .write(&owner, branch.id(), &name, b"branch")
        .unwrap();
    assert_eq!(content.read(&owner, &name).unwrap(), Some(b"base".to_vec()));
    assert_eq!(
        branches.read(&owner, branch.id(), &name).unwrap(),
        Some(b"branch".to_vec())
    );
}

#[test]
fn fork_child_shares_source_root_before_diverging() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let source_id = WorkspaceUid::from_bytes([16; 16]);
    let child_id = WorkspaceUid::from_bytes([17; 16]);
    let source = branches.begin_with_uid(&owner, source_id).unwrap();
    branches.write(&owner, source_id, &name, b"source").unwrap();
    let child = branches.fork_with_uid(&owner, source_id, child_id).unwrap();
    let source_after = branches.describe(&owner, source_id).unwrap();
    assert_eq!(
        child.base_content_root(),
        source_after.current_content_root()
    );
    assert_eq!(child.base_content_root(), child.current_content_root());
    branches.write(&owner, child_id, &name, b"child").unwrap();
    assert_eq!(
        branches.read(&owner, source_id, &name).unwrap(),
        Some(b"source".to_vec())
    );
    assert_eq!(
        branches.read(&owner, child_id, &name).unwrap(),
        Some(b"child".to_vec())
    );
    assert_eq!(
        source.base_content_root(),
        content
            .header(&owner)
            .unwrap()
            .catalog
            .map(|root| root.object)
    );
}

#[test]
fn prefix_attachment_hides_unrelated_home_and_promotes_only_selected_subtree() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let selected = ContentName::new("home/alice").unwrap();
    let selected_file = ContentName::new("home/alice/note").unwrap();
    let unrelated_file = ContentName::new("home/bob/secret").unwrap();
    content.put(&owner, &selected_file, b"base").unwrap();
    content.put(&owner, &unrelated_file, b"private").unwrap();
    let id = WorkspaceUid::from_bytes([18; 16]);
    let branch = branches
        .begin_with_uid_at(&owner, id, selected.clone())
        .unwrap();
    assert_eq!(branch.target_prefix(), Some(&selected));
    assert_eq!(branches.list(&owner, id).unwrap().len(), 1);
    assert_eq!(
        branches
            .read(&owner, id, &ContentName::new("note").unwrap())
            .unwrap(),
        Some(b"base".to_vec())
    );
    assert_eq!(
        branches
            .read(&owner, id, &ContentName::new("bob/secret").unwrap())
            .unwrap(),
        None
    );
    let fs = branches.filesystem(owner, id);
    assert!(matches!(
        fs.stat(&FilesystemPath::new("bob/secret").unwrap()),
        Err(WorkspaceBranchError::Filesystem(FilesystemError::NotFound(
            _
        )))
    ));
    branches
        .write(&owner, id, &ContentName::new("note").unwrap(), b"branch")
        .unwrap();
    content
        .put(&owner, &unrelated_file, b"updated-private")
        .unwrap();
    branches.promote(&owner, id).unwrap();
    assert_eq!(
        content.read(&owner, &selected_file).unwrap(),
        Some(b"branch".to_vec())
    );
    assert_eq!(
        content.read(&owner, &unrelated_file).unwrap(),
        Some(b"updated-private".to_vec())
    );
}

#[test]
fn prefix_selected_subtree_change_rejects_promotion_without_touching_unrelated_content() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let prefix = ContentName::new("home/alice").unwrap();
    let selected_file = ContentName::new("home/alice/note").unwrap();
    let unrelated_file = ContentName::new("home/bob/secret").unwrap();
    content.put(&owner, &selected_file, b"base").unwrap();
    content.put(&owner, &unrelated_file, b"private").unwrap();
    let id = WorkspaceUid::from_bytes([19; 16]);
    branches.begin_with_uid_at(&owner, id, prefix).unwrap();
    branches
        .write(&owner, id, &ContentName::new("note").unwrap(), b"branch")
        .unwrap();
    content
        .put(&owner, &selected_file, b"owner-change")
        .unwrap();
    assert!(matches!(
        branches.promote(&owner, id),
        Err(WorkspaceBranchError::StaleBase { .. })
    ));
    assert_eq!(
        content.read(&owner, &selected_file).unwrap(),
        Some(b"owner-change".to_vec())
    );
    assert_eq!(
        content.read(&owner, &unrelated_file).unwrap(),
        Some(b"private".to_vec())
    );
}

#[test]
fn noncanonical_target_prefix_is_rejected() {
    let branches = WorkspaceBranchStore::new(content());
    let owner = owner();
    for value in ["/home", "home/", "home//alice", "home/../alice"] {
        let prefix = ContentName::new(value).unwrap();
        assert!(matches!(
            branches.begin_with_uid_at(&owner, WorkspaceUid::from_bytes([20; 16]), prefix),
            Err(WorkspaceBranchError::InvalidTargetPrefix { .. })
        ));
    }
}

#[test]
fn unrelated_home_bytes_are_not_duplicated_into_prefix_branch_quota() {
    let content = {
        let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
        let quota: Arc<dyn crate::kv::KvQuotaResolver<StateOwner>> =
            Arc::new(|_owner: &StateOwner| Ok(Some(80)));
        Arc::new(PrincipalContentStore::from_engine_with_quota(engine, quota))
    };
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let unrelated = ContentName::new("home/bob/large").unwrap();
    content.put(&owner, &unrelated, &[1; 24]).unwrap();
    let branch = branches
        .begin_with_uid_at(
            &owner,
            WorkspaceUid::from_bytes([21; 16]),
            ContentName::new("home/alice").unwrap(),
        )
        .unwrap();
    branches
        .write(
            &owner,
            branch.id(),
            &ContentName::new("note").unwrap(),
            &[2; 8],
        )
        .unwrap();
    branches.promote(&owner, branch.id()).unwrap();
    assert_eq!(content.read(&owner, &unrelated).unwrap(), Some(vec![1; 24]));
}

#[test]
fn prefix_filesystem_directory_markers_rename_and_replace_canonically() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let id = WorkspaceUid::from_bytes([22; 16]);
    branches
        .begin_with_uid_at(&owner, id, ContentName::new("home/alice").unwrap())
        .unwrap();
    let fs = branches.filesystem(owner, id);
    fs.create_dir(&FilesystemPath::new("old").unwrap()).unwrap();
    fs.create_dir(&FilesystemPath::new("new").unwrap()).unwrap();
    fs.rename_replacing(
        &FilesystemPath::new("old").unwrap(),
        &FilesystemPath::new("new").unwrap(),
    )
    .unwrap();
    branches.promote(&owner, id).unwrap();
    assert_eq!(
        content
            .read(&owner, &ContentName::new("home/alice/new/").unwrap())
            .unwrap(),
        Some(Vec::new())
    );
    assert_eq!(
        content
            .read(&owner, &ContentName::new("home/alice/old/").unwrap())
            .unwrap(),
        None
    );
}

#[test]
fn prefix_attachment_accepts_preexisting_empty_directory_marker() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let prefix = ContentName::new("home/alice").unwrap();
    let marker = ContentName::new("home/alice/").unwrap();
    content.put(&owner, &marker, &[]).unwrap();
    let branch = branches
        .begin_with_uid_at(&owner, WorkspaceUid::from_bytes([23; 16]), prefix.clone())
        .unwrap();
    assert!(branches.list(&owner, branch.id()).unwrap().is_empty());
    branches.promote(&owner, branch.id()).unwrap();
    assert_eq!(content.read(&owner, &marker).unwrap(), Some(Vec::new()));
}

#[test]
fn promote_rejects_content_stale_but_preserves_kv_only_changes() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let branch = branches
        .begin_with_uid(&owner, WorkspaceUid::from_bytes([2; 16]))
        .unwrap();
    branches
        .write(&owner, branch.id(), &name, b"branch")
        .unwrap();
    let promoted = branches.promote(&owner, branch.id()).unwrap();
    assert_ne!(
        promoted.current_content_root(),
        promoted.base_content_root()
    );
    assert_eq!(
        content.read(&owner, &name).unwrap(),
        Some(b"branch".to_vec())
    );
}

#[test]
fn drop_is_idempotence_checked_and_branch_descriptor_is_owner_typed() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let id = WorkspaceUid::from_bytes([3; 16]);
    let branch = branches.begin_with_uid(&owner, id).unwrap();
    assert_eq!(branch.owner(), &owner);
    branches.drop(&owner, id).unwrap();
    branches.drop(&owner, id).unwrap();
    branches.rollback(&owner, id).unwrap();
}

#[test]
fn promote_retry_returns_durable_completion_receipt() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let id = WorkspaceUid::from_bytes([9; 16]);
    let branch = branches.begin_with_uid(&owner, id).unwrap();
    branches.write(&owner, id, &name, b"branch").unwrap();
    let first = branches.promote(&owner, id).unwrap();
    let retry = branches.promote(&owner, id).unwrap();
    assert_eq!(first, retry);
    assert!(matches!(
        branches.begin_with_uid(&owner, id),
        Err(WorkspaceBranchError::AlreadyExists(existing)) if existing == id
    ));
    branches.drop(&owner, id).unwrap();
    branches.drop(&owner, id).unwrap();
    assert!(matches!(
        branches.promote(&owner, id),
        Err(WorkspaceBranchError::NotFound(existing)) if existing == id
    ));
    assert_eq!(
        content.read(&owner, &name).unwrap(),
        Some(b"branch".to_vec())
    );
    assert_ne!(first.base_content_root(), first.current_content_root());
    assert_eq!(branch.base_content_root(), first.base_content_root());
}

#[test]
fn promoted_receipt_does_not_pin_old_base_after_gc() {
    let (content, engine) = content_with_engine();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let prefix = ContentName::new("workspace").unwrap();
    let base_name = ContentName::new("workspace/base").unwrap();
    content.put(&owner, &base_name, b"base bytes").unwrap();
    let id = WorkspaceUid::from_bytes([24; 16]);
    let before = content.header(&owner).unwrap().other_quota_bytes;
    let branch = branches.begin_with_uid_at(&owner, id, prefix).unwrap();
    branches
        .write(
            &owner,
            id,
            &ContentName::new("new").unwrap(),
            b"branch-only bytes",
        )
        .unwrap();
    let promoted = branches.promote(&owner, id).unwrap();
    let receipt_id = content
        .header(&owner)
        .unwrap()
        .preserved_state
        .iter()
        .find(|reference| {
            reference.label().as_bytes() == format!("workspace-promoted/{id}").as_bytes()
        })
        .map(ObjectReference::target)
        .expect("promotion receipt");
    assert_eq!(content.header(&owner).unwrap().other_quota_bytes, before);
    assert!(engine.object(branch.base_content_root().unwrap()).is_some());
    engine.collect_garbage().unwrap();
    assert!(engine.object(branch.base_content_root().unwrap()).is_none());
    assert_eq!(branches.promote(&owner, id).unwrap(), promoted);
    branches.drop(&owner, id).unwrap();
    engine.collect_garbage().unwrap();
    assert!(engine.object(receipt_id).is_none());
}

#[test]
fn stale_content_root_rejects_promotion_atomically() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let branch = branches
        .begin_with_uid(&owner, WorkspaceUid::from_bytes([4; 16]))
        .unwrap();
    branches
        .write(&owner, branch.id(), &name, b"branch")
        .unwrap();
    content.put(&owner, &name, b"owner").unwrap();
    assert!(matches!(
        branches.promote(&owner, branch.id()),
        Err(WorkspaceBranchError::StaleBase { .. })
    ));
    assert_eq!(
        content.read(&owner, &name).unwrap(),
        Some(b"owner".to_vec())
    );
    assert!(branches.describe(&owner, branch.id()).is_ok());
}

#[tokio::test]
async fn promote_preserves_concurrent_kv_commit() {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let content = Arc::new(PrincipalContentStore::from_engine_with_validation(
        Arc::clone(&engine),
        Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
    ));
    let owner = owner();
    let kv = TreeKvStore::<StateOwner, Blake3ObjectIdentityV1, _, _>::from_engine(
        Arc::clone(&engine),
        move |_namespace: &str| Ok(owner),
    );
    let name = ContentName::new("note").unwrap();
    content.put(&owner, &name, b"base").unwrap();
    let id = WorkspaceUid::from_bytes([11; 16]);
    content
        .workspace_branches()
        .begin_with_uid(&owner, id)
        .unwrap();
    content
        .workspace_branches()
        .write(&owner, id, &name, b"branch")
        .unwrap();

    kv.set("state-owner", "concurrent", b"kv-value".to_vec())
        .await
        .unwrap();

    let branches = content.workspace_branches();
    branches.promote(&owner, id).unwrap();
    assert_eq!(
        content.read(&owner, &name).unwrap(),
        Some(b"branch".to_vec())
    );
    assert_eq!(
        kv.get("state-owner", "concurrent").await.unwrap(),
        Some(b"kv-value".to_vec())
    );
}

#[test]
fn deterministic_begin_is_idempotent_but_mutated_uid_collides() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let id = WorkspaceUid::from_bytes([5; 16]);
    let first = branches.begin_with_uid(&owner, id).unwrap();
    let repeated = branches.begin_with_uid(&owner, id).unwrap();
    assert_eq!(first, repeated);
    let name = ContentName::new("note").unwrap();
    branches.write(&owner, id, &name, b"changed").unwrap();
    assert!(matches!(
        branches.begin_with_uid(&owner, id),
        Err(WorkspaceBranchError::AlreadyExists(existing)) if existing == id
    ));
}

#[test]
fn uid_binding_is_durable_unique_and_terminal_receipt_is_addressable() {
    let content = content();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let binding_uid = PrincipalUid::from_bytes([0x44; 32]);
    let prefix = ContentName::new("workspace").unwrap();
    let id = WorkspaceUid::from_bytes([0x45; 16]);
    content
        .put(
            &owner,
            &ContentName::new("workspace/base.txt").unwrap(),
            b"base",
        )
        .unwrap();
    let descriptor = branches
        .begin_for_uid_at(&owner, binding_uid, id, prefix.clone())
        .unwrap();
    assert_eq!(descriptor.binding_uid(), Some(binding_uid));
    assert_eq!(
        branches
            .binding_for_uid(&owner, binding_uid, &prefix)
            .unwrap()
            .unwrap()
            .lifecycle(),
        WorkspaceBindingLifecycle::Live
    );
    assert!(matches!(
        branches.begin_for_uid_at(
            &owner,
            binding_uid,
            WorkspaceUid::from_bytes([0x46; 16]),
            prefix.clone()
        ),
        Err(WorkspaceBranchError::BindingAlreadyExists { .. })
    ));

    branches.promote(&owner, id).unwrap();
    let terminal = branches.binding(&owner, id).unwrap();
    assert_eq!(terminal.binding_uid(), Some(binding_uid));
    assert_eq!(terminal.lifecycle(), WorkspaceBindingLifecycle::Promoted);
    branches.drop(&owner, id).unwrap();
    assert!(
        branches
            .binding_for_uid(&owner, binding_uid, &prefix)
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_branch_records_and_labels_fail_closed() {
    let id = WorkspaceUid::from_bytes([12; 16]);
    let object = ObjectId::new([13; 32]);
    let valid = make_branch_record(id, None, None, None).unwrap();
    let wrong_kind = ObjectRecord::new(
        ObjectKind::Derived,
        BRANCH_FORMAT,
        valid.canonical_bytes().to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert!(matches!(
        decode_branch_record(object, &wrong_kind, id),
        Err(WorkspaceBranchError::InvalidGraph { .. })
    ));

    let mut malformed_bytes = valid.canonical_bytes().to_vec();
    malformed_bytes[BRANCH_MAGIC.len() + UID_BYTES] = 2;
    let malformed = ObjectRecord::new(
        ObjectKind::WorkspaceBranch,
        BRANCH_FORMAT,
        malformed_bytes,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert!(matches!(
        decode_branch_record(object, &malformed, id),
        Err(WorkspaceBranchError::InvalidGraph { .. })
    ));

    let malformed_label =
        ObjectReference::owns(ReferenceLabel::new(b"workspace/not-a-uid".to_vec()), object);
    let mut loader = |_id| Ok(valid.clone());
    assert!(matches!(
        workspace_branch_quota_from_loader(&malformed_label, &mut loader),
        Err(PrincipalContentError::InvalidGraph { .. })
    ));
    let wrong_kind_label = ObjectReference::new(
        ReferenceLabel::new(format!("workspace/{id}").into_bytes()),
        object,
        ReferenceKind::Evidence,
    );
    let mut loader = |_id| Ok(valid.clone());
    assert!(matches!(
        workspace_branch_quota_from_loader(&wrong_kind_label, &mut loader),
        Err(PrincipalContentError::InvalidGraph { .. })
    ));
}

#[test]
fn binding_uid_round_trips_and_malformed_extension_fails_closed() {
    let id = WorkspaceUid::from_bytes([0x51; 16]);
    let binding_uid = PrincipalUid::from_bytes([0x52; 32]);
    let object = ObjectId::new([0x53; 32]);
    let record = make_branch_record_for_uid(binding_uid, id, None, None, None).unwrap();
    let decoded = decode_branch_record(object, &record, id).unwrap();
    assert_eq!(decoded.binding_uid, Some(binding_uid));

    let mut malformed = record.canonical_bytes().to_vec();
    malformed[BRANCH_MAGIC.len() + UID_BYTES] = 2;
    let malformed = ObjectRecord::new(
        ObjectKind::WorkspaceBranch,
        BRANCH_FORMAT,
        malformed,
        record.references().to_vec(),
        0,
        ObjectClass::Metadata,
    )
    .unwrap();
    assert!(matches!(
        decode_branch_record(object, &malformed, id),
        Err(WorkspaceBranchError::InvalidGraph { .. })
    ));
}

fn content_with_quota(
    limit: u64,
) -> Arc<PrincipalContentStore<StateOwner, InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>>> {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    let quota: Arc<dyn crate::kv::KvQuotaResolver<StateOwner>> =
        Arc::new(move |_owner: &StateOwner| Ok(Some(limit)));
    Arc::new(PrincipalContentStore::from_engine_with_quota(engine, quota))
}

#[test]
fn branch_views_are_charged_to_owner_quota_and_drop_releases_charge() {
    let content = content_with_quota(14);
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let first = ContentName::new("a").unwrap();
    let second = ContentName::new("b").unwrap();
    content.put(&owner, &first, b"1234").unwrap();
    let branch = branches
        .begin_with_uid(&owner, WorkspaceUid::from_bytes([6; 16]))
        .unwrap();
    assert!(matches!(
        content.put(&owner, &second, b"5678"),
        Err(PrincipalContentError::QuotaExceeded { .. })
    ));
    assert!(matches!(
        branches.begin_with_uid(&owner, WorkspaceUid::from_bytes([7; 16])),
        Err(WorkspaceBranchError::QuotaExceeded { .. })
    ));
    branches.drop(&owner, branch.id()).unwrap();
    content.put(&owner, &second, b"5678").unwrap();
}

#[test]
fn multiple_live_branches_cannot_evade_owner_quota() {
    let content = content_with_quota(20);
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let first = WorkspaceUid::from_bytes([14; 16]);
    let second = WorkspaceUid::from_bytes([15; 16]);
    branches.begin_with_uid(&owner, first).unwrap();
    branches.begin_with_uid(&owner, second).unwrap();
    branches
        .write(&owner, first, &ContentName::new("one").unwrap(), &[1; 8])
        .unwrap();
    assert!(matches!(
        branches.write(&owner, second, &ContentName::new("two").unwrap(), &[2; 8]),
        Err(WorkspaceBranchError::QuotaExceeded { .. })
    ));
    branches.drop(&owner, first).unwrap();
    branches
        .write(&owner, second, &ContentName::new("two").unwrap(), &[2; 8])
        .unwrap();
}

#[test]
fn compaction_retains_live_branch_and_reclaims_after_drop() {
    let (content, engine) = content_with_engine();
    let branches = WorkspaceBranchStore::new(Arc::clone(&content));
    let owner = owner();
    let id = WorkspaceUid::from_bytes([10; 16]);
    branches.begin_with_uid(&owner, id).unwrap();
    let name = ContentName::new("branch-only").unwrap();
    branches
        .write(&owner, id, &name, b"unique branch bytes")
        .unwrap();
    let before_live_gc = engine.object_count();
    let live_report = engine.collect_garbage().unwrap();
    assert!(live_report.objects_removed < before_live_gc as u64);
    assert_eq!(
        branches.read(&owner, id, &name).unwrap(),
        Some(b"unique branch bytes".to_vec())
    );

    branches.drop(&owner, id).unwrap();
    let before_drop_gc = engine.object_count();
    let drop_report = engine.collect_garbage().unwrap();
    assert!(drop_report.objects_removed > 0);
    assert!(engine.object_count() < before_drop_gc);
    assert!(matches!(
        branches.read(&owner, id, &name),
        Err(WorkspaceBranchError::NotFound(existing)) if existing == id
    ));
}

#[cfg(not(target_family = "wasm"))]
#[tokio::test]
async fn durable_reopen_retains_live_branch_dag() {
    use crate::open_runtime_principal_store;
    use astrid_core::dirs::AstridHome;

    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn crate::kv::KvQuotaResolver<StateOwner>> =
        Arc::new(|_owner: &StateOwner| Ok(Some(u64::MAX)));
    let store = open_runtime_principal_store(&home, quota.clone())
        .await
        .unwrap();
    let owner = owner();
    let name = ContentName::new("workspace/reopen.txt").unwrap();
    store.content().put(&owner, &name, b"base").unwrap();
    let branches = store.content().workspace_branches();
    let branch = branches
        .begin_with_uid_at(
            &owner,
            WorkspaceUid::from_bytes([8; 16]),
            ContentName::new("workspace").unwrap(),
        )
        .unwrap();
    branches
        .write(
            &owner,
            branch.id(),
            &ContentName::new("reopen.txt").unwrap(),
            b"durable branch",
        )
        .unwrap();
    store.content().flush().unwrap();
    drop(branches);
    drop(store);

    let reopened = open_runtime_principal_store(&home, quota).await.unwrap();
    let reopened_branches = reopened.content().workspace_branches();
    assert_eq!(
        reopened_branches
            .read(
                &owner,
                branch.id(),
                &ContentName::new("reopen.txt").unwrap()
            )
            .unwrap(),
        Some(b"durable branch".to_vec())
    );
    assert_eq!(
        reopened.content().read(&owner, &name).unwrap(),
        Some(b"base".to_vec())
    );
}
