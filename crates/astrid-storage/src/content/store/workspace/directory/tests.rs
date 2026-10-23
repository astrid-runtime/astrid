use super::super::{make_branch_record_for_uid, make_promotion_receipt_for_uid};
use std::sync::Arc;

use super::*;
use crate::engine::InMemoryEngine;
use crate::principal_state::{Blake3ObjectIdentityV1, StateOwner};

type TestEngine = InMemoryEngine<StateOwner, Blake3ObjectIdentityV1>;
type TestBranches = WorkspaceBranchStore<StateOwner, TestEngine>;

fn fixture() -> (TestBranches, Arc<TestEngine>) {
    let engine = Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1));
    (
        WorkspaceBranchStore::new(Arc::new(PrincipalContentStore::from_engine(Arc::clone(
            &engine,
        )))),
        engine,
    )
}

pub(super) fn owner() -> StateOwner {
    StateOwner::Fleet(astrid_core::FleetUid::from_bytes([8; 32]))
}
pub(super) fn uid(index: u32) -> PrincipalUid {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    PrincipalUid::from_bytes(bytes)
}
pub(super) fn id(index: u32) -> WorkspaceUid {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    WorkspaceUid::from_bytes(bytes)
}
pub(super) fn prefix() -> ContentName {
    ContentName::new("workspace/default").unwrap()
}

#[test]
fn more_than_128_uid_branches_reconstruct_exactly_with_cache_disabled() {
    let (branches, engine) = fixture();
    let owner = owner();
    let name = ContentName::new("sentinel").unwrap();
    for index in 0..257 {
        branches
            .begin_for_uid_at(&owner, uid(index), id(index), prefix())
            .unwrap();
        branches
            .write(&owner, id(index), &name, &index.to_le_bytes())
            .unwrap();
    }
    let reconstructed =
        WorkspaceBranchStore::new(Arc::new(PrincipalContentStore::from_engine(engine)));
    assert_eq!(reconstructed.list_branches(&owner).unwrap().len(), 257);
    for index in 0..257 {
        let binding = reconstructed
            .binding_for_uid(&owner, uid(index), &prefix())
            .unwrap()
            .unwrap();
        assert_eq!(binding.branch_id(), id(index));
        assert_eq!(binding.binding_uid(), Some(uid(index)));
        assert_eq!(
            reconstructed
                .read(&owner, id(index), &name)
                .unwrap()
                .unwrap(),
            index.to_le_bytes()
        );
    }
    assert_eq!(
        reconstructed
            .content
            .header(&owner)
            .unwrap()
            .preserved_state
            .iter()
            .filter(|reference| reference.label().as_bytes() == DIRECTORY_LABEL)
            .count(),
        1
    );
}

#[test]
fn terminal_receipts_survive_fresh_live_binding_and_selector_removal() {
    let (branches, _) = fixture();
    let owner = owner();
    let uid = uid(1);
    for index in 0..3 {
        branches
            .begin_for_uid_at(&owner, uid, id(index), prefix())
            .unwrap();
        branches.promote(&owner, id(index)).unwrap();
    }
    branches
        .begin_for_uid_at(&owner, uid, id(3), prefix())
        .unwrap();
    assert_eq!(
        branches
            .binding_for_uid(&owner, uid, &prefix())
            .unwrap()
            .unwrap()
            .branch_id(),
        id(3)
    );
    branches.drop(&owner, id(1)).unwrap(); // Old receipt must not remove the live selector.
    assert_eq!(
        branches
            .binding_for_uid(&owner, uid, &prefix())
            .unwrap()
            .unwrap()
            .branch_id(),
        id(3)
    );
    branches.drop(&owner, id(3)).unwrap(); // A remaining receipt still has a current selector.
    assert_eq!(
        branches
            .binding_for_uid(&owner, uid, &prefix())
            .unwrap()
            .unwrap()
            .lifecycle(),
        WorkspaceBindingLifecycle::Promoted
    );
    assert_eq!(branches.list_bindings_by_uid(&owner, uid).unwrap().len(), 2);
    for index in [0, 2] {
        assert_eq!(
            branches.promote(&owner, id(index)).unwrap().binding_uid(),
            Some(uid)
        );
        branches.drop(&owner, id(index)).unwrap();
    }
    assert!(
        branches
            .binding_for_uid(&owner, uid, &prefix())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        branches.content.header(&owner).unwrap().other_quota_bytes,
        0
    );
}

#[test]
fn legacy_migration_preserves_exact_records_and_rejects_mixed_layouts() {
    let (branches, engine) = fixture();
    let owner = owner();
    let record = make_branch_record_for_uid(uid(1), id(1), Some(&prefix()), None, None).unwrap();
    let object = branches.content.engine.identify_object(&record);
    let receipt =
        make_promotion_receipt_for_uid(Some(uid(2)), id(2), Some(&prefix()), None, None).unwrap();
    let receipt_object = branches.content.engine.identify_object(&receipt);
    let mut header = ContentHeader::empty();
    header.preserved_state.push(ObjectReference::owns(
        super::super::workspace_ref_label(id(1)),
        object,
    ));
    header.preserved_state.push(ObjectReference::owns(
        super::super::workspace_receipt_label(id(2)),
        receipt_object,
    ));
    let transaction = branches
        .content
        .encode_transaction(
            owner,
            header,
            None,
            [(object, record.clone()), (receipt_object, receipt.clone())].into(),
        )
        .unwrap();
    engine.commit(transaction).unwrap();
    assert_eq!(
        branches
            .binding_for_uid(&owner, uid(1), &prefix())
            .unwrap()
            .unwrap()
            .branch_id(),
        id(1)
    );
    branches
        .begin_for_uid_at(&owner, uid(3), id(3), prefix())
        .unwrap();
    let header = branches.content.header(&owner).unwrap();
    assert!(
        header
            .preserved_state
            .iter()
            .all(
                |reference| !is_workspace_branch_label(reference.label().as_bytes())
                    && !is_workspace_receipt_label(reference.label().as_bytes())
            )
    );
    assert_eq!(engine.object(object), Some(record));
    assert_eq!(engine.object(receipt_object), Some(receipt));
    assert_eq!(branches.list_bindings(&owner).unwrap().len(), 3);
    let mut mixed = header.as_ref().clone();
    mixed.preserved_state.push(ObjectReference::owns(
        super::super::workspace_ref_label(id(1)),
        object,
    ));
    engine
        .commit(
            branches
                .content
                .encode_transaction(owner, mixed, None, BTreeMap::new())
                .unwrap(),
        )
        .unwrap();
    let fresh = WorkspaceBranchStore::new(Arc::new(PrincipalContentStore::from_engine(engine)));
    assert!(fresh.binding_for_uid(&owner, uid(1), &prefix()).is_err());
}

#[test]
fn index_bijection_wrong_layout_and_false_quota_fail_closed() {
    let (branches, _) = fixture();
    let record = make_branch_record_for_uid(uid(1), id(1), Some(&prefix()), None, None).unwrap();
    let object = branches.content.engine.identify_object(&record);
    let (branch, _) = decode_row(object, &record).unwrap();
    let charge = row_charge(&record, &branch, false).unwrap();
    let identify = |record: &ObjectRecord| branches.content.engine.identify_object(record);
    let mut entries = BTreeMap::from([(
        key("b", id(1)).unwrap(),
        CatalogValue {
            file: object,
            logical_bytes: charge,
        },
    )]);
    let validate = |entries: &BTreeMap<ContentName, CatalogValue>| {
        let (root, mut records) =
            tree::build_catalog_with_layout::<WorkspaceLayout>(entries, &identify).unwrap();
        records.insert(object, record.clone());
        let root = root.unwrap();
        let reference =
            ObjectReference::owns(ReferenceLabel::new(DIRECTORY_LABEL.to_vec()), root.object);
        validate_from_loader(&reference, &mut |object| {
            records
                .get(&object)
                .cloned()
                .ok_or(PrincipalContentError::InvalidGraph {
                    object,
                    detail: "missing test object",
                })
        })
    };
    assert!(validate(&entries).is_err()); // A primary row without its UID inventory/selector is invalid.
    entries.insert(
        binding_key(&branch).unwrap().unwrap(),
        CatalogValue {
            file: object,
            logical_bytes: 0,
        },
    );
    assert!(validate(&entries).is_err()); // Selector alone cannot replace the UID inventory.
    entries.insert(
        inventory_key(&branch).unwrap().unwrap(),
        CatalogValue {
            file: object,
            logical_bytes: 0,
        },
    );
    assert!(validate(&entries).is_ok());
    entries
        .get_mut(&key("b", id(1)).unwrap())
        .unwrap()
        .logical_bytes += 1;
    assert!(validate(&entries).is_err());
    let (root, records) =
        tree::build_catalog_with_layout::<WorkspaceLayout>(&entries, &identify).unwrap();
    let root = root.unwrap();
    assert!(root_from_record(root.object, &records[&root.object]).is_err());
    let (content_root, content_records) = tree::build_catalog(&entries, &identify).unwrap();
    let content_root = content_root.unwrap();
    assert!(
        tree::root_from_record_with_layout::<WorkspaceLayout>(
            content_root.object,
            &content_records[&content_root.object]
        )
        .is_err()
    );
}
