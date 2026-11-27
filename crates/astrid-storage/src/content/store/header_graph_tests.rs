//! Commit-to-state validation at the owner-scoped object loader boundary.
use super::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    ReferenceKind, ReferenceLabel, RootState, STATE_LABEL, header_graph,
};
use crate::storage_model::RootGeneration;
use std::{cell::RefCell, sync::Arc};

fn record(kind: ObjectKind, links: Vec<ObjectReference>) -> Arc<ObjectRecord> {
    Arc::new(
        ObjectRecord::new(
            kind,
            ObjectFormatVersion::V1,
            Vec::new(),
            links,
            0,
            ObjectClass::Metadata,
        )
        .unwrap(),
    )
}

#[test]
fn state_read_requires_an_owning_edge_and_preserves_the_selected_load_error() {
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([1; 32]),
    };
    let target = ObjectId::new([2; 32]);
    let owner = crate::StateOwner::System;
    for kind in [ReferenceKind::Lineage, ReferenceKind::Owns] {
        let links = [
            b"parent".as_slice(),
            b"stat",
            STATE_LABEL,
            b"state-extra",
            b"z",
            b"zz",
        ]
        .into_iter()
        .map(|label| {
            if label == STATE_LABEL {
                ObjectReference::new(ReferenceLabel::new(label.to_vec()), target, kind)
            } else {
                ObjectReference::owns(ReferenceLabel::new(label.to_vec()), root.commit)
            }
        })
        .collect();
        let commit = record(ObjectKind::Commit, links);
        let calls = RefCell::new(Vec::new());
        let result = header_graph::read(&owner, root, ObjectFormatVersion::V1, |p, id| {
            calls.borrow_mut().push((*p, id));
            if id == root.commit {
                Ok(Arc::clone(&commit))
            } else {
                Err(id)
            }
        });
        if kind == ReferenceKind::Lineage {
            assert!(
                matches!(result,Err(header_graph::Error::Invalid(id,"required principal reference is not owning")) if id == root.commit)
            );
            assert_eq!(calls.take(), [(owner, root.commit)]);
        } else {
            assert!(matches!(result,Err(header_graph::Error::Read(id)) if id == target));
            assert_eq!(calls.take(), [(owner, root.commit), (owner, target)]);
        }
    }
}

#[test]
fn encoded_transaction_retains_owner_expected_root_and_commit_relations() {
    use super::{ContentName, PARENT_LABEL, PrincipalContentStore, owned_target};
    use crate::engine::InMemoryEngine;
    use crate::{Blake3ObjectIdentityV1, StateOwner};
    use std::collections::BTreeMap;
    let store =
        PrincipalContentStore::from_engine(Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1)));
    let owner = StateOwner::System;
    store
        .put(&owner, &ContentName::new("seed").unwrap(), b"initial")
        .unwrap();
    let mut header = store.header(&owner).unwrap().as_ref().clone();
    let prior = header.root.unwrap();
    let preserved = ObjectReference::new(
        ReferenceLabel::new(b"extension".to_vec()),
        prior.commit,
        ReferenceKind::Lineage,
    );
    header.preserved_commit.push(preserved.clone());
    let tx = store
        .encode_transaction(owner, header, None, BTreeMap::new())
        .unwrap();
    assert_eq!(tx.principal(), &owner);
    assert_eq!(tx.expected(), Some(prior));
    let record = |id| &tx.records().iter().find(|(key, _)| *key == id).unwrap().1;
    let commit = record(tx.commit());
    assert_eq!(commit.kind(), ObjectKind::Commit);
    assert_eq!(commit.references().len(), 3);
    assert!(commit.references().contains(&preserved));
    let parent = commit
        .reference(&ReferenceLabel::new(PARENT_LABEL))
        .unwrap();
    assert_eq!(
        (parent.kind(), parent.target()),
        (ReferenceKind::Lineage, prior.commit)
    );
    let state_id = owned_target(tx.commit(), commit, STATE_LABEL).unwrap();
    assert_eq!(record(state_id).kind(), ObjectKind::PrincipalState);
}
