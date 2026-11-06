use super::*;
use crate::content_dag::verified_content_from_certified_membership;
use crate::engine::InMemoryEngine;
use crate::kv::tree::header::TreeHeader;
use crate::kv::tree_tests::TestIdentity;

#[test]
fn membership_cannot_authorize_an_unrelated_opened_file() {
    let engine = InMemoryEngine::new(TestIdentity);
    let owner = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &owner);
    let tree = context
        .build_sorted(vec![(b"ns\0key".to_vec(), vec![0x42; 512 * 1024])])
        .unwrap();
    let certificate = context.validate_tree(tree).unwrap().certificate();
    let first = context.get_slot(tree, b"ns\0key").unwrap().unwrap();
    let second_tree = context
        .build_sorted(vec![(b"ns\0key".to_vec(), vec![0x43; 512 * 1024])])
        .unwrap();
    let second = context.get_slot(second_tree, b"ns\0key").unwrap().unwrap();
    let opened = |value| match value {
        ValueSlot::Spilled { object, length } => context
            .open_chunked_value(object, length, &context.record(object).unwrap())
            .unwrap(),
        ValueSlot::Inline(_) => panic!("fixture must use chunked content"),
    };
    let first = opened(first);
    let second = opened(second);
    let membership = certificate
        .membership_for_retrieved_file(first.descriptor().file())
        .unwrap();
    assert!(verified_content_from_certified_membership(first, membership).is_some());
    assert!(verified_content_from_certified_membership(second, membership).is_none());
    assert!(
        ValidatedCheckpoint::empty()
            .membership_for_retrieved_file(first.descriptor().file())
            .is_none()
    );
}

#[test]
fn empty_or_mismatched_certificate_does_not_turn_present_data_into_absence() {
    let engine = InMemoryEngine::new(TestIdentity);
    let owner = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &owner);
    let first = context
        .build_sorted(vec![(b"ns\0key".to_vec(), b"first".to_vec())])
        .unwrap();
    let first_certificate = context.validate_tree(first).unwrap().certificate();
    let second = context
        .build_sorted(vec![(b"ns\0key".to_vec(), b"second".to_vec())])
        .unwrap();
    let mut header = TreeHeader::empty(owner.clone());
    header.tree = second;
    for certificate in [ValidatedCheckpoint::empty(), first_certificate] {
        assert_eq!(
            context
                .read_certified_tree_value(&header, b"ns\0key", certificate)
                .unwrap(),
            Some(b"second".to_vec())
        );
    }
    header.owner = "bob".to_owned();
    assert!(context.build_validated_checkpoint(&header).is_err());
}
