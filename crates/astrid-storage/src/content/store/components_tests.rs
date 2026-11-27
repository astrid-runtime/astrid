//! Owner-state component decoding and quota limits.
use super::{
    ObjectId, ObjectReference, ReferenceLabel, RootState,
    components::{self, Charge},
};
use crate::{StateOwner, storage_model::RootGeneration};
use std::cell::RefCell;

#[test]
fn overflow_stops_at_the_workspace_that_exceeds_the_owner_budget() {
    let owner = StateOwner::System;
    let root = RootState {
        generation: RootGeneration::INITIAL,
        commit: ObjectId::new([1; 32]),
    };
    let edge = |label: &[u8], id: u8| {
        ObjectReference::owns(ReferenceLabel::new(label.to_vec()), ObjectId::new([id; 32]))
    };
    let refs = [
        edge(b"extension", 2),
        edge(b"kv", 3),
        edge(b"workspace/a", 4),
        edge(b"workspace/b", 5),
    ];
    let calls = RefCell::new(Vec::new());
    let result = components::fold(
        &owner,
        root,
        &refs,
        |_, _, _| -> Result<(), ()> { panic!("unexpected content component") },
        |p, kind, r, sample| {
            assert_eq!((*p, sample), (owner, root));
            calls.borrow_mut().push(r.target());
            Ok(match kind {
                Charge::Kv => u64::MAX,
                Charge::Workspace => 1,
            })
        },
    );
    assert!(matches!(result, Err(components::Error::Overflow)));
    assert_eq!(calls.take(), [refs[1].target(), refs[2].target()]);
}
