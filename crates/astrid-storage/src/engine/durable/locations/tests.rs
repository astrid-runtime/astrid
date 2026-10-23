use super::*;
use crate::engine::durable::tests::TestIdentity;
use crate::engine::durable::{
    ClosureObjects, File, RecoveryLimits, materialize_closure, preload_indexed_closures,
};

pub(in crate::engine::durable) struct FailedLookup;

impl LocationLookup for FailedLookup {
    fn location(&self, _: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        Err(failure())
    }
    fn location_count(&self) -> usize {
        1
    }
    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        Box::new(std::iter::once(Err(failure())))
    }
}

fn failure() -> DurableError {
    DurableError::Corrupt {
        file: "injected locator",
        offset: 0,
        detail: "cold location authentication failed",
    }
}

#[test]
fn cold_lookup_failure_is_not_missing_object_in_owning_closure_or_recovery() {
    let mut arena = File::native(tempfile::tempfile().unwrap());
    let id = ObjectId::new([7; 32]);
    let records = BTreeMap::new();
    let mut source = ClosureObjects::<_, ()> {
        arena: &mut arena,
        index: &FailedLookup,
        incoming: &records,
        pending: None,
        identity: &TestIdentity,
        limits: RecoveryLimits::process_addressable(),
    };
    let error = materialize_closure(&mut source, id).unwrap_err();
    assert!(matches!(
        error,
        DurableError::Corrupt {
            file: "injected locator",
            ..
        }
    ));
    let error = preload_indexed_closures(
        &arena,
        &FailedLookup,
        [id],
        &TestIdentity,
        RecoveryLimits::process_addressable(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DurableError::Corrupt {
            file: "injected locator",
            ..
        }
    ));
}
