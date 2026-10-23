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

#[test]
fn locator_allocates_for_actual_entries_instead_of_eagerly_reserving_the_budget() {
    let budget = LocationIndexMemoryBudget::default();
    let mut index = PagedLocations::new(budget.entries());
    let id = ObjectId::new([1; 32]);
    let location = ArenaLocation {
        offset: 0,
        payload_len: 1,
        checksum: [2; 32],
    };
    index.insert(id, location).unwrap();
    assert!(
        index.resident_capacity_bytes() <= 2 * std::mem::size_of::<(ObjectId, ArenaLocation)>()
    );
    let before = index.resident_capacity_bytes();
    index
        .set_limit(std::num::NonZeroUsize::new(budget.entries().get() * 2).unwrap())
        .unwrap();
    assert_eq!(index.resident_capacity_bytes(), before);
    assert_eq!(index.location(id).unwrap(), Some(location));
    for byte in 2..64 {
        index.insert(ObjectId::new([byte; 32]), location).unwrap();
        assert!(index.resident_capacity_bytes() as u64 <= budget.bytes().get());
    }
}
