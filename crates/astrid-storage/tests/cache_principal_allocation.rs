//! Real decoded-cache reads must not allocate a membership tree for one owner.
#![cfg(not(target_family = "wasm"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use astrid_storage::engine::{
    DurableEngine, ObjectCacheCapacity, ObjectCacheConfig, ObjectCacheController, PrincipalCodec,
    RecoveryLimits,
};
use astrid_storage::principal_state::Blake3ObjectIdentityV1;
use astrid_storage::storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
};

#[derive(Clone, Copy, Default)]
struct Probe {
    size: usize,
    allocations: usize,
    deallocations: usize,
    last_size: usize,
    allocated_bytes: usize,
    deallocated_bytes: usize,
}

thread_local! {
    // The synchronous production reads and cache callbacks run on this thread.
    // Harness allocations and concurrent tests are outside the measurement.
    static PROBE: Cell<Probe> = const { Cell::new(Probe {
        size: 0, allocations: 0, deallocations: 0, last_size: 0, allocated_bytes: 0, deallocated_bytes: 0,
    }) };
}

fn account(size: usize, allocated: bool) {
    let _ = PROBE.try_with(|probe| {
        let mut state = probe.get();
        if state.size == size || state.size == usize::MAX {
            if allocated {
                state.allocations = state.allocations.saturating_add(1);
                state.allocated_bytes = state.allocated_bytes.saturating_add(size);
            } else {
                state.deallocations = state.deallocations.saturating_add(1);
                state.deallocated_bytes = state.deallocated_bytes.saturating_add(size);
            }
            state.last_size = size;
            probe.set(state);
        }
    });
}

struct Allocator;

// SAFETY: every operation forwards System's unchanged pointer/layout contract.
// Allocation-free, thread-local counters never unwind or affect allocation.
#[allow(
    unsafe_code,
    reason = "Test-only observation forwards System unchanged."
)]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: preserve the caller's allocation contract and exact layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        account(layout.size(), false);
        // SAFETY: the allocation originated from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct ResetProbe;
impl Drop for ResetProbe {
    fn drop(&mut self) {
        PROBE.set(Probe::default());
    }
}

fn measure<R>(size: usize, body: impl FnOnce() -> R) -> (R, Probe) {
    PROBE.set(Probe {
        size,
        ..Probe::default()
    });
    let reset = ResetProbe;
    let result = body();
    let observed = PROBE.get();
    drop(reset);
    (result, observed)
}

// Fixed-size, allocation-free principals distinguish membership-tree nodes
// from object payloads and the cache's other index nodes. Calibrate the node
// allocation using this toolchain's actual BTreeSet, without assuming its ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Principal([u8; 128]);

const FIRST: Principal = Principal([0; 128]);
const SECOND: Principal = Principal([1; 128]);

fn membership_node_size() -> usize {
    let (set, probe) = measure(usize::MAX, || {
        let mut set = BTreeSet::new();
        set.insert(FIRST);
        set
    });
    assert_eq!(probe.allocations, 1);
    assert!(probe.last_size > 0);
    drop(set);
    probe.last_size
}

struct Codec;
impl PrincipalCodec<Principal> for Codec {
    fn encode(&self, principal: &Principal) -> Vec<u8> {
        principal.0.to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<Principal> {
        bytes.try_into().ok().map(Principal)
    }
}

type Engine = DurableEngine<Principal, Blake3ObjectIdentityV1, Codec>;

fn fixture(count: u64) -> (tempfile::TempDir, Engine, Vec<ObjectId>, Arc<AtomicBool>) {
    let directory = tempfile::tempdir().unwrap();
    let retire_second = Arc::new(AtomicBool::new(false));
    let retired = retire_second.clone();
    let engine = Engine::open_with_object_cache(
        directory.path(),
        Blake3ObjectIdentityV1,
        Codec,
        RecoveryLimits::process_addressable(),
        ObjectCacheConfig::new(
            ObjectCacheController::disabled(),
            Arc::new(move |principal: &Principal| {
                if *principal != FIRST && retired.load(Ordering::SeqCst) {
                    ObjectCacheCapacity::Disabled
                } else {
                    ObjectCacheCapacity::Unbounded
                }
            }),
        ),
    )
    .unwrap();
    let ids = (0..count)
        .map(|index| {
            let record = ObjectRecord::new(
                ObjectKind::Chunk,
                ObjectFormatVersion::V1,
                index.to_le_bytes().to_vec(),
                Vec::new(),
                8,
                ObjectClass::Data,
            )
            .unwrap();
            engine.persist_standalone_object(&record).unwrap().0
        })
        .collect::<Vec<_>>();
    // Warm immutable recovery/locator state independently of decoded retention.
    for id in &ids {
        assert!(engine.shared_object_for(&FIRST, *id).unwrap().is_some());
    }
    assert_eq!(engine.object_cache_stats().resident_objects, 0);
    engine.set_object_cache_capacity(ObjectCacheCapacity::Unbounded);
    (directory, engine, ids, retire_second)
}

#[test]
fn sole_principal_records_do_not_allocate_membership_trees() {
    let node_size = membership_node_size();
    let (_directory, engine, ids, _) = fixture(64);
    let ((), observed) = measure(node_size, || {
        for id in &ids {
            assert!(engine.shared_object_for(&FIRST, *id).unwrap().is_some());
        }
    });
    assert_eq!(engine.object_cache_stats().resident_objects, 64);
    assert_eq!(engine.object_cache_stats().resident_associations, 64);
    assert!(engine.object_cache_principal_charge(&FIRST) > 0);
    assert_eq!(
        observed.allocations, 0,
        "single-owner reads allocated membership tree nodes"
    );
}

#[test]
fn sharing_reuses_one_principal_reference_and_retirement_releases_it() {
    let (reference, probe) = measure(usize::MAX, || Arc::new(SECOND));
    assert_eq!(probe.allocations, 1);
    let node_size = probe.last_size;
    drop(reference);
    let (_directory, engine, ids, retire_second) = fixture(1);
    let original = engine.shared_object_for(&FIRST, ids[0]).unwrap().unwrap();
    let first_charge = engine.object_cache_principal_charge(&FIRST);
    let before = engine.object_cache_stats();
    let (shared, promotion) = measure(node_size, || {
        engine.shared_object_for(&SECOND, ids[0]).unwrap().unwrap()
    });
    assert!(Arc::ptr_eq(&original, &shared));
    assert_eq!(
        promotion.allocations, 1,
        "sharing must allocate only the new canonical principal reference"
    );
    assert_eq!(engine.object_cache_principal_charge(&SECOND), first_charge);
    let shared_stats = engine.object_cache_stats();
    assert_eq!(
        shared_stats.resident_record_bytes,
        before.resident_record_bytes
    );
    assert_eq!(shared_stats.resident_objects, 1);
    assert_eq!(shared_stats.resident_associations, 2);
    retire_second.store(true, Ordering::SeqCst);
    let ((), demotion) = measure(node_size, || engine.reclaim_object_cache());
    assert_eq!(
        demotion.deallocations, 1,
        "retirement must release the retired canonical principal reference"
    );
    assert_eq!(engine.object_cache_principal_charge(&SECOND), 0);
    assert_eq!(engine.object_cache_principal_charge(&FIRST), first_charge);
    let after = engine.object_cache_stats();
    assert_eq!(
        after.resident_association_bytes,
        before.resident_association_bytes
    );
    assert_eq!(after.resident_associations, 1);
    assert!(Arc::ptr_eq(
        &original,
        &engine.shared_object_for(&FIRST, ids[0]).unwrap().unwrap()
    ));
}

#[test]
fn retiring_shared_owners_releases_the_compact_tree_at_one_owner() {
    let (set, probe) = measure(usize::MAX, || BTreeSet::from([0_usize]));
    assert_eq!(probe.allocations, 1);
    let node_size = probe.last_size;
    drop(set);
    let (_directory, engine, ids, retire_second) = fixture(1);
    let original = engine.shared_object_for(&FIRST, ids[0]).unwrap().unwrap();
    for owner in [Principal([2; 128]), Principal([3; 128])] {
        let shared = engine.shared_object_for(&owner, ids[0]).unwrap().unwrap();
        assert!(Arc::ptr_eq(&original, &shared));
    }
    let (shared, promotion) = measure(node_size, || {
        engine.shared_object_for(&SECOND, ids[0]).unwrap().unwrap()
    });
    assert!(Arc::ptr_eq(&original, &shared));
    assert_eq!(promotion.allocations, 1);
    assert_eq!(engine.object_cache_stats().resident_associations, 4);
    let first_charge = engine.object_cache_principal_charge(&FIRST);
    retire_second.store(true, Ordering::SeqCst);
    let ((), demotion) = measure(node_size, || engine.reclaim_object_cache());
    assert_eq!(
        demotion.deallocations, 1,
        "spill storage must be released when only one owner remains"
    );
    assert_eq!(engine.object_cache_principal_charge(&SECOND), 0);
    assert_eq!(engine.object_cache_principal_charge(&FIRST), first_charge);
    assert_eq!(engine.object_cache_stats().resident_associations, 1);
}

// This allocation-observed profile is separate from the uninstrumented CPU
// benchmark. It measures all retained allocation requests after warming the
// durable locator path; logical resource charges are not heap measurements.
#[test]
fn native_principal_retained_allocation_profile() {
    use astrid_core::PrincipalUid;
    use astrid_storage::principal_state::{StateOwner, StateOwnerCodecV2};
    for (objects, owners) in [(128_u64, 1_u64), (128, 2), (128, 4), (1, 10_000)] {
        let directory = tempfile::tempdir().unwrap();
        let engine = DurableEngine::open_with_object_cache(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            ObjectCacheConfig::new(
                ObjectCacheController::disabled(),
                Arc::new(|_: &StateOwner| ObjectCacheCapacity::Unbounded),
            ),
        )
        .unwrap();
        let owner = |index: u64| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&index.to_le_bytes());
            StateOwner::Principal(PrincipalUid::from_bytes(bytes))
        };
        let ids = (0..objects)
            .map(|index| {
                let record = ObjectRecord::new(
                    ObjectKind::Chunk,
                    ObjectFormatVersion::V1,
                    index.to_le_bytes().to_vec(),
                    Vec::new(),
                    8,
                    ObjectClass::Data,
                )
                .unwrap();
                let id = engine.persist_standalone_object(&record).unwrap().0;
                assert!(engine.shared_object_for(&owner(0), id).unwrap().is_some());
                id
            })
            .collect::<Vec<_>>();
        assert_eq!(engine.object_cache_stats().resident_objects, 0);
        engine.set_object_cache_capacity(ObjectCacheCapacity::Unbounded);
        let ((), retained) = measure(usize::MAX, || {
            for index in 0..owners {
                for id in &ids {
                    assert!(
                        engine
                            .shared_object_for(&owner(index), *id)
                            .unwrap()
                            .is_some()
                    );
                }
            }
        });
        assert_eq!(
            engine.object_cache_stats().resident_associations,
            objects * owners
        );
        let net = retained
            .allocated_bytes
            .checked_sub(retained.deallocated_bytes)
            .unwrap();
        assert!(net > 0);
        println!(
            "{}",
            serde_json::json!({
                "profile": "native_principal_retained_allocations", "objects": objects, "owners": owners,
                "allocation_requests_bytes": retained.allocated_bytes,
                "deallocation_requests_bytes": retained.deallocated_bytes,
                "retained_requested_bytes": net,
                "logical_resident_bytes": engine.object_cache_stats().resident_bytes,
            })
        );
    }
}
