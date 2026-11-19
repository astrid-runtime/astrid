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
}

thread_local! {
    // The synchronous production reads and cache callbacks run on this thread.
    // Harness allocations and concurrent tests are outside the measurement.
    static PROBE: Cell<Probe> = const { Cell::new(Probe {
        size: 0, allocations: 0, deallocations: 0, last_size: 0,
    }) };
}

fn account(size: usize, allocated: bool) {
    let _ = PROBE.try_with(|probe| {
        let mut state = probe.get();
        if state.size == size || state.size == usize::MAX {
            if allocated {
                state.allocations = state.allocations.saturating_add(1);
            } else {
                state.deallocations = state.deallocations.saturating_add(1);
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
                if *principal == SECOND && retired.load(Ordering::SeqCst) {
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
fn sharing_allocates_one_tree_and_principal_reclaim_releases_it() {
    let node_size = membership_node_size();
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
        "sharing must allocate exactly one membership tree"
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
        "retirement must release the shared membership tree"
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
