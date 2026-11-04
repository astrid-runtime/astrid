//! Canonical validation must not retain a second complete payload set.
#![cfg(not(target_family = "wasm"))]

use astrid_storage::storage_model::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    // Account only allocations inside the invoking validation call. Input
    // ownership outlives that call; the harness and other threads are excluded.
    static ACCOUNTING: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static INVALID_ACCOUNTING: Cell<bool> = const { Cell::new(false) };
}

struct Allocator;

fn account(size: usize, allocated: bool) {
    let _ = ACCOUNTING.try_with(|state| {
        if let Some((live, peak)) = state.get() {
            let next = if allocated {
                live.checked_add(size)
            } else {
                live.checked_sub(size)
            };
            let Some(live) = next else {
                // Allocators cannot unwind. Mark an invalid measurement and
                // reject it outside the allocator after validation returns.
                state.set(None);
                INVALID_ACCOUNTING.set(true);
                return;
            };
            state.set(Some((live, peak.max(live))));
        }
    });
}

// SAFETY: every allocation and deallocation forwards the unchanged layout to
// System. Accounting uses allocation-free thread-local cells only.
#[allow(
    unsafe_code,
    reason = "Test-only peak allocation accounting forwards System unchanged."
)]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forward the allocator contract and original layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        account(layout.size(), false);
        // SAFETY: all allocations originate from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Identity;
impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key(context);
        hash.update(material);
        *hash.finalize().as_bytes()
    }
}

struct ResetAccounting;
impl Drop for ResetAccounting {
    fn drop(&mut self) {
        ACCOUNTING.set(None);
    }
}

fn validate_without_retaining_input_payloads(dense: bool) {
    let count = 128_usize;
    let value_bytes = 64 * 1024_usize;
    let entries = (0..count)
        .map(|index| {
            (
                PhysicalMapKey::new(*blake3::hash(&index.to_le_bytes()).as_bytes()),
                vec![0x5a; value_bytes],
            )
        })
        .collect();
    let map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, entries)
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries)
    }
    .unwrap();
    INVALID_ACCOUNTING.set(false);
    ACCOUNTING.set(Some((0, 0)));
    let reset = ResetAccounting;
    let result = CanonicalPhysicalMap::validate_root(
        &Identity,
        PhysicalMapDomain::Placement,
        map.root(),
        map.nodes(),
    );
    let accounting = ACCOUNTING.get();
    let invalid = INVALID_ACCOUNTING.get();
    drop(reset);
    assert!(
        !invalid,
        "temporary allocation accounting overflowed or underflowed"
    );
    let (_, peak) = accounting.unwrap();
    assert_eq!(result.unwrap(), u64::try_from(count).unwrap());
    // Room for transient node encoding, traversal sets and allocator rounding;
    // a second full input payload set alone exceeds this bound eightfold.
    assert!(
        peak < count * value_bytes / 8,
        "validation retained {peak} temporary bytes"
    );
}

#[test]
fn legacy_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(false);
}

#[test]
fn dense_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(true);
}

fn peak_during<R>(body: impl FnOnce() -> R) -> (R, usize) {
    INVALID_ACCOUNTING.set(false);
    ACCOUNTING.set(Some((0, 0)));
    let reset = ResetAccounting;
    let result = body();
    let accounting = ACCOUNTING.get();
    let invalid = INVALID_ACCOUNTING.get();
    drop(reset);
    assert!(
        !invalid,
        "temporary allocation accounting overflowed or underflowed"
    );
    let (_, peak) = accounting.expect("accounting active");
    (result, peak)
}

fn build_lookup_fixture(dense: bool, count: usize) -> (CanonicalPhysicalMap, Vec<PhysicalMapKey>) {
    let keys = (0..count)
        .map(|index| PhysicalMapKey::new(*blake3::hash(&index.to_le_bytes()).as_bytes()))
        .collect::<Vec<_>>();
    let entries = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            (
                *key,
                u64::try_from(index)
                    .expect("fixture index fits u64")
                    .to_le_bytes()
                    .to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, entries)
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries)
    }
    .expect("fixture map");
    (map, keys)
}

fn assert_get_hit_miss_zero_alloc(dense: bool) {
    let (map, keys) = build_lookup_fixture(dense, 64);
    let miss = PhysicalMapKey::new(*blake3::hash(b"missing-lookup-key").as_bytes());
    assert!(!keys.contains(&miss));

    let (hit, hit_peak) = peak_during(|| map.get(keys[0]));
    assert_eq!(hit, Some(0_u64.to_le_bytes().as_slice()));
    assert_eq!(
        hit_peak,
        0,
        "hit lookup allocated {hit_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );

    let middle_index = keys.len() / 2;
    let (middle, middle_peak) = peak_during(|| map.get(keys[middle_index]));
    assert_eq!(
        middle,
        Some(
            u64::try_from(middle_index)
                .expect("fixture index fits u64")
                .to_le_bytes()
                .as_slice(),
        )
    );
    assert_eq!(
        middle_peak,
        0,
        "interior hit lookup allocated {middle_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );

    let (missed, miss_peak) = peak_during(|| map.get(miss));
    assert_eq!(missed, None);
    assert_eq!(
        miss_peak,
        0,
        "miss lookup allocated {miss_peak} bytes on {}",
        if dense { "dense" } else { "legacy" }
    );
}

#[test]
fn legacy_physical_map_get_hit_and_miss_are_zero_alloc() {
    assert_get_hit_miss_zero_alloc(false);
}

#[test]
fn dense_physical_map_get_hit_and_miss_are_zero_alloc() {
    assert_get_hit_miss_zero_alloc(true);
}
