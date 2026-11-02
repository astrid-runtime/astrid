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
}

struct Allocator;

fn account(size: usize, allocated: bool) {
    let _ = ACCOUNTING.try_with(|state| {
        if let Some((live, peak)) = state.get() {
            let live = if allocated { live + size } else { live - size };
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

#[test]
fn canonical_validation_borrows_the_complete_input_payload_set() {
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
    let map =
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries).unwrap();
    ACCOUNTING.set(Some((0, 0)));
    let reset = ResetAccounting;
    let result = CanonicalPhysicalMap::validate_root(
        &Identity,
        PhysicalMapDomain::Placement,
        map.root(),
        map.nodes(),
    );
    let (_, peak) = ACCOUNTING.get().unwrap();
    drop(reset);
    assert_eq!(result.unwrap(), u64::try_from(count).unwrap());
    // Room for transient node encoding, traversal sets and allocator rounding;
    // a second full input payload set alone exceeds this bound eightfold.
    assert!(
        peak < count * value_bytes / 8,
        "validation retained {peak} temporary bytes"
    );
}
