//! Collection-allocation failure must remain an error in the owned decoder.
#![cfg(not(target_family = "wasm"))]

use astrid_storage::storage_model::{
    PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    // Faults affect only the invoking test thread, never concurrent tests.
    static FAILED_SIZE: Cell<usize> = const { Cell::new(0) };
}

struct AllocationFault;

// SAFETY: successful allocations and every deallocation use System with the
// caller's unchanged layout. Returning null injects a permitted allocation error.
#[allow(
    unsafe_code,
    reason = "Test-only allocation fault injection forwards the System allocator contract unchanged."
)]
unsafe impl GlobalAlloc for AllocationFault {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAILED_SIZE
            .try_with(|size| size.get() == layout.size())
            .unwrap_or(false)
        {
            return std::ptr::null_mut();
        }
        // SAFETY: forward the allocator contract and exact layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: every non-null allocation originated from System above.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: AllocationFault = AllocationFault;

struct ResetFault;

impl Drop for ResetFault {
    fn drop(&mut self) {
        FAILED_SIZE.set(0);
    }
}

#[test]
fn owned_map_decode_reports_small_collection_allocation_failures() {
    let domain = PhysicalMapDomain::Placement;
    let cases = [
        (
            PhysicalMapNode::Radix {
                domain,
                prefix_nibbles: 0,
                prefix: Vec::new(),
                child_bitmap: u16::MAX,
                children: (0..16)
                    .map(|index| PhysicalMapNodeId::new([index; 32]))
                    .collect(),
                subtree_entries: 16,
            },
            16 * std::mem::size_of::<PhysicalMapNodeId>(),
        ),
        (
            PhysicalMapNode::Page {
                domain,
                entries: vec![(PhysicalMapKey::new([1; 32]), Vec::new())],
            },
            std::mem::size_of::<(PhysicalMapKey, Vec<u8>)>(),
        ),
    ];
    for (node, size) in cases {
        let bytes = node.encode().unwrap();
        assert_eq!(PhysicalMapNode::decode(&bytes).unwrap(), node);
        FAILED_SIZE.set(size);
        let fault = ResetFault;
        let result = PhysicalMapNode::decode(&bytes);
        drop(fault);
        assert!(matches!(result, Err(PhysicalModelError::LengthOverflow)));
    }
}
