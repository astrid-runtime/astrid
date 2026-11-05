//! Test-only requested-allocation accounting; System behavior is unchanged.

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

struct ResetAccounting;
impl Drop for ResetAccounting {
    fn drop(&mut self) {
        ACCOUNTING.set(None);
    }
}

pub(crate) fn peak_during<R>(body: impl FnOnce() -> R) -> (R, usize) {
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
