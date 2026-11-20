//! Requested heap bytes are observed separately from uninstrumented timings.
#![cfg(not(target_family = "wasm"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::sync::Arc;

use astrid_events::rate_limiter::IpcRateLimiter;

#[derive(Clone, Copy, Default)]
struct Probe {
    enabled: bool,
    allocated: usize,
    deallocated: usize,
}

thread_local! {
    static PROBE: Cell<Probe> = const { Cell::new(Probe {
        enabled: false, allocated: 0, deallocated: 0,
    }) };
}

fn account(bytes: usize, allocated: bool) {
    let _ = PROBE.try_with(|cell| {
        let mut probe = cell.get();
        if probe.enabled {
            if allocated {
                probe.allocated = probe.allocated.saturating_add(bytes);
            } else {
                probe.deallocated = probe.deallocated.saturating_add(bytes);
            }
            cell.set(probe);
        }
    });
}

struct Allocator;

// SAFETY: every pointer and layout is forwarded unchanged to System. The
// allocation-free thread-local observer cannot change allocator behavior.
#[allow(unsafe_code, reason = "Test-only observation delegates to System.")]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: preserve the caller's exact allocation contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        account(layout.size(), false);
        // SAFETY: this pointer originated from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PROBE.set(Probe::default());
    }
}

fn observe<T>(body: impl FnOnce() -> T) -> (T, Probe) {
    PROBE.set(Probe {
        enabled: true,
        ..Probe::default()
    });
    let reset = Reset;
    let result = body();
    let probe = PROBE.get();
    drop(reset);
    (result, probe)
}

#[test]
fn unused_limiter_requires_no_heap_allocation() {
    drop(black_box(IpcRateLimiter::new()));
    let (limiter, probe) = observe(|| black_box(IpcRateLimiter::new()));
    assert_eq!(
        probe.allocated, 0,
        "unused IPC limiter allocated heap storage"
    );
    drop(limiter);
}

#[test]
fn native_idle_allocation_profile() {
    drop(black_box(IpcRateLimiter::new()));
    for count in [1, 16, 10_000] {
        // Vec storage is outside the observation; runtime-owned Arc wrappers
        // remain included. This is requested heap storage, not logical charge
        // or allocator/process RSS. Every fixture is dropped before the next.
        let mut held = Vec::with_capacity(count);
        let ((), creation) = observe(|| {
            for _ in 0..count {
                held.push(black_box(Arc::new(IpcRateLimiter::new())));
            }
        });
        let ((), destruction) = observe(|| held.clear());
        assert_eq!(creation.allocated, destruction.deallocated);
        assert_eq!(creation.deallocated, 0);
        assert_eq!(destruction.allocated, 0);
        println!(
            "{}",
            serde_json::json!({"limiters":count,"retained_requested_bytes":creation.allocated})
        );
    }
}
