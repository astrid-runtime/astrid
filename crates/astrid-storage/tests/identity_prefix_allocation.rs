//! Prefix selection must not retain every unrelated raw link value.
//!
//! This integration binary owns its allocator. Global accounting includes the
//! native adapter's blocking worker; thread-local accounting would miss it.
#![cfg(not(target_family = "wasm"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use astrid_storage::engine::InMemoryEngine;
use astrid_storage::identity::{IdentityStore, KvIdentityStore};
use astrid_storage::principal_state::Blake3ObjectIdentityV1;
use astrid_storage::{
    KvStore, MemoryKvStore, ScopedKvStore, StateOwner, StorageError, TreeKvStore,
};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static INVALID: AtomicBool = AtomicBool::new(false);

struct Allocator;

// SAFETY: allocation/deallocation forward the caller's exact layout to System.
// Accounting is allocation-free and never unwinds, including on counter errors.
#[allow(
    unsafe_code,
    reason = "Test-only cross-thread allocation accounting forwards System unchanged."
)]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: preserve the caller's allocator contract and exact layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let previous = LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            if let Some(current) = previous.checked_add(layout.size()) {
                PEAK.fetch_max(current, Ordering::Relaxed);
            } else {
                INVALID.store(true, Ordering::Relaxed);
            }
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let previous = LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        if previous < layout.size() {
            INVALID.store(true, Ordering::Relaxed);
        }
        // SAFETY: every allocation originates from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

const NAMESPACE: &str = "system:identity";
const LINK_COUNT: usize = 128;
const METHOD_BYTES: usize = 8 * 1024;
// One retained raw prefix alone is four times the allowed scratch. The fixture
// stays below native automatic checkpoint admission, keeping setup quiescent.
const SCRATCH_BUDGET: usize = LINK_COUNT * METHOD_BYTES / 4;

fn native_store() -> Arc<dyn KvStore> {
    let resolver = |namespace: &str| {
        if namespace == NAMESPACE {
            Ok(StateOwner::System)
        } else {
            Err(StorageError::InvalidKey(
                "unowned test namespace".to_owned(),
            ))
        }
    };
    Arc::new(
        TreeKvStore::<StateOwner, Blake3ObjectIdentityV1, _, _>::from_engine(
            Arc::new(InMemoryEngine::new(Blake3ObjectIdentityV1)),
            resolver,
        ),
    )
}

async fn measure_selection(backend: Arc<dyn KvStore>) -> usize {
    let store = KvIdentityStore::new(ScopedKvStore::new(backend.clone(), NAMESPACE).unwrap());
    let target = store.create_user(Some("target")).await.unwrap();
    let other = store.create_user(Some("other")).await.unwrap();
    let method = "x".repeat(METHOD_BYTES);
    for index in 0..LINK_COUNT {
        store
            .link(
                "service",
                &format!("row-{index:04}"),
                if index == 0 { target.id } else { other.id },
                &method,
            )
            .await
            .unwrap();
    }

    // Warm the same projection and blocking pool outside the measured window.
    // Original fixture ownership remains live, so only query scratch is added.
    drop(
        backend
            .get(NAMESPACE, "link/service/row-0000")
            .await
            .unwrap(),
    );
    assert!(!INVALID.load(Ordering::Relaxed));
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let links = store.list_links(target.id).await.unwrap();
    let peak = PEAK.load(Ordering::Relaxed).strict_sub(baseline);
    assert!(!INVALID.load(Ordering::Relaxed));
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].astrid_user_id, target.id);
    assert_eq!(links[0].method, method);
    peak
}

#[tokio::test]
async fn identity_selection_releases_unrelated_prefix_payloads() {
    let mut failures = Vec::new();
    for (name, backend) in [
        ("memory", Arc::new(MemoryKvStore::new()) as Arc<dyn KvStore>),
        ("native", native_store()),
    ] {
        let peak = measure_selection(backend).await;
        eprintln!("{name}: peak_query_bytes={peak}, budget={SCRATCH_BUDGET}");
        if peak >= SCRATCH_BUDGET {
            failures.push((name, peak));
        }
    }
    assert!(
        failures.is_empty(),
        "query retained unrelated raw values: {failures:?}"
    );
}
