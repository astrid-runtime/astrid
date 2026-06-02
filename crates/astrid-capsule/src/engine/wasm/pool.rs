//! Per-capsule pool of WASM instances for concurrent interceptor invocation.
//!
//! Before the pool, each non-run-loop capsule had a single `Store<HostState>`
//! behind one mutex, so `invoke_interceptor` serialised every principal's
//! invocation through that one instance — the throughput floor behind the
//! `astrid#813` orchestration cliff (one LLM turn every ~3s, invariant to
//! concurrency, measured directly as a 2000+ deep invocation backlog on one
//! Store; see `astrid#816`).
//!
//! A [`CapsuleInstancePool`] holds N independent `(Store, Instance)` pairs
//! built from the same compiled component. Invocations lease a free instance
//! and run genuinely concurrently — N principals' interceptors execute in
//! parallel instead of single-file.
//!
//! ## Free checkout
//!
//! Any available instance serves any invocation. This is sound only because
//! interceptor capsules use wasmtime resources (subscriptions, HTTP streams)
//! *within* a single invocation (subscribe → publish → recv → drop in one
//! call), so no handle created on one Store is reused on another. The
//! per-capsule pool-safety audit confirmed this for every pooled capsule;
//! the one capsule that holds a live resource across invocations
//! (`astrid-capsule-shell`'s background-process handles) is carved out to
//! `size == 1` via its `host_process` capability and so never leases a
//! second Store.
//!
//! ## Run-loop capsules are not pooled
//!
//! Capsules that export `run()` keep their single dedicated Store (owned by
//! the run-loop task) and never go through this pool — they receive events
//! via auto-subscribed IPC inside `run()`, not via `invoke_interceptor`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use wasmtime::Store;
use wasmtime::component::Instance;

use super::host_state::HostState;

/// One leasable `(Store, Instance)` pair. The `Instance` is a `Copy` handle
/// into `store`'s resource table, so the two are bound together for the
/// instance's lifetime.
pub(super) struct PooledInstance {
    pub(super) store: Store<HostState>,
    pub(super) instance: Instance,
}

/// A pool of [`PooledInstance`]s for one non-run-loop capsule.
///
/// `permits` (a [`Semaphore`] sized to the instance count) gates checkout:
/// holding a permit guarantees an instance is sitting in `available` to pop,
/// so the pop is infallible. The `available` mutex is held only for the O(1)
/// pop/push — never across a guest call.
pub(super) struct CapsuleInstancePool {
    available: Arc<Mutex<VecDeque<PooledInstance>>>,
    permits: Arc<Semaphore>,
}

impl CapsuleInstancePool {
    /// Build a pool from pre-instantiated instances. `instances.len()` is the
    /// pool size (1 for carved-out capsules, N otherwise).
    pub(super) fn new(instances: Vec<PooledInstance>) -> Self {
        let size = instances.len();
        Self {
            available: Arc::new(Mutex::new(VecDeque::from(instances))),
            permits: Arc::new(Semaphore::new(size)),
        }
    }

    /// Lease a free instance, awaiting a permit if all instances are in use.
    ///
    /// Returns `None` only if the semaphore has been closed (the capsule is
    /// unloading) — the caller treats that as "not invocable".
    pub(super) async fn checkout(&self) -> Option<PoolCheckout> {
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok()?;
        let pooled = self
            .available
            .lock()
            .expect("instance pool mutex poisoned")
            .pop_front()
            .expect("semaphore permit guarantees an available instance");
        Some(PoolCheckout {
            pooled: Some(pooled),
            available: Arc::clone(&self.available),
            _permit: permit,
        })
    }
}

/// RAII lease of one pooled instance.
///
/// On drop — through every exit path: normal return, `?`, panic-unwind, or
/// future-drop on caller cancellation — it runs the Phase-3 CLEAR (resets the
/// per-invocation `HostState` fields) and returns the instance to the pool.
/// Folding the clear into the return guarantees the next lease of this
/// instance observes a clean `HostState`, and that no instance (or permit) is
/// leaked on an error path.
pub(super) struct PoolCheckout {
    pooled: Option<PooledInstance>,
    available: Arc<Mutex<VecDeque<PooledInstance>>>,
    _permit: OwnedSemaphorePermit,
}

impl PoolCheckout {
    /// The leased instance handle (`Copy`), for typed-func lookup. Taking it
    /// by copy leaves `store_mut` free to borrow the store mutably.
    pub(super) fn instance(&self) -> Instance {
        self.pooled.as_ref().expect("active checkout").instance
    }

    /// Mutable access to the leased store for the SET phase and the guest
    /// call.
    pub(super) fn store_mut(&mut self) -> &mut Store<HostState> {
        &mut self.pooled.as_mut().expect("active checkout").store
    }
}

impl Drop for PoolCheckout {
    fn drop(&mut self) {
        if let Some(mut pooled) = self.pooled.take() {
            // Phase 3: CLEAR. Reset every per-invocation field before the
            // instance returns to the pool so the next lease starts clean.
            // Mirrors the old `ClearOnDrop` guard from the single-Store path.
            let state = pooled.store.data_mut();
            state.caller_context = None;
            state.interceptor_active = false;
            state.invocation_kv = None;
            state.invocation_home = None;
            state.invocation_tmp = None;
            state.invocation_secret_store = None;
            state.invocation_capsule_log = None;
            state.invocation_profile = None;
            state.invocation_env_overlay = None;
            self.available
                .lock()
                .expect("instance pool mutex poisoned")
                .push_back(pooled);
        }
    }
}
