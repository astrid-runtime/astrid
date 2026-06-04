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
    /// Whether returning an instance tears down its per-invocation host
    /// resources (resource table + the resource-table-mirror counters).
    ///
    /// `true` for free-checkout pools (any instance serves any invocation):
    /// the free-checkout soundness invariant is "subscribe → use → drop
    /// within one completed call", so a cancelled or panicked invocation that
    /// orphans a live resource (HTTP stream, IPC subscription, net stream,
    /// process handle, WASI fd) in the returned Store must NOT leak it into
    /// the next lease — possibly a different principal. The CLEAR phase drops
    /// the whole resource table to close those handles before the instance is
    /// reusable. See [`PoolCheckout::drop`].
    ///
    /// `false` for the `host_process` carve-out (`size == 1`): that capsule
    /// deliberately holds live `ManagedProcess` handles across invocations
    /// (background processes), so tearing the resource table down on return
    /// would kill them. It is sound to skip the reset there precisely because
    /// it never leases a *second* Store, so no cross-principal reuse occurs.
    reset_resources_on_return: bool,
}

impl CapsuleInstancePool {
    /// Build a pool from pre-instantiated instances. `instances.len()` is the
    /// pool size (1 for carved-out capsules, N otherwise).
    ///
    /// `reset_resources_on_return` is `true` for free-checkout pools and
    /// `false` for the `host_process` carve-out — see the field docs.
    pub(super) fn new(instances: Vec<PooledInstance>, reset_resources_on_return: bool) -> Self {
        let size = instances.len();
        Self {
            available: Arc::new(Mutex::new(VecDeque::from(instances))),
            permits: Arc::new(Semaphore::new(size)),
            reset_resources_on_return,
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
            reset_resources_on_return: self.reset_resources_on_return,
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
    /// Mirrors [`CapsuleInstancePool::reset_resources_on_return`]; copied at
    /// checkout so the drop path needs no back-pointer to the pool.
    reset_resources_on_return: bool,
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
            clear_on_return(pooled.store.data_mut(), self.reset_resources_on_return);
            self.available
                .lock()
                .expect("instance pool mutex poisoned")
                .push_back(pooled);
        }
    }
}

/// Tear down a returned instance's per-invocation [`HostState`] so the next
/// lease starts clean. Runs on **every** [`PoolCheckout`] exit path — normal
/// return, `?`, panic-unwind, future-drop on caller cancellation.
///
/// Two layers:
///
/// 1. The per-invocation principal-scoping fields (the `invocation_*` set plus
///    `caller_context` / `interceptor_active`). Always cleared — these are
///    plain `Option`/`bool` references to shared services, not live OS
///    resources, but a stale one would mis-scope the next call's reads/writes.
///
/// 2. When `reset_resources` is set (free-checkout pools only): the
///    per-Store-lifetime *resource* state — the wasmtime `ResourceTable` and
///    the O(1) resource-table-mirror counters. A cancelled or panicked
///    invocation can return here while it still holds live handles (an HTTP
///    stream, an IPC subscription, a net stream, a background process, a WASI
///    fd) it never got to `drop`. Replacing the table with a fresh one runs
///    `Drop` on every orphaned entry — closing fds/streams and killing+reaping
///    child processes via their `Drop` impls — so the next lessee (possibly a
///    *different* principal under free checkout) inherits NO live resource.
///    The counters are reset to match the now-empty table.
///
///    Resetting an already-empty table (the normal subscribe→use→drop path) is
///    a cheap no-op: a fresh `ResourceTable` allocation and a few field writes.
///
/// `reset_resources` is `false` for the `host_process` carve-out, whose
/// `ManagedProcess` handles legitimately persist across invocations; it is
/// sound to skip there because that capsule never leases a second Store, so no
/// cross-principal reuse can occur (see [`CapsuleInstancePool`]).
///
/// NOTE: the per-Store *owner* state (`vfs`, `kv`, `secret_store`,
/// `ipc_limiter`, `host_semaphore`, `process_tracker`, `event_bus`, …) is
/// deliberately untouched — it is shared, immutable for the Store's lifetime,
/// and must survive every checkout. `wasi_ctx` likewise needs no reset:
/// capsules import zero `wasi:*` functions, so the only WASI-created handles
/// (streams/pollables) live in the `resource_table` cleared above, not in the
/// ctx, whose sole content is the inherited-stderr stdio config.
fn clear_on_return(state: &mut HostState, reset_resources: bool) {
    state.caller_context = None;
    state.interceptor_active = false;
    state.invocation_kv = None;
    state.invocation_home = None;
    state.invocation_tmp = None;
    state.invocation_secret_store = None;
    state.invocation_capsule_log = None;
    state.invocation_profile = None;
    state.invocation_env_overlay = None;

    if reset_resources {
        // Drops every entry still in the old table (orphaned subscriptions,
        // HTTP/net streams, process handles, WASI fds) via their `Drop` impls.
        state.resource_table = wasmtime::component::ResourceTable::new();
        // The mirror counters are O(1) shadows of the table's contents; reset
        // them to the empty-table baseline so the per-(principal) gates start
        // from zero for the next lease.
        state.active_http_streams.clear();
        state.net_stream_count = 0;
        state.subscription_count = 0;
        state.process_count_total = 0;
        state.process_count_by_principal.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use wasmtime::component::Resource;

    use super::super::test_fixtures::minimal_host_state;
    use super::*;

    /// A resource-table entry that records its own `Drop` through a shared
    /// flag — stands in for any host resource whose `Drop` closes an fd /
    /// stream / kills a child (`NetStream`, `ActiveHttpStream`,
    /// `SubscriptionEntry`, `ManagedProcess`).
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A cancelled/panicked invocation can return an instance whose
    /// `resource_table` still holds a live handle. The CLEAR phase
    /// (`reset_resources = true`) must drop it — closing the underlying OS
    /// resource — and zero the mirror counters, so the next (possibly
    /// different-principal) lease inherits nothing.
    #[test]
    fn clear_on_return_resets_orphaned_resources() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut state = minimal_host_state(rt.handle().clone());

        // Simulate an orphaned resource from a call that never reached its
        // `drop`: an entry in the table plus the counters it would have bumped.
        let dropped = Arc::new(AtomicBool::new(false));
        let res = state
            .resource_table
            .push(DropFlag(Arc::clone(&dropped)))
            .expect("push test resource");
        state.net_stream_count = 1;
        state.subscription_count = 2;
        state.process_count_total = 1;
        state
            .process_count_by_principal
            .insert(astrid_core::PrincipalId::default(), 1);
        state.interceptor_active = true;

        clear_on_return(&mut state, true);

        // The orphaned entry's `Drop` ran (its real-world analogue closes the
        // fd / stream / child), and the handle is gone from the table.
        assert!(
            dropped.load(Ordering::SeqCst),
            "orphaned resource must be dropped on return"
        );
        assert!(
            state
                .resource_table
                .get::<DropFlag>(&Resource::<DropFlag>::new_borrow(res.rep()))
                .is_err(),
            "returned instance must observe an empty resource table"
        );
        // Mirror counters back to the empty-table baseline.
        assert_eq!(state.net_stream_count, 0);
        assert_eq!(state.subscription_count, 0);
        assert_eq!(state.process_count_total, 0);
        assert!(state.process_count_by_principal.is_empty());
        // Per-invocation scoping fields cleared too.
        assert!(!state.interceptor_active);
    }

    /// The `host_process` carve-out (`reset_resources = false`) deliberately
    /// keeps its `ManagedProcess` handles across invocations — the resource
    /// table and its counters must survive the return.
    #[test]
    fn clear_on_return_preserves_resources_for_carveout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut state = minimal_host_state(rt.handle().clone());

        let dropped = Arc::new(AtomicBool::new(false));
        let res = state
            .resource_table
            .push(DropFlag(Arc::clone(&dropped)))
            .expect("push test resource");
        state.process_count_total = 1;
        state.interceptor_active = true;

        clear_on_return(&mut state, false);

        // Resource table untouched: the entry is still live and reachable.
        assert!(
            !dropped.load(Ordering::SeqCst),
            "carve-out must not drop cross-invocation resources"
        );
        assert!(
            state
                .resource_table
                .get::<DropFlag>(&Resource::<DropFlag>::new_borrow(res.rep()))
                .is_ok(),
            "carve-out resource table must persist across return"
        );
        assert_eq!(state.process_count_total, 1);
        // Per-invocation scoping fields are still cleared even for the carve-out.
        assert!(!state.interceptor_active);
    }
}
