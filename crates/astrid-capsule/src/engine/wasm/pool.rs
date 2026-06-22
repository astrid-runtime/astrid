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
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wasmtime::Store;
use wasmtime::component::{Instance, InstancePre};

use super::host_state::HostState;
use crate::error::{CapsuleError, CapsuleResult};

/// How often the idle-eviction timer trims warm instances back down to
/// `min_idle`, reclaiming the linear memory of instances built during a burst
/// that has since subsided. A coarse interval keeps the timer's own cost at
/// effectively zero (it sleeps, then does an O(excess) drain) — it is a gentle
/// reclaimer, not a hot loop.
const EVICT_INTERVAL: Duration = Duration::from_secs(30);

/// One leasable `(Store, Instance)` pair. The `Instance` is a `Copy` handle
/// into `store`'s resource table, so the two are bound together for the
/// instance's lifetime.
pub(super) struct PooledInstance {
    pub(super) store: Store<HostState>,
    pub(super) instance: Instance,
}

/// The immutable ingredients to mint a fresh `(Store, Instance)` on demand,
/// captured once at load so the pool can grow lazily without re-running the
/// linker.
///
/// `make_state` is the per-Store `HostState` factory — the same one used for
/// the eager warm-start instances — so a lazily-grown instance is identical to
/// an eagerly-built one. It is `Arc<dyn Fn>` (shared, callable many times):
/// each call clones the capsule's shared services (KV, event bus, the host
/// semaphores, …) into a fresh `HostState` with its own `wasi_ctx` and empty
/// `resource_table`.
pub(super) struct InstanceBuilder {
    engine: wasmtime::Engine,
    instance_pre: InstancePre<HostState>,
    make_state: Arc<dyn Fn() -> HostState + Send + Sync>,
    /// Initial epoch deadline seeded on every fresh Store (the per-invocation
    /// epoch is re-applied at invoke time, exactly as for eager instances).
    epoch_deadline: u64,
    /// Fuel seed so `instantiate_async` (which runs guest component-init code)
    /// does not trap a fresh, zero-fuel Store on its first instruction.
    fuel_budget: u64,
}

impl InstanceBuilder {
    pub(super) fn new(
        engine: wasmtime::Engine,
        instance_pre: InstancePre<HostState>,
        make_state: Arc<dyn Fn() -> HostState + Send + Sync>,
        epoch_deadline: u64,
        fuel_budget: u64,
    ) -> Self {
        Self {
            engine,
            instance_pre,
            make_state,
            epoch_deadline,
            fuel_budget,
        }
    }

    /// Instantiate one fresh pooled instance. Identical to the eager warm-start
    /// build, so eager and lazy instances are interchangeable under free
    /// checkout.
    pub(super) async fn build(&self) -> CapsuleResult<PooledInstance> {
        let mut store = Store::new(&self.engine, (self.make_state)());
        store.limiter(|state| &mut state.store_meter);
        store.set_epoch_deadline(self.epoch_deadline);
        // Fuel is engine-wide; a fresh Store starts at 0 and would trap on the
        // first instruction of `instantiate_async`. Seed it; the per-invocation
        // budget re-sets fuel afterwards.
        store.set_fuel(self.fuel_budget).map_err(|e| {
            CapsuleError::UnsupportedEntryPoint(format!("Failed to seed store fuel: {e}"))
        })?;
        let instance = self
            .instance_pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "Failed to instantiate WASM component: {e}"
                ))
            })?;
        Ok(PooledInstance { store, instance })
    }
}

/// A dynamic pool of [`PooledInstance`]s for one non-run-loop capsule.
///
/// `permits` (a [`Semaphore`] sized to `max`) bounds concurrency: a held permit
/// guarantees the pool is below `max` instances, so the holder may either pop a
/// warm instance from `available` or — if none is warm — mint a fresh one
/// ([lazy grow](Self::checkout)). The pool warm-starts with `min_idle`
/// instances, grows on demand toward `max`, and an idle-eviction timer trims
/// `available` back to `min_idle`, reclaiming memory after a burst. The
/// `available` mutex is held only for the O(1) pop/push — never across a guest
/// call or an instantiate.
///
/// ## Total-instance invariant: never more than `max`
///
/// An instance is created only by [`checkout`](Self::checkout) while holding a
/// permit and only when `available` is empty (every other instance is then in
/// flight under another permit). At most `max` permits exist, so at most `max`
/// instances exist at once; eviction only ever *decreases* the count. This
/// replaces the old fixed-size invariant ("a permit guarantees a poppable
/// instance") with "a permit guarantees we are under `max`, so pop-or-build".
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
    /// On-demand instance factory for lazy growth.
    builder: Arc<InstanceBuilder>,
    /// Whether a checkout that finds no warm instance may build one. `false`
    /// for the size-1 `host_process` carve-out (`max == min_idle == 1`): its
    /// single instance is always warm, so this is belt-and-suspenders — if a
    /// build were ever reached it would mint a *second* Store and violate the
    /// carve-out, so we fail closed instead.
    allow_grow: bool,
    /// Idle-eviction timer; aborted on drop. `None` when the pool cannot grow
    /// (`max == min_idle`) — `available` can then never exceed `min_idle`, so
    /// there is nothing to evict.
    evict_task: Option<JoinHandle<()>>,
}

impl CapsuleInstancePool {
    /// Build a dynamic pool.
    ///
    /// `initial` are the eagerly-built warm-start instances (`min_idle` of
    /// them); `max` is the concurrency / total-instance ceiling; `builder`
    /// mints more on demand up to `max`; `cancel_token` (the capsule's unload
    /// signal) stops the eviction timer.
    ///
    /// `reset_resources_on_return` is `true` for free-checkout pools and
    /// `false` for the `host_process` carve-out — see the field docs.
    pub(super) fn new(
        initial: Vec<PooledInstance>,
        max: usize,
        min_idle: usize,
        reset_resources_on_return: bool,
        builder: InstanceBuilder,
        cancel_token: &CancellationToken,
    ) -> Self {
        debug_assert!(max >= 1, "pool max must be >= 1");
        debug_assert!(min_idle >= 1 && min_idle <= max, "1 <= min_idle <= max");
        debug_assert!(initial.len() <= max, "warm-start cannot exceed max");

        let available = Arc::new(Mutex::new(VecDeque::from(initial)));
        // Only a pool that can grow above its warm set ever needs reclaiming.
        let allow_grow = max > min_idle;
        let evict_task = allow_grow.then(|| {
            let available = Arc::clone(&available);
            let cancel = cancel_token.clone();
            tokio::spawn(async move { evict_loop(available, min_idle, cancel).await })
        });

        Self {
            available,
            permits: Arc::new(Semaphore::new(max)),
            reset_resources_on_return,
            builder: Arc::new(builder),
            allow_grow,
            evict_task,
        }
    }

    /// Lease an instance, awaiting a permit if `max` are already in use.
    ///
    /// With a permit in hand the pool is below `max`, so this pops a warm
    /// instance or — when none is warm — builds a fresh one (lazy grow).
    /// Returns `None` if the semaphore is closed (capsule unloading), if a
    /// lazy build fails, or if a non-growable pool somehow finds no warm
    /// instance — all treated by the caller as "not invocable".
    pub(super) async fn checkout(&self) -> Option<PoolCheckout> {
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok()?;
        // Pop the most-recently-returned instance (the BACK — return pushes
        // back) so we lease the warmest, hottest store for cache locality and
        // memory residency. Idle instances sink toward the front, where
        // `drain_excess` reclaims them. Pop under the lock; never hold it
        // across the build `.await` below.
        let warm = self
            .available
            .lock()
            .expect("instance pool mutex poisoned")
            .pop_back();
        let pooled = match warm {
            Some(pooled) => pooled,
            None => {
                if !self.allow_grow {
                    // Unreachable for a size-1 carve-out (its instance is
                    // always warm); fail closed rather than mint a second Store.
                    return None;
                }
                match self.builder.build().await {
                    Ok(pooled) => pooled,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to grow capsule instance pool");
                        return None;
                    },
                }
            },
        };
        Some(PoolCheckout {
            pooled: Some(pooled),
            available: Arc::clone(&self.available),
            reset_resources_on_return: self.reset_resources_on_return,
            _permit: permit,
        })
    }
}

impl Drop for CapsuleInstancePool {
    fn drop(&mut self) {
        // Stop the eviction timer when the pool goes away (capsule unload). The
        // task also exits on its own when the capsule's cancel token fires;
        // this is the backstop for any path that drops the pool first.
        if let Some(task) = self.evict_task.take() {
            task.abort();
        }
    }
}

/// Idle-eviction timer: every [`EVICT_INTERVAL`], trim `available` back down to
/// `min_idle`, dropping the excess so their Stores (and linear memory) are
/// freed. Exits promptly when `cancel` fires (capsule unload). Instances in
/// flight are never touched — only warm ones sitting in `available` — so this
/// reclaims memory only after load genuinely subsides.
async fn evict_loop(
    available: Arc<Mutex<VecDeque<PooledInstance>>>,
    min_idle: usize,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(EVICT_INTERVAL) => {
                // Drain under the lock, but DROP the evicted Stores outside it:
                // a Store's `Drop` unmaps its linear memory and must not hold
                // the pool mutex (and certainly not across the lock).
                let evicted = {
                    let mut q = available.lock().expect("instance pool mutex poisoned");
                    drain_excess(&mut q, min_idle)
                };
                if !evicted.is_empty() {
                    tracing::debug!(
                        evicted = evicted.len(),
                        min_idle,
                        "evicted idle pool instances"
                    );
                }
                drop(evicted);
            }
        }
    }
}

/// Pop entries above `min_idle` off the **front** of `queue` (the
/// oldest-returned, since checkout pops the back and return pushes the back, so
/// idle instances accumulate at the front). Evicting the front reclaims the
/// coldest instances first (LRU). Returns them for the caller to drop outside
/// any lock.
fn drain_excess<T>(queue: &mut VecDeque<T>, min_idle: usize) -> Vec<T> {
    let mut evicted = Vec::new();
    while queue.len() > min_idle {
        match queue.pop_front() {
            Some(item) => evicted.push(item),
            None => break,
        }
    }
    evicted
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
/// `ipc_limiter`, `blocking_semaphore`, `io_semaphore`, `process_tracker`,
/// `event_bus`, …) is
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
    // The in-flight verified ingress principal AND its authenticating device
    // key_id are per-frame state; a fresh lease must not inherit a stale one
    // (issue #45/#852).
    state.ingress_principal = None;
    state.ingress_device_key_id = None;

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
        // Rebuilding the table drops every `NetStream` (the raw value's
        // `Drop`, not the host-trait `drop` that normally calls
        // `unbind_connection_principal`), so clear the per-connection
        // principal registry to the same empty-table baseline rather than
        // leaking entries for connections whose stream is now gone
        // (issue #45/#852).
        state.connection_principals.clear();
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

    /// Eviction trims the warm set down to exactly `min_idle`, evicting the
    /// oldest-returned (front of the queue) first, and is a no-op at/below
    /// `min_idle`.
    #[test]
    fn drain_excess_trims_to_min_idle_from_the_front() {
        // 5 warm, min_idle 2 → evict 3 (the oldest-returned: 0, 1, 2 off the
        // front), keeping the 2 most-recently-returned at the back (3, 4).
        let mut q: VecDeque<i32> = (0..5).collect();
        let evicted = drain_excess(&mut q, 2);
        assert_eq!(
            evicted,
            vec![0, 1, 2],
            "evict oldest-returned off the front"
        );
        assert_eq!(q.into_iter().collect::<Vec<_>>(), vec![3, 4]);

        // At min_idle: nothing to evict.
        let mut q: VecDeque<i32> = (0..2).collect();
        assert!(drain_excess(&mut q, 2).is_empty());
        assert_eq!(q.len(), 2);

        // Below min_idle: nothing to evict.
        let mut q: VecDeque<i32> = (0..1).collect();
        assert!(drain_excess(&mut q, 2).is_empty());
        assert_eq!(q.len(), 1);

        // min_idle 0 drains everything.
        let mut q: VecDeque<i32> = (0..3).collect();
        assert_eq!(drain_excess(&mut q, 0).len(), 3);
        assert!(q.is_empty());
    }

    /// Build a real (but empty) component pool so checkout exercises actual
    /// wasmtime instantiation. An empty `(component)` imports nothing, so a bare
    /// linker instantiates it; that is all we need to lease, grow, and bound.
    async fn empty_pool(
        max: usize,
        min_idle: usize,
        cancel: &CancellationToken,
    ) -> CapsuleInstancePool {
        let engine = super::super::build_wasmtime_engine().expect("engine");
        let component =
            wasmtime::component::Component::new(&engine, "(component)").expect("empty component");
        let linker: wasmtime::component::Linker<HostState> =
            wasmtime::component::Linker::new(&engine);
        let instance_pre = linker.instantiate_pre(&component).expect("instantiate_pre");
        let handle = tokio::runtime::Handle::current();
        let make_state: Arc<dyn Fn() -> HostState + Send + Sync> =
            Arc::new(move || minimal_host_state(handle.clone()));
        let builder = InstanceBuilder::new(engine, instance_pre, make_state, u64::MAX, 1_000_000);

        let mut initial = Vec::with_capacity(min_idle);
        for _ in 0..min_idle {
            initial.push(builder.build().await.expect("warm-start build"));
        }
        CapsuleInstancePool::new(initial, max, min_idle, true, builder, cancel)
    }

    /// Checkout pops the warm instances first, then grows lazily (building fresh
    /// instances) up to `max`, and blocks once `max` are in flight — releasing
    /// only when one is returned. Exercises the real instantiate path.
    #[tokio::test(flavor = "multi_thread")]
    async fn checkout_grows_lazily_then_bounds_at_max() {
        let cancel = CancellationToken::new();
        let pool = empty_pool(4, 2, &cancel).await;

        // First two pop the warm set; the next two force a lazy build.
        let c1 = pool.checkout().await.expect("warm 1");
        let c2 = pool.checkout().await.expect("warm 2");
        let c3 = pool.checkout().await.expect("lazy grow 3");
        let c4 = pool.checkout().await.expect("lazy grow 4");

        // Five would exceed max=4: the permit wait must not resolve.
        let blocked = tokio::time::timeout(Duration::from_millis(100), pool.checkout()).await;
        assert!(
            blocked.is_err(),
            "checkout must block once max are in flight"
        );

        // Returning one frees a permit and a warm instance; the wait resolves.
        drop(c4);
        let c5 = tokio::time::timeout(Duration::from_millis(1000), pool.checkout())
            .await
            .expect("a returned instance must unblock the waiter")
            .expect("checkout after return");

        drop((c1, c2, c3, c5));
        cancel.cancel();
    }

    /// A size-1 carve-out (`max == min_idle == 1`, `allow_grow == false`) never
    /// builds a second Store: its single warm instance serialises checkouts and
    /// is always the same one, but it is never grown.
    #[tokio::test(flavor = "multi_thread")]
    async fn carveout_pool_never_grows() {
        let cancel = CancellationToken::new();
        let pool = empty_pool(1, 1, &cancel).await;
        assert!(!pool.allow_grow, "size-1 pool must not be growable");
        assert!(
            pool.evict_task.is_none(),
            "non-growable pool spawns no evictor"
        );

        let c1 = pool.checkout().await.expect("the one instance");
        // A second concurrent checkout must block (only one Store ever exists).
        let blocked = tokio::time::timeout(Duration::from_millis(100), pool.checkout()).await;
        assert!(blocked.is_err(), "carve-out serialises: no second Store");
        drop(c1);
        let c2 = tokio::time::timeout(Duration::from_millis(1000), pool.checkout())
            .await
            .expect("unblocks on return")
            .expect("same instance again");
        drop(c2);
        cancel.cancel();
    }
}
