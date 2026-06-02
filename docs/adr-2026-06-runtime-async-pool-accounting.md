# ADR: Runtime Async + Smart Instance Pool + Per-Principal Resource Accounting

- **Status:** Proposed (design locked, implementation deferred behind option 2)
- **Date:** 2026-06-02
- **Tracking:** `astrid#813` (epic), `astrid#816` (this option), `astrid#815` (dependency)
- **Authors:** Astrid kernel team
- **Supersedes:** Option 1 of `astrid#816` (single-Store-per-capsule serialization)

## Context

The runtime-cliff investigation (`astrid#813`) traced concurrent-invocation tail latency and head-of-line blocking to two distinct problems in the current kernel runtime:

1. **Sync wasmtime on the bus dispatch path.** Every IPC invocation runs to completion on the dispatcher's executor task. With sync wasmtime, a slow capsule call parks an entire OS thread; the bus's bounded concurrency semaphore protects the kernel from thread exhaustion, but only by clamping throughput well below what the host could deliver.
2. **No per-capsule fairness or accounting under contention.** Capsule instance creation is unbounded but uncached; the cost of "warm" (`#815`) is paid on every invocation once the host is busy. Worse, a single misbehaving principal can starve the global concurrency budget without the kernel having any signal to throttle it specifically.

The investigation enumerated three remediation options against `astrid#816`:

| Option | Description | Status |
|--------|-------------|--------|
| 1 | Single-Store-per-capsule serialization | **Superseded** — re-introduces head-of-line blocking we just removed |
| 2 | Async wasmtime (epoch-driven yields, async host calls) | **Shipping first** — unblocks the dispatcher, ships per-call fuel deadlines |
| 3 | Smart capsule instance pool + per-principal resource accounting | **This ADR** — deferred behind option 2 + measurement |

Option 2 ships first because it is the necessary substrate: async wasmtime is what makes concurrent in-flight calls per capsule possible without thread-per-call. Without async wasmtime, a pool of instances is a pool of parked OS threads.

Option 3 builds on the four-layer IPC plumbing already shipped (`feat/per-principal-end-to-end`):

1. **Wire layer** carries `PrincipalId` end-to-end (uplink → bus → capsule).
2. **Bus layer** has per-principal rate limiting (`IpcRateLimiter`) and tracks `process_count_by_principal` via `ProcessTracker`.
3. **Host layer** authenticates every host call against the calling principal.
4. **Audit layer** attributes every event to a principal.

Option 3 adds the missing fifth layer: **per-principal resource accounting at the wasmtime boundary** (CPU fuel, memory bytes, concurrent leases) and a **bounded instance pool** that turns "warm" from a best-effort optimization into a contractual guarantee.

### What option 3 buys

- **Throughput at warm latency.** `#815` shows a ~30x gap between cold-instantiate and warm-invoke. With a pool, every checkout is warm by construction; under load the kernel is bounded by lease availability, not instantiation cost.
- **Principal-attributed DoS resistance.** Today the bus rate-limits IPC events per principal, but a principal that gets past the limiter can still consume unbounded fuel and memory inside the guest. A `PrincipalLedger` makes that consumption visible and capped.
- **Fairness under contention.** A per-principal concurrent-lease cap turns the global concurrency budget into a fair-share scheduler. The `System` principal is not at the mercy of a runaway `Agent`.
- **Committed-RSS efficiency.** `PoolingAllocationStrategy` + a tighter `WASM_MAX_MEMORY_BYTES` cap moves us from "every Store mmaps the full max-memory range" to "the pool's total memory footprint is bounded and reused."

The ADR is being written **now**, before implementation, so that when option 2 ships and we measure whether option 3 is required at deployment scale, the question is "do the numbers cross the threshold this ADR defines?" rather than "what would option 3 even look like?" Locking the design prevents re-litigating it under deadline pressure.

## Decision

We will implement option 3 of `astrid#816` as specified in this document:

1. A **smart capsule instance pool** (`CapsuleInstancePool`) that maintains warm pre-instantiated capsule instances keyed by capsule identity, with bounded concurrency and idle eviction.
2. **Per-principal resource accounting** via a `PrincipalLedger` per `(CapsuleId, PrincipalId)` pair, tracking fuel consumed, peak memory, concurrent leases, and last-active time.
3. A wasmtime `ResourceLimiter` installed on every Store, parameterized by the current lease's principal context.
4. **Quota policy** sourced from `etc/quotas.toml` with per-principal-class defaults (`System` / `User` / `Agent`) and per-bearer overrides.

Implementation is gated on:

- Option 2 (`astrid#816`, async wasmtime) shipped and stable.
- Measurement showing option 2 alone does not meet target tail-latency / fairness goals under realistic load (threshold to be established as part of option 2 validation).
- Completion of the in-Store mutable static state audit (see below).

## Rationale

### Why pool over alternatives

**Alternative A: raise the bus concurrency semaphore.** The current semaphore (default 8, configurable) is the cheapest knob, but it does not solve the underlying problem. Raising it without option 2 just creates more parked threads. Raising it after option 2 lets more invocations through but each one still pays cold-instantiate cost on contention, and there is still no per-principal fairness.

**Alternative B: async-only (option 2 alone).** Async wasmtime removes the dispatcher bottleneck and gives us per-call fuel deadlines. It does not address (i) the cold-vs-warm cost asymmetry (`#815` shows warm is dramatically cheaper, but option 2 doesn't keep instances warm), (ii) per-principal fairness inside the wasmtime budget, or (iii) the unbounded-RSS-per-Store problem. Option 2 is necessary but not sufficient if measurement shows contention is bottlenecked on instance lifecycle or principal fairness.

**Alternative C: pool without per-principal accounting.** A bare pool gives us warm-by-construction throughput but no fairness. The first principal to grab leases owns the pool until it returns them. With multi-tenant uplinks (CLI + Discord + web on one kernel) this is a regression in isolation, not an improvement.

The combined design — pool with per-principal accounting — is the smallest construction that solves all three problems together. They share infrastructure (the lease lifecycle is where both pool checkout and ledger updates happen) and the cost of building one without the other is roughly the cost of building both.

### Throughput math at #815-warm latency

`#815` measured cold-instantiate at ~30x warm-invoke for representative capsules. A pool with `max_concurrent = N` and adequate `min_idle` makes every checkout warm: steady-state throughput becomes `N / warm_latency` rather than `N / (cold_amortized + warm_latency)`. At realistic capsule sizes the amortization is small (cold cost is paid once per pool slot per process lifetime), so the practical ceiling is approximately `30x` over a no-pool baseline at the same concurrency, before considering memory effects.

## Architecture

### `CapsuleInstancePool`

```rust
pub struct CapsuleInstancePool {
    /// Compiled module, shared across all instances in this pool.
    module: Arc<wasmtime::Module>,

    /// Warm, pre-instantiated, ready-to-checkout instances.
    available: parking_lot::Mutex<VecDeque<PooledInstance>>,

    /// Currently leased instances (excludes `available`).
    in_flight: AtomicUsize,

    /// Knobs.
    min_idle: usize,         // pool refills to this on eviction
    max_concurrent: usize,   // hard cap on `in_flight + available.len()`
    idle_evict: Duration,    // per-instance idle TTL before eviction
}

struct PooledInstance {
    store: wasmtime::Store<HostState>,
    instance: wasmtime::Instance,
    last_returned: Instant,
}
```

`Arc<Module>` is the wasmtime-recommended sharing point: compilation is paid once, instantiation is cheap, and the module artifact is the largest immutable cost per capsule.

`available` is a `VecDeque` (FIFO for predictable idle distribution; LIFO would bias toward hot caches but make idle eviction harder to reason about — revisit if profiling justifies).

`in_flight` is an `AtomicUsize` rather than derived from a second mutex to keep the fast path lock-free for the concurrency check.

### Lease lifecycle

```
checkout():
  1. fast path: if available.pop_front() succeeds, return it
  2. capacity check: if in_flight + available.len() < max_concurrent,
     instantiate a new PooledInstance from Arc<Module>
  3. queue: otherwise, park on a notify channel until a return or eviction
     wakes a waiter
  4. on success: in_flight.fetch_add(1), bind principal context, hand out Lease

Lease::invoke():
  - runs the wasm call (async, post-option-2)
  - ResourceLimiter sees per-lease principal context
  - fuel and memory are debited against PrincipalLedger on completion

Lease::Drop (return path):
  - reset HostState (clear per-invocation buffers, NOT module-linear-memory)
  - in_flight.fetch_sub(1)
  - push to available, notify one waiter

Lease::cancel() (cancellation path):
  - DO NOT return Store to pool
  - drop Store entirely; pool reinstantiates on next checkout if below min_idle
  - rationale: a cancelled invocation may have left HostState or guest
    memory in an indeterminate state. Cheaper to pay one cold-instantiate
    than to risk poisoning the pool.
```

The reset step is **HostState only**. Guest linear memory persists across leases — that is the whole point of pooling. Capsules that rely on in-Store mutable static state must be identified by the audit below and either (a) carve out single-Store mode, or (b) move state to bus-mediated capsules that own their state explicitly.

### Allocation strategy

We use wasmtime's `PoolingAllocationStrategy` for the underlying memory backing:

- Total committed RSS is bounded by `pool_count * WASM_MAX_MEMORY_BYTES`.
- We will tighten `WASM_MAX_MEMORY_BYTES` from the current value as part of this work — most capsules use far less, and the per-Store mmap cost was masked by infrequent instantiation.
- `madvise(MADV_DONTNEED)` on pool reclamation returns physical pages without freeing virtual range; this is the layer-4 reclamation step described below.

### Allocation key

**For v1: free pool checkout.** Any available instance can serve any principal's request. Lease-time principal context is set on the Store before invocation.

**Deferred: sticky-per-principal.** Hold a per-principal preference (e.g. last-used instance) to improve guest cache locality. This is a profile-driven optimization, not a correctness requirement. We will revisit after option 3 ships with concrete cache-miss measurements.

The decision matters because sticky allocation interacts with the fairness model: pure sticky breaks fairness under contention; weighted-sticky-with-fallback is the likely shape, but the implementation cost is non-trivial and current data does not justify it.

### State-model audit (blocker)

Before implementation, every shipped capsule must be audited for:

- Mutable static state in linear memory that assumes single-Store semantics (e.g. once-init lazies, in-process caches that assume the same process serves all invocations).
- Host-imported handle tables that assume linear ownership across calls.

Capsules in this category get a **carve-out classification**: they run in single-Store mode, bypassing the pool, until they are refactored. The audit determines:

- Who runs it (capsule team per-capsule? kernel team triage?).
- The classification bar (presence of `thread_local!` / `static mut` is necessary but not sufficient — many uses are per-call ephemeral and pool-safe).
- The carve-out config surface (`Capsule.toml` flag? kernel-side allow-list? default-deny with explicit opt-in to pool?).

This is an **open decision** below, not a free choice in implementation.

## Resource accounting model

### `PrincipalLedger`

```rust
/// Keyed by (CapsuleId, PrincipalId). One row per (capsule, principal)
/// active pair. Eviction is independent of pool state.
pub struct PrincipalLedger {
    cpu_fuel_consumed: AtomicU64,    // monotonic; reset on quota window roll
    memory_peak_bytes: AtomicU64,    // high-water mark across active leases
    concurrent_leases: AtomicU32,    // current in-flight leases for this pair
    last_active: AtomicI64,          // unix millis, for eviction
}
```

The ledger is the kernel's authoritative attribution surface. Every accounting decision (rate, throttle, evict, deny) reads the ledger; every wasmtime-side observation (fuel consumed, memory grown, lease taken/returned) writes to it.

### `ResourceLimiter` on Store

Wasmtime's `ResourceLimiter` trait is the supported hook for bounding memory growth and table growth per Store. We install a limiter that:

- Reads the current lease's principal context.
- Looks up the ledger row for `(CapsuleId, PrincipalId)`.
- Compares the proposed `memory.grow` against the principal's quota.
- Updates `memory_peak_bytes` on success; denies growth on quota exceeded.

The principal context lives on the Store and is rebound on each checkout (cheap — it's a pointer-and-ID swap, not a Store recreate).

### Fuel-based CPU debit

Wasmtime fuel is the supported hook for CPU accounting. Option 2 ships per-call fuel deadlines for liveness; option 3 reuses the same fuel mechanism for per-principal CPU attribution:

- Each lease starts with a fuel budget from `min(per-call deadline, principal remaining quota)`.
- On lease return, `consumed = budget - remaining` is debited from `cpu_fuel_consumed`.
- A principal that hits zero remaining quota is denied checkout until the quota window rolls.

### Concurrent-lease cap

Per-principal cap on `concurrent_leases` is the pool's fairness gate. This is a soft cap enforced at checkout: a principal at its cap parks on the same notify channel as a principal blocked on pool capacity, with no special treatment — fairness comes from the cap itself, not queue priority.

### Quota policy

Quotas are configured in `etc/quotas.toml`. Three levels of granularity:

1. **Principal-class defaults** (always present):
   - `[class.System]` — high or unbounded; runs critical capsules
   - `[class.User]` — generous; interactive uplinks
   - `[class.Agent]` — bounded; recursive delegation needs strict caps
2. **Per-bearer override** (optional): pin a specific principal to non-default values, for known-trusted services or known-problem agents.
3. **Per-capsule override** (optional, deferred): capsule-author-declared quota expectations. Not v1.

```toml
# etc/quotas.toml
[class.System]
cpu_fuel_per_minute = "unbounded"
memory_bytes        = 256_000_000
concurrent_leases   = 32

[class.User]
cpu_fuel_per_minute = 10_000_000_000
memory_bytes        = 64_000_000
concurrent_leases   = 8

[class.Agent]
cpu_fuel_per_minute = 1_000_000_000
memory_bytes        = 16_000_000
concurrent_leases   = 2

[bearer."did:key:z6Mk..."]
class               = "User"
concurrent_leases   = 16
```

### Existing infrastructure to extend

- `ProcessTracker::process_count_by_principal` — already counts uplink processes per principal. Extend with `lease_count_by_principal` derived from the ledger.
- `IpcRateLimiter` — already enforces per-principal IPC rate. Layer the ledger checks underneath: rate-limited request denied before ledger ever sees it; ledger denies after rate limit passes but quota exhausted.
- `audit` — every quota-deny event is an audit event with principal, capsule, quota class, and which dimension tripped.

## Idle reclamation

Five layers, from cheapest to most expensive:

| Layer | Trigger | Action | Latency |
|-------|---------|--------|---------|
| 1 | Per-invocation | Reset `HostState`, keep Store warm | μs |
| 2 | Lease return | Push to `available`, notify waiter | μs |
| 3 | Per-instance idle TTL (`idle_evict`, default 60s) | Drop one `PooledInstance`, free Store | ms |
| 4 | Pool watermark below threshold | `madvise(MADV_DONTNEED)` on freed allocator slots | μs (kernel) |
| 5 | Capsule unload | Drop `Arc<Module>`, full reclamation | ms-s |

Background reclamation runs on a single timer task per pool, ticking every `idle_evict / 4`. Watermark policy: keep at least `min_idle` instances; evict above `min_idle` once `last_returned` exceeds `idle_evict`.

### Ledger eviction (independent)

The `PrincipalLedger` is **not** evicted in lockstep with pool instances. A ledger row persists for 30 minutes of inactivity (configurable) regardless of whether the underlying capsule instance has been evicted. This is because:

- Quota windows are time-based, not instance-based. Evicting a ledger row resets a principal's quota debt, which is a security-relevant action.
- Re-creating the row from cold is cheap; the cost of holding it is small (a few hundred bytes per active principal-capsule pair).

Ledger eviction logs an audit event so the operator can see when a principal "goes quiet."

## Open decisions

The following must be resolved before implementation lands:

1. **Sticky vs free-checkout allocation.** v1 spec is free-checkout (any-instance-for-any-principal). Sticky is deferred pending profiling. Decision needed: confirm v1 is free-checkout and we revisit only with measured cache-miss data, OR commit upfront to a weighted-sticky-with-fallback design.

2. **Cancellation: drop-not-return vs return-and-reset.** Spec is drop-not-return for safety. Decision needed: confirm we accept the cold-reinstantiate cost on cancellation, OR define a "safe-reset" protocol that lets us return cancelled Stores to the pool.

3. **Quota config surface.** Spec is file-based (`etc/quotas.toml`) with principal-class defaults and per-bearer overrides. Decision needed: file-only at v1, OR admin-API-mutable (requires capability + audit surface), OR principal-class-only (drop per-bearer overrides as overcomplication).

4. **In-Store-state audit ownership and bar.** Audit blocks implementation. Decision needed: who runs it (capsule teams per-capsule, kernel team triage, or hybrid), and what evidence promotes a capsule to carve-out status (presence of static state is necessary; we need a sufficient-criteria definition).

5. **`ResourceLimiter` perf overhead.** Wasmtime's limiter is called on every `memory.grow` and `table.grow`. For capsules that grow frequently this is non-trivial. Decision needed: is the overhead acceptable on hot paths, what is the measured ceiling, do we need a fast-path that skips the limiter under a per-class "trusted" flag?

## Threat model

The runtime today has three principal-attributed DoS vectors that this design closes or significantly reduces:

| Vector | Current state | After option 3 |
|--------|---------------|----------------|
| **Concurrency exhaustion** | One principal can consume the global bus concurrency budget; other principals queue indefinitely. | Per-principal `concurrent_leases` cap prevents single-principal monopolization. |
| **Memory exhaustion in guest** | Guest can grow linear memory up to `WASM_MAX_MEMORY_BYTES`. No principal attribution; one bad call costs the host RSS that all principals share. | `ResourceLimiter` denies `memory.grow` past per-principal cap; `memory_peak_bytes` attributed to the responsible principal. |
| **CPU exhaustion in guest** | Option 2 caps per-call fuel. No per-principal budget — a principal making many small calls under the per-call cap can still saturate CPU. | Per-principal `cpu_fuel_per_minute` quota composes with the per-call cap; rolling window prevents amortization-attack. |

The design does **not** address: side-channel attacks (timing, cache), denial via legitimate request flooding past `IpcRateLimiter` (handled at the bus layer, not here), or host-resource attacks via the SDK surface (handled at the host-call layer).

A residual concern: an attacker who controls multiple principals (via account creation or compromise) can sum quotas. The mitigation is principal-class budgets at the operator layer (limit number of `Agent`-class principals per `User`); this is operator policy, not kernel mechanism.

## Migration plan

Option 3 can land incrementally. The dependency order is:

1. **Block:** option 2 must ship and prove stable (async wasmtime, per-call fuel).
2. **Block:** in-Store mutable static state audit completes; carve-out list exists.
3. **Block:** measurement confirms option 3 is required (criteria established as part of option 2 validation).
4. **Phase A:** Pool only, no per-principal accounting. `CapsuleInstancePool` with free-checkout, fixed `max_concurrent` from config, no ledger. Validates pool correctness and the lease lifecycle.
5. **Phase B:** Add `PrincipalLedger` + `ResourceLimiter`, but read-only (observe, audit, do not enforce). Validates accounting accuracy.
6. **Phase C:** Enable enforcement (memory + concurrent leases first, fuel-quota last because it interacts most with option 2's per-call deadlines).
7. **Phase D:** Quota config surface, `etc/quotas.toml` schema, audit events for deny actions.

Each phase is independently revertable. The audit blocks the start of Phase A; everything else gates only the phase it introduces.

## WIT impact

**Zero.** This work is entirely kernel-internal:

- `CapsuleInstancePool` lives in the kernel runtime crate; capsules see no API change.
- `ResourceLimiter` is a wasmtime-side concept; the guest cannot observe it except by hitting the cap.
- `PrincipalLedger` is kernel state; capsules already have a `PrincipalId` plumbed through host-call context.
- `etc/quotas.toml` is operator-facing config, not part of the capsule contract.

Per `feedback_rfc_scope_is_wit`: RFCs gate changes to the kernel-to-user-space contract surface. This work is below that surface. **No RFC needed.**

This ADR is the design artifact; review happens in this repo, not the `astrid-rfcs` repo.

## References

- `astrid#813` — runtime cliff investigation epic
- `astrid#815` — warm-vs-cold instantiate measurement (dependency)
- `astrid#816` — three-option runtime upgrade tracking issue
  - option 1: superseded (re-introduces head-of-line blocking)
  - option 2: deferred-shipping-first (async wasmtime)
  - option 3: **this ADR**
- `core/docs/metrics.md` — host-ops gateway metrics surface (where pool / ledger metrics will be exported)
- `feat/per-principal-end-to-end` — the four-layer IPC plumbing this builds on
