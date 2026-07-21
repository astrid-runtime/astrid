# Principal-affine WASM services

Principal affinity is an experimental execution mode for capsules that need
guest state to survive between calls without becoming an unmetered daemon. It
keeps one Wasmtime `Store` bound to one kernel-verified principal, subject to a
bounded resident-set and the principal's normal CPU and memory quotas.

It is intentionally opt-in through the existing package metadata escape hatch
while the behavior is exercised:

```toml
[package.metadata.astrid-runtime]
component-residency = "principal"
```

The namespace is parsed as a typed, fail-closed contract. Unknown keys, invalid
values, a `run()` export, `host_process`, uplink daemon semantics, or an
external invocation without a kernel-stamped principal prevent the component
from loading or running. The one exception is the runtime's generated
`tool_describe` probe, which is bound to the verified load owner because it has
no bus envelope. The public manifest structs and serialized API shape do not
change. A stable manifest field should go through the WIT/manifest RFC process
after this contract has production evidence.

## Lifecycle

```text
absent -> building -> active -> idle -> active
                     |          |
                     |          +-> evicted -> absent
                     +-> idle
```

- `absent`: no Store exists for this principal and capsule.
- `building`: the first call lazily creates a Store after the runtime knows the
  verified principal and its live memory profile. Cancellation or failure
  releases the pool slot and all memory reservations.
- `active`: one invocation owns the Store. A second call for the same principal
  waits without consuming capacity. Other principals can execute on their own
  Stores concurrently.
- `idle`: guest linear memory and globals remain resident, but guest code is not
  executing. Per-invocation overlays, cancellation state, and host resource
  handles are cleared before the Store becomes idle.
- `evicted`: when `instance_pool_size` resident slots are full, admission of a
  new principal destroys the least-recently-used idle Store. Active Stores are
  never evicted. Capsule unload destroys every resident Store.

There is no durability promise for resident guest memory. A capsule must commit
durable state through principal-scoped KV or home storage before returning from
an invocation. Eviction is equivalent to losing a cache and constructing a new
guest process from durable state.

## Resource invariants

1. The principal comes from the kernel-stamped envelope, never the payload.
   The internal `tool_describe` probe uses the verified load owner.
2. A Store is never retargeted or leased to a different principal.
3. The normal invocation path still seeds and charges Wasmtime fuel to the
   invoking principal. Residency grants no background CPU.
4. Linear-memory limits apply to the aggregate of all memories in a Store.
   Shared guest memory is disabled because Wasmtime does not expose it to
   `ResourceLimiter`.
5. Every resident Store reserves its admitted linear-memory bytes in the shared
   kernel ledger. The sum across all resident capsules for one principal cannot
   exceed that principal's `max_memory_bytes` quota.
6. A live quota reduction is enforced on the next checkout. An over-quota Store
   is destroyed because WebAssembly linear memory cannot shrink. Store creation
   then succeeds only if its initialization also fits the new aggregate limit.
7. `usage.get.memory_bytes_current_total` reports the resident aggregate.
   Free-checkout Stores have no stable idle owner and therefore contribute only
   to peak telemetry.

## What survives a call

| State | Survives while idle? | Reason |
|---|---:|---|
| Guest linear memory and globals | Yes | They belong to the affined Store. |
| Principal-scoped KV and home data | Yes | They are durable host services. |
| Invocation env/profile overlays | No | Re-resolved for every call. |
| IPC, HTTP, stream, process, or WASI handles | No | The host resource table is cleared on return. |
| Running guest instructions | No | A resident service is asleep between invocations. |

This makes the mode suitable for a stateful command processor or an in-memory
guest machine whose external devices are host calls. It does not by itself make
an existing `run()` actor or a request-scoped VM persistent: the capsule must
expose metered tool/interceptor entry points and keep the machine object in
guest state, with explicit durable devices for disk and home data.

## Required proof before stabilization

- A real component invocation demonstrates same-principal global/memory reuse
  and cross-principal isolation through the dispatcher.
- Pool saturation proves LRU eviction touches only idle Stores.
- Cancellation during construction and invocation leaves no stranded slot or
  current-memory reservation.
- Lowering a quota destroys or denies every Store needed to return below the
  new aggregate ceiling.
- Capsule unload returns current resident usage to zero.
- The Linux realm proves a persistent command channel and durable filesystem
  independently of the residency cache.
