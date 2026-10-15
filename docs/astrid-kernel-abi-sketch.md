# Astrid Kernel v0 ABI Sketch

Status: Milestone 0 exit artifact; the version-zero native ABI shape, not a stable contract

Last reviewed: 2026-07-21

Companions: [kernel charter](astrid-kernel-charter.md),
[ADRs](astrid-kernel-adrs.md),
[requirement-to-evidence matrix](astrid-kernel-evidence-matrix.md),
[native-kernel scope](astrid-native-kernel.md)

This is the version-zero sketch of the native ABI between ring 0 and a
ring-3 domain. It is the last Milestone 0 exit artifact, and the charter sets
its acceptance bar directly: the sketch must have "no path, no stringly
syscall, and no ambient-authority handle" (charter §2, exit gate). It exists
to prove the seven ADRs compose into a coherent, capability-oriented,
non-POSIX operation set before any of it is implemented.

**This is a sketch, not a contract.** The native ABI is private and versioned
(charter §4.1); it is explicitly *not* a supported capsule contract (support
policy). Capsules target `wasm32-unknown-unknown` and the `astrid:*` WIT
worlds; the runtime host translates those into these operations. Nothing here
is a stable interface, and every signature will move during implementation.
What must *not* move is the shape: capability-oriented, totally fallible,
bounded, path-free, string-subject-free, ambient-free.

## Reading the sketch

Types are written in a neutral pseudo-IDL, pointer-width explicit, `no_std`
and fuzzable by construction (charter §4.6). The conventions:

- `Cap` — a capability, named only by a per-domain table **slot index**
  (`u32`), never a pointer or a string (ADR-K2). Every `Cap` argument is a
  slot; the kernel resolves slot → entry → generation-checked object.
- `Rights` — a bitmask; operations that derive a capability take a requested
  mask and the result is `requested ∩ source` (ADR-K3), never wider.
- `Result<T>` — every operation is total: it returns `Ok(T)` or a typed
  `Fault`; there is no undefined argument space and no panic (charter §4.3;
  REQ-ABI-1).
- Bounded — every length, count, and buffer has a declared compile-time
  ceiling charged to the caller's budget (charter §4.4; REQ-ABI-4). `&[u8]`
  in a signature means "bounded slice with a stated max," never unbounded.
- All multi-field inputs are copied and validated once at the boundary
  (charter §4.6; REQ-ABI-2).

Handles carry a generation (ADR-K2); a stale generation faults before any
state changes. Nothing in the ABI takes an address, a path, a name, or a
topic string as an authority-bearing argument.

## Object and fault types

```
Domain        // a protection domain (ADR-K1)
CapTable      // a domain's capability table (ADR-K2), addressed by slot
SchedContext  // CPU budget+period as a capability (ADR-K6)
FaultEndpoint // one per domain, birth-reserved death slot (ADR-K5)
MemRegion     // a bounded, W^X-typed physical/virtual region
Endpoint      // a bounded typed IPC rendezvous/queue object
DeviceObj     // a kernel-discovered device claim (driver contract)
DmaBuffer     // a broker-owned bounded DMA buffer (TM §6)
AuditRoot     // the monotonic order + hash accumulator (ADR-K7)

Fault {       // the typed failure of any operation
  kind: enum { BadSlot, StaleGeneration, RightsExceeded, OutOfRange,
               PoolExhausted, WouldWiden, Unbounded, NotPermitted, Busy },
  detail: u64  // operation-specific, never a pointer or string
}

DeathRecord { // delivered exactly once to a FaultEndpoint (ADR-K5)
  domain: DomainId,
  cause: enum { Trap, PageFault, BudgetExhausted, Killed, Revoked },
  final_accounting: Accounting,
  generation: u64
}
```

## Operation families

The families follow the scope document's minimal ABI (scope §2.2), refined by
the ADRs and extended with the legibility family the charter requires from v0.

### Domain (ADR-K1)

```
domain_create(image: Cap, plan_slot: u32, rights: Rights) -> Result<Cap>
domain_start(d: Cap) -> Result<()>
domain_stop(d: Cap) -> Result<()>
domain_inspect(d: Cap) -> Result<DomainStatus>   // read-only projection
domain_destroy(d: Cap) -> Result<()>             // → revocation (ADR-K4)
```

`domain_create` mints a domain only within the authority the measured boot
plan derived to the caller (`plan_slot`); a manifest claim is never authority
(charter §2.10; REQ-CAP-4). No domain names another by string or index it was
not granted.

### Memory (charter §3; ADR-K1)

```
mem_alloc(pool: Cap, class: MemClass) -> Result<Cap>       // fixed-slot (ADR-K1)
mem_map(d: Cap, region: Cap, rights: Rights) -> Result<()> // W^X enforced
mem_unmap(d: Cap, region: Cap) -> Result<()>
mem_share(region: Cap, to: Cap, rights: Rights) -> Result<Cap> // ∩, never widen
```

`mem_map` faults with `WouldWiden` on any request for a write+execute mapping
(REQ-MEM-4). Allocation faults `PoolExhausted` per class, never fragmenting
(ADR-K1; REQ-MEM-1).

### IPC (charter §4; ADR-K3)

```
ipc_endpoint_create(pool: Cap) -> Result<Cap>
ipc_send(ep: Cap, msg: &Message, caps: &[Cap]) -> Result<()>   // caps: bounded
ipc_recv(ep: Cap, buf: &mut Message) -> Result<Received>
ipc_call(ep: Cap, msg: &Message, caps: &[Cap]) -> Result<Received>
```

`caps` is the explicit, bounded set of capabilities transferred (ADR-K3):
each is derived into the receiver's table with `requested ∩ source` rights.
A capability the message does not name is not transferred. `Message` is a
bounded typed payload with a declared ceiling; there is no unbounded byte
stream and no path/topic string as a routing subject — routing is by
endpoint capability, not by name.

### Wait and time (charter §3)

```
wait(on: &[WaitCap], deadline: Nanos) -> Result<WaitResult>  // on: bounded
yield_now() -> ()
time_monotonic() -> Nanos
random_bytes(buf: &mut [u8]) -> Result<()>                   // buf: bounded
```

`wait` blocks on a bounded set of endpoints/timers/fault-endpoints until one
is ready or the deadline passes. Time is monotonic ring-0 time (ADR-K6's
budget accounting is separate and unforgeable). Entropy is a typed host
effect, matching the existing `astrid:sys` random source.

### Scheduling (ADR-K6)

```
sched_context_create(pool: Cap, budget: Nanos, period: Nanos) -> Result<Cap>
sched_bind(d: Cap, sc: Cap) -> Result<()>
sched_derive(sc: Cap, budget: Nanos, period: Nanos) -> Result<Cap> // ≤ source
```

A domain runs only while bound to a scheduling context with budget
(ADR-K6). `sched_derive` produces a child context whose budget is never
larger than the source's — CPU attenuates on delegation exactly like every
other authority. Budget exhaustion raises `BudgetExhausted` to the domain's
fault endpoint.

### Fault and supervision (ADR-K5)

```
fault_endpoint_create(pool: Cap, for_domain: Cap) -> Result<Cap>
fault_recv(fe: Cap, buf: &mut DeathRecord) -> Result<()>
```

The death-record delivery slot is reserved from the recovery pool at
`domain_create` time and bound to the endpoint, so delivery never allocates
and never fails for want of capacity (ADR-K5; REQ-FAULT-5). A supervisor
holds the `fault_recv` capability; a domain never holds the fault authority
over itself (ADR-K4; REQ-FAULT-3).

### Device and DMA (driver contract; TM §6)

```
device_claim(plan_slot: u32) -> Result<Cap>                 // kernel-discovered only
device_queue(dev: Cap) -> Result<Cap>                       // mediated queue
dma_buffer_alloc(pool: Cap, len: Bounded) -> Result<Cap>    // broker-owned
dma_map(dev: Cap, buf: Cap, dir: Direction) -> Result<()>   // IOMMU-domain scoped
dma_unmap(dev: Cap, buf: Cap) -> Result<()>                 // strict invalidation
irq_wait(dev: Cap) -> Result<()>                            // deferred bottom half
```

Only kernel-discovered devices are claimable, and only within the boot plan
(TM §6). The v0 device surface is mediated queues and broker-owned DMA
buffers — no raw MMIO, no arbitrary physical address, no ATS-trusted
translation (TM §6; REQ-DMA-1..5). `dma_map` is scoped to the device's IOMMU
domain and mappings are minted only for broker-owned buffers, never live
kernel memory.

### Trust and audit (ADR-K7)

```
audit_stamp(event: &AuditEvent) -> Result<Seq>   // monotonic total order
audit_root() -> Result<RootHash>                 // attested, never parsed
measure_verify(obj: Cap) -> Result<Measurement>
```

`audit_stamp` assigns a monotonic sequence and advances the hash accumulator;
ring 0 orders and roots but never interprets the record (charter §2; ADR-K7).
The user-space audit domain reads the ordered stream and builds the
BLAKE3-sealed, ed25519-signed chain.

### Legibility (charter §3) — the AI-kernel family

```
legible_enumerate(rel: RelationKind) -> Result<RelationSnapshot>  // domain-visible only
legible_subscribe(rel: RelationKind, sink: Cap) -> Result<Cap>    // bounded deltas
```

This is the family that makes the kernel the ground floor of the system
ontology (charter §3). `legible_enumerate` returns the caller-visible
projection of an object-table relation — domains, capabilities, endpoints,
scheduling contexts — as typed tuples read directly from the tables, never a
mirrored store (ADR-K2; REQ-LEG-1). `legible_subscribe` delivers bounded
deltas to a sink endpoint, in the Genode report/ROM shape (TM §10). Every
relation is capability-gated per relation and domain-visible only
(REQ-LEG-2); relations carrying timing-correlated counters are rate-limited
and quantized (REQ-LEG-3). This is an ABI family, not a debug channel: the
base relations a user-space reasoner reads as fact are emitted here because
they *are* ring 0's state.

### Debug (charter §3; scope §2.2)

```
debug_write(buf: &[u8]) -> Result<()>   // bounded; capability-gated or absent in production
```

Bounded boot diagnostics only, capability-gated, and absent in a production
image. It is never an authority path.

## What is deliberately absent

The absences are the proof the sketch meets its bar:

- **No path or name** as an authority argument — every subject is a `Cap`
  slot. There is no `open(path)`, no `connect(name)`, no `lookup(string)`.
- **No ambient handle** — nothing returns authority the caller did not derive
  from a capability it already held or from the measured plan.
- **No POSIX** — no `fork`, `exec`, `signal`, file descriptor, user/group, or
  environment.
- **No unbounded input** — every buffer, list, and count has a declared
  ceiling.
- **No inference** — nothing here evaluates a model, a similarity, or a
  nonzero-temperature operation; the legibility family emits facts, it does
  not reason over them (charter §2 item 7).
- **No raw device authority** — no arbitrary MMIO, port I/O, physical
  address, or unconstrained map (TM §6).
- **No dynamic kernel code** — no operation loads a module into ring 0.

## From sketch to Milestone 1

The Milestone 1 skeleton (scope §9) implements the boot, allocator,
exception, and timer substrate beneath this ABI, exposing only the smallest
subset needed for the first vertical slice: `domain_create`/`start`, one
`mem_*`, one `ipc_*` pair, `wait`, `fault_recv`, and `debug_write`. The
device, DMA, and full legibility families arrive with their milestones (M6,
M3). Each operation lands with the evidence-matrix rows that falsify it, so
the ABI grows only as fast as its tests. This sketch is the shape those
signatures must keep; the charter's amendment procedure governs any change to
the shape, not merely to a signature.
