# Astrid Kernel Architecture Decision Records

Status: Milestone 0 exit artifact; the concrete mechanism choices under the charter

Last reviewed: 2026-07-21

Companions: [kernel charter](astrid-kernel-charter.md),
[threat model](astrid-kernel-threat-model.md),
[requirement-to-evidence matrix](astrid-kernel-evidence-matrix.md),
[native-kernel scope](astrid-native-kernel.md)

The charter sets the invariants; the threat model says what we defend
against; the matrix says how each claim is falsified. This document records
the concrete mechanism decisions that live inside those constraints — the
choices where more than one design would satisfy the charter and one had to
be picked. Each record states context, the decision, the alternatives
weighed, and the consequences, so a later reader sees not just what was
chosen but what was rejected and why.

These are the seven decisions the [workplan](astrid-ai-native-os-workplan.md)
requires before the v0 ABI sketch: protection domains, capability object
representation, handle transfer, revocation, fault endpoints, scheduling,
and audit ordering. Each is numbered `ADR-K<n>` and referenced from the ABI
sketch and from evidence-matrix rows. An ADR changes only by the charter's
amendment procedure (charter §10): a superseding ADR names the record it
replaces and the evidence that forced the change.

The convention here is deliberately lightweight — a single decision log
rather than one file per record — because the seven are tightly coupled and
a reviewer needs to read them together. If the kernel later accumulates many
independent decisions, splitting to one-file-per-ADR is itself an ADR.

---

## ADR-K1: Protection domains

**Context.** The charter (§3) says a domain has a page table, tasks, a
capability table, budgets, and one fault endpoint, and (§2) that it is
smaller than a POSIX process: no fork, users, file descriptors, or global
namespace. The first machine is one CPU (scope §6.2). What remains to decide
is the domain's concrete shape and whether domains nest.

**Decision.** A protection domain is the unit of isolation and of authority,
represented by a fixed-layout kernel object holding: a page-table root, a
capability table (ADR-K2), a scheduling context (ADR-K6), a single fault
endpoint (ADR-K5), and a pool-charge account (charter §6). A domain is
**single-threaded in the v0 kernel** — one task, one instruction stream —
matching the one-CPU machine contract and the Realm actor model that already
proved a single-threaded guest boundary is sufficient for a first system.
Domains do **not** nest: there is no parent-owns-child address-space
containment. Supervision is a capability relationship (ADR-K5), not a
structural one. The init/recovery domain is an ordinary domain distinguished
only by the grants the measured boot plan derives to it (charter §7).

**Alternatives.** (a) POSIX-process-shaped domains with threads, fds, and a
namespace — rejected by the covenant; it is the exact surface the charter
excludes. (b) Nested domains with hierarchical address-space ownership
(à la some hypervisor designs) — rejected because it conflates the fault
tree with the authority tree, and the charter deliberately keeps supervision
a capability, not a containment; nesting would also make revocation
completeness (ADR-K4) reason about transitive containment rather than a flat
derivation graph. (c) Multi-threaded domains from v0 — deferred: SMP and
intra-domain concurrency are a scope-M7 concern, and admitting them now would
force the scheduler and capability table to be concurrent structures before
the single-hart boundary is even proven.

**Consequences.** The object is fixed-size and pool-allocated (REQ-MEM-1).
Single-threaded domains make the capability table and fault handling free of
intra-domain races in v0. Multi-threading later is an additive change to this
ADR, not a rewrite, because nothing here assumes single-threading in the
*authority* model — only in the execution model. Evidence: REQ-CAP-4,
REQ-MEM-4.

## ADR-K2: Capability object representation

**Context.** The charter requires unforgeable per-domain handles that carry a
rights mask and provenance, only ever shrink on transfer, and support both
scoped and complete revocation (charter §4, §7). Two mature designs exist and
pull in different directions: seL4's CNode plus capability-derivation tree
(CDT), where revocation walks the tree; and EROS's version/allocation counts
on objects, where bumping a count invalidates every outstanding capability in
O(1) without a walk.

**Decision.** A capability is an entry in a domain's fixed-size capability
table: `{ object handle, rights mask, derivation link }`. The referenced
kernel object carries a **generation counter**. A capability entry is valid
only if its recorded generation matches the object's current generation —
the EROS insight, giving O(1) mass invalidation by generation bump. For
**scoped** revocation (revoke everything derived from one capability without
destroying the object), the derivation link threads a parent→children graph
that is walked incrementally under the zombie/preemption-point discipline
(ADR-K4). The table index is unforgeable because it is never a pointer and
never leaves the kernel; user space names capabilities only by table slot,
and the kernel resolves slot→entry→generation-checked object.

**Alternatives.** (a) Pure seL4 CDT — rejected as the *sole* mechanism
because whole-object destruction then always costs a tree walk, and the
common case (a domain dies, all its capabilities to a destroyed object must
die) should be O(1). (b) Pure EROS generation counts — rejected as the sole
mechanism because it cannot express scoped revocation of a sub-delegation
while keeping the object alive, which the charter's attenuated-delegation
model needs. (c) Sparse-capability / password capabilities (unguessable
bit-strings, no table) — rejected: they resist revocation and audit, and the
charter's legibility requirement wants capabilities enumerable as typed
relations, which a per-domain table gives directly.

**Consequences.** The hybrid pays one generation compare per capability use
(cheap) and keeps a derivation link per entry (one pool slot). Mass
invalidation on domain/object death is O(1); scoped revoke is a bounded walk.
The table *is* the base relation the legibility surface exports (charter §3):
owner domain, object, rights, provenance — no separate store (REQ-LEG-1).
Evidence: REQ-CAP-1, REQ-CAP-2, REQ-FAULT-2.

## ADR-K3: Handle transfer

**Context.** Capabilities move between domains via IPC (charter §4.2): rights
must only shrink, transfer must be explicit and bounded, and the result must
survive serialization (charter §4.5) so the same mechanism works across a
future network hop.

**Decision.** Transfer is an explicit operation carried in a bounded, typed
IPC message that names source slot(s) and a rights mask. The kernel creates a
new entry in the recipient's table whose rights are `requested ∩ source`
(never more), whose object handle and generation copy the source's, and whose
derivation link points at the source entry — extending the ADR-K2 graph so
the transferred capability is revocable both by object-generation bump and by
scoped revoke of its ancestor. There is no ambient or implicit transfer: a
capability the message does not name is not transferred, and a domain cannot
transfer a capability it does not hold. Transfer is by derivation, not by
move: the source retains its capability unless it explicitly also revokes its
own (the "dup then close-parent" shape the Realm's spawn record already
uses).

**Alternatives.** (a) Move semantics (transfer consumes the source) as the
default — rejected as the default because delegation, not handoff, is the
common case; move is expressible as transfer-then-revoke. (b) Rights widening
via a trusted broker — rejected outright; it violates the monotonic-shrink
invariant and there is no trusted-enough broker in the model. (c) Transfer of
raw object pointers or addresses — rejected: pointers do not survive
serialization and would forbid the network hop the charter reserves.

**Consequences.** All transfers are auditable derivation-graph edges, which is
what makes "when did this domain get this authority, from whom" a query
(charter identity; audit ordering ADR-K7). Serialization-clean because the
message names slots and masks, not addresses (REQ-ABI-5). Evidence:
REQ-CAP-2.

## ADR-K4: Revocation

**Context.** The charter (§7) specifies revocation as externally atomic and
internally preemptible, with self-referential revocation made
unrepresentable and completion reported only at the terminal state. The
mechanism must deliver that without the seL4-documented pathology where
revoking one's own authority mid-operation leaves partial state.

**Decision.** Revocation has two paths, both from ADR-K2. **Mass
invalidation** (object or domain death): bump the object generation; every
capability referencing the old generation is instantly invalid on next use,
O(1). The object's pool slots are then reclaimed by an incremental sweep that
runs under preemption points (the seL4 zombie discipline), during which the
object is in an explicit `dying` state — uninvocable, not observable as
alive, and not yet reported complete. **Scoped revocation** (revoke a
sub-delegation, keep the object): walk the derivation subtree from the named
capability, invalidating each entry, incrementally and preemptibly, leaving
the object and unrelated delegations intact. In both, **completion is gated
on the terminal state**: the death record (ADR-K5) or the revoke-complete
return is emitted only after the sweep finishes. Self-reference is
unrepresentable because the authority to tear down a domain is sourced only
from the measured boot plan (charter §7) and is never a capability in the
domain's own table — a domain cannot hold, and therefore cannot revoke, the
authority by which it is being destroyed.

**Alternatives.** (a) Fully synchronous atomic revoke (no preemption) —
rejected: revoking a large subtree is unbounded work and would block the
single hart, violating the scheduler's bounded-work rule (ADR-K6). (b)
Deferred/lazy reclamation (mark now, collect later) — rejected for the
security-relevant case because it reopens the stale-reference window the
threat model closes (cf. the IOTLB lazy-invalidation class, TM §6); the
generation bump makes *invalidation* immediate even though *reclamation* is
incremental. (c) Leaving self-referential edge cases to "avoid by
construction at user level," as seL4 documents — rejected: the charter's
standard is to make them unrepresentable in the kernel, not to warn user
space.

**Consequences.** Invalidation is immediate (no stale-authority window);
reclamation is bounded and preemptible (no DoS on the hart); partial state is
never observable (REQ-FAULT-1); self-revocation cannot occur (REQ-FAULT-3).
The generation-bump/derivation-walk split is exactly the ADR-K2 hybrid paying
off. Evidence: REQ-FAULT-1, REQ-FAULT-2, REQ-FAULT-3.

## ADR-K5: Fault endpoints

**Context.** The charter (§7) requires exactly one death record per domain
termination, delivered to a supervisor, with the delivery slot reserved at
domain creation and re-parenting to the watchdog if the supervisor is dead.
The open sub-question the threat model flagged: does a faulting domain block
(seL4 synchronous rendezvous, no buffer to overflow) or does the record
queue (Erlang async, unbounded mailbox we cannot afford)?

**Decision.** Each domain has one fault endpoint, a kernel object. Its
supervisor holds a receive capability to it, established by the measured boot
plan or by an explicit supervision grant (never self-held — see ADR-K4).
Death delivery is **asynchronous into a single reserved slot**: at domain
creation, one death-record slot is minted from the recovery pool and bound to
the fault endpoint, so delivery never allocates and never fails for want of
capacity (charter §6, §7). This is the reserved-slot resolution of the
synchronous-vs-async question — it takes the async model's non-blocking
property (a dying domain does not wait on a live supervisor) without the
unbounded mailbox, because the mailbox is exactly one slot and it already
exists. If the supervisor is itself dead when the record lands, the record
re-parents up the supervision chain together with the supervisor's own death
record, terminating at the watchdog, which is guaranteed live by the boot
plan.

**Alternatives.** (a) Synchronous rendezvous (seL4 fault-handler model): the
faulting domain's thread blocks until the handler receives — rejected
because a dead domain has nothing left to block, and it couples liveness of
teardown to liveness of the supervisor. (b) Unbounded queue (Erlang monitor
model) — rejected: no unbounded allocation in ring 0 (charter §2). (c) Fault
handled inline in the faulting domain (signal-handler style) — rejected: it
is the POSIX signal model the covenant excludes, and a domain cannot be
trusted to handle its own fault.

**Consequences.** Exactly-once delivery is structural: one slot, minted once,
consumed once (REQ-FAULT-4, REQ-FAULT-5). Teardown liveness is independent of
supervisor liveness. The watchdog is the guaranteed terminal supervisor,
which is why the boot plan must reserve it. Evidence: REQ-FAULT-4,
REQ-FAULT-5, REQ-MEM-3.

## ADR-K6: Scheduling

**Context.** The charter requires preemptive scheduling with bounded work and
explicit per-domain budgets; the first machine is one CPU (scope §6.2). The
Realm program already meters guest work as fuel, and the reserved-capacity
rules (charter §6) mean CPU, like memory, must be an accountable resource.

**Decision.** CPU time is a **capability**: a scheduling context object
(period + budget) that a domain must hold to run, in the shape seL4's MCS
kernel validated. The scheduler is single-hart, preemptive, and
priority-ordered with budget enforcement: a domain runs while its scheduling
context has budget; budget exhaustion preempts it and raises a bounded
timeout condition its supervisor can observe. Kernel operations that could
run long (revocation sweeps, ADR-K4) are the preemptible work the budget
bounds — the same preemption points serve scheduling and revocation.
Reservation: the recovery and watchdog domains hold scheduling contexts that
guarantee them CPU even under contention, mirroring the reserved memory pool.

**Alternatives.** (a) Fixed-priority preemptive without budgets (classic
RTOS) — rejected: it gives no accountable CPU resource and lets a
high-priority domain starve others, with no capability to attenuate on
delegation. (b) Fair-share / CFS-style — rejected: non-deterministic and
policy-heavy for a first kernel, and the charter wants determinism at the
enforcement layer. (c) Cooperative yielding (the Realm's current
between-slice model) — rejected for the kernel: it cannot bound a malicious
domain that never yields, which the threat model requires. The Realm's
cooperative model is fine *inside* a domain; the kernel between domains must
preempt.

**Consequences.** CPU is delegable and attenuable exactly like every other
authority — a child scheduling context is a shorter budget, never a longer
one (charter's recursive-attenuation principle). Budget exhaustion is a
bounded, observable event (matches the MCS timeout-exception design). Single
hart now; SMP is a scope-M7 change to this ADR. Evidence: REQ-MEM-3 (reserved
CPU for recovery), REQ-FAULT-6 (infinite loop → bounded teardown).

## ADR-K7: Audit ordering

**Context.** The charter (§3, §7) says ring 0 anchors a sequence or root hash
and never interprets a record; the existing Astrid audit chain is a
BLAKE3-sealed, ed25519-signed chain built in user space. The decision is what
ordering guarantee ring 0 provides and where the cryptographic chain lives.

**Decision.** Ring 0 stamps a **monotonic total order** on auditable
cross-domain events (capability derivations, domain lifecycle, fault records)
via a single kernel-held sequence counter, and anchors integrity by
maintaining a running root: each stamped event advances a hash accumulator
whose current value ring 0 will attest but never parse. The **cryptographic
chain itself is built in user space** by the audit system-host domain (T3),
which reads the ordered event stream, seals each entry with BLAKE3 over the
prior, and signs with ed25519 — unchanged from the existing Astrid audit
design. Ring 0 guarantees order and non-gap (every sequence number is
accounted); user space guarantees tamper-evidence and authenticity. The two
compose: a verifier checks the user-space chain against the ring-0-attested
root, so a compromised audit domain cannot silently drop or reorder events
without the root diverging.

**Alternatives.** (a) Full audit chain in ring 0 (kernel does BLAKE3 +
ed25519 over records) — rejected: it puts record interpretation and crypto
policy in ring 0, violating the covenant, and bloats the TCB. (b) Ordering
left entirely to user space — rejected: a user-space-only order cannot prove
non-gap across a compromised audit domain; the kernel must own the counter
and root for the chain to be trustworthy under T3 compromise. (c) Per-domain
independent sequences with no global order — rejected: cross-domain causality
(who granted what to whom, when) needs a total order, which the legibility
and delegation-audit stories both depend on.

**Consequences.** Ring 0's audit surface is a counter and a hash accumulator
— minimal TCB, no record parsing (charter §2). The existing user-space chain
is reused wholesale. "When did the system learn X, from whom" and "prove the
audit log has no gaps" both become checkable (the afterword's derivation-on-
the-chain claim, and the delegation-audit identity). This is the seam where
the kernel's ground truth meets the user-space reasoner and mouth: the
ordered, rooted event stream is what a later reasoner reads as fact. Evidence:
REQ-LEG-1 (single source of truth), and the audit-chain conformance carried
by the existing audit tests.

---

## Cross-cutting consequence

The seven decisions share one spine: **the derivation graph** (ADR-K2/K3),
**the generation counter** (ADR-K2/K4), and **the reserved pool**
(ADR-K1/K5/K6) recur across capability integrity, revocation, fault
delivery, and scheduling. This is intentional — a small number of mechanisms
carrying many properties is easier to verify and to fuzz than one mechanism
per property. The v0 ABI sketch (next workplan item) exposes exactly these:
domain, capability-table slot, scheduling context, fault endpoint, and the
audit-ordered event surface — and nothing else that would require a path, a
string subject, or an ambient handle.
