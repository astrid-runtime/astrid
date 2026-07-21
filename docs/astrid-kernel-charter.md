# Astrid Kernel Charter

Status: Milestone 0 exit artifact; binding on all native-kernel work

Last reviewed: 2026-07-21

Companions: [native-kernel scope](astrid-native-kernel.md),
[AI-native OS workplan](astrid-ai-native-os-workplan.md),
[driver domain contract](astrid-driver-domain-contract.md),
[Tensor Logic composition](astrid-tensor-logic-composition.md)

This charter states what the Astrid native kernel is, what may never enter it,
and the decisions that are now closed. It exists so that the kernel cannot
drift into a shape that gets the important things wrong. Wherever this charter
and convenience disagree, this charter wins; changing it requires the amendment
procedure in section 10, not a code review.

## 1. Identity

The Astrid native kernel is a capability microkernel whose only product is
enforced boundaries between mutually distrusting protection domains. It is
mechanism without policy: it routes, isolates, meters, revokes, and records.
It is dumb at the center and honest in its ledger.

Its authority model is Plan 9's namespace idea completed. In Plan 9, authority
is the shape of the world a process was given: it cannot open what its
namespace does not contain, because it cannot even name it. The Astrid kernel
generalizes that from file trees to typed capability objects and hardens it
from administrative trust to cryptographic proof. A domain's capability table
IS its world. There is no ambient authority to fall back on, no global
namespace to escape into, and no operation whose subject is a name rather than
a held handle.

Three lineages contribute, and their division of labor is permanent:

| Lineage | What it supplies | What it lacked |
|---|---|---|
| Plan 9 / Inferno | Per-process worlds; drivers as unprivileged servers; hosted and native duality; distribution by construction | Enforcement rooted in machine trust, not proof; no tenant that needed it |
| Object capabilities / seL4 | Possession-based authority; testable isolation claims; rights that only shrink | No portable substrate or component ecosystem |
| The symbolic thread (Leibniz to tensor logic) | A mind that can show its work, running over the system's own live self-description | A home whose facts are born true and enforced |

The kernel is the ground floor of that third inheritance without hosting any
of it. Every object in ring 0 is a typed fact with provenance, and the
kernel's single epistemic guarantee is that those facts are exactly the
enforced reality. The map cannot overclaim the territory, because the map is
what the territory is enforced against. Minds, models, reasoners, and
planners are tenants above; the reasoner proposes, ed25519 disposes, and
ring 0 is what disposal is made of.

## 2. The covenant: what may never enter ring 0

The following are excluded from ring 0 permanently. Each exclusion is a
design load-bearing wall, not a deferral:

1. **Application and product policy.** No websites, agents, LLM providers,
   USB classes, or tool semantics. Ring 0 does not know what a capsule does.
2. **The POSIX model.** No fork, users, groups, signals, file descriptors,
   environment variables, paths, or global filesystem namespace.
3. **Strings as authority.** No operation names its subject by path, URI,
   topic, or identifier. Authority is a held, unforgeable handle, always.
4. **Filesystems and databases.** Durable state is a user-space service over
   block and KV protocols. Ring 0 may anchor an audit root; it never
   interprets a record.
5. **Network protocols.** No TCP/IP, TLS, HTTP, or DNS. Ring 0 mediates
   device queues; protocol stacks are domain tenants.
6. **Wasmtime and all component execution.** A runtime memory-safety or
   code-generation defect terminates a ring-3 domain, never the kernel.
7. **Inference of any kind.** No learned weights, embeddings, similarity,
   nonzero temperature, heuristic scoring, or planning. The soundness
   fragment of tensor logic is its deterministic fragment, and ring 0 must
   live entirely inside determinism. The kernel hosts no part of the mind.
8. **Unbounded allocation.** No kernel object is created without charging a
   fixed, pre-sized pool. Exhaustion is a fallible result, never a panic and
   never a silent fallback.
9. **Dynamic kernel code.** No modules, JIT, eBPF-alikes, or runtime code
   loading in ring 0. The kernel that was measured at boot is the kernel
   that runs.
10. **Manifest trust.** A manifest, image note, or self-declaration is never
    authority. Only the measured boot plan and recorded capability
    derivations mint power.

Anything not on this list is not automatically admitted; section 3 is the
complete positive obligation set, and additions to it require amendment.

## 3. Obligations: what ring 0 must provide

- architecture boot, CPU initialization, physical and virtual memory, W^X;
- protection domains: page tables, task state, capability table, budgets,
  and one fault endpoint each;
- preemptive scheduling with bounded work and explicit domain budgets;
- IPC endpoints carrying bounded typed messages and explicit handle transfer;
- interrupt, timer, entropy, IOMMU, DMA mediation, reset, and watchdog;
- image measurement and verification; audit-root anchoring and attestation;
- **revocation completeness:** when a domain dies or a handle is revoked,
  every derived handle, mapping, DMA range, and reservation is reclaimed
  before the death or revocation is reported complete;
- **exactly-one death record:** a domain's termination produces one record
  on its supervisor's fault endpoint, carrying cause, final accounting, and
  the identity tuple. Restart, backoff, quarantine, and rollback are
  supervisor policy in the init/recovery domain, never kernel behavior;
- **legibility.** Kernel state is typed facts. The ABI includes, from
  version zero, capability-gated operations to enumerate a domain-visible
  projection of the object tables as typed relations and to subscribe to
  bounded relation deltas. Owner, type, direction, authority, provenance,
  budget, and lifecycle are first-class fields, aligned with the catalog
  model in [Tensor Logic composition](astrid-tensor-logic-composition.md).
  This is an ABI family, not a debug channel: the system ontology's base
  relations are emitted by the kernel because they ARE the kernel's state,
  never scraped from it after the fact. Reasoning over those relations
  happens in tenant capsules only.

## 4. ABI ground rules

1. The ABI is versioned before it is stable and private to the native host
   until two host consumers exist. Capsules continue to target
   `wasm32-unknown-unknown` and the `astrid:*` WIT worlds; native-kernel
   mechanics never leak into portable capsule contracts.
2. Handles are unforgeable indices into per-domain object tables. Transfer
   derives a new handle with an equal or smaller rights mask. Rights never
   widen, on any path, including supervision and recovery.
3. Every operation is fallible and total: any argument pattern returns a
   typed result or a typed fault. There are no undefined argument spaces.
4. Messages are bounded and typed. No operation takes or returns an
   unbounded list, string, or user-controlled length without a declared
   ceiling charged to the caller's budget.
5. **Serialization cleanliness (the unwritten chapter clause).** No kernel
   object's semantics may depend on shared address space as the only
   possible transport. Handles, messages, and capability derivations must
   remain meaningful under serialization, so that the network hop Plan 9's
   namespaces could not survive, and Astrid's signed capabilities were
   designed to survive, stays implementable without ABI redesign. This
   clause buys distribution-readiness only; it does not put networking,
   naming, or consensus in ring 0.
6. All user-supplied structures are copied and validated exactly once at the
   boundary, then trusted internally. ABI parsers are host-fuzzable by
   construction: `no_std`, pointer-width explicit, no kernel-global state.

## 5. Runtime-domain strategy

Ring 3 component hosts embed Wasmtime; the Component Model is the capsule
ABI and reimplementing its canonical ABI and resource semantics is not
credible. The execution mode decision is closed:

- **Pulley first.** The first component host interprets Wasmtime's portable
  Pulley bytecode. This avoids the executable-mapping, trap-delivery, and
  code-publication portions of Wasmtime's unstable custom-platform surface,
  preserves ISA portability, and is livable for the first proofs: the Realm
  programme demonstrated that interpreted substrates carry real workloads
  when the boundary is right.
- **AOT as verified cache, later.** Native AOT artifacts are an
  optimization admitted only behind the binding
  `source component hash + host ABI set + engine compatibility hash +
  target ISA -> compiled artifact identity`. The canonical `.capsule`
  archive remains the sole source and signature identity. A compiled
  artifact is never a silent substitute for the component hash.
- The Wasmtime custom-platform adapter is one pinned, isolated crate. Its
  version moves by explicit decision with a conformance rerun, never by
  routine dependency bumps.

## 6. Resource discipline

Ring 0 allocates from fixed pools sized at boot from the measured plan:
domains, endpoints, capability slots, message buffers, timers, and DMA
descriptors are all bounded up front. Every mint is fallible. Recovery
holds pre-reserved pool capacity so that teardown, death reporting, and
supervisor restart can always complete under global exhaustion. Exhaustion
of any pool is a reportable, attributable event, charged to a domain, and
visible through the legibility surface.

## 7. Fault semantics

The kernel is the monitor; init is the supervisor. Ring 0 detects, contains,
revokes completely, accounts finally, and reports exactly once. It never
decides whether to restart, how often to retry, when to quarantine, or which
slot to roll back to. The init/recovery domain is system TCB without
Wasmtime; its domain-creation authority is bounded by the measured boot
plan, so it is a constrained builder, not a capability mint. A fault in the
supervisor is itself reported, to the watchdog path, and the machine's last
resort is reset into the A/B recovery slot, never a wedged hang.

## 8. Evidence discipline

A property this charter claims is not held until a test would fail if it
were lost. The Realm programme's standard applies unchanged:

- negative properties are tested as first-class acceptance (forged handles,
  widened rights, out-of-range memory, replayed transfers, exhausted pools);
- every milestone's exit gate is executable, deterministic, and recorded
  with exact toolchain, image, and machine identity;
- measurements are recorded with raw samples and never promoted across
  boundaries (a native microbenchmark is never quoted as end-to-end
  latency);
- claims of compatibility, performance, or security not yet backed by an
  executable gate are stated as not yet held.

## 9. Naming

The ring-0 artifact is `astrid-native-kernel` (crate and workspace naming
per the [scope document](astrid-native-kernel.md)). The existing
`astrid-kernel` crate, the semantic capsule/event supervisor, is unchanged
and over time becomes the user-space `astrid-system` supervisor. The two
are different objects and are never referred to interchangeably in code,
docs, or commits.

## 10. Amendment

This charter changes only by a recorded ADR that names the clause, the
evidence that forced the change, and the property given up. Covenant items
(section 2) additionally require demonstrating that the excluded capability
cannot be provided by a ring-3 domain at acceptable cost, with measurements.
Convenience, schedule pressure, and dependency drift are not evidence.
