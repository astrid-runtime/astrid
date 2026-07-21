# Astrid Kernel Requirement-to-Evidence Matrix

Status: Milestone 0 exit artifact; the falsifiability contract for the kernel

Last reviewed: 2026-07-21

Companions: [kernel charter](astrid-kernel-charter.md),
[threat model](astrid-kernel-threat-model.md),
[native-kernel scope](astrid-native-kernel.md)

The charter and threat model make claims. This document is the rule that a
claim is not held until a test would fail if the property were lost. It maps
every load-bearing security and correctness property to concrete, executable
evidence, and states which milestone must produce that evidence. It is the
charter's evidence discipline (charter §8) made into a checklist a reviewer
can audit against CI.

## How to read this

Each row is one property. Columns:

- **ID** — stable identifier (`REQ-<area>-<n>`), referenced from ADRs, PRs,
  and test names.
- **Property** — the invariant, phrased so its negation is a concrete bug.
- **Source** — the charter clause or threat-model section that asserts it.
- **Evidence** — the executable check whose failure disproves the property.
- **Kind** — one or more of `host` (runs off-target on an ordinary build),
  `qemu` (runs in the QEMU serial-assertion harness), `fuzz`
  (coverage-guided), or `build` (a property of the image/artifact pipeline).
  A row combines kinds with `+` when its evidence genuinely spans stages
  (for example `host+qemu` when a property is proven both off-target and in
  the harness); each named kind is an independent obligation for that row.
- **Gate** — the milestone whose exit this row blocks (M1–M6, per the
  [scope document](astrid-native-kernel.md) execution plan).

A property with no evidence column filled is not a property; it is a wish,
and must not be described as held in any doc, PR, or release note.

Two rules govern the whole matrix. **Negative-first:** for every capability,
the evidence includes the denial case, not only the success case — a handle
that must not forge, a mint that must fail closed, a device that must not
reach ungranted memory. **No silent green:** a test that cannot fail (a
skipped case, a stubbed assertion, an unreachable branch) is treated as a
missing test, and CI must surface it as such.

## 1. Capability and handle integrity

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-CAP-1 | A handle is an unforgeable per-domain table index; a fabricated index is rejected | charter §4.2; TM §4 | Domain presents an out-of-range and a plausible-but-unowned index → typed fault, no object access | qemu | M2 |
| REQ-CAP-2 | Handle transfer only ever narrows rights | charter §4.2; TM §4 | Transfer with a widened rights mask → rejected; transferred handle's rights ⊆ source rights, asserted | qemu | M2 |
| REQ-CAP-3 | No operation names its subject by string/path | charter §2.3 | ABI surface review + a compile-time check that no syscall takes a path/URI argument | build | M1 |
| REQ-CAP-4 | A manifest claim is never authority | charter §2.10; TM §8 | A domain image asserting a grant not in the measured plan → grant absent at runtime | qemu | M3 |

## 2. Memory and pool discipline

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-MEM-1 | Per-class pools have fixed slots; a class cannot fragment into starvation | charter §6; TM §4 | Adversarial alloc/free churn on one class → mint fails only when that class is genuinely full, never due to layout | host+qemu | M2 |
| REQ-MEM-2 | Every mint is fallible and attributable | charter §6 | Exhaust each pool → typed failure charged to a domain, visible via legibility, no panic | qemu | M2 |
| REQ-MEM-3 | Recovery capacity is reserved and never consumed by normal operation | charter §6, §7; TM §9 | Under global exhaustion, teardown + death report + supervisor restart still complete | qemu | M2 |
| REQ-MEM-4 | W^X holds for all domain mappings | scope §4.2; TM §5 | Attempt to map a page writable+executable → rejected; no domain has a W+X mapping, asserted | qemu | M2 |
| REQ-MEM-5 | A domain cannot read another domain's memory | charter §1; TM §4 | Cross-domain read attempt → fault; pooling-reuse residual read returns zeroed, not stale (cf. CVE-2026-34988) | qemu | M2 |

## 3. Revocation and fault semantics

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-FAULT-1 | Revocation is externally atomic: no partially-torn-down object is observable | charter §7; TM §4 | Interrupt a large revoke mid-teardown → in-progress objects are uninvocable; completion reported only at terminal state | qemu | M2 |
| REQ-FAULT-2 | Revocation completeness: every derived handle, mapping, DMA range, reservation reclaimed before completion | charter §7; TM §4,§6 | Post-revoke sweep finds zero live references to the dead domain's resources | qemu | M2 |
| REQ-FAULT-3 | Self-referential revocation is unrepresentable | charter §7 | No capability path lets a domain revoke its own teardown authority; construction test asserts teardown authority is plan-sourced only | qemu | M2 |
| REQ-FAULT-4 | Exactly one death record per domain termination | charter §7 | Terminate a domain by trap, page fault, infinite loop, and explicit kill → exactly one record each, with cause + final accounting | qemu | M2 |
| REQ-FAULT-5 | Death-record delivery cannot fail for want of capacity | charter §7; TM §9 | Delivery slot reserved at domain creation; supervisor-dead → record re-parents to watchdog, none dropped | qemu | M2 |
| REQ-FAULT-6 | A component trap stays inside Wasmtime; a host-domain fault stays inside the domain | charter §2.6, §7; TM §5 | Component trap → invocation failure, host survives; runtime-host page fault/loop → domain teardown + restart, ring 0 survives | qemu | M3 |

## 4. ABI and parser boundary

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-ABI-1 | Every ABI operation is total: any argument pattern yields a typed result or typed fault | charter §4.3 | Exhaustive/`proptest` argument-space sweep per operation → no undefined behavior, no panic | host+fuzz | M2 |
| REQ-ABI-2 | User structures are copied and validated exactly once at the boundary | charter §4.6; TM §7 | TOCTOU test: mutate a user structure after the boundary → kernel operates on its validated copy only | qemu | M2 |
| REQ-ABI-3 | ABI parsers survive adversarial input | charter §4.6; TM §7 | Spec-driven (syzkaller-style) + `cargo-fuzz` corpus in CI → no OOB, no panic, no hang | fuzz | M2 |
| REQ-ABI-4 | No message carries an unbounded length | charter §4.4 | Every ABI struct has a declared ceiling; a message exceeding it → rejected before allocation | host | M1 |
| REQ-ABI-5 | Handles/messages/derivations remain meaningful under serialization | charter §4.5 | Serialize→deserialize round-trip of the object graph preserves identity and rights; no pointer-identity dependence | host | M2 |

## 5. Runtime-host containment

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-RT-1 | A runtime-host compromise reaches only its domain's grant union | charter §1, §7; TM §5 | A host domain granted set S attempts an operation outside S → denied at ring 0 regardless of host cooperation | qemu | M3 |
| REQ-RT-2 | Component fuel/memory/deadline limits are enforced | scope §4.3; TM §5 | A capsule exceeding fuel, memory, or deadline → bounded failure, not host impact | qemu | M3 |
| REQ-RT-3 | Pulley Component-Model conformance before any bare-metal dependence | charter §5; TM §5 | Astrid component conformance corpus passes under a Pulley-configured engine on a host build (the charter's gate) | host | M3 |
| REQ-RT-4 | Co-located capsules do not exceed their domain's authority union | charter §7; TM §5 | Two capsules in one host → neither reaches a grant held by neither; image builder reports the union | qemu+build | M3 |

## 6. Device, DMA, and IOMMU

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-DMA-1 | A driver domain has no direct DMA in the mediated-queue phase | driver contract; TM §6 | Driver capsule attempts DMA outside the mediated queue → no such capability exists | qemu | M6 |
| REQ-DMA-2 | DMA mappings are minted only for broker-owned buffers | charter; TM §6 (ASPLOS 2016) | A device cannot map live kernel/other-domain memory; only shadow buffers are mappable | qemu | M6 |
| REQ-DMA-3 | IOTLB invalidation is strict/synchronous | TM §6 (DATE 2024) | Freed/remapped page is unreachable by the device immediately; no lazy-window access | qemu | M6 |
| REQ-DMA-4 | ATS is disabled for untrusted devices | TM §6 (Google PCIe 2017) | A device asserting already-translated on a TLP → translation still enforced | qemu | M6 |
| REQ-DMA-5 | Descriptor/ring/config data from a device is validated before use | TM §3,§6 (RT-Thread, TDX spec) | Malformed virtqueue descriptors (crosvm-style corpus) → rejected, no memory corruption | fuzz | M4 |
| REQ-DMA-6 | The IOMMU group, not the device, is the unit of assignment | TM §6 | Two devices in one group cannot be split across trust domains; assignment test enforces group atomicity | build+qemu | M6 |

## 7. Boot, artifact, and update integrity

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-BOOT-1 | Deterministic, reproducible image build | scope §5.1; TM §8 | Same source+env → bit-identical image (`SOURCE_DATE_EPOCH`); a diffing CI job asserts it | build | M1 |
| REQ-BOOT-2 | Malformed boot data fails closed | scope M1 gate; TM §2 | Corrupt boot structures → structured crash record, never silent hang or continued boot | qemu | M1 |
| REQ-ART-1 | A compiled artifact is never a silent substitute for the component hash | charter §5; TM §8 | Artifact identity binds source hash + ABI set + engine hash + ISA; a mismatched artifact → refused | build | M3 |
| REQ-ART-2 | An unverified/tampered artifact is inert | charter §2.10; TM §8 | Poisoned-provenance artifact (sigstore/in-toto verify fails) → not executed | build | M4 |
| REQ-UPD-1 | Rollback refused: monotonic version + active revocation | TM §2,§9 (BlackLotus, TUF) | A validly-signed older artifact → refused by revocation, not merely out-ranked | build+qemu | M4 |
| REQ-UPD-2 | Freeze/mix-and-match/endless-data refused | TM §9 (TUF) | Stale-past-expiry metadata, cross-time file mix, oversized payload → each refused | build | M4 |
| REQ-UPD-3 | A/B slot integrity survives interrupted update | scope M4 gate; TM §9 | Torn write / bad slot / interrupted update → recovery path intact, no widened authority | qemu | M4 |

## 8. Legibility and channels

| ID | Property | Source | Evidence | Kind | Gate |
|---|---|---|---|---|---|
| REQ-LEG-1 | Kernel state is the single source of truth; no mirrored fact base | charter §3; TM §10 | Legibility relations are read directly from object tables; a test asserts no second store exists to drift | host+qemu | M3 |
| REQ-LEG-2 | Every relation is capability-gated and domain-visible only | charter §3; TM §10 | A domain enumerates only its visible projection; cross-domain relation read → denied | qemu | M3 |
| REQ-LEG-3 | Timing-correlated relations are rate-limited and quantized | charter §3; TM §10 (ProcHarvester) | A relation carrying counters exposes quantized values at a bounded rate; raw high-resolution timing not observable | qemu | M3 |
| REQ-CHAN-1 | Flush-on-domain-switch primitive exists and is exercised | TM §10 (Ge/Heiser) | Domain switch performs the deterministic flush; a test asserts the flush occurs on every switch | qemu | M2 |
| REQ-CHAN-2 | Residual microarchitectural timing risk is documented, not claimed closed | charter §8; TM §10 | The support-policy doc records timing channels as a known residual with the time-protection roadmap | build | M1 |

## 9. Coverage obligations

Two properties govern the matrix itself, and their violation is a process
bug, not a kernel bug:

- **REQ-META-1 (traceability):** every security claim in the charter and
  threat model maps to at least one row here; a claim with no row is a
  documentation defect caught in review.
- **REQ-META-2 (no silent cap):** where any test bounds its own coverage
  (sampling, top-N, no-retry), it logs what it dropped, so a partial run is
  never mistaken for a complete one (charter §8).

This matrix is itself amended by the charter's amendment procedure (charter
§10): a new claim adds a row before it may be described as held, and a
removed property removes its row with the ADR that justifies it.
