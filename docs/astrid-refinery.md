# The Astrid Refinery

Status: design contract, observer seam, and explicit engine compaction
mechanism. The resource-authority scheduler and audit-outbox drain must exist
before compaction runs automatically.

The Refinery is one bounded cold-path pipeline for work that already needs to
stream live stored bytes:

- integrity scrub;
- SHA-384 cross-hash attestation;
- bottom-k resemblance sketching;
- physical arena compaction;
- locality reordering;
- representation migration;
- future recompression; and
- optional contiguous representation materialization.

These are one operational machine: a frozen live snapshot is traversed under
one scheduler, one resource authority, and one evidence grammar. No subsystem
grows a private background loop.

## Authority split

Shared scheduling does not imply shared mutation authority.

Ordinary Refinery passes are observers. They receive bounded verified streams
selected by the engine and emit proposed Evidence or Derived records. They
cannot mutate roots, choose another principal, rewrite an ObjectId, publish a
trusted representation directly, or delete bytes.

Compaction is an engine-private operation. It may rewrite physical placement
and representation only while preserving every live logical ObjectId and
recoverable closure. The compaction mutation surface is sealed; an installed
capsule or registered observer cannot acquire it through configuration.

Conceptually:

```text
RefineryPass
    observe(snapshot, verified stream)
    -> proposed Evidence/Derived outputs

EngineCompactionPass
    consume(frozen liveness snapshot)
    -> atomically publish new physical placement
```

The Rust seam encodes that distinction in types rather than a runtime
`privileged` flag: `RefineryPass` receives only verified immutable records and
an untrusted proposal sink, while `EngineCompactionPass` has a private sealed
supertrait that external observers cannot implement.

## Pass identity

Every observer pass has a pinned descriptor:

```text
RefineryPassDescriptor {
    format_version
    transform_contract
    runtime_semantic_profile
    accepted_object_kinds
    output_contracts
    checkpoint_format
    maximum_expansion
}
```

The descriptor ObjectId participates in the derivation invocation. A pass
upgrade is a new descriptor unless it preserves every semantics-visible field
under the same registered contract.

Native integrity verification and compaction record their engine operation
version and format contract in evidence. Capsule transforms execute through
the ordinary deterministic sandbox and can become Muninn consumers.

## Scheduler

The scheduler works over immutable snapshot units, initially arena segments
and bounded root closures. Each work item records:

- snapshot/root and placement epochs;
- pass descriptor set;
- cursor or checkpoint;
- resource lease;
- retry count and failure state; and
- emitted evidence identities.

Passes are resumable and idempotent by invocation identity. A crash may repeat
bounded work but cannot publish half an Evidence object or partially replace
arena placement.

One failed observer pass does not block unrelated observers or make safe
compaction impossible. Policy may quarantine that pass while the remaining
pipeline proceeds. A failed compaction publication retains the old complete
arena and placement epoch.

## Resource budget

The Refinery does not own a second resource manager. It leases from Astrid's
common operator authority:

- CPU time;
- resident byte-time;
- read bandwidth and bytes;
- physical writes;
- device/GPU work when supported; and
- retained Evidence and Derived bytes.

Operators configure cadence, priority, quiet periods, maximum concurrent
leases, and per-pass ceilings. Maintenance sheds before principal-critical
work. Compaction may receive emergency priority under disk pressure without
allowing optional recompression or sketching to inherit that priority.

Sampling work for Muninn uses the same maintenance budget and audit shape.
One compaction cycle currently performs three complete fact captures: initial
planning, proof-time recheck, and the mutation-fence recheck. Scheduler budgets
therefore account for approximately three full store reads before the
replacement traversal, rather than pricing only the final rewrite.

## Registered initial passes

### Integrity scrub

Reads every selected frame and canonical object, verifies frame checksums,
identity, object grammar, references, and retained closure completeness, and
emits bounded scrub Evidence.

Latent corruption is reported while redundant or backup representations may
still exist. Scrub never treats a failed read as permission to delete the
object.

### SHA-384 cross-hash attestation

While canonical object bytes are already streaming, computes the SHA-384
cross-hash tree specified by the storage freeze decision and emits signed
Evidence binding the live BLAKE3 closure to that tree.

This adds CPU and Evidence bytes but no second full source traversal when
co-scheduled with scrub or compaction.

### Bottom-k sketching

Runs the pinned DF-1 resemblance transform over verified chunk bytes and emits
Derived sketch records. It is deliberately separate from ingest chunking.
Sketches never participate in the source ObjectId or semantic identity.

The selected descriptor retains 256 unsigned-lexicographic 128-bit scores.
The scheduler requests it only for multi-chunk Files; exact whole-object dedup
already handles empty and single-chunk content. The transform remains total for
those inputs so replay and independent verification never depend on scheduler
policy.

## Compaction as the representation-migration window

Compaction already reads every live object and writes surviving physical
state. During that traversal it may also:

- reverify frames and canonical object bytes;
- emit or refresh cross-hash and scrub evidence;
- compute missing sketches;
- order objects and index pages for observed stream locality;
- replace a physical representation with a better verified encoding;
- recompress cold data under a pinned representation contract; and
- materialize a contiguous whole-file representation for measured hot
  projection workloads.

The design promise is zero additional full traversal of live source bytes, not
zero marginal cost. Hashing, compression, Evidence objects, alternate
representations, and writes remain metered and reported.

At least one recoverable representation of every live ObjectId remains
reachable throughout publication. Compaction never exposes a window where the
new placement is authoritative before its complete closure is durable.
The binding catalog, dependency liveness, replacement order, and cost model are
fixed by [Exact-Byte Physical Representations](astrid-physical-representations.md);
Refinery passes do not define a second encoding path.

## Evidence shape

Every completed work batch emits an auditable record:

```text
RefineryBatchEvidence {
    snapshot_epoch
    placement_epoch_before
    pass_descriptors
    input_scope_digest
    completed_invocations
    failures
    resource_measurements
    derived_outputs
    placement_epoch_after
}
```

Observer output is proposed first and enters trusted state only through normal
identity, closure, contract, quota, and root-CAS validation.

Compaction records the exact old and new segment/placement sets. Optional
Tensor Logic explanations may audit relationships, but native liveness and
publication fences remain enforcement.

## Interaction with garbage collection

GC determines the liveness snapshot; compaction realizes it physically. Before
destructive collection ships, each batch has:

1. a `GcPlanEvidence` object binding the complete fact snapshot, condemned set,
   retention policy, and Tensor Logic proof;
2. a fence-held native liveness revalidation;
3. a commit-time check that the current snapshot digest equals the plan's
   snapshot digest; and
4. `GcCommitEvidence` referencing the plan by ObjectId and binding the actual
   placement transition.

The commit fails closed if the digest differs. A proof for one plan can never
be attached to another deletion. The plan owns its fact snapshot, retention
policy, and proof so the receipt's owning closure retains everything needed to
replay the deletion explanation; condemned-object edges stay non-owning.

Before intent publication, the engine durably prepares that complete evidence
closure in its transactional GC outbox. The intent names the receipt and exact
destination placement. Recovery may install only that placement and makes the
bundle ready before cleaning the old generation. Automatic scheduling remains
disabled until kernel composition can durably append and acknowledge each
ready bundle in the independent audit chain.

## Acceptance

- All initial observer passes run through one scheduler and resource authority.
- No observer pass can acquire compaction mutation authority.
- Work resumes from a bounded checkpoint after a crash.
- Repeating a completed invocation produces no conflicting Evidence.
- One failing optional pass does not block unrelated work.
- Compaction failure preserves the complete old placement.
- Compaction never collects the final recoverable representation of a live
  ObjectId.
- Co-scheduled scrub, cross-hash, and sketch passes require one live-byte
  traversal.
- Resource evidence distinguishes bytes read, bytes written, CPU, resident
  byte-time, and retained outputs.
- GC commit rejects a plan whose fence-held snapshot digest changed.
