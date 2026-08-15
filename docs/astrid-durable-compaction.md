# Astrid Durable Compaction

Status: implemented engine mechanism; composition policy remains explicit

Tracks: [#1386](https://github.com/astrid-runtime/astrid/issues/1386)

Companions:
[Principal Store Engine](astrid-principal-store-engine.md),
[Refinery](astrid-refinery.md), and
[Format 1](../crates/astrid-storage/formats/principal-store-v1.txt)

## Authority boundary

Compaction is the only storage pass that removes physical object frames. It is
therefore an engine-owned `EngineCompactionPass`, sealed against external
implementations. Observer passes may inspect verified objects and propose
Evidence or Derived records; they never receive an arena, root-journal,
placement, or deletion handle.

The operation binds:

- a pinned native operation-contract `ObjectId`;
- an identified retention-policy Evidence object;
- every current principal commit;
- typed system, pin, lease, handle, quarantine, and audit roots supplied by
  native composition;
- the complete object universe and every typed reference relation;
- the native condemned set;
- a deterministic Tensor Logic proof over that exact fact snapshot; and
- a fence-held byte-exact recheck immediately before replacement.

Tensor Logic is an auditor. Native closure traversal computes liveness, the
engine mutex enforces the transition, and a changed snapshot rejects the plan.

### Fact-snapshot grammar

The generic Evidence record identified as `GcFactSnapshotId` has empty
references, metadata class, logical size zero, and these canonical bytes:

```text
"astrid-gc-fact-snapshot-v1\0"
ObjectId operation_contract
ObjectId retention_policy
u64 current_root_count
    repeated in principal-byte order:
        u64 principal_length
        u8[] principal
        u64 root_generation
        ObjectId commit
u64 retained_root_count
    repeated in (reason, ObjectId) order:
        u8 reason
        ObjectId root
u64 object_count
    repeated in ObjectId order:
        ObjectId object
        u64 reference_count
        repeated in canonical reference-label order:
            u64 label_length
            u8[] label
            ObjectId target
            u8 reference_kind
```

All integers are little-endian and every ObjectId in this construction is the
current 32-byte in-memory digest. Retained-root reason codes are: system `0`,
explicit pin `1`, operation lease `2`, read handle `3`, quarantine `4`, and
audit custody `5`. Reference-kind codes are the frozen ObjectRecord codes.
This snapshot records all relations for replay and explanation; only owning
edges plus the selected roots determine native liveness.

The format-1 snapshot proves reachability only. A future policy that
discriminates by object kind, class, age, or another absent attribute requires
an explicitly extended fact grammar and a new `GcFactSnapshotId` derivation
contract; it cannot reinterpret this snapshot.

## Retention is not inferred

Current roots are always live. Additional roots are a strictly ordered,
deduplicated set of `(reason, ObjectId)` facts covering whichever objects
composition has independently authorized, including:

- the RÚNATAL specification named by `store.meta`;
- system bootstrap and identity-migration evidence;
- active export, import, bulk-ingest, and placement leases;
- immutable read-handle closures;
- named rollback pins and legal holds; and
- operator-selected history roots.

No parent/Lineage edge retains history by accident. This engine mechanism does
not select current-only, keep-N, time-window, or hybrid history policy. The
policy object and roots make that decision inspectable and keep its accounting
separate.

The raw engine contract remains policy-neutral and can therefore omit any
standalone object. Native runtime composition must instead construct retention
through `RuntimePrincipalStore::prepare_compaction_retention`. That boundary
adds every object in the single runtime-bootstrap registry as a typed `System`
root and identity-checks each record before returning a retention value. A
missing RÚNATAL specification or future registered bootstrap object therefore
fails before a destructive plan can be verified, rather than after compaction
at the next reopen.

## Dedup-resurrection and handle fences

Commit preparation, root publication, liveness capture, and physical
replacement share the durable engine mutation mutex. A committing closure is
therefore either visible to the collector and copied, or publishes after
replacement into the new arena. It cannot publish a root into an object
discarded between lookup and commit.

An immutable handle whose reads may outlive a root replacement must contribute
its selected `ObjectId` as an additional root before leaving the same ordering
boundary, and release that lease only after its final read. The current durable
engine exposes the explicit retained-root input; adapters that add independent
positional handles must wire lease acquisition before they may use compaction.

## Replacement protocol

The stable authority names are `objects.arena` and `roots.journal`. A
compaction writes and verifies private replacements first:

1. copy every selected live closure into `objects.arena.compacting`;
2. write the complete current-root map as the first
   `roots.journal.compacting` snapshot frame;
3. flush both replacements and their directory entries;
4. construct the self-contained plan/commit evidence bundle, write it as a
   private `gc-outbox/*.prepared` file, and flush the outbox directory;
5. publish and flush `compaction.intent`, naming the receipt, pinned operation
   contract, and exact destination placement;
6. rename each active authority file to `.previous`, then promote its
   `.compacting` successor;
7. flush the directory and reopen the promoted pair;
8. recompute its physical placement identity and require an exact match with
   the intent;
9. rebuild the disposable `objects.index`;
10. rename the evidence bundle to `*.ready` and flush the outbox;
11. remove old/private generations and flush; and
12. remove `compaction.intent` last and flush again.

The marker and prepared receipt jointly form the recovery authority. Without
the marker, private replacement files and prepared evidence are unpublished
remnants and the active pair wins. With it, recovery requires the named
evidence bundle, validates available arena/root combinations, and installs
only the pair whose full physical placement identity equals the receipt. A
merely valid old pair is not an admissible fallback after intent publication.
Recovery marks the receipt ready before discarding old generations and removes
the intent only after cleanup is durable.

Named fault injection covers:

- replacement files durable, intent absent;
- evidence prepared, intent absent;
- intent durable;
- arena backup and arena promotion;
- root-journal backup and root-journal promotion;
- promoted directory durable; and
- evidence ready for independent delivery; and
- cleanup durable immediately before intent removal.

Every interruption poisons mutation until the engine's next operation runs
bounded in-process recovery under the retained singleton lock. Recovery either
selects the exact receipted successor or fails closed. Successful recovery
rebuilds the index, preserves every root generation, leaves one ready receipt,
and accepts the next compare-and-swap transition through the original engine
handle.

## Evidence

`GcPlanEvidence` owns the frozen fact snapshot, retention policy, and Tensor
Logic proof and names the condemned set through non-owning Evidence edges.
`GcCommitEvidence` binds that plan to commit-time facts, old/new physical
placement sets, and execution measurements.

The engine outbox carries eight identity-verified records in fixed order:
fact snapshot, retention policy, Tensor Logic proof, plan, old placement, new
placement, measurements, and commit receipt. A bundle is not delivery-visible
while it is merely prepared. It becomes visible through
`pending_compaction_evidence` only after the exact destination placement is
durable. The kernel appends the bundle to the independent audit log and calls
`acknowledge_compaction_evidence` only after that append is durable.
Acknowledgement deletes the delivery copy, not evidence already anchored by
the audit sink.

The outbox is deliberately not the audit chain. It is a transactional delivery
buffer inside the singleton store directory. Audit remains independently
append-only so storage corruption cannot erase its own witness. No background
scheduler may invoke destructive compaction until kernel composition drains
this outbox and applies retry/backpressure policy.

### Physical-placement Evidence grammar

Each old/new placement is generic metadata Evidence with empty references and:

```text
"astrid-gc-placement-set-v1\0"
ObjectId operation_contract
u64 arena_bytes
u64 root_journal_bytes
[u8; 32] root_journal_digest
u64 object_count
    repeated in ObjectId order:
        ObjectId object
        u64 arena_frame_offset
        u64 arena_payload_length
        [u8; 32] arena_frame_checksum
u64 root_count
    repeated in principal-byte order:
        u64 principal_length
        u8[] principal
        u64 root_generation
        ObjectId commit
```

Integers are little-endian. The root-journal digest is BLAKE3 under derive-key
context `astrid gc placement root journal digest v1`; the Evidence prefix
versions that choice. Arena locations plus frame checksums bind every canonical
object frame and its ordering. Consequently the destination identity describes
the exact promoted authority pair, not merely an equivalent root map.

Execution measurements use prefix
`astrid-gc-transition-measurements-v1\0` followed by seven little-endian
`u64` values: objects before, after, and reclaimed; arena bytes before and
after; and root-journal bytes before and after.

## Operational measurements

Each run reports object and arena byte counts before and after replacement, the
number of condemned objects omitted, and the exact fact-snapshot identity.
Scheduler integration additionally accounts for bytes read/written, CPU time,
resident byte-time, device work, and retention byte-time under the common
Refinery resource authority.
