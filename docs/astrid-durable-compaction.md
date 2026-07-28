# Astrid Durable Compaction

Status: implemented engine mechanism; composition policy remains explicit

Tracks: [#1386](https://github.com/astrid-runtime/astrid/issues/1386)

Companions:
[Principal Store Engine](astrid-principal-store-engine.md),
[Refinery](astrid-refinery.md), and
[Format 1](astrid-principal-store-format-v1.txt)

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

## Retention is not inferred

Current roots are always live. Additional roots are a strictly ordered,
deduplicated set of `(reason, ObjectId)` facts covering whichever objects
composition has independently authorized, including:

- the Rosetta specification named by `store.meta`;
- system bootstrap and identity-migration evidence;
- active export, import, bulk-ingest, and placement leases;
- immutable read-handle closures;
- named rollback pins and legal holds; and
- operator-selected history roots.

No parent/Lineage edge retains history by accident. This engine mechanism does
not select current-only, keep-N, time-window, or hybrid history policy. The
policy object and roots make that decision inspectable and keep its accounting
separate.

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
4. publish and flush `compaction.intent`;
5. rename each active authority file to `.previous`, then promote its
   `.compacting` successor;
6. flush the directory and reopen the promoted pair;
7. rebuild the disposable `objects.index`;
8. remove old/private generations and flush;
9. remove `compaction.intent` last and flush again.

The marker is the recovery authority. Without it, private files are
unpublished remnants and the active pair wins. With it, recovery validates
available arena/root combinations, installs one complete pair that reconstructs
the same current roots, discards the stale index, and removes the marker only
after cleanup is durable. Logical roots do not change during compaction, so an
old arena can pair with the root snapshot and a compacted arena can pair with
the prior journal when both validate the complete selected closure.

Named fault injection covers:

- replacement files durable, intent absent;
- intent durable;
- arena backup and arena promotion;
- root-journal backup and root-journal promotion;
- promoted directory durable; and
- cleanup durable immediately before intent removal.

Every interruption requires dropping the poisoned engine instance. Reopen
recovers one complete authority pair, rebuilds the index, preserves every root
generation, and accepts the next compare-and-swap transition.

## Evidence

`GcPlanEvidence` owns the frozen fact snapshot, retention policy, and Tensor
Logic proof and names the condemned set through non-owning Evidence edges.
`GcCommitEvidence` binds that plan to commit-time facts, old/new physical
placement sets, and execution measurements.

The engine currently constructs and retains the plan inputs during replacement.
Before the compactor is scheduled automatically, the kernel integration must
atomically deliver the plan and commit receipt to the independent audit
outbox. The audit chain remains outside the store so storage corruption cannot
erase its own witness. No background scheduler may invoke destructive
compaction until that delivery path is wired and crash-tested.

## Operational measurements

Each run reports object and arena byte counts before and after replacement, the
number of condemned objects omitted, and the exact fact-snapshot identity.
Scheduler integration additionally accounts for bytes read/written, CPU time,
resident byte-time, device work, and retention byte-time under the common
Refinery resource authority.
