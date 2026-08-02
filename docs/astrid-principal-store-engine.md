# Astrid Principal Store Engine Realization

This implementation companion to
[Astrid Principal Store](astrid-principal-store.md) records the executable
engine, KV projection, native migration, durability boundary, and agent
working-set claim. The primary design remains authoritative for the logical
state and authority model.

## In-memory engine contract

The first `astrid-storage-engine` implementation refines the model behind a
thread-safe user-space API without selecting a persistent object encoding. It:

- accepts an injected `ObjectIdentity` implementation;
- binds semantic object kind and kind-scoped format version into identity;
- recomputes every declared object identifier before admission;
- stages and validates a complete immutable closure before root publication;
- rejects roots that do not name a typed `Commit` envelope;
- rejects known-stale compare-and-swap requests before they consume storage;
- publishes one linearizable principal-root generation under concurrent
  writers;
- captures a root and its deterministic closure under one read lock;
- preserves roots retained by other principals or explicit pins during garbage
  collection.

This engine is evidence about transaction semantics, not durability. It does
not claim recovery, disk atomicity, canonical format stability, encryption,
quota enforcement, or production placement. Those claims begin only with the
arena and root-journal backend plus the fault matrix in the evidence document.

## KV compatibility bridge

`astrid-storage::PrincipalKvStore` remains the whole-state compatibility oracle
used by differential tests. It implements the existing async `KvStore` surface
without changing callers. The bridge:

- requires an injected authority-aware resolver from namespace to a
  domain-bearing principal identifier;
- never derives authority by splitting an arbitrary namespace string;
- places every capsule namespace owned by one principal under the same
  principal root;
- represents values and indexes as the typed path
  `KvLeaf -> KvBranch -> NamespaceMap -> PrincipalState -> Commit`;
- replaces only the `kv` state component and preserves unrelated filesystem,
  audit, evidence, or future component references;
- retries exact-root conflicts from a new snapshot so concurrent mutations do
  not lose updates;
- keeps empty values distinct from missing keys and omits empty namespaces;
- accounts repeated visible values logically even when their immutable leaf
  object is physically shared.

The projection grammar is an internal version-one logical shape. Object
identity remains injected, and the adapter does not select a production digest,
serialized object framing, or disk layout.

The initial differential suite runs generated get, set, delete, exists, list,
prefix, clear, and compare-and-swap traces against `MemoryKvStore`,
`SurrealKvStore`, and the adapter. Each operation result and the complete
resulting namespace state must agree. Invalid raw namespaces and keys now have
the same `InvalidKey` class in the memory and persistent legacy backends.

The bridge is a compatibility oracle, not the intended production hot path.
Each mutation currently reconstructs the complete in-memory KV projection,
which is linear in that principal's KV state.

The native runtime instead uses `TreeKvStore`, a content-addressed persistent
AVL tree over composite namespace/key bytes. Its fanout is bounded, sorted
inserts remain height-balanced, point reads touch one search path, and a point
mutation copies only that path plus a constant number of rotation and root
envelope objects. A 256-key durable regression constrains one replacement to at
most 16 new objects, while generated point/range/CAS/clear traces compare the
tree against an ordered-map oracle. Root conflicts restart from current state,
so compare-and-swap and quota checks remain linearizable under concurrent
writers.

The KV contract, memory/scoped stores, compatibility oracle, and persistent tree
are unconditional. `legacy-surrealkv` gates only the legacy reader and
migrator. The former `kv` gate is removed because runtime KV is not optional and
the migration reader has its own precise name. `legacy-surrealkv` can be removed
when the supported migration window closes.

## Runtime cutover

Native kernel startup always opens the principal store. It is authoritative
state, not a configurable backend. Under the existing process singleton lock
startup:

1. pins the store, identity, owner-codec, and projection versions in
   `store.meta`, including the complete tagged identity of the frozen format
   specification;
2. persists that plain-text specification as an immutable `Evidence` object
   before any principal root and verifies it on every completed-store open;
3. imports the read-only legacy database in bounded pages, grouping every
   host-stamped capsule namespace under its validated principal and all
   kernel namespaces under an explicit system owner;
4. verifies a canonical entry digest independently for every owner;
5. flushes the durable engine and atomically publishes one global completion
   marker before the kernel can serve requests.

The legacy directory is never mutated. A partial destination is quarantined and
rebuilt; a completed destination is never re-imported. Migration history,
supported-version floor, transform, verification rule, and rollback status live
together in the ordered migration registry. Old executable transforms can move
to a standalone migrator when the supported floor advances.

No daemon or workspace setting can select the stale legacy representation.
Recovery accepts any frame addressable by the running process and uses fallible
allocation, so parser safety does not create a hidden deployment quota. The
same invalidatable `PrincipalProfileCache` supplies capsule runtime and storage
limits, so admin quota changes affect the next mutation. The default storage
budget is the largest positive TOML integer—reported as `unlimited`—and finite
operator budgets charge user-visible values plus canonical namespace/key bytes.
This keeps empty values from creating free, unbounded principal-controlled
metadata. Growth above the ceiling is rejected while an over-budget principal
may still delete or shrink state; host structural overhead remains governed by
operator pool capacity and watermarks.

## First durable host-file realization

`astrid-storage-engine::DurableEngine` is the first actual I/O realization of
the model. It uses one active append-only object arena and a separate
append-only root journal:

```text
objects.arena:
    repeated checksummed {
        physical_frame_version,
        tagged_object_identity,
        encoded_record_with_tagged_reference_identities
    }

roots.journal:
    repeated checksummed {
        principal_bytes,
        tagged_expected_root,
        tagged_replacement_root
    }
```

The encoded record is a versioned physical representation of `ObjectRecord`.
Each identity occurrence carries a non-zero algorithm code, non-zero
construction version, `u32` digest length, and digest bytes. Production
BLAKE3-256 is registered as `(1, 1, 32)`, while the persistent grammar can
carry 48-byte and longer successors without changing its frame layout. The
current engine intentionally supports one configured scheme and a 32-byte
in-memory `ObjectId`; that is an implementation boundary, not a disk-format
ceiling.

The arena is not the canonical export format. The durable survival unit is the
deterministically ordered owning closure plus selected evidence and the in-band
format-specification object. A live arena is a cache and placement of that
logical bundle. The native runtime pins a domain-separated BLAKE3 object
identity and canonical tagged `System | Principal(PrincipalId)` codec in
metadata; generic engines retain injected identities/codecs for tests and
future explicit transforms.

Commit order is:

1. verify identities, root expectation, the newly introduced closure frontier,
   encoding, and frame resource bounds without writing;
2. append every immutable object frame, including the commit frame, then flush
   the object arena once;
3. append and flush one root-journal compare-and-swap record;
4. update the in-memory root map, validated frontier, and disposable index.

The root-journal flush is the durable linearization point. `objects.index` is a
disposable recovery accelerator, never a third authority file. It contains a
checksummed checkpoint followed by checksummed deltas that cache:

- the exact object-arena prefix covered by the checkpoint; and
- tagged object identities and their physical arena locations.

Principal roots and validated closures are intentionally not cached. Reopen
always replays the authoritative root journal and verifies every final live
closure against identity-checked arena objects. A corrupt index therefore
cannot select a principal root or bless an invalid closure.

An index delta is appended only after the arena and root-journal durability
order above has completed. It does not add another flush to a commit. Explicit
engine flush and orderly shutdown flush the cache; a crash may therefore leave
the index behind the authoritative files without making either ambiguous.

On reopen, an index is usable only when its frame chain is canonical, its
identity scheme matches the store, its covered lengths do not exceed the
authoritative files, and its recorded physical locations still agree with the
corresponding arena frame headers. A clean exact-prefix match restores the
cached object-location index without scanning orphaned payloads. The root
journal and every final live closure are still replayed and verified. An
uncovered authoritative arena tail currently causes a complete arena rebuild;
incremental tail replay is a compatible future optimization. Any malformed,
corrupt, ahead-of-authority, or otherwise inconsistent index is discarded and
rebuilt from the arena. No index failure may prevent recovery that succeeds
without it.

Checkpoint replacement uses a same-directory temporary file and file flush.
Unix publishes it with atomic replacement plus a directory flush. Windows,
whose standard rename does not replace an existing file, rotates the old cache
through a backup name before publishing the new one. A crash in that window may
lose the cache and trigger authoritative recovery, but cannot lose logical
state. The cache format is not part of `export_closure` or the RÚNATAL promise
and may change or disappear without migrating logical state.

An interrupted mutation poisons the engine until authoritative recovery has
selected the durable prefix. The next operation performs that recovery in
process while retaining the singleton store lock, replaces the stale arena and
journal handles inside the existing engine, clears disposable decoded caches,
and then proceeds through the same `Arc` values already held by KV and content
projections. No daemon restart or projection reconstruction is required. When
the persistent cache cannot be used, recovery performs the complete
authoritative path:

- runs under the already-held exclusive process lock;
- scans and identity-checks every complete object frame;
- rebuilds the `ObjectId`-to-arena-offset index without retaining payloads;
- truncates an incomplete final frame, or a final frame with invalid physical
  magic/checksum only when no valid physical frame follows it;
- rejects invalid interior frames and every unsupported-version, resource,
  grammar, canonicality, identity, collision, or model failure with its file
  and byte offset;
- replays root records using the same model compare-and-swap transition and
  verifies the recorded generation;
- validates every final live root closure and then lazy-loads object payloads
  for point operations;
- during in-process recovery, flushes the selected arena prefix before the
  selected root-journal prefix so bytes left merely readable after an earlier
  failed flush cannot become usable without regaining durable order;
- flushes newly created directory entries on Unix.

Recovery work is bounded per foreground operation by an injected
`RecoveryRetryPolicy`. The default makes three attempts with 10 milliseconds
between retryable filesystem failures. Structural corruption and model errors
fail immediately. A later operation receives a new bounded attempt, so a long
ENOSPC or transient device incident remains loud while it exists but does not
permanently brick the process after the operator repairs it. The retry policy
is runtime behavior, not persistent format or principal capacity.

`RecoveryLimits` can impose an explicit parser allocation guard when an
embedding needs one. Native Astrid instead accepts every process-addressable
frame with fallible allocation, so this boundary is not a workspace, principal,
or per-file quota. Host-file support is excluded from
`target_family = "wasm"` while the portable model, in-memory engine, and
compatibility adapter remain available there.

Native boot recovery and every `TreeKvStore` operation that may read or mutate
the arena run on Tokio's blocking pool. Filesystem latency and writers waiting
on the engine mutex therefore consume blocking workers rather than parking the
asynchronous workers that schedule capsules and IPC.

The frozen byte-level specification is
[`astrid-principal-store-format-v1.txt`](astrid-principal-store-format-v1.txt).
It defines both frame magics, every field width and byte order, both exact
BLAKE3 derive-key context strings, all object/reference tags, identity
construction, current KV/content canonical grammars, and root-journal replay.
A deliberately primitive Python reader shares no parser or cryptographic code
with Rust; CI runs it against a Rust-produced store and requires it to verify
checksums, recompute object identities, replay roots, and validate live
closures. This is the minimum two-readers rule for any format called durable.

This realization deliberately has one active arena. Runtime KV, the disposable
persistent recovery index, live per-principal logical quotas, and proof-audited
generation replacement are integrated. It does not yet seal arenas, persist a
history-pin policy, expose root removal, drain GC receipts into the independent
kernel audit log, inject short writes or disk-full errors, encrypt erasure
domains, or select final export `BlobId` profiles. The engine-owned
transactional outbox now preserves each self-contained receipt until the audit
sink explicitly acknowledges it; composition still owns retry, backpressure,
and audit anchoring. Those claims remain attached to their evidence gates.

Live logical quota becomes a physical bound only after the durable compactor
runs. The compactor copies the closures selected by current principal roots and
explicit native retention roots into a replacement arena, writes a canonical
current-root snapshot, and publishes both files under a durable recovery
intent. The persistent index removes payload re-hashing from clean reopen;
compaction makes arena and journal size proportional to the selected retained
set. Heavy content workloads remain gated on operational scheduling,
accounting, independent-audit delivery, and measured compaction cadence even
though the logical format and engine mechanism exist.

The engine does not infer a history policy. Callers provide the identified
retention contract and exact extra roots for system objects, export/import
leases, active immutable read handles, legal holds, and operator pins. Current
principal roots are always included. Commit publication, liveness capture,
proof recheck, and generation replacement share one mutation fence, so a
dedup hit cannot be collected between closure validation and root publication.
The pass is sealed inside the engine: an observer or Tensor Logic adapter can
reject a plan but cannot implement the physical deletion capability.

## Why this matters particularly for agents

Agent workspaces are unusually expensive to copy and unusually valuable to
checkpoint. A single durable Linux realm may contain a source checkout, Rust
`target/` trees, package-manager caches, `node_modules/`, toolchains, model
artifacts, and a long-lived home directory. Most bytes remain unchanged across
an agent turn even when a build creates thousands of new files.

With immutable content-addressed objects, a warm turn admits only new or
changed chunks and metadata. Checkpoint publication is one root transition;
rollback is another root transition; a local fork initially shares the same
objects; and an incremental transfer sends only objects the receiver does not
already have. Work therefore scales primarily with the changed state, rather
than with the total size of the agent's world. This is a structural advantage
over recursively copying a workspace or serializing a whole VM image for every
turn.

This is an architectural complexity claim, not a benchmark result for the
in-memory reference engine. The durable implementation must measure cold
ingest, warm turn checkpoints, fork, rollback, incremental export, garbage
collection, and materialization on real Rust projects and persisted Linux
homes. It may lose on first ingest, tiny stores, cold random reads, or
high-entropy and independently encrypted data; those results must remain
visible rather than being averaged away.
