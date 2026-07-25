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

The `kv` Cargo feature no longer exists. The KV contract, memory/scoped stores,
compatibility oracle, and persistent tree are unconditional.
`legacy-surrealkv` gates only the legacy reader and migrator. It can be
removed when the supported migration window closes.

## Runtime cutover

Native kernel startup always opens the principal store. It is authoritative
state, not a configurable backend. Under the existing process singleton lock
startup:

1. pins the store, identity, owner-codec, and projection versions in
   `store.meta`;
2. imports the read-only legacy database in bounded pages, grouping every
   host-stamped capsule namespace under its validated principal and all
   kernel namespaces under an explicit system owner;
3. verifies a canonical entry digest independently for every owner;
4. flushes the durable engine and atomically publishes one global completion
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
    repeated checksummed { physical_frame_version, object_id, encoded_record }

roots.journal:
    repeated checksummed {
        principal_bytes,
        expected_root,
        replacement_root
    }
```

The encoded record is a versioned physical representation of `ObjectRecord`.
It is not declared to be the final canonical export format. The native runtime
pins a domain-separated BLAKE3 object identity and canonical tagged
`System | Principal(PrincipalId)` codec in metadata; generic engines retain
injected identities/codecs for testing and future explicit transforms.

Commit order is:

1. verify identities, root expectation, the newly introduced closure frontier,
   encoding, and frame resource bounds without writing;
2. append and flush non-commit immutable object frames;
3. append and flush the immutable commit frame;
4. append and flush one root-journal compare-and-swap record;
5. update the in-memory root map, validated frontier, and disposable index.

The root-journal flush is the durable linearization point. An interrupted
engine is poisoned and refuses both reads and writes until reopen. On reopen,
the engine:

- takes an exclusive process lock;
- scans and identity-checks every complete object frame;
- rebuilds the `ObjectId`-to-arena-offset index without retaining payloads;
- truncates only an incomplete final header or payload;
- rejects a complete checksum, grammar, canonicality, identity, collision, or
  model failure with its file and byte offset;
- replays root records using the same model compare-and-swap transition and
  verifies the recorded generation;
- validates every final live root closure and then lazy-loads object payloads
  for point operations;
- flushes newly created directory entries on Unix.

`RecoveryLimits` can impose an explicit parser allocation guard when an
embedding needs one. Native Astrid instead accepts every process-addressable
frame with fallible allocation, so this boundary is not a workspace, principal,
or per-file quota. Host-file support is excluded from
`target_family = "wasm"` while the portable model, in-memory engine, and
compatibility adapter remain available there.

This realization deliberately has one active arena and an in-memory rebuilt
offset index. Runtime KV and live per-principal logical quotas are integrated.
It does not yet seal arenas, compact unreachable history, persist pins, expose
root removal, coordinate an audit/outbox record, inject short writes or
disk-full errors, encrypt erasure domains, or select final export `BlobId`
profiles. Those claims remain attached to their evidence gates.

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
