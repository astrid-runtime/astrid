# Astrid Principal Store Operations

This companion to [Astrid Principal Store](astrid-principal-store.md) carries
the operational model above its logical object, authority, provenance, and
portable import/export foundation. Runtime realization and delivery order
continue in [Astrid Principal Store Runtime
Realization](astrid-principal-store-runtime.md).

## 12. Clone and inheritance

Local clone becomes an O(1) root fork plus a new principal profile. Future
writes copy only changed objects.

State-only inheritance can select component roots rather than enumerating live
KV keys and files. Existing explicit secret-copy behavior remains a separate
operation during compatibility migration; it must not become an implicit
consequence of sharing a state root.

This removes the current best-effort partial-copy failure mode:

```text
old: list keys -> copy key by key -> copy files -> warn and continue
new: select source root -> authorize selected components -> commit destination root
```

The agent-workspace complexity case and its benchmark boundary are recorded
with the implemented engine in
[Principal Store Engine Realization](astrid-principal-store-engine.md).

## 13. Sysadmin rebalancing

Rebalancing moves physical replicas. It does not export, import, rename, fork,
or rewrite a principal.

### 13.1 Placement

Placement is a pure, versioned function over an operator map:

```text
targets = place(
    placement_epoch,
    BlobId,
    replication_or_erasure_profile,
    node_weights,
    failure_domains,
    policy_labels
)
```

Weighted rendezvous hashing or a CRUSH-like algorithm is a suitable starting
point. The decision must follow measured movement, availability, and repair
behavior rather than the algorithm's name.

Placement metadata is not embedded in `ObjectId`, `PrincipalState`, or
`Commit`. A root remains identical when a node is added, drained, replaced, or
reweighted.

### 13.2 Online movement

For each affected object:

1. calculate old and new target sets;
2. copy missing encoded replicas to new targets;
3. verify `BlobId` and durability on the targets;
4. make the new placement epoch readable;
5. retain old placement while readers with old-epoch leases drain;
6. delete old replicas only after target durability, lease expiry, retention,
   export, snapshot, and erasure holds permit it.

Reads may consult both epochs during the transition. No point may have fewer
verified recoverable fragments than policy requires.

### 13.3 Operator surface

The operator needs:

- `rebalance plan` with no mutation;
- selection by principal, storage domain, node drain, failure domain, or all;
- predicted bytes read, written, and removed;
- temporary headroom and time estimate;
- availability and policy violations before execution;
- resumable, idempotent operation IDs;
- pause, resume, cancel-before-commit, and status;
- rate limits and maintenance windows;
- a durable receipt stating old/new epochs and verified counts.

Per-principal rebalancing is a filter over objects reachable by those
principals. Shared objects move once. An operator can move Alice without
rewriting Bob's root even when both reference the same immutable object.

## 14. Deduplication and the actual mathematics

### 14.1 There is no universal finite shortcut

For fixed blocks of `n` bits, there are `2^n` possible values. A lossless
identifier that reconstructs every possible block must distinguish all of them,
so its worst-case representation needs at least `n` bits. This follows directly
from the pigeonhole principle.

For 4 KiB blocks:

```text
possible blocks = 2^(8 * 4096) = 2^32768
dictionary bytes = 4096 * 2^32768
log10(dictionary bytes) ~= 9867.76
```

The literal universal block dictionary would therefore require a number with
9,868 decimal digits of bytes. Astrid must never promise that.

The useful observation is empirical: real user data is repetitive and
correlated. Content addressing stores identical objects once. It cannot make
random, already-compressed, or independently encrypted data deduplicate.

### 14.2 Chunking

Large files use a balanced tree over content-defined chunks. Chunking parameters
are an explicitly versioned profile:

```text
ChunkingProfile {
    algorithm,
    min_bytes,
    average_bytes,
    max_bytes,
    normalization,
}
```

Content-defined chunking avoids shifting every later boundary after an
insertion near the start of a file. A FastCDC-like algorithm is a candidate,
not a pre-selected dependency. Astrid must benchmark source trees, package
caches, model artifacts, databases, VM images, compressed media, encrypted
data, and adversarial random data before pinning parameters.

### 14.3 Collision probability

For a uniformly distributed 256-bit digest and `m` objects, the birthday-bound
approximation is:

```text
p_collision ~= m * (m - 1) / 2^257
```

At `m = 10^12`, this is approximately `4.32 * 10^-54`. This is not a proof that
a hash implementation is correct or eternally secure. Format versioning,
domain separation, byte comparison on suspicious duplicate insertion, and an
algorithm migration path remain required.

### 14.4 Metadata is data

At a 64 KiB average chunk, 2 TiB contains `2^25 = 33,554,432` chunk
references. Even a flat 40-byte reference array is about 1.25 GiB before tree,
index, transaction, and replication metadata. The implementation therefore
needs:

- bounded fan-out trees;
- compact canonical references;
- packed small objects;
- metadata accounting and quotas;
- measured index amplification;
- no arbitrary per-file ceiling disguised as a safety control.

## 15. Accounting

Report different quantities instead of calling all of them “usage.”

For principal `p`:

```text
logical_bytes(p) =
    bytes visible through files and KV values, including repeated contents

retained_object_bytes(p) =
    sum(size(o)) for distinct objects reachable from root(p)

metadata_bytes(p) =
    principal roots, commits, references, indexes, leases, and retained history

exclusive_bytes(p) =
    bytes reachable by p and by no other authoritative root

shared_bytes(p) =
    retained_object_bytes(p) - exclusive_bytes(p)

physical_bytes(store) =
    encoded replicas + indexes + WAL + free-space/compaction amplification
```

`size(o)` is the stable logical canonical-record size, not merely the payload
length. It includes the object's kind, format version, accounting class,
logical byte declaration, canonical bytes, and every reference's label, target
identity, and relation kind. Engine framing, checksums, algorithm tags, indexes,
and allocator overhead remain physical costs reported separately. This keeps
quota and garbage-collection accounting independent of a particular arena
encoding without leaving attacker-controlled reference metadata unmetered.

Enforce a stable per-principal quota on retained logical ownership plus
metadata, not on a moving “fair share” of physical bytes. Alice's permitted
state must not shrink because Bob deleted his reference or grow because Bob
imported the same data.

Operators additionally enforce pool capacity, replication headroom, temporary
import/rebalance headroom, and physical watermarks. A proportional shared-byte
figure may be reported for cost analysis:

```text
fair_share(p) = sum(size(o) / number_of_principals_reaching(o))
```

It is unsuitable as the principal's hard quota because it changes when
unrelated principals appear or disappear.

### 15.1 Resource-policy resolution

The engine contains no arbitrary total-workspace or per-file quota. Format
bounds protect parsers and memory allocation; resource policy controls admitted
state.

The effective principal budget is resolved outside the engine from:

- an optional per-principal override;
- group, organization, or deployment policy;
- the principal's shared CPU/memory/storage budget;
- current pool capacity and a non-consumable recovery reserve;
- temporary import and rebalance headroom.

A local single-user installation may use an `auto` policy that grows with the
available pool while preserving recovery headroom. A managed deployment may set
an explicit byte budget per principal. `unlimited` means no principal-specific
ceiling, not the ability to exceed physical capacity or consume the recovery
reserve.

The current `Quotas::max_storage_bytes: u64` remains a compatibility input. It
must not cause the principal-store engine to acquire a hidden 1 GiB, 3 GiB, or
other compiled ceiling. A later additive policy representation can distinguish
`auto`, `unlimited`, and `bytes` without changing the stored object format.

## 16. Privacy, encryption, and erasure domains

Cross-principal deduplication is a policy decision.

Possible domains:

- principal;
- operator-defined organization;
- local host;
- trusted cluster;
- no deduplication for a protected class.

In a trusted local storage service, Astrid can identify plaintext equality,
encrypt a shared object with a random data key, and wrap that key for authorized
domains. In an opaque remote store, ordinary client-side randomized encryption
prevents cross-client deduplication. Message-locked or convergent encryption
restores it but leaks equality and is vulnerable to confirmation or brute-force
attacks on predictable content. Astrid must not enable that trade silently.

Hard deletion:

1. removes the principal root and its retained pins after policy permits;
2. revokes domain key wraps and live access;
3. marks now-unreachable objects;
4. removes all eligible replicas, old placement epochs, caches, and repair
   queues;
5. performs media-appropriate sanitization or cryptographic erase;
6. writes a non-sensitive erasure receipt.

If another root still reaches an object, its physical bytes remain. Astrid can
prove the deleted principal no longer has a root or key wrap; it cannot claim
the shared bytes vanished. Strict physical-erasure classes must use an
unshared erasure domain from ingestion.

## 17. Garbage collection and retention

Authoritative liveness is graph reachability, not a fallible reference count:

```text
Live = closure(
    current_principal_roots
    union rollback_pins
    union snapshot_pins
    union export_pins
    union import_staging_roots
    union audit_or_legal_holds
    union active_reader_and_replication_leases
)
```

Here `closure` follows `Owns` edges. Evidence, lineage, and derived objects enter
`Live` only through their own authoritative retention roots or pins.

An object may be collected only when it is outside `Live` for every supported
placement epoch and the deletion policy permits removal. Reference counts and
reachability summaries are performance indexes; a rebuild from roots must be
possible.

“Nothing is ever deleted” is not the model. Retention is explicit, finite or
held by policy, and visible to the principal and operator. Fork and rollback do
not require infinite storage.
