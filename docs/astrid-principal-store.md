# Astrid Principal Store

Status: proposed architecture and implementation contract

Last reviewed: 2026-07-25

Companions: [native-kernel scope](astrid-native-kernel.md),
[AI-native OS workplan](astrid-ai-native-os-workplan.md),
[kernel evidence matrix](astrid-kernel-evidence-matrix.md), and
[principal-store evidence plan](astrid-principal-store-evidence.md)

## 1. Decision

Astrid should keep durable principal storage in the `astrid-runtime/astrid`
monorepo as a small crate family. Storage is not a generic database choice for
Astrid: it defines principal isolation, quotas, provenance, rollback, export,
import, erasure, audit continuity, and the migration path to a native Astrid
system.

The selected architecture is a hybrid:

1. **State plane:** immutable, typed, content-addressed objects describe the
   exact logical state of a principal.
2. **Transition plane:** a small signed commit record advances a principal from
   one state root to another.
3. **Placement plane:** a replaceable engine decides where encoded object
   replicas live and moves them without changing logical state.
4. **Projection plane:** compatibility adapters expose the same state as KV
   namespaces, a filesystem tree, export streams, and current Astrid APIs.

The principal's stable identity and current root are mutable. Objects below a
root are not. A root hash proves which bytes and typed relationships constitute
a state; an authorized, signed transition proves who advanced the principal to
that state. The hash alone is neither authority nor provenance.

The principal root contains only state that the principal owns durably. It does
not silently absorb operator policy, capability grants, the human's mounted
workspace, process scratch space, or rebuildable indexes. Those are separate
authority, attachment, ephemeral, and derived domains. This boundary is
necessary for an export, rollback, fork, or erasure request to mean what its
caller thinks it means.

This is deliberately more than replacing SurrealKV with a content-addressed
backend. It is a principal-state substrate that SurrealKV, the VFS, the audit
log, the Linux realm, and a future native Astrid system can use without changing
their public interfaces at once.

## 2. Claim boundary

This design can support:

- exact reconstruction of committed principal state;
- atomic snapshot, fork, rollback, export, and import;
- deduplication within an explicitly configured privacy domain;
- bounded, testable crash behavior;
- proof of integrity and signed transition history;
- stable logical state across physical rebalancing;
- scoped erasure statements;
- per-principal accounting independent of another principal's lifecycle.

It cannot support:

- compression of arbitrary data by a fixed high ratio;
- a finite dictionary containing every possible large block;
- proof that a signed transition was semantically wise or truthful;
- deletion of copies that have already been exported to another custodian;
- physical erasure of an object still referenced by another principal;
- global deduplication with both perfect tenant privacy and no equality leakage;
- universal correctness merely because a bounded model checker or property test
  passes.

Those limits are part of the contract, not implementation inconveniences.

## 3. Why the simple designs are insufficient

| Candidate | Strength | Failure as Astrid's sole model |
|---|---|---|
| Pure content-addressed block store | Immutable blocks, integrity, deduplication, simple replication | No principal transaction, authority, mutable name, audit transition, quota, or erasure semantics |
| Per-principal event log | Excellent history and provenance; natural replication stream | Unbounded replay, difficult compaction, awkward large-file reads, and event-schema evolution becomes state recovery |
| Copy-on-write virtual disk | Runs an unmodified filesystem and Linux immediately | Principal state is opaque blocks; poor semantic export, weak cross-image deduplication, difficult KV/audit proofs |
| Database-native temporal tables | Mature transactions and queries | Couples the native system to a large database and does not naturally cover files, disks, or portable offline bundles |
| Filesystem watching plus backup | Easy bridge to today's host files | Races, symlink hazards, no atomic state cut across KV/files/audit, and provenance begins after an untrusted observation |

The hybrid keeps the useful part of each:

- Venti-like immutable blocks;
- Fossil-like mutable snapshots above the archive;
- event-log provenance at state-root granularity;
- copy-on-write roots for cheap forks;
- database adapters for current callers;
- a separate placement map for fleet operations.

This separation is the key alternative to “CAS all the things.” Content objects
answer **what**. Transition records answer **who changed what, under which
authority**. Placement records answer **where the recoverable copies are**.

## 4. Current Astrid state and migration constraints

Today:

- `astrid-storage` exposes `KvStore`, `MemoryKvStore`, `SurrealKvStore`,
  `ScopedKvStore`, identity storage, secret storage, and optional SurrealDB.
- `astrid-audit` writes entries, indexes, and chain heads through a private
  storage trait backed by `KvStore`.
- `astrid-vfs` exposes host copy-on-write and in-process overlays. The
  in-process overlay does not yet have a lower-layer whiteout model.
- `PrincipalProfile::quotas.max_storage_bytes` exists, but it is not the
  accounting definition for a deduplicated store.
- `agent create --inherit-from` and `--clone` copy selected files, KV keys, and
  secrets. The copy is best-effort rather than one atomic state cut.
- `astrid agent export` and `astrid agent import` already parse as deferred CLI
  surfaces.

The migration must therefore be additive:

- preserve the public `KvStore` shape while an adapter changes persistence;
- do not change capsule WIT contracts;
- do not make the kernel understand files, database rows, or object graphs;
- keep principal IDs and existing on-disk layouts importable;
- give `astrid-audit` an injected transactional/outbox surface before claiming
  state-plus-audit atomicity;
- convert existing clone/inheritance behavior deliberately rather than silently
  changing its secret-copy semantics.

## 5. Crate boundary

Avoid a crate per data structure. Two new crates are enough.

### 5.1 `astrid-storage-model`

`#![no_std]` with `alloc`.

Owns:

- domain-bearing identifiers and versioned object kinds;
- canonical object, root, commit, export, and placement types;
- pure graph closure, reconstruction, accounting, and validation algorithms;
- state-machine transitions used by executable models;
- format limits and typed validation errors.

It must not depend on Tokio, SurrealDB, filesystem APIs, policy engines, clocks,
or operator configuration. Hashing, signing, encoding, and time are supplied by
narrow traits or parameters where that keeps the model portable.

This crate is usable by:

- the current user-space engine;
- import/export verifiers;
- offline recovery tools;
- a future native Astrid storage domain;
- formal or exhaustive test harnesses.

### 5.2 `astrid-storage-engine`

`std` user-space implementation.

Owns:

- chunking and object encoding;
- append-only segments or packs, indexes, WAL, and recovery;
- atomic principal-root transactions;
- streaming import and export;
- snapshots, pins, leases, garbage collection, and compaction;
- encryption-domain integration;
- replication, placement epochs, repair, and rebalancing;
- fault injection and operational metrics.

The engine is not ring-0 code. A native Astrid kernel grants block devices,
bounded memory, IPC endpoints, and a compact root-anchor operation to a storage
service domain.

### 5.3 Existing crates

`astrid-storage` remains the compatibility and integration facade:

- its existing `KvStore` implementations remain available;
- a principal-store-backed `KvStore` adapter is additive;
- identity and secret migrations remain explicit;
- callers do not import the engine merely to name a storage model type.

`astrid-vfs` projects a typed filesystem root. `astrid-audit` consumes a
transactional append/outbox adapter. `astrid-core` owns principal policy, not
object storage machinery.

### 5.4 Engine realization

The strongest durable-engine candidate is an arena plus a small root journal:

```text
sealed arena:
    header
    repeated { length, blob_id, encoding_profile, checksum, encoded_bytes }
    optional compact local index
    footer

rebuildable global index:
    BlobId -> { arena_id, offset, length, verification_state }

root journal:
    { generation, principal, old_commit, new_commit, outbox_ref, checksum }
```

Writes append encoded blobs, flush them, then append one root transaction. A
sealed arena is immutable. Compaction copies live blobs into a new arena,
verifies them, publishes the new index generation, and only then reclaims the
old arena. The same engine can target a host file today and a bounded block
capability later.

This is preferable to:

- one host file per object, which turns inode and directory behavior into the
  scale limit;
- storing every large chunk as a database row, which inherits database
  write/index amplification and a difficult bare-metal port;
- making a complete filesystem the storage substrate, which hides principal
  transactions below opaque mutable metadata;
- making the root journal contain data, which turns recovery into unbounded
  replay.

The index is disposable performance state. Arenas, root records, and explicit
pins are authoritative. The initial engine remains in memory until the model
semantics are stable; the first durable implementation must include index
rebuild and fault injection rather than treating either as later cleanup.

The implemented engine contract, compatibility oracle, native cutover, and
durable host-file realization are maintained in
[Principal Store Engine Realization](astrid-principal-store-engine.md).

## 6. Three identifiers, not one overloaded hash

The system must not turn possession of a hash into permission to read data.

### 6.1 `ObjectId`

Logical identity of one canonical typed object:

```text
ObjectId = H(
    "astrid-object-id-v1" ||
    object_kind ||
    object_format_version ||
    canonical_object_encoding
)
```

The canonical object encoding commits the payload, ordered labelled
references, reference reachability kinds, logical-byte contribution, and
accounting class. `ObjectId` makes object equality and logical roots stable. It can be kept
inside authorized metadata because exposing it leaks equality and permits
confirmation guesses for predictable content.

### 6.2 `BlobId`

Identity of encoded bytes actually placed on storage:

```text
BlobId = H(
    "astrid-blob" ||
    encoding_profile ||
    encoded_bytes
)
```

Compression, encryption, erasure coding, or a future encoding migration may
produce a new `BlobId` for the same `ObjectId`. Logical roots do not change.

### 6.3 Capabilities and root authority

A capability authorizes an operation on a principal or root. It is not an
`ObjectId` or `BlobId`. Storage backends may be given verify-only access,
read access, replication access, or deletion access independently.

This distinction lets an untrusted placement node verify stored ciphertext
without learning plaintext or acquiring principal authority.

## 7. Logical object model

All references are typed, canonical, versioned, and acyclic. Persistent
decoders apply deployment/resource bounds without embedding an arbitrary
capacity ceiling in the logical model. Their reachability meaning is also
typed:

```text
ObjectRef {
    relation,
    content_id,
    reachability: Owns | Evidence | Lineage | Derived
}
```

- `relation` is the canonical typed edge label: a principal-state field, a
  directory name, a KV branch/key slot, a chunk position, or another
  schema-defined relation. Labels are unique and ordered within one object.
  Multiple labels may intentionally point to the same content.
- `Owns` is a strong edge. It must resolve for the principal state to be
  complete and contributes to export, quota, retention, and garbage-collection
  reachability.
- `Evidence` binds an observation, receipt, audit checkpoint, or external
  attachment without silently taking ownership of its closure. The evidence
  remains available only while its own receipt/retention root pins it.
- `Lineage` names another commit used to create, fork, import, or merge state.
  It proves identity/history but does not import that commit's data, authority,
  quota, or retention.
- `Derived` names a rebuildable index or materialization and never makes that
  representation authoritative.

A minimum object family is:

```text
Chunk(bytes)
ChunkTree(children: [ChunkRef], logical_len)
File(content_root, logical_len, executable, metadata)
Symlink(target_bytes)
Directory(sorted [name_bytes -> EntryRef])
KvLeaf(sorted [key_bytes -> value_ref])
KvBranch(separator_keys, children)
NamespaceMap(sorted [capsule_id -> KvRoot])
PrincipalState(
    home_root,
    capsule_kv_root,
    capsule_state_root,
    principal_memory_root?,
    principal_preferences_root?,
    schema_set
)
Commit(
    principal_id,
    primary_parent?,
    lineage_inputs,
    state_root,
    operation_id,
    actor,
    authority_epoch,
    attachment_observation_root?,
    audit_checkpoint?,
    format_version
)
```

Secrets and authentication material are not ordinary state objects:

- runtime and device private keys never enter the principal object DAG;
- secret values use a separate encryption and export policy;
- capability grants are destination authority, not data a bundle may
  self-assert;
- a profile may be exported as a non-authoritative template for operator
  review.

Directory entry names are byte strings with an explicit normalization policy.
They are never interpreted as host paths while validating an object graph.
Symlinks are data leaves. A materializer must not follow them while writing an
export or host projection.

The executable model reflects these distinctions directly:

- `ObjectId`, `BlobId`, `ReferenceLabel`, `PinId`, `RootGeneration`,
  `PlacementEpoch`, `StorageNodeId`, `ObjectFormatVersion`, and `ReplicaCount`
  are separate domain types rather than interchangeable integers or bytes;
- object format versions and replica requirements are non-zero by
  construction;
- a published principal root must name an `ObjectKind::Commit`;
- closure import rejects both missing and unrelated supplied objects;
- placement epochs advance monotonically, contain only registered blobs, and
  cannot silently retire an unknown or active epoch.

### 7.1 State ownership classes

One root must not become a bag of everything visible to an agent. Astrid uses
five explicit state classes:

| Class | Examples | Canonical principal export? | Authority |
|---|---|---:|---|
| Principal-owned durable state | agent home, capsule KV, capsule durable state, explicit principal memory/preferences | Yes | principal-scoped storage capability |
| System/operator authority state | profile, group membership, grants, budgets, runtime/device keys, policy | No | operator/kernel authority |
| External attachment | human workspace, removable volume, remote repository, shared data set | No; explicit ingest or separate export only | mount/resource capability |
| Ephemeral execution state | `/tmp`, process memory, uncommitted overlay, scheduler state | No; only an explicit checkpoint contract may promote it | invocation/runtime |
| Derived state | indexes, tensor relations, build cache, search cache, placement index | Rebuildable and excluded by default | derived from a named source root |

`config_root` is intentionally not an undifferentiated field. Principal-owned
preferences may live under `principal_preferences_root`; operator policy and
capability state remain outside the principal DAG and are only bound by an
authority epoch or receipt. Likewise, the audit checkpoint belongs to the
commit/transition envelope, not to mutable principal-owned content.

The current host workspace selected from the CLI/Codex CWD is an external
attachment. Astrid may:

- mount it live under a logical name such as `cwd://` or `/workspace`;
- create an observed snapshot root for one invocation or receipt;
- ingest an explicitly selected subtree into principal-owned state; or
- write changes back under the granted workspace capability.

It must not retain, export, fork, or delete the human's whole workspace merely
because an agent could see it. A workspace capture records source identity,
selection, before/after observations, and writeback status separately from the
principal root.

`lineage_inputs` records additional roots used by an authorized,
subsystem-specific merge or import. `primary_parent` remains the root against
which the compare-and-swap occurred. Naming another commit as lineage never
imports its authority, secrets, profile, or principal identity.

`attachment_observation_root`, `audit_checkpoint`, and `lineage_inputs` are
non-owning references. A complete principal export follows `Owns` edges only
unless the caller separately selects and is authorized to disclose evidence or
lineage. This prevents a harmless reference from becoming an accidental
retention, quota, export, or deletion dependency.

## 8. Mutable principal root and transition

Let:

- `O : ObjectId -> Object` be the immutable object map;
- `R : PrincipalId -> (generation, CommitId)` be current roots;
- `A` be the set of authorized actors and capability epochs;
- `P : (placement_epoch, BlobId) -> ReplicaSet` be physical placement.

A transition from `c_old` to `c_new` is valid when:

1. `c_new.principal_id` names the target principal;
2. `c_new.primary_parent = c_old`, except for an authorized genesis/import;
3. every object reachable from `c_new.state_root` is durable;
4. the actor was authorized for the transition at `authority_epoch`;
5. the expected principal generation still equals the stored generation;
6. the signed transition and audit outbox entry are committed with the root
   compare-and-swap.

The write order is:

1. encode, write, and verify new immutable objects;
2. flush the complete new closure;
3. write and flush the immutable commit;
4. transactionally compare-and-swap `(generation, commit)` and append a durable
   audit/outbox record;
5. acknowledge success;
6. asynchronously compact unreachable data only after all pins and leases allow
   it.

A crash before step 4 leaves unreachable garbage. A crash after step 4 leaves a
complete visible state. Recovery may remove the garbage; it must not repair a
visible root by guessing.

## 9. Provenance

Content addressing proves byte integrity, not authorship. Astrid provenance is
the signed transition chain:

```text
Transition = Sign_runtime_or_actor(
    principal_id,
    old_commit,
    new_commit,
    operation_id,
    authority_epoch,
    policy_decision_ref,
    timestamp_or_logical_clock
)
```

The transition records the boundary fact Astrid can prove: an identified actor,
holding an accepted authority at a particular epoch, requested an accepted
state change. It does not claim the input data is true or the change is useful.

High-volume file writes need not create a signed record per syscall. A
transaction or filesystem synchronization boundary can fold many object writes
into one new state root, while optional detailed audit events remain separately
chained.

### 9.1 Authenticated structural transition witnesses

A signed transition says an authorized Astrid boundary accepted a root change.
An optional structural witness lets an independent verifier check the storage
part of that claim without downloading either complete state.

Conceptually:

```text
StatePatch {
    source_commit,
    typed_operations,
    operation_id,
}

TransitionWitness {
    before_root,
    after_root,
    partial_before_tree,
    patch_digest,
    proof_format,
}
```

The partial tree contains concrete values and branches touched by the canonical
patch and blinded hashes for untouched subtrees. A verifier:

1. reconstructs `before_root` from the partial tree;
2. applies the same bounded, deterministic typed operations;
3. reconstructs the resulting root;
4. requires it to equal `after_root`;
5. binds the witness, patch, authority epoch, and operation ID to the signed
   transition and execution receipt.

File-tree, KV-tree, namespace, and component-root operations have separate
typed patch grammars. The storage layer must not invent a universal semantic
mutation language.

The first executable model implements only `ReplaceOwnedSubtree(path,
expected, replacement)`. Labelled path verification and bottom-up parent
rehashing prove the common root-rewrite primitive. File/KV-specific patches may
later prove finer mutation semantics without weakening or replacing it.

The witness proves that the stated structural mutation transforms one committed
root into another. It does not prove that capsule computation was correct, that
an input was true, or that the actor should have wanted the result. Those claim
boundaries remain with authority validation and execution/observation receipts.

Proof generation is optional on ordinary local writes and may occur
asynchronously while the immutable nodes remain available. The root commit
cannot depend on a remote proof service. Deployments that require proof-carrying
commits can make witness durability part of their acknowledgement policy.

### 9.2 Verified state views and causal slices

A `StateView` is a capability-scoped, independently verifiable selection from a
committed root:

```text
StateView {
    source_commit,
    selector,
    selected_roots,
    inclusion_proof,
    disclosure_profile,
}
```

Selectors are typed and bounded, for example:

- one principal-owned component root;
- a filesystem subtree or explicit path set;
- one capsule KV namespace or key prefix;
- a set of objects observed by one execution receipt.

The view contains the selected closure plus enough blinded parent structure to
prove that the selection came from `source_commit`. It is neither a bearer
capability nor evidence that the holder may retrieve undisclosed siblings.
Authorization is checked separately before generation and on every backing
object read.

A causal slice is a view whose selector is derived from the reads admitted to a
governed execution. It can package the smallest retained state needed to
inspect, transfer, or—when the receipt's coverage permits—replay that execution.
The access trace is untrusted input to view generation; the host verifies every
selected object against the source root.

Views make partial export, remote execution, receipts, and federation one
primitive rather than four incompatible bundle formats. They also preserve an
important ergonomic rule: the agent receives normal files, values, and tool
results; proof material travels as structured metadata and is requested only by
verifiers or diagnostic tools.

## 10. Principal export

Export captures one immutable root, then streams its closure. The principal
does not need to remain stopped while the bytes stream.

### 10.1 Snapshot barrier

1. request a principal checkpoint;
2. stop admission of new storage transactions briefly;
3. flush or abort in-flight transactions;
4. capture `(generation, CommitId)` and add an export pin;
5. resume new transactions;
6. stream the captured closure;
7. release the pin after completion or expiry.

Long-running capsule processes continue only if their durable state contract
can checkpoint consistently. A raw process memory image is not silently
invented as durable state.

### 10.2 Bundle

The wire format is a framed, streaming `Astrid Principal Bundle`, not a tarball
and not a host directory:

```text
BundleHeader {
    magic,
    bundle_format_version,
    source_principal,
    source_commit,
    export_operation_id,
    schema_set,
    hash_profiles,
    encoding_profiles,
    dedup_domain_descriptor,
    logical_bytes,
    object_count,
    closure_digest,
    created_at,
    source_runtime_identity,
}

ObjectFrame { ObjectId, object_kind, canonical_or_encoded_object }
SecretEnvelopeFrame? { recipient, cipher_suite, encrypted_secret_set }
ProfileTemplateFrame? { non_authoritative_profile }
AuditLineageFrame? { checkpoint, selected_transition_proofs }
BundleFooter { observed_counts, closure_digest, signature }
```

The format needs both:

- **full export**, containing the entire reachable closure;
- **thin/incremental export**, where the receiver supplies an authenticated
  “have” set or Bloom/filter summary and the sender emits only missing objects.
- **view export**, containing a typed selected closure plus proof that it was
  selected from the declared source commit.

A thin export is unusable without its declared base closure. Validation must
fail closed rather than yield a partial principal. A view export is
intentionally partial and never installs a complete principal unless its
selector is the canonical full principal-owned state.

Full export means the closure of `PrincipalState`, not everything mounted or
visible during an invocation. External attachments require a separate,
explicitly authorized snapshot/export, and system authority must be
re-established at the destination.

### 10.3 Secret and authority rules

Default export excludes:

- device and runtime private keys;
- host keychain material;
- bearer tokens and live sessions;
- capability grants as operative destination authority;
- secrets.

An explicit secret export produces a separate recipient-encrypted envelope,
requires a stronger capability and approval, and creates a security audit event.
The destination re-authorizes capabilities and imports profile data only as an
operator-reviewable template.

Once an export crosses the source custody boundary, the source cannot guarantee
its destruction. The source can prove that it deleted local roots, pins, keys,
and replicas under its control.

## 11. Principal import

Import is staged and invisible until one root transaction succeeds.

### 11.1 Validation

The receiver:

1. validates header, versions, algorithms, sizes, and declared limits before
   allocation;
2. verifies every object frame against its `ObjectId` or encoded `BlobId`;
3. rejects duplicate IDs with different bytes;
4. checks object-kind grammar, bounds, ordering, and acyclicity;
5. computes closure from the declared root and rejects missing or extraneous
   data according to bundle mode;
6. verifies source signatures and records the trust result without treating it
   as destination authority;
7. checks dedup/encryption-domain compatibility;
8. checks principal and host quotas, including metadata and temporary staging;
9. flushes staged objects;
10. atomically installs the destination genesis/root and import audit record.

Failed import exposes no principal root. Staged objects are garbage-collectable.

### 11.2 Import modes

- `create`: allocate a new local principal, retaining source lineage.
- `restore`: restore the same principal identity only when absent or when
  explicit recovery authority and lineage checks permit it.
- `fork`: allocate a new principal rooted at the imported state. Locally this
  can share immutable objects immediately.
- `replace`: atomically replace a disabled destination after an explicit
  expected-root check and retained rollback pin.
- `merge`: allowed only through subsystem-specific merge logic. There is no
  generic “merge two principals” byte operation.

Name collisions never silently overwrite state. Importing the same bundle twice
is idempotent at the object layer and produces either the same declared result
or a typed principal-collision outcome.

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

Per-principal rebalancing is a filter over objects reachable by those principals.
Shared objects move once. An operator can move Alice without rewriting Bob's
root even when both reference the same immutable object.

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

Content-defined chunking avoids shifting every later boundary after an insertion
near the start of a file. A FastCDC-like algorithm is a candidate, not a
pre-selected dependency. Astrid must benchmark source trees, package caches,
model artifacts, databases, VM images, compressed media, encrypted data, and
adversarial random data before pinning parameters.

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
length and not Rust heap capacity. The executable model charges the fixed
kind/version/class/length fields, canonical payload bytes, and every
reference's label length, label bytes, target `ObjectId`, and reachability
kind. Durable framing, checksums, algorithm tags, indexes, and allocator
amplification belong to `physical_bytes(store)`. Keeping this calculation on
`ObjectRecord` gives quota and garbage-collection reports one definition.

Enforce a stable per-principal quota on retained logical ownership plus metadata,
not on a moving “fair share” of physical bytes. Alice's permitted state must not
shrink because Bob deleted his reference or grow because Bob imported the same
data.

Operators additionally enforce pool capacity, replication headroom, temporary
import/rebalance headroom, and physical watermarks. A proportional shared-byte
figure may be reported for cost analysis:

```text
fair_share(p) = sum(size(o) / number_of_principals_reaching(o))
```

It is unsuitable as the principal's hard quota because it changes when unrelated
principals appear or disappear.

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

## 18. Host filesystem projection

The object graph is authoritative. A normal filesystem is a projection and
ingestion boundary.

For an Astrid-managed workspace:

- a successful write transaction creates a new root;
- external host changes are ingested through a watcher plus periodic
  reconciliation;
- watcher events are hints, never proof of a complete history;
- deletion becomes a directory entry removal in a new root, while prior roots
  remain only under explicit retention;
- materialization occurs in a new directory or file and becomes visible through
  atomic rename;
- path resolution uses beneath/no-follow semantics and rejects device nodes,
  sockets, escaping links, and platform-specific special names;
- symlink targets remain uninterpreted bytes during import/export.

On platforms where exact mutation capture is required, Astrid should mount a
filesystem service or route writes through a mediated interface rather than
claim provenance from after-the-fact watching.

Runtime integration, tensor-ready scaffolding, implementation order, open
evidence questions, prior art, and the Astrid-specific synthesis continue in
[Principal Store Runtime Realization](astrid-principal-store-runtime.md).
