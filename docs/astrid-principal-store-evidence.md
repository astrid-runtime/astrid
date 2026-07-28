# Astrid Principal Store Evidence Plan

Status: proposed falsifiability contract

Last reviewed: 2026-07-25

Companions:
[principal-store architecture](astrid-principal-store.md) and
[semantic representations](astrid-semantic-representations.md)

This document separates three kinds of confidence:

- **mathematical argument** proves a property of the stated abstract model;
- **bounded model evidence** exhausts a finite state space and finds
  counterexamples within that bound;
- **implementation evidence** tests that production code refines the model
  under real concurrency, crashes, I/O, and hostile inputs.

None substitutes for the others.

## 1. Abstract model

Let `Ids` be a digest space, `Objects` a set of canonical typed values,
`refs(o)` the typed references encoded by object `o`, and `owns(o)` the subset
whose relation is `Owns`.

```text
O : Ids -> Objects
R : Principal -> (Generation, CommitId)
Pins : PinId -> CommitId
Leases : LeaseId -> (PlacementEpoch, Set<BlobId>, Expiry)
P : (PlacementEpoch, BlobId) -> Set<Replica>
V : (CommitId, Selector) -> (SelectedClosure, InclusionProof)
W : (BeforeRoot, TypedPatch) -> (AfterRoot, PartialTreeProof)
SemanticContracts :
    SemanticContractId -> (EquivalenceContract, AuthorityEpoch)
RepresentationContracts :
    RepresentationContractId -> (RepresentationContract, AuthorityEpoch)
S : (ObjectId, RepresentationContractId)
    -> (SemanticId, DecoderEvidenceId, CanonicalizerEvidenceId)
Representations :
    SemanticId
    -> Set<(ObjectId | BlobId, RepresentationContractId, TrustClass, EvidenceId)>
```

Assumptions:

1. `id(o)` is deterministic over canonical bytes, type, domain, and version.
2. A digest collision is detected on insertion by comparing canonical bytes.
3. Every admitted object has bounded size and bounded reference count.
4. Owning object references form a finite DAG.
5. The root metadata store provides durable compare-and-swap transactions.
6. Flush establishes the durability guarantee declared by the storage device.
7. A semantic contract binds its reference canonicalizer; a representation
   contract binds its reference decoder and target semantic contract.
8. A semantic binding is admitted only after both pinned transforms execute or
   their pinned proof verifiers accept the results.
9. Adding a representation contract cannot alter the construction of an
   existing semantic identity domain.
10. Object, semantic, representation, and evidence identifiers grant no
    principal authority by themselves.
11. Authorization and signature primitives satisfy their separate contracts.
12. Reference relation labels, typed selectors, and patches have deterministic,
    bounded canonical semantics.
13. Principal-owned state, system authority, external attachments, ephemeral
    state, and derived state are distinguishable before root construction.
14. Principal roots name typed commit objects, imports admit only the declared
    owning closure, and published placement epochs advance monotonically using
    registered blob representations.

The evidence must test violations of assumptions 2–14 rather than hiding them.

## 2. Mathematical obligations

### STO-MATH-1: universal-compression impossibility

For `n`-bit values, any lossless fixed identifier space for every value has at
least `2^n` identifiers and therefore needs at least `n` bits per identifier in
the worst case.

**Argument:** if fewer than `2^n` identifiers exist, the pigeonhole principle
maps two distinct inputs to the same identifier, so reconstruction is not
lossless.

### STO-MATH-2: reconstruction

If a root's graph reachable through `owns(o)` is finite, acyclic, complete in
`O`, and each object passes canonical identity validation, deterministic
reconstruction yields exactly one logical state.

**Argument:** induction over DAG height. Leaves decode uniquely by canonical
grammar. If all children below height `h` decode uniquely, a canonical parent at
height `h` has one ordered child sequence and decodes uniquely.

### STO-MATH-3: import idempotence

Inserting a verified closure twice changes neither the immutable object map nor
its byte cardinality after the first insertion.

**Argument:** insertion is keyed by `id(o)`; equal identifiers require equal
canonical bytes, and the second mapping is already present.

### STO-MATH-4: root-based garbage-collection safety

If the collector deletes only `dom(O) - closure(all_authoritative_roots)`, every
authoritative root remains reconstructable.

**Argument:** every object needed by reconstruction is, by definition, inside
the closure and outside the deletion set.

The closure follows owning edges. Evidence, lineage, and derived references are
retained only when separately rooted or pinned.

### STO-MATH-5: rebalance observational equivalence

If rebalance changes only `P`, every logical read through unchanged `O` and `R`
returns the same value before and after rebalance.

**Argument:** logical reconstruction is a function of `O` and `R`; `P` selects a
verified physical representation but is not an input to logical decoding.

### STO-MATH-6: fair-share conservation

For object size `s(o)` and non-empty principal reachability set `Q(o)`:

```text
sum over p in Q(o) of s(o) / |Q(o)| = s(o)
```

Summing over objects conserves unique object bytes, subject to numeric rounding.
This establishes a reporting identity, not a stable quota.

### STO-MATH-7: verified-view soundness

If `verify_view(root, selector, closure, proof)` succeeds, every disclosed root
is selected by the canonical selector from `root`, every disclosed object
validates against that selected root, and blinded siblings contribute only
their committed hashes.

**Argument:** reconstruct the source root bottom-up from disclosed nodes and
blinded sibling hashes, then apply the deterministic selector grammar. Any
substituted value, path, selector, or sibling changes either canonical selector
evaluation or the reconstructed source root.

This proves origin and selection, not authorization to generate or read the
view.

### STO-MATH-8: structural-transition witness

If `verify_transition(before, patch, witness)` succeeds with result `after`, the
canonical typed patch applied to the concrete paths disclosed by the witness
reconstructs `after`, while every untouched subtree remains bound by its blinded
hash.

**Argument:** the witness first reconstructs `before`. Deterministic patch
evaluation replaces only authenticated paths, and bottom-up rehashing produces
one resulting root. Requiring that root to equal `after` binds the patch and
both roots.

This proves a structural storage mutation. It does not prove the semantic
correctness of the computation that requested it.

## 3. Model-checking obligations

A compact TLA+ model or exhaustive Rust transition system covers:

- two principals;
- two storage nodes plus one joining or draining node;
- a small finite object and digest space with deliberate collisions;
- two root generations;
- full, thin, and view import;
- one external workspace attachment that is visible but not principal-owned;
- bounded state selectors, partial proof trees, and typed patches;
- root, snapshot, export, and reader pins;
- crash at every durability boundary;
- overlapping writer compare-and-swap;
- rebalance with old-epoch readers;
- garbage collection concurrent with import and rebalance.

Required invariants:

| ID | Invariant |
|---|---|
| STO-MOD-1 | Every visible principal root has a complete durable closure |
| STO-MOD-2 | A principal generation advances at most once from one expected value |
| STO-MOD-3 | Different canonical bytes never occupy one accepted ID |
| STO-MOD-4 | Failed import creates no visible principal |
| STO-MOD-5 | GC never deletes an object reachable from a root, pin, or live lease |
| STO-MOD-6 | Rebalance never drops below the declared recoverable-fragment count |
| STO-MOD-7 | Old-epoch reads remain satisfiable until their leases expire |
| STO-MOD-8 | Rebalance changes no principal root or logical read |
| STO-MOD-9 | A source capability or bundle field cannot mint destination authority |
| STO-MOD-10 | A deleted principal has no live root, key wrap, or unexpired access lease |
| STO-MOD-11 | Default export/fork/erasure closure contains principal-owned state only |
| STO-MOD-12 | A verified view is bound to its source root, selector, and disclosed closure |
| STO-MOD-13 | A verified transition witness is bound to its before root, typed patch, and after root |
| STO-MOD-14 | A workspace attachment becomes principal-owned only through explicit authorized ingest |
| STO-MOD-15 | Evidence, lineage, and derived references do not change principal closure, quota, or default export |
| STO-MOD-16 | Every installed principal root names a typed commit object |
| STO-MOD-17 | Import admits exactly the declared owning closure, never unrelated supplied objects |
| STO-MOD-18 | Placement epochs advance monotonically and name only registered blob representations |
| STO-MOD-19 | Only an authority-registered immutable semantic contract can define an identity domain, and only a registered representation contract can map an encoding into it |
| STO-MOD-20 | Every semantic binding is reproduced by its pinned representation decoder and semantic canonicalizer or verified by their pinned proof verifiers |
| STO-MOD-21 | Alternate transforms, conformance results, and spot checks cannot mint semantic identity |
| STO-MOD-22 | A source representation is never served across principals without a separately approved representation derivation and trust class |
| STO-MOD-23 | Similarity relations change no identity, authority, ownership, quota, retention, or erasure reachability |
| STO-MOD-24 | Derived representation eviction changes no principal root or authoritative exact-byte read |
| STO-MOD-25 | Equal semantic digests collapse only after complete canonical-stream comparison |
| STO-MOD-26 | Semantic retention always keeps at least one authoritative representation that can reproduce the canonical stream |
| STO-MOD-27 | Adding or correcting a representation contract cannot redefine existing semantic identities |
| STO-MOD-28 | A transform capsule can access only host-selected bounded streams and cannot select a principal, path, contract, or identity |
| STO-MOD-29 | An encoding whose decoded canonical value differs is a derived semantic object, never an equal representation |

Every discovered counterexample becomes a minimized checked-in trace and a Rust
regression test.

## 4. Reference-model properties

`astrid-storage-model` supplies a deterministic in-memory world. Property tests
generate operation traces and compare the resulting world to simple
specification functions.

| ID | Generated property |
|---|---|
| STO-PROP-1 | Commit then read equals applying the same mutation to a plain map/tree |
| STO-PROP-2 | Snapshot then arbitrary writes leave the snapshot unchanged |
| STO-PROP-3 | Fork then writes isolate roots while sharing unchanged object IDs |
| STO-PROP-4 | Rollback restores every file and KV value in the retained root |
| STO-PROP-5 | Full export/import reconstructs an equal state root |
| STO-PROP-6 | Thin export plus declared base reconstructs the same root as full export |
| STO-PROP-7 | Removing any required object makes import fail before root visibility |
| STO-PROP-8 | Corrupting any object, root, footer, or signature makes validation fail |
| STO-PROP-9 | Importing the same bundle twice adds zero object bytes the second time |
| STO-PROP-10 | GC result equals a fresh reachability calculation |
| STO-PROP-11 | Rebalance preserves all reads and root IDs |
| STO-PROP-12 | Random/incompressible unique input reports approximately zero deduplication |
| STO-PROP-13 | Metadata usage grows with references even when every value deduplicates |
| STO-PROP-14 | Another principal's import/delete never changes a principal's enforced quota usage |
| STO-PROP-15 | A full-state view reconstructs the same closure as full export |
| STO-PROP-16 | Any selector, disclosed value, sibling hash, or source-root substitution invalidates a view proof |
| STO-PROP-17 | Applying the same typed patch through full state and a valid partial witness yields the same root |
| STO-PROP-18 | Any patch, before-root, after-root, or partial-tree substitution invalidates a transition witness |
| STO-PROP-19 | Default export excludes external attachments, operator authority, ephemeral state, and derived indexes |
| STO-PROP-20 | Explicit workspace ingest copies only the selected observed closure and records its external lineage |
| STO-PROP-21 | Adding a non-owning reference changes commit identity but not principal-owned closure or usage |
| STO-PROP-22 | Unpinned evidence can be collected while the referring principal remains reconstructable |
| STO-PROP-23 | Pinning the same evidence retains it without charging it as principal-owned state |
| STO-PROP-24 | Adding an unrelated valid object to an import causes atomic rejection rather than hidden admission |
| STO-PROP-25 | A stale placement epoch or unregistered blob is rejected without changing the active epoch |
| STO-PROP-26 | Changing any identity-bearing semantic-contract field changes its contract and semantic identities |
| STO-PROP-27 | A claimed decoded or canonical stream from an alternate transform is rejected unless the relevant reference reproduces it or the pinned verifier accepts its proof |
| STO-PROP-28 | An untrusted source encoding that is semantically valid is never selected where another principal requested a trusted representation |
| STO-PROP-29 | Exact-byte lookup returns the requested object or fails; it never substitutes a semantically equivalent object |
| STO-PROP-30 | Transform trap, exhaustion, oversized output, and over-depth or cyclic route planning create no semantic binding |
| STO-PROP-31 | Evicting every derived representation preserves all principal roots and rebuilds the same verified semantic bindings |
| STO-PROP-32 | A forced semantic-digest collision is rejected when canonical streams differ |
| STO-PROP-33 | Collection rejects removal of the final authoritative representation of semantically retained content |
| STO-PROP-34 | Adding or replacing a representation contract preserves existing semantic identities whenever canonical output is equal |
| STO-PROP-35 | Transform streams enforce confinement, backpressure, and execution bounds without admitting partial output |
| STO-PROP-36 | Lossy encode/decode produces a distinct semantic identity and typed derivation rather than an equal representation binding |

The deliberate tiny digest model must generate collisions and assert byte
comparison rejects them. Production collision probability is not a substitute
for collision-path code coverage.

## 5. Engine conformance

Every applicable conformance target runs the same black-box trace suite:

- `MemoryKvStore`, as the in-memory behavioral oracle;
- legacy `SurrealKvStore`, as the migration compatibility oracle;
- the in-memory principal-store engine;
- the durable segment engine;
- the future native block-backed engine.

Only the durable principal-store engine is a selectable native runtime store.
The legacy implementation is exercised to prove migration compatibility, not
retained as an operator-selected backend.

The suite covers:

- get, set, delete, list, exists, clear, and compare-and-swap;
- invalid namespace/key names, empty values, and configured resource-policy
  boundaries when present;
- namespace isolation;
- concurrent writers;
- flush, close, reopen, and recovery;
- stable error classes;
- quota charging before visible commit;
- cancellation at every await point.

The compatibility oracles need not expose new snapshot/export features. The
adapter's observable `KvStore` behavior must remain compatible.

The in-memory compatibility gate runs deterministic generated traces against
`MemoryKvStore`, `SurrealKvStore`, and `PrincipalKvStore`. It compares every
operation result and reconstructs every exercised namespace after each step.
It also covers raw-name validation, empty values, principal isolation,
concurrent insert-if-absent, and concurrent writes to distinct keys. Flush,
close, reopen, recovery, quota charging, and cancellation remain
durable-backend obligations; an in-memory adapter cannot provide evidence for
them.

## 6. Crash and storage faults

The durable engine exposes named fault points:

```text
after_object_append
after_object_flush
after_commit_append
after_commit_flush
before_root_cas
after_root_cas
before_outbox_flush
after_outbox_flush
mid_index_checkpoint
mid_compaction_copy
mid_rebalance_copy
after_new_epoch_publish
before_old_replica_delete
```

The first host-file realization implements and exercises the prefix through
`after_root_cas`. For each implemented point, an interrupted instance is
discarded and reopened: all points before the durable root record recover the
old complete root, while `after_root_cas` recovers the new complete root.
Separate tests cover incomplete arena headers, incomplete journal payloads,
complete checksum corruption, index rebuild, exclusive locking, stale-root
zero-write rejection, configured frame bounds, and concurrent root writers.
The remaining outbox, index-checkpoint, compaction, rebalance, replica, short
write, and disk-full cases remain open gates and are not implied by this slice.

For each point:

1. execute a generated transaction;
2. terminate without normal destructors;
3. reopen from the persisted bytes;
4. assert the old complete root or the new complete root is visible, never a
   mixture;
5. assert audit/outbox recovery emits exactly the committed transition;
6. assert leaked staging objects are reclaimable but not prematurely removed.

Device-fault tests include short writes, reordered completion where the platform
permits it, checksum mismatch, disk-full during every append, lost replica,
stale placement epoch, torn metadata page, and corrupt index rebuild.

Named fault points are only landmarks. The stronger crash test records the
byte-level write trace for a generated workload and reopens copies at every
write prefix, then at torn and legally reordered tail-block variants. Every
copy must yield the old complete root, the new complete root, or a typed
corruption result for a genuinely invalid interior frame. No prefix may yield
a mixed closure. This ALICE-style enumeration is the acceptance gate for
future frame, batching, group-commit, and compaction changes; adding a named
fault point is not a substitute.

## 7. Concurrency evidence

- `loom` explores root compare-and-swap, pin acquisition, reader leases, and
  concurrent collection.
- stress tests run writers, exporters, importers, collectors, and rebalancers
  for the same principals.
- duplicate operation IDs prove retry idempotence.
- cancellation tests prove that dropping a client request cannot leave a
  visible half-transaction.
- stale authorization epochs prove revocation is checked at commit, not only at
  transaction creation.

## 8. Export/import adversarial matrix

| Case | Required outcome |
|---|---|
| Truncated header/frame/footer | Typed rejection; no principal visible |
| Huge declared length | Rejected before allocation |
| Unknown mandatory format/schema | Rejected; optional extension safely skipped only when declared skippable |
| Duplicate ID, identical bytes | Accepted once |
| Duplicate ID, different bytes | Fatal collision/corruption |
| Missing child | Closure failure |
| Valid but unrelated object outside the declared owning closure | Atomic import rejection |
| Reference cycle | Grammar failure |
| Unsorted or duplicate directory/KV entries | Canonicality failure |
| Path separators, `..`, NUL, platform special name | Stored only if grammar permits; safe projection rejects/escapes |
| Symlink to host path | Imported as inert symlink data; materializer never follows it |
| Device node/socket/FIFO request | Unsupported typed-object rejection |
| Forged source signature | Trust failure |
| Valid source grant in profile template | Data retained for review; no destination grant |
| Secret frame without explicit recipient authorization | Rejected |
| Quota exceeded after decompression | Rejected before root commit |
| Decompression bomb | Bounded decode rejection |
| Same bundle retry | Idempotent result |
| Destination name collision | Explicit create/fork/replace decision required |
| Default export while a host workspace is mounted | Workspace bytes and host path excluded |
| View selector exceeds caller capability | Rejected before object disclosure |
| View claims a subtree from another source root | Inclusion-proof failure |
| View omits an object required by its selected closure | Closure failure |
| External workspace snapshot changes during capture | Retry/fail with no falsely coherent observation root |

Fuzz targets include every frame parser, canonical decoder, tree walker, safe
materializer, compression decoder, and signature/envelope parser.

## 9. Rebalance adversarial matrix

| Case | Required outcome |
|---|---|
| Node joins | Only calculated objects move; roots unchanged |
| Node drains | No old replica removed before verified target durability |
| Target fills mid-copy | Operation pauses/fails resumably; old placement remains |
| Source dies mid-copy | Repair continues from another verified source or reports degraded |
| Operator changes map twice | Epochs serialize; stale worker cannot delete a newer replica |
| Reader holds old epoch | Old placement retained until lease expiry |
| Shared object selected through two principals | Copied once and accounted once physically |
| Cancellation before epoch publication | New copies are reclaimable staging; old placement authoritative |
| Cancellation after publication | Forward-complete or explicit rollback while both copies remain |
| Corrupt target acknowledgement | Independent digest verification rejects it |
| Insufficient failure domains | Plan rejected before mutation unless explicit degraded-mode policy exists |

## 10. Deduplication benchmark contract

Publish measurements, not a universal ratio. Corpus classes:

- multiple revisions of source trees;
- Rust/C/C++ build outputs and dependency caches;
- package-manager stores;
- Linux root filesystems and VM images;
- database files and logs;
- model weights and tensor artifacts;
- text, media, compressed archives;
- encrypted files;
- uniform random and adversarial boundary-shifting data.

For each chunking profile record:

- logical input bytes;
- unique chunk and metadata bytes;
- deduplication ratio;
- compression ratio separately;
- chunk count and size distribution;
- ingest throughput and peak memory;
- small-edit write amplification;
- index and reference amplification;
- export/import throughput;
- cold and warm reconstruction latency.

A candidate profile fails if it relies on a hard total-size ceiling, unbounded
RAM, or a workload-specific ratio presented as a general claim.

## 11. Erasure evidence

Erasure tests distinguish:

- logical deletion;
- authorization/key revocation;
- removal of exclusive physical replicas;
- retention/legal holds;
- shared objects still reachable elsewhere;
- exported copies outside local custody;
- media sanitization.

Required checks:

1. deleted principal root cannot be resolved;
2. revoked credentials and cached capabilities fail;
3. exclusive objects disappear from active and old placement epochs after GC;
4. shared objects remain readable only through surviving authorized roots;
5. indexes, WAL, compaction remnants, caches, repair queues, and backups obey
   the declared sanitization policy;
6. the receipt says exactly which scope was completed and which holds or remote
   custody remain.

## 12. Cryptographic continuity

Object and signature algorithms are replaceable dependencies, not archival
assumptions. Persistent identities carry algorithm, construction version, and
digest length at every occurrence. A successor identity migration reconstructs
each retained owning closure while the old algorithm remains trusted, computes
successor identities bottom-up, publishes successor-tagged roots, and retains
old-to-new mappings as independently rooted `Evidence` records with typed
`Lineage` and `Evidence` relations. Old and new roots overlap through at least
one independently verified export/import and backup-rotation cycle. The frozen
format specification gives the byte-exact construction; an implementation
cannot redefine old bytes by changing only metadata.

Signature continuity uses a separate periodic **re-attestation ceremony**.
Before a signing algorithm enters its deprecation window, the live system:

1. freezes the current audit chain head, including its principal or system
   identity, sequence/generation, current corpus-root set, and format-spec
   identity;
2. reconstructs the retained canonical export closures and records a
   successor-tagged hash witness over that corpus;
3. signs the ceremony statement and audit head with both the still-trusted old
   signing key and the successor key, when both mechanisms permit it; and
4. publishes the statement as an immutable `Evidence` object retained by the
   audit custody root or an explicit legal/archival pin and included in
   subsequent archival exports.

The overlap begins before deprecation, not after a practical forgery, and lasts
until every configured verifier accepts the successor, at least one full
export/import plus independent-reader recovery succeeds, and every protected
backup tier has crossed one rotation. Policy may retain the old evidence
forever, but serving authority moves only after those checks. The ceremony
record names the old and successor algorithm identifiers, keys/certificates,
audit head, old and successor corpus roots, mapping evidence, policy version,
sequence, and claimed time. A timestamp alone is not proof; custody comes from
the overlapping signatures and verified hash lineage.

No special storage kind is needed thirty years in advance: `Evidence` already
holds the canonical statement, typed non-owning references bind both eras, and
tagged identities admit the successor digest. The ceremony changes roots and
evidence; it never reinterprets an old digest or signature in place.

The operational audit log remains independent of the store and periodically
anchors its signed chain head through the Evidence/root-CAS protocol in
[Audit Chain Anchoring into Principal Storage](astrid-audit-store-anchoring.md).
The store therefore adds export and archaeological custody without becoming
the only witness to its own correctness.

## 13. CI gates

| Gate | Evidence |
|---|---|
| Model crate lands | Unit and property tests for ownership, views, witnesses, roots, import, and GC; `no_std` compile; docs build |
| In-memory engine lands | Model refinement, import/export and GC properties |
| KV adapter lands | Differential backend suite |
| Durable engine lands | Crash matrix, write-prefix enumeration, independent reader, corruption recovery, disk-full behavior |
| Filesystem projection lands | Adversarial path/symlink tests on each supported host |
| Export/import ships | Full/thin/view parser fuzzing, selector proofs, quota/decompression bounds, ownership and authority non-transfer tests |
| Rebalance ships | Multi-node epoch/lease/failure matrix and dry-run accounting |
| Native transport ships | Same conformance suite over the block capability plus power-cut harness |

Production documentation may say a property is held only after the corresponding
evidence runs against the shipped artifact and storage format.
