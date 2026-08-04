# Astrid Exact Physical Representations

Status: design contract; no capsule or WIT surface is activated

Tracks: [#1396](https://github.com/astrid-runtime/astrid/issues/1396)

This document defines the physical seam between a logical `ObjectId` and the
bytes from which that object can be recovered. It covers the current arena,
adopted contiguous staging files, packed and compressed bytes, exact deltas,
and deterministic generator recipes without turning any of them into a second
logical object model.

The deterministic `export_closure` bundle remains the archival authority. The
live engine, its representation catalogue, placement records, and indexes are
verified caches of that materialized model.

## Boundary

Four identifiers answer four different questions:

```text
ObjectId
    Which exact canonical ObjectRecord is this?

BlobId
    Which exact encoded byte string under which physical profile is this?

RepresentationRecordId
    Which verified recipe maps zero or more BlobIds and dependencies back to
    exact ObjectIds?

PlacementEpoch
    Where are the BlobIds needed by the active representation set?
```

`SemanticId` remains above this boundary. A semantic contract may establish
that different exact objects contain the same typed value; a physical
representation must reproduce the exact `ObjectRecord` identified by its
`ObjectId`. Similarity changes neither identity nor recoverability.

The current model's `BlobId -> ObjectId` relation is therefore a strict subset
of the design here. It remains valid for direct one-object representations,
but a contiguous file may efficiently cover many chunk objects and one
logical object may depend on several physical blobs.

## Binding invariants

1. Every live `ObjectId` has at least one complete, durable, recoverable
   representation at every publication and collection boundary.
2. A representation is admitted only after the engine reconstructs the target
   canonical record and recomputes its `ObjectId`. A supplied identity,
   checksum, recipe, size, or cost is never trusted as the result.
3. A digest match is candidate equality. Existing bytes are compared before a
   second binding collapses into the first.
4. Physical dependencies do not create principal ownership. They affect
   representation liveness and physical accounting, not logical closure,
   quota, export, fork, or erasure authority.
5. A new representation is verified and durable before it is published. The
   old final recovery path remains placed until publication is durable and all
   readers, commits, and maintenance passes that pinned it have released it.
6. Full export materializes canonical object records. A self-contained recipe
   may accompany them, but RÚNATAL promises only the materialized form.
7. Representation selection is kernel-side, bounded, and metered. Guests do
   not choose recipes, observe dedup outcomes, or learn which representation
   served an operation.
8. Cache exhaustion or representation rejection never invalidates a readable
   object. The selector tries another verified path; absence of every valid
   path is integrity failure, not a cache miss.
9. Reconstruction graphs are acyclic and bounded in depth, fanout, input
   bytes, output bytes, fuel, resident memory, and wall-clock policy.
10. No engine-local representation format changes the `ObjectId`, principal
    root, or canonical export of existing content.

## Identity constructions

Persistent identity envelopes use the algorithm-tagged, variable-digest
grammar already required by format one. The in-memory newtypes may remain
32-byte BLAKE3 values while the wire admits tagged 48-byte and longer
successors.

`RepresentationProfileId` identifies one immutable canonical physical-profile
record:

```text
RepresentationProfileV1 {
    version: u16 = 1,
    kind: direct-canonical | packed-canonical | contiguous-file | transform,
    decoder_or_generator: Option<ObjectId>,
    transform_closure: Option<ObjectId>,
    runtime_semantic_profile: Option<ObjectId>,
    canonical_parameters: length-prefixed bytes,
    immutable_dependencies: sorted unique DependencyV1[],
    reconstruction_bounds: ReconstructionBoundsV1,
    frozen_specification: ObjectId,
}

ReconstructionBoundsV1 {
    version: u16 = 1,
    maximum_dependency_depth: u32,
    maximum_dependency_fanout: u32,
    maximum_encoded_bytes: u64,
    maximum_output_bytes: u64,
    maximum_fuel: u64,
    maximum_resident_bytes: u64,
    maximum_elapsed_micros: u64,
}

RepresentationProfileId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-representation-profile-v1\0" ||
        canonical_profile_bytes
    )
)
```

Bounds encode in the field order shown, little-endian, with no padding. Every
maximum is non-zero. Admission requires direct fanout and transitive depth to
fit, the sum of encoded inputs to fit `maximum_encoded_bytes`, and both
`canonical_output_bytes` and `maximum_reconstruction_bytes` to fit
`maximum_output_bytes`. The sandbox meters fuel, peak resident bytes, and
elapsed time and discards partial output on any breach. An operator may impose
stricter limits by making the candidate unavailable, never by accepting a
different result under the same profile.

The profile pins the encoding grammar, decoder or generator closure,
deterministic runtime profile, dictionaries and other immutable data,
reconstruction-visible failure behavior, and reconstruction bounds. Built-in
direct, packed, and contiguous profiles pin their frozen engine grammar rather
than a transform capsule.
Registering a transform-backed profile is operator/signature authority: exact
output verification prevents substitution, but an untrusted decoder can still
waste resources or attack its sandbox.

Profile and recipe compatibility is closed in format one:

| Profile kind | Allowed recipe | Allowed coverage | Transform fields |
|---|---|---|---|
| `direct-canonical` | `DirectCanonical` | `Exact` | all absent |
| `packed-canonical` | `PackedSlice` | `Exact` | all absent |
| `contiguous-file` | `ContiguousFile` | `CanonicalFileChunks` | all absent |
| `transform` | `Compressed`, `Delta`, or `Generated` | `Exact` | all present |

For built-in profiles, `canonical_parameters` is the frozen empty value and
`frozen_specification` identifies the corresponding engine grammar. For a
transform profile, `decoder_or_generator`, `transform_closure`, and
`runtime_semantic_profile` are all present and included in
`immutable_dependencies`. `Generated` additionally requires that the
invocation's transform and runtime profile equal those profile fields.
Compressed and delta recipes treat the named transform as their decoder.
Every other field combination, recipe pairing, or coverage pairing is invalid
even if its bytes otherwise decode canonically.

```text
BlobId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-blob-identity-v1\0" ||
        encode(RepresentationProfileId) ||
        encoded_length_u64_le ||
        encoded_bytes
    )
)
```

Including the profile prevents the same bytes under two incompatible decoders
from sharing a physical name. A candidate-equal admission compares the complete
preimage: tagged identity envelope, profile identifier, encoded length, and all
encoded bytes. Placement retains the profile and length needed for that check.
Any unequal field is a fatal collision, never a dedup hit. Comparison streams
the bytes and does not require a whole-buffer allocation.

A representation record has its own canonical physical grammar rather than a
new logical `ObjectKind`. This keeps physical migration out of `ObjectId`
construction and avoids reopening the frozen object-kind table.

```text
RepresentationRecordV1 {
    version: u16 = 1,
    profile: RepresentationProfileId,
    coverage: CoverageV1,
    recipe: RecipeV1,
    dependencies: sorted unique DependencyV1[],
    canonical_output_bytes: u64,
    maximum_reconstruction_bytes: u64,
    verification_evidence: Option<ObjectId>,
}

RepresentationRecordId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-representation-record-v1\0" ||
        canonical_record_bytes
    )
)
```

Dependencies have an explicit tag and canonical tagged identity:

```text
DependencyV1 =
    LogicalObject(ObjectId)
  | PhysicalBlob(BlobId)
  | Representation(RepresentationRecordId)
  | Profile(RepresentationProfileId)
  | Invocation(InvocationId)
  | Evidence(ObjectId)
```

They are ordered first by tag and then by canonical identity bytes. The
dependency list is the complete set of direct profile, recipe, and evidence
dependencies; recursive traversal produces their complete closure. Coverage
has the separate deterministic traversal defined below and is not duplicated
in this array. Every representation record includes its profile as a `Profile`
dependency, and every profile includes its decoder, specification, runtime,
dictionary, and other direct dependencies. Nothing else may be fetched
ambiently during replay.

The canonical wire follows the existing format-one discipline:

- every integer is fixed-width little-endian;
- every tagged identity is `u16 algorithm`, `u16 construction`, `u32 digest
  length`, then exactly that many digest bytes;
- every byte string and sequence begins with a `u64` byte or item count;
- every option is one byte (`0` absent, `1` present) followed by the value;
- profile-kind tags are direct canonical `0`, packed canonical `1`,
  contiguous file `2`, and transform `3`;
- coverage tags are exact `0` and canonical-file-chunks `1`;
- recipe tags are direct `0`, packed slice `1`, contiguous file `2`,
  compressed `3`, delta `4`, and generated `5`; and
- dependency tags are logical object `0`, physical blob `1`, representation
  `2`, profile `3`, invocation `4`, and evidence `5`.

Counts must equal the bytes or items consumed, reserved values are rejected,
and there is no alignment padding. The eventual in-band specification freezes
the complete field-by-field layout and golden vectors before catalogue
activation; these tags may not ship with a different meaning.

Every decoder rejects unknown tags, non-minimal lengths, duplicate or
unordered dependencies, trailing bytes, non-canonical identities, arithmetic
overflow, and decode-then-re-encode inequality.

`canonical_output_bytes` is the sum of complete canonical record encodings for
the unique objects in `coverage`; repeated chunk occurrences count once.
`maximum_reconstruction_bytes` is an admission bound for one complete replay,
not a quota or total-store ceiling. The dependency array must equal the sorted
direct set derived from the profile identifier, recipe, and evidence fields.
The profile record and coverage grammar supply their own deterministic edges;
they are traversed rather than repeated in every representation. Omitting or
adding an array dependency is non-canonical rather than a second representation
of the same record. New alternate representations require evidence. Existing
implicit arena records use the arena's ordinary admission/recovery proof and
encode no invented evidence identifier.

### Coverage

Coverage states which exact logical records a representation can recover.

```text
CoverageV1 =
    Exact {
        object: ObjectId,
        canonical_record_bytes: u64,
    }
  | CanonicalFileChunks {
        file: ObjectId,
        content_root: Option<ObjectId>,
        logical_bytes: u64,
        chunk_count: u64,
        chunking_profile: ChunkingProfile,
    }
```

`CanonicalFileChunks` is the compact form required for staged-file adoption.
The referenced canonical File and ChunkTree records determine a unique ordered
sequence of chunk identities and lengths. The contiguous blob contains their
payload bytes in exactly that order. The representation therefore covers each
Chunk record without persisting a second `(ObjectId, offset, length)` record
for every chunk. A disposable reverse index may cache those slices.

The coverage fields are assertions, not an alternate File descriptor.
Admission decodes `file` and requires `content_root`, `logical_bytes`,
`chunk_count`, and `chunking_profile` to equal the canonical File fields and
its ownership edge exactly. It then validates the complete canonical tree
shape and totals. A mismatch is rejected; readers never choose between the
coverage copy and the File. This makes one accepted coverage encoding name one
File DAG.

Coverage traversal is output-aware. It retains the File record and every
reachable ChunkTree record as physical metadata dependencies, validates their
canonical shape, and stops whenever an ownership edge reaches a Chunk. That
Chunk is a covered output, not a dependency of the representation that
reconstructs it. For a single-chunk File the content edge therefore stops
immediately; for an empty File there are no outputs. Ordinary owning-closure
traversal must not be substituted here, because it would turn covered Chunk
leaves into a self-dependency. The derived metadata set is canonical and need
not be serialized per chunk.

The File and ChunkTree metadata remain ordinary canonical records. They are
small and are not replaced by the raw file blob. If the File ceases to be
logically live while one of its chunks remains live elsewhere, representation
GC may retain the metadata as a physical dependency, retain the whole blob, or
materialize the surviving chunks before dropping the file-wide representation.
Physical retention does not revive the dead File in a principal closure.

New coverage grammars require new tags. A decoder must never reinterpret an
old coverage record.

### Recipes

```text
RecipeV1 =
    DirectCanonical { blob: BlobId }
  | PackedSlice {
        blob: BlobId,
        offset: u64,
        length: u64,
    }
  | ContiguousFile { blob: BlobId }
  | Compressed {
        blob: BlobId,
        dictionary: Option<BlobId>,
    }
  | Delta {
        patch: BlobId,
        base: ObjectId,
    }
  | Generated {
        invocation: InvocationId,
        output_ordinal: u32,
        evidence: ObjectId,
    }
```

`DirectCanonical` and `PackedSlice` reproduce one complete canonical
`ObjectRecord` encoding. `ContiguousFile` is valid only with
`CanonicalFileChunks`; raw chunk payload plus the fixed Chunk grammar
reconstructs each covered canonical Chunk record. `Compressed`, `Delta`, and
`Generated` must produce a complete canonical record before identity
validation.

A delta names a logical base rather than a preferred base representation. The
selector independently finds a valid path to that `ObjectId`. Admission rejects
self-reference and cycles across representation, profile, logical-object, and
invocation dependencies and caps the complete dependency depth. Generated
recipes use the format-one invocation contract; effectful invocations are
ineligible because replay must not repeat side effects.

## Authoritative catalogue and disposable indexes

The persistent catalogue contains two canonical path-copy maps:

```text
RepresentationCatalogueRootV1 {
    version: u16 = 1,
    generation: u64,
    profiles_root: Option<PhysicalMapNodeId>,
    profile_count: u64,
    representations_root: Option<PhysicalMapNodeId>,
    representation_count: u64,
}

profiles:
    RepresentationProfileId -> RepresentationProfileV1
representations:
    RepresentationRecordId -> RepresentationRecordV1
```

The profile map is authoritative. An identifier without its verified profile
record is not a usable recovery path. Profile records and all dependencies
reachable from them remain live while any admitted representation names that
profile. Revocation blocks new admission only; admitted paths remain eligible
for reads and recovery until every dependent final path is replaced and leases drain.

All three authoritative maps use one frozen path-copy node grammar:

```text
PhysicalMapNodeV1 =
    Leaf {
        version: u16 = 1, domain, tag: u8 = 0,
        key: TaggedIdentity, value_bytes: u64, value,
    }
  | Branch {
        version: u16 = 1, domain, tag: u8 = 1,
        prefix_bits: u32, prefix: ceil(prefix_bits / 8) bytes,
        zero: PhysicalMapNodeId, one: PhysicalMapNodeId,
        subtree_entries: u64,
    }
```

The search key is the big-endian u32 byte length of a tagged identity followed
by its canonical bytes. This compressed binary radix trie stores the longest
common descendant prefix at each branch; the next bit selects `zero` or `one`.
Unused final-byte bits are zero, unary branches are forbidden, subtree counts
are exact, and leaf values re-derive their keys. The key set determines one
shape independent of insertion order. A point update path-copies at most the
search-key bit length. Empty maps have no root. Domain tags are profile `0`,
representation `1`, and placement `2`.
The domain participates in the node identity, so a profile page cannot be
reinterpreted as a placement page. The catalogue root, map nodes, profile
records, representation records, placement set, and state record are always
stored as direct canonical arena frames; metadata that explains an alternate
path never depends solely on that path.

Placement is a third authoritative map rooted by one placement set:

```text
PlacementSetV1 {
    version: u16 = 1,
    epoch: u64,
    entries_root: Option<PhysicalMapNodeId>,
    blob_count: u64,
    replica_count: u64,
}

PlacementEntryV1 {
    blob: BlobId,
    profile: RepresentationProfileId,
    encoded_length: u64,
    replicas: sorted non-empty unique ReplicaV1[],
}

ReplicaV1 {
    storage_node: StorageNodeId,      // canonical wire is u32
    locator: ArenaFrame { arena_generation: u64, offset: u64,
                          payload_length: u64, frame_checksum: [u8; 32] }
           | LooseBlob { namespace_generation: u64 }
           | PackFrame { pack_generation: u64, offset: u64,
                         frame_length: u64, frame_checksum: TaggedIdentity },
}
```

Placement leaves are keyed by `blob`; replicas sort by storage node, locator
tag, then locator bytes. Arena generation zero denotes verified `objects.arena`
at activation; its locator matches the durable index tuple. Each compaction
publishes a successor generation in the same placement CAS. A loose path derives
from `(namespace_generation, BlobId)` below an already-open private directory;
host paths never enter the wire. Pack ranges are in-bounds and non-overlapping.
Locators agree with frame headers; profile and length reproduce the BlobId
preimage. Counts never trust a disposable index. Tags are arena `0`, loose `1`,
and pack `2`.

The catalogue and placement roots become authoritative only as one pair:

```text
RepresentationStateV1 {
    version: u16 = 1,
    generation: u64, previous: Option<RepresentationStateId>,
    catalogue: RepresentationCatalogueRootId, placements: PlacementSetId,
}
```

State generations increase by exactly one from the previous state; creation
starts at one. Catalogue generations and placement epochs increase by exactly
one when their respective map changes and remain equal when that map is reused.

`PhysicalMapNodeId`, `RepresentationCatalogueRootId`, `PlacementSetId`, and
`RepresentationStateId` each use the full
`TaggedIdentity(algorithm, construction_version, digest_length, H(domain ||
canonical_bytes))` envelope. Their format-one derive-key strings are,
respectively, `astrid-physical-map-node-v1\0`,
`astrid-representation-catalogue-root-v1\0`,
`astrid-placement-set-v1\0`, and `astrid-representation-state-v1\0`. The
in-band specification freezes their golden vectors before activation.

Representation state never enters the principal `roots.journal`. Authority is
in `representations/CURRENT` and
`representations/generations/<16-lowercase-hex>/state.journal`. Both use the
format-one 52-byte frame and checksum with eight-byte magics `ASTCUR1\0` and
`ASTREP1\0`. `CURRENT` has one frame: `(journal_generation:u64,
checkpoint_digest:TaggedIdentity, max_tail_frames:u32, max_tail_bytes:u64)`.
A journal payload is one of:

```text
StateCasV1 = 0:u8 || journal_generation:u64 || expected:Option<RepresentationStateId> || replacement:RepresentationStateId
CheckpointV1 = 1:u8 || journal_generation:u64
    || active:Option<RepresentationStateId> || state_generation:u64 ||
       prior_journal_digest:Option<TaggedIdentity>
```
Options use tag `0` for absent and `1` plus the identity for present. Other tags,
trailing bytes, generation mismatches, or wrong file magics are invalid.
Every frame generation equals its directory name; `CURRENT`'s digest covers
the exact first checkpoint frame. Journal digests use derive key
`astrid-representation-journal-bytes-v1\0`. The first generation checkpoints
absence at generation zero with no prior digest. A CAS requires expected to
equal active; replacement names expected as `previous` and advances by one.
Blobs and metadata flush before the CAS frame, whose flush acknowledges it.
Recovery validates both selected closures and never activates either alone.
Tail limits are non-zero operator recovery budgets fixed for that generation.
Recovery counts frames and wrapper bytes after the checkpoint; publication
rolls over before exceeding either. A frame larger than the budget is rejected.
`previous` authenticates ordering but is not a liveness edge. Journal
compaction captures active state under the mutation fence and starts the next
generation with a checkpoint digesting every preceding journal byte. It flushes,
reopens, and verifies the journal before atomically replacing `CURRENT`. The old
generation remains authoritative until then and is reclaimed only after lease
drain. The audit chain retains history without extending startup replay.

Activation installs an amended in-band RÚNATAL object specifying these files.
After the new journal and `CURRENT` are durable it atomically changes
`store.meta`'s existing `format-spec-object`. Old readers reject that unknown
specification; until the change, implicit-direct mode remains authoritative.

The following are disposable and may be rebuilt from the catalogue,
placement set, and self-identifying blobs:

- `ObjectId -> candidate RepresentationRecordId[]` reverse lookup;
- chunk slice offsets derived from `CanonicalFileChunks` traversal;
- `BlobId -> local file/arena offset` lookup pages;
- verified-object, verified-edge, and cost-model caches; and
- access-frequency and locality observations.

A reverse-index miss is not proof that a representation is absent. It falls
back to the authoritative catalogue and repairs the index before returning
`MissingObject`; a corrupt positive is rejected and rebuilt. Disposable state
can therefore slow a lookup but cannot fabricate an object, authorize a root,
or hide the only recovery path. Rebuild compares every candidate against
authoritative identities.

The existing arena is an implicit `DirectCanonical` profile. Opening an
arena-only store synthesizes those representation entries in memory from its
verified object frames; no eager rewrite or logical migration is required.

### Recovery versus lazy byte verification

Open-time recovery verifies the active `RepresentationStateId`, both roots it
binds, blob existence and declared length, complete dependency closure,
canonical records, and retained admission evidence. It does not silently treat
an editable sidecar or filesystem timestamp as proof that every byte of a
multi-terabyte blob is still unchanged.

Direct arena frames retain their physical checksum validation. A contiguous
blob is reverified per covered Chunk before bytes cross the logical read
boundary; background scrub can recompute its whole BlobId, and an operator may
require a full open-time pass. A failed slice or whole-blob check quarantines
that representation and tries another path. If it was the final path, the read
fails with integrity error and the audit records loss rather than returning
unverified bytes.

An authenticated Evidence object proves what admission observed and binds the
exact representation, BlobId, File, and runtime/profile inputs. It supports
audit and process-local memo reconstruction; it does not claim that storage
media can never decay after the observation.

## Read and verification path

Selection occurs after authorization and before physical I/O:

```text
authorized ObjectId
    -> authoritative candidate lookup
    -> hard constraint filtering
    -> bounded cost selection
    -> acquire representation and placement lease
    -> reconstruct or read slice
    -> recompute canonical ObjectId on the verification boundary
    -> return bytes
```

Hard constraints precede scoring: privacy domain, trust state, complete placed
dependency closure at the required replica count, decoder and key-epoch
availability, bounds, lease acquisition, and caller resource authority. A
failed candidate is quarantined and the selector continues only when another
complete path exists.

For a contiguous file range, the File DAG supplies chunk boundaries and
identities. A cold read obtains complete overlapping chunks, validates slice
bounds, reconstructs their Chunk records, and recomputes each `ObjectId`.
Boundary-neighbor checks follow the existing content grammar. Process-local
principal-scoped verification evidence may skip work already proven; durable
verification state, if added, is an authenticated Evidence object bound to the
exact File, representation record, and BlobId, never an editable sidecar bit.

The blob's whole identity is verified at adoption and by scrub. This permits
sequential read-ahead while chunk identities retain bounded random-read
verification. A hosted `mmap` promise requires a provider-specific immutable
handle and tamper/degradation story. This design does not silently convert a
prior whole-blob verification into protection against privileged mutation of
a mapped host file.

## Costed selection

The selector minimizes an operator policy over measured candidates:

```text
cost(r) =
    w_read       * expected_physical_bytes_read(r)
  + w_write      * expected_physical_bytes_written(r)
  + w_cpu        * expected_cpu_time(r)
  + w_latency    * expected_tail_latency(r)
  + w_memory     * peak_resident_bytes(r)
  + w_retention  * retained_byte_time(r)
```

The weights and observations are deployment policy, not identity. The
selection receipt records the policy identity and actual resource
measurements. A recipe's own cost claim is only a hint; the engine applies
hard ceilings and charges actual execution. A small recipe with unbounded
reconstruction is rejected rather than preferred.

The search is a bounded traversal over representation dependencies. Cycles,
missing nodes, expired placements, depth overflow, or budget exhaustion make
that candidate unavailable. They never change the requested `ObjectId` or
fall through to unverified bytes.

## Publication and replacement

General representation publication uses this order:

1. reserve temporary physical bytes, resident memory, and compute from the
   operator resource authority;
2. create or locate candidate blobs without making them authoritative;
3. recompute every `BlobId`, reconstruct every declared target, compare
   candidate-equal existing bytes, and produce verification evidence;
4. flush all new blobs and their containing directories;
5. append and flush new profile/representation records, path-copy catalogue
   nodes, placement nodes, and their candidate roots;
6. under the representation mutation fence, recheck dependencies, limits, and
   the expected `RepresentationStateId`;
7. append and flush one state record and representation-journal CAS binding the new
   catalogue root and placement set;
8. release temporary reservations; and
9. retire replaced representations only after reader and transaction leases
   drain.

Publishing an alternate representation before any principal references its
objects is safe: it is an unowned recoverable cache entry. Publishing a
principal root before at least one representation is durable and catalogued is
forbidden. Root commit revalidates representation liveness while holding the
same mutation fence used by the resurrection rule.

Replacement is additive before it is subtractive:

```text
old valid
    -> old valid + new staged
    -> old valid + new published
    -> new published, old retiring
    -> new published
```

There is no state in which neither path is valid. ENOSPC, cancellation,
verification failure, or a root conflict leaves the old catalogue and
placement authoritative. A durability failure poisons and reopens the engine
through the existing recovery path before another mutation.

## Contiguous staged-file adoption

The native staging file is already the one physical write made on the
user-visible path. Adoption turns that sealed file into the raw-content blob
instead of copying its bytes into the object arena.

Preconditions:

- the staged generation is sealed, durable, and no longer writable;
- its intent, owner, content name, generation, length, and source file identity
  are canonical and verified;
- the blob store and staging area share an atomic-rename domain, or the engine
  explicitly falls back to copy publication; and
- an operation lease pins the staged generation until root publication or
  retry completes.

Protocol:

1. Validate the staging footer and require physical length to equal the
   declared logical prefix plus its encoded intent and 32-byte trailer. Stream
   exactly `logical_bytes` through FastCDC and the identity builders; the
   footer is never hashed as content. In the same pass compute the raw-content
   `BlobId`, emit File/ChunkTree records, and construct coverage.
2. Recheck the sealed generation and file identity. Any mutation rejects the
   attempt without publishing a root.
3. Write and flush an adoption intent naming the stage generation, logical and
   physical lengths, canonical encoded staging intent and its digest, source
   file identity, BlobId, representation record, expected principal root, and
   target path. This record preserves the complete recovery metadata before
   the in-file footer is lost.
4. Atomically rename the sealed generation to a non-authoritative incoming
   blob name and flush both namespaces. Truncate that inode to `logical_bytes`,
   flush it, and recompute its length and `BlobId`; then install it at the final
   BlobId path atomically with no-replace semantics. If it exists, open it
   no-follow below the pinned directory and never mutate it. Verify its complete
   preimage and reuse only an exact match; inequality is fatal. Without
   no-replace rename, exclusive-create and flush the final copy while retaining
   the sealed original; it stays non-authoritative.
5. Stage and flush every canonical File and ChunkTree metadata record required
   by coverage-aware traversal.
6. Publish the verified representation and placement. No placement ever names
   the incoming file or a file that still contains the staging trailer. Crash
   recovery uses the intent and physical length to validate and resume either
   the footer-bearing or truncated state, or quarantines an unrecognized one.
7. Publish the principal root. The commit fence rechecks the complete metadata
   and representation closure and the active `RepresentationStateId`.
8. Write the ordinary durable publication marker and reap the staging
   generation. A root conflict retries the catalog/root mutation without
   rereading the blob.

This path writes the source bytes once. It still writes bounded metadata and
durability records. Dropping one small file into a mounted filesystem remains
native staging work followed by asynchronous publication; large-file adoption
removes the second full-byte arena append measured in #1392.

## Liveness, GC, and compaction

Let `L` be the set of live logical `ObjectId`s and `R` the selected physical
representation records. Collection may publish only when:

```text
L is a subset of union(coverage(r) for r in R)

and

every transitive blob, object, profile, representation, invocation,
dictionary, delta-base, and generator dependency of each r in R is placed and
recoverable.
```

Logical reachability and representation reachability are separate fact
families. The existing format-one `GcFactSnapshotId` continues to describe the
logical object universe and root/pin reachability. Representation selection and
blob retirement use a separate canonical representation-placement snapshot;
they do not reinterpret historical GC snapshots or receipts.

The native collector enforces both proofs while holding the mutation fence.
Tensor Logic may explain or audit the relations, but it cannot authorize
deletion. Every destructive batch records the logical GC receipt plus the
exact representation catalogue and placement transition it executed.

Two races receive explicit fences:

- A commit that found a deduplicated object pins a valid representation until
  its root CAS. A hit on a quarantined object resurrects a path before publish.
- An immutable read handle pins its chosen representation record, BlobIds, and
  placement epoch. Compaction may install a new path but cannot remove the
  leased path until the handle closes.

A contiguous blob can retain far more bytes than the surviving slices need.
Compaction measures this amplification. It may keep the blob for hot sequential
reads, materialize independent live chunks, or add a compressed representation
before retiring it. It must never delete the blob while it is the final path
for any live covered object.

Compaction is the preferred representation-migration window because it already
streams live bytes. Reverification, sketches, reordering, recompression, and
contiguous materialization may share that traversal, while their CPU,
metadata, and writes remain measured rather than called free.

## Accounting and privacy

The accounting surface has five dimensions:

```text
logical ownership bytes
resident byte-time
CPU-time
physical bytes written
retention byte-time
```

For accounting interval `t`:

```text
logical_charge(domain, t)
    = sum(record.logical_bytes for each distinct ObjectRecord
          in the domain's owning closure at t)

physical_pool_bytes(t)
    = sum(allocator-reported bytes for every distinct live host extent at t)

retention_byte_time(domain, [a,b])
    = integral from a to b of bytes retained solely by that domain's pins,
      leases, history, or representation dependencies

request_compute(principal)
    = measured CPU-time + resident byte-time used to reconstruct its request
```

The logical sum is the existing identity-bearing accounting rule: structural
chunks and metadata may contribute zero, while catalogue records charge visible
occurrences. It may intentionally exceed the physical pool because sharing is
not exposed through price. Physical totals never sum principal charges.

Logical ownership is charged from the principal closure exactly as today,
independent of deduplication or selected representation. Within a declared
trust domain, shared learning/storage resources may be billed once to the
domain; splitting that charge among members is explicit domain policy.
Across domains each principal or domain is charged full logical freight. The
difference between logical charges and physical cost is the operator's sharing
dividend, never a guest-visible discount.

The operator ledger includes replicas, arena/journal metadata, pack slack,
disposable indexes/caches, staging, compaction, and temporary files. Loose
extents key by `(node, namespace generation, BlobId)`; pack extents key by
`(node, pack generation, offset, length)`. Replicas count separately; aliases
do not. Shared backing allocations charge at their container. Replacement
reserves overlap; same-volume adoption reclassifies sealed bytes.

Reconstruction compute and resident memory are charged to the requesting
principal/domain even when another principal made the representation warm.
History pins, legal holds, export leases, delta bases, and generator closures
accrue retention byte-time. Shared dependency costs use the same physical and
logical double ledger.

No guest-visible price, quota movement, admission result, status detail, or
error may depend on whether another privacy domain already had equal content.
Detailed reuse, selected path, physical cost, and insert/no-op outcomes remain
operator diagnostics. Timing warmth is the documented residual shared with
the host page cache; explicit APIs must not amplify it.

Deduplication and hard erasure remain exclusive on the same bytes. Root removal
plus representation GC deletes only uniquely owned physical closures. A shared
blob survives while any live object needs it. A domain requiring independent
cryptographic erasure uses domain-specific encryption and gives up cross-domain
deduplication for those encodings.

Format one deliberately defines no encryption recipe or `KeyEpochId` wire
tag. A future encryption extension must allocate new profile, recipe, and
dependency tags; define the canonical key-authority record and its tagged
identity; specify how recovery proves an unwrap path is available; and teach
RÚNATAL that grammar before activation. It may never smuggle an opaque key
identifier into format one. Once defined, the key authority is a liveness
dependency: losing its final unwrap path makes the representation
unrecoverable, and destroying it is the cryptographic-erasure operation for
that privacy domain.

## Export, import, and longevity

A full export reconstructs every reachable `ObjectRecord` and writes the
canonical materialized bundle grammar in deterministic ObjectId order.
Representation records, local placement, host paths, cost observations, and
cache indexes are excluded from the archival requirement.

An export may additionally include verified representation blobs and recipes
as optional acceleration. A recipient that cannot decode them still recovers
the complete root from materialized records. A thin export may omit records
only when its declared authenticated base proves possession of those exact
ObjectIds.

Import verifies materialized records first. Optional representations are
admitted only through the ordinary server-side BlobId, reconstruction,
collision-comparison, bounds, and registration path. An imported recipe never
becomes authority because it appeared beside correct bytes.

Successor hash or codec migration is additive: create tagged successor blobs
and representation records, verify them, publish them alongside old paths, and
retire old encodings only after policy and leases permit. Logical roots remain
unchanged.

## Existing-store compatibility

Arena-only stores require no principal migration:

1. Open verifies the existing arena and synthesizes implicit
   `DirectCanonical` candidates.
2. Creating an explicit representation catalogue is additive. Until its
   activation marker is durable, the arena remains the required recovery path.
3. Alternate representations may be populated without changing roots.
4. Compaction may remove the final arena copy only after the store records a
   minimum-reader capability that understands the representation catalogue.
5. Downgrade after that point materializes canonical arena records from the
   active representations before clearing the capability marker.

The activation marker, catalogue, and placement formats are engine-local
recovery state. They receive the same torn-tail and byte-prefix crash testing
as the arena. Before activation, the store's in-band RÚNATAL specification and
independent reader must learn their byte-exact grammar and be able to enumerate
every representation. Direct and contiguous materialized profiles must be
recoverable without Astrid code. Transform recipes may remain an optional live
economy only because their complete archived closure is retained and full
export materializes their outputs; they do not weaken RÚNATAL's canonical
materialized-export promise.

## Lifecycle summary

```text
admission
    untrusted candidate -> bounded reconstruction -> identity comparison
    -> durable staging -> catalogue/placement publication

adoption
    durable sealed file -> one-pass DAG and BlobId -> durable rename intent
    -> blob placement -> representation publication -> principal root CAS

selection
    authorized ObjectId -> constrained candidates -> lease -> reconstruct
    -> identity verification -> read result

compaction
    fenced live snapshot -> additive replacement representations
    -> verified placement epoch -> lease drain -> old-byte retirement

export
    pinned principal root -> representation-independent reconstruction
    -> canonical materialized bundle -> release pin

garbage collection
    logical reachability proof + representation coverage proof
    -> receipt-bound placement transition -> quarantine/lease drain
    -> physical deletion
```

## Failure and adversarial matrix

| Event or attack | Required outcome |
|---|---|
| Crash before blob durability | Candidate discarded; old path remains |
| Blob durable, record absent | Orphan quarantined and resumable/reclaimable |
| Record durable, representation-state CAS absent | Record remains unselected staging |
| Catalogue published, principal root absent | Valid unowned cache entry; root unchanged |
| Principal root proposed without a live representation | Commit fails closed |
| Profile record absent or unregistered | Dependent representation is unusable |
| File coverage field differs from the canonical File | Admission rejects the representation |
| File coverage traversal reaches a Chunk | Record it as output and stop; never add a self-dependency |
| Catalogue or placement root differs from the state record | Recovery fails closed; neither half activates |
| Crash while replacing a representation checkpoint | `CURRENT` selects the complete old or complete new generation |
| Crash during replacement | Recovery selects old or old-plus-new, never neither |
| ENOSPC during adoption or compaction | Old bytes/root survive; engine reopens in process |
| Blob digest collision with unequal bytes | Fatal collision; no catalogue mutation |
| Blob digest matches but profile or length differs | Fatal collision; no deduplication |
| Final BlobId path already exists | No-replace preserves it; exact preimage reuses it, mismatch is fatal |
| Reconstruction bound is zero, malformed, or exceeded | Candidate rejected; partial output discarded |
| Slice overflow, gap, wrong order, or wrong chunk | Representation rejected |
| Staged-file symlink, reparse, or identity swap | Adoption rejected; bytes preserved |
| Staged trailer remains after incoming rename | Placement stays unpublished; recovery truncates and reverifies or quarantines |
| Crash before File/ChunkTree metadata flush | Representation state remains inactive |
| Delta cycle or excessive chain | Candidate rejected before execution |
| Decompression/generator expansion bomb | Bounded execution fails without publication |
| Nondeterministic generator replay | Mismatch is an audit event; result not trusted |
| Guest supplies a cheaper cost or preferred recipe | Hint ignored; kernel policy selects |
| GC races a dedup hit | Commit lease preserves or resurrects the representation |
| Compaction races an open reader | Old placement remains until the read lease drains |
| One live slice retains a huge blob | Account amplification; materialize before dropping |
| Corrupt disposable index | Rebuild or slower verified path; never false bytes |
| Another principal already has equal content | Same logical charge and API result |
| Final representation selected for deletion | Native liveness proof rejects the batch |

## Internal API boundary

The first implementation is engine-private. It needs domain types rather than
guest host functions:

```text
RepresentationCatalogue
    candidates(ObjectId) -> verified candidate descriptors
    publish(expected_state, verified_profiles, verified_records, placements)
        -> RepresentationStateId

RepresentationLease
    pins record, blobs, dependencies, and placement epoch

RepresentationReader
    reconstruct(ObjectId, lease, bounded sink) -> canonical record
    read_file_range(File ObjectId, lease, range, bounded sink) -> bytes

RepresentationAdmission
    verify(candidate, resource lease) -> VerifiedRepresentation

RepresentationSelector
    choose(candidates, operator policy, resource authority) -> lease
```

Only the engine can construct `VerifiedRepresentation` or authorize catalogue
publication. Provider adapters consume the ordinary content open/read/write,
seal, and publish interfaces. Capsules continue to see authorized logical
objects and paths, not BlobIds, recipes, or dedup status. Any future WIT
surface requires a separate RFC after the interface freeze.

## Implementation and evidence order

1. Add canonical model types, golden vectors, decode/re-encode tests, and a
   primitive independent reader for the representation catalogue.
2. Model existing arena frames as implicit direct representations and add the
   authoritative catalogue plus disposable reverse index without deleting any
   arena bytes.
3. Add representation and placement leases, final-path liveness proofs, and
   crash-prefix enumeration.
4. Implement contiguous staged-file adoption and verified file-range reads.
5. Teach compaction to choose between retained contiguous blobs and
   materialized chunks while preserving receipts.
6. Add compressed, delta, and generated profiles only with pinned decoders,
   bounds, and corpus evidence.

The benchmark matrix compares direct arena, packed slice, contiguous file,
compressed, delta, and generated paths. It records ingest and reconstruction
throughput, latency by range size, physical bytes read/written, CPU, peak
resident memory, retained byte-time, metadata bytes, read amplification,
first-touch verification, warm verification, post-reopen behavior, and
compaction cost. Required workloads include random and repetitive files,
version chains, model-scale content, one-live-slice amplification, cache-cold
reads, concurrent principals, ENOSPC, and every named crash boundary.

No representation may replace the last direct arena path until independent
recovery, full materialized export/import, adversarial bounds, crash-prefix
testing, and the final-representation liveness proof all pass.
