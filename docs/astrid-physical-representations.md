# Astrid Exact Physical Representations

Status: historical design reference; no capsule or WIT surface is activated

Tracks: [#1396](https://github.com/astrid-runtime/astrid/issues/1396)

This document defines the physical seam between a logical `ObjectId` and the
bytes from which that object can be recovered. The current durable path is the
packed arena.

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

`SemanticId` remains above this boundary. A semantic contract may equate typed values, but a
physical representation reproduces the exact `ObjectRecord` named by `ObjectId`; similarity
changes neither identity nor recoverability. The current `BlobId -> ObjectId` relation remains
the direct-one-object subset; objects may use many blobs.

## Binding invariants

1. Every live `ObjectId` has a complete durable representation at publication and collection.
2. Admission reconstructs the canonical record and recomputes `ObjectId`; supplied identity,
   checksum, recipe, size, and cost are never trusted as results.
3. A digest match is only candidate equality; existing bytes compare before collapse.
4. Physical dependencies affect liveness and accounting, never principal ownership, logical
   closure, quota, export, fork, or erasure authority.
5. New paths verify and become durable before publication. The old final path remains through
   durability and release of every reader, commit, and maintenance lease.
6. Full export materializes canonical records; recipes may accompany them, but RÚNATAL promises bytes.
7. Selection is kernel-side, bounded, and metered; guests cannot choose or observe representations.
8. Cache exhaustion or candidate rejection tries another verified path; no path is integrity failure.
9. Reconstruction graphs bound acyclic depth, fanout, input/output bytes, fuel, memory, and time.
10. Physical formats change no `ObjectId`, principal root, or canonical export.

## Identity constructions

Persistent identity envelopes use the algorithm-tagged, variable-digest
grammar already required by format one. The in-memory newtypes may remain
32-byte BLAKE3 values while the wire admits tagged 48-byte and longer
successors.

Every physical ID introduced here uses registered tuple `(algorithm=1,
construction_version=2, digest_length=32)`, meaning BLAKE3 physical identity v1:

```text
PhysicalId(context, material) = TaggedIdentity(1, 2, 32,
    BLAKE3_DERIVE_KEY(context, material)[0..32])
```

`context` is the exact UTF-8 derive-key string shown, including its terminal NUL;
`material` is only the following canonical bytes. The context is never prefixed
to message data. BLAKE3 uses DERIVE_KEY_CONTEXT then DERIVE_KEY_MATERIAL as in
RÚNATAL. Logical `ObjectId` remains registered tuple `(1,1,32)`.

`RepresentationProfileId` identifies one immutable canonical physical-profile
record:

```text
RepresentationProfileV1 {
    version: u16 = 1,
    kind: direct-canonical | packed-canonical | transform,
    decoder_or_generator: Option<ObjectId>,
    transform_contract: Option<ObjectId>,
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

RepresentationProfileId = PhysicalId("astrid-representation-profile-v1\0", canonical_profile_bytes)
```

Bounds encode in the field order shown, little-endian, with no padding. Every
maximum is non-zero. Admission requires fanout and depth to fit, encoded-input
sum to fit `maximum_encoded_bytes`, and `canonical_output_bytes` <=
`maximum_reconstruction_bytes` <= `maximum_output_bytes`. The sandbox meters
fuel, peak resident bytes, and
elapsed time and discards partial output on any breach. An operator may impose
stricter limits by making the candidate unavailable, never by accepting a
different result under the same profile.

The profile pins the encoding grammar, decoder or generator closure,
deterministic runtime profile, dictionaries and other immutable data,
reconstruction-visible failure behavior, and reconstruction bounds. Built-in
direct and packed profiles pin their frozen engine grammar rather
than a transform capsule.
Registering a transform-backed profile is operator/signature authority: exact
output verification prevents substitution, but an untrusted decoder can still
waste resources or attack its sandbox.

Profile and recipe compatibility is closed in format one:

| Profile kind | Allowed recipe | Allowed coverage | Transform fields |
|---|---|---|---|
| `direct-canonical` | `DirectCanonical` | `Exact` | all absent |
| `packed-canonical` | `PackedSlice` | `Exact` | all absent |
| `transform` | `Compressed`, `Delta`, or `Generated` | `Exact` | all present |

For built-in profiles, `canonical_parameters` is empty and
`immutable_dependencies` is exactly
`[LogicalObject(frozen_specification)]`. Transform profiles require exactly one
value in each named transform field. Their dependency array is the sorted
unique union of `LogicalObject(decoder_or_generator)`,
`LogicalObject(transform_contract)`,
`LogicalObject(runtime_semantic_profile)`,
`LogicalObject(frozen_specification)`, and the dependency slots required by the
frozen transform contract. An ObjectId slot always contributes
`LogicalObject`; a BlobId slot, including a profile-wide dictionary,
contributes `PhysicalBlob`. Other dependency tags are invalid in a profile.
`canonical_parameters` contains scalar canonical values only: every additional
identity is a typed contract slot and contributes to the array. The contract
fixes slot count and type; missing, extra, differently tagged, or duplicate
entries reject. When one identity fills several named roles, role multiplicity
remains in the named fields while the sorted array contains one typed entry.

`Generated` requires `invocation.transform == decoder_or_generator`,
`invocation.transform_contract == transform_contract`, and
`invocation.runtime_semantic_profile == runtime_semantic_profile`.
Compressed and delta recipes use the named decoder; every other field, recipe, or coverage combination is invalid even if canonically encoded.
Bootstrap specification objects are terminal: the current `store.meta` specification and recognized
downgrade predecessors remain pinned direct `objects.arena` frames. Loaded before selection and
copied by compaction, they have no profile-backed representation, preventing a recovery cycle.

```text
BlobId = PhysicalId("astrid-blob-identity-v1\0",
    encode(RepresentationProfileId) || encoded_length_u64_le || encoded_bytes)
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

RepresentationRecordId = PhysicalId("astrid-representation-record-v1\0", canonical_record_bytes)
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
dependency. Profile traversal follows exactly its validated
`immutable_dependencies`: a built-in profile retains only its frozen
specification, while a transform profile retains the role-typed set derived
above. Nothing else may be fetched ambiently during replay.

The record array is exactly the sorted unique union of `Profile(profile)` and
these recipe-derived entries: direct and packed add
`PhysicalBlob(blob)`; compressed adds `PhysicalBlob(blob)` and its optional
`PhysicalBlob(dictionary)`; delta adds `PhysicalBlob(patch)` and
`LogicalObject(base)`; generated adds `Invocation(invocation)` and
`Evidence(evidence)`. A present `verification_evidence` adds
`Evidence(verification_evidence)`, collapsing only when it is the generated
recipe's same evidence ObjectId. No other entry is admitted.

An `Invocation` dependency has a specialized replay-liveness traversal. It
retains the invocation record, its complete `Owns` closure, the optional
`05-provenance-snapshot` Evidence target, every `10-input/` Evidence target,
and each such target's complete `Owns` closure. It does not retain derived
outputs. This rule makes replay inputs and a SnapshotBound observation live
even though the logical invocation deliberately records them as non-owning
evidence edges. Representation GC applies this traversal; a generic owning-only
walk is invalid for generated-representation liveness. Default
`export_closure` does not apply this traversal: it materializes only the
principal's logical owning closure and omits physical recipes, evidence, and
their non-owned inputs. An explicitly selected and separately authorized
recipe/evidence export may include the replay closure; it is not the default
full export.

The canonical wire follows the existing format-one discipline:

- every integer is fixed-width little-endian;
- every discriminant is one `u8` unless its field explicitly states another width;
- every tagged identity is `u16 algorithm`, `u16 construction`, `u32 digest
  length`, then exactly that many digest bytes;
- every byte string and sequence begins with a `u64` byte or item count;
- every option is one byte (`0` absent, `1` present) followed by the value;
- profile-kind tags are direct canonical `0`, packed canonical `1`, and
  transform `3` (tag `2` is invalid);
- coverage tags are exact `0` (tag `1` is invalid);
- recipe tags are direct `0`, packed slice `1`, compressed `3`, delta `4`,
  and generated `5` (tag `2` is invalid); and
- dependency tags are logical object `0`, physical blob `1`, representation `2`, profile `3`, invocation `4`, and evidence `5`.

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
```

The coverage fields are assertions, not an alternate File descriptor.
For `Exact`, `canonical_record_bytes` equals the byte length of the target
ObjectId's complete canonical `ObjectRecord` encoding produced by replay;
admission and recovery reconstruct, identify, and compare that record before
accepting the length. An arbitrary claimed length is invalid.

File and ChunkTree metadata remain ordinary canonical records published
through packed arena ingest. New coverage grammars require new tags. A
decoder must never reinterpret an old coverage record.

### Recipes

```text
RecipeV1 =
    DirectCanonical { blob: BlobId }
  | PackedSlice {
        blob: BlobId,
        offset: u64,
        length: u64,
    }
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
`ObjectRecord` encoding. `Compressed`, `Delta`, and
`Generated` must produce a complete canonical record before identity
validation.

For direct, packed, compressed, and delta recipes, the
`PlacementEntry.profile` of the primary `blob` or `patch` must equal
`RepresentationRecordV1.profile`. A dictionary and any other dependency blob
retains its own profile. A mismatch is invalid rather than an opportunity to
run one profile's decoder over bytes named by another.

A delta names a logical base, not a preferred representation; the selector finds a path to
that `ObjectId`. Admission rejects cycles across representation, profile, logical-object,
and invocation dependencies and caps total depth. Generated recipes admit only format-one's
memoizable `Pure` and `SnapshotBound` classes; `Effectful` and `Nondeterministic` are rejected.
Their evidence must decode canonically as `DerivationEvidence`, identify itself, and validate
the named invocation. `output_ordinal` is zero-based and in-bounds; its evidence output must equal
the sole `Exact` coverage ObjectId. Any mismatch makes the representation inadmissible.

### Admission evidence

Non-generated alternate encodings use one closed evidence grammar. The
evidence is an `ObjectKind::Evidence` (kind 10), format version 1, Metadata
class, `logical_bytes = 0`, with no references and canonical bytes:

```text
RepresentationAdmissionEvidenceV1 {
    magic: [u8; 8] = "ASTRAE1\0",
    version: u16 = 1,
    subject: RepresentationAdmissionSubjectId,
    method: u8,
    primary_blob: BlobId,
    observed_encoded_bytes: u64,
    observed_output_bytes: u64,
    transcript: TaggedIdentity,
}
```

Method tags are direct `0`, packed slice `1`, compressed `3`, and delta `4`
(tag `2` is invalid), and must match the recipe. The subject is
`PhysicalId("astrid-representation-admission-subject-v1\0", bytes)` where
`bytes` is the candidate representation's canonical encoding normalized by
setting `verification_evidence` absent and removing precisely its derived
Evidence dependency. This breaks the otherwise circular evidence-to-record
identity while binding every profile, coverage, recipe, bound, and remaining
dependency field.

The transcript is
`PhysicalId("astrid-representation-admission-transcript-v1\0", material)`,
where material is `covered_output_count:u64` followed, in the coverage-defined
traversal order, by each recomputed output ObjectId envelope and its complete
canonical-record byte length as `u64`. Counts and lengths are checked. The
observed byte fields equal the primary placement's encoded length and the
record's `canonical_output_bytes` respectively.

For `Exact`, the transcript has one output. `covered_output_count` is the
unique emitted count and agrees with the unique-object rule for
`canonical_output_bytes`.

The engine reconstructs the outputs, recomputes the evidence, and admits only
the identical ObjectId; a guest or importer never supplies a trusted claim.
The evidence records an observation and does not replace lazy read verification
or scrub. A direct representation of the exact canonical bytes already stored
in a checksummed `objects.arena` frame may omit evidence because ordinary
server-side object admission is its proof and it is not an alternate encoding.
Every other non-generated representation requires this evidence. A generated
record instead requires `verification_evidence == Some(recipe.evidence)` and
that object must be the canonical `DerivationEvidence` validated above.

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

The verified entry count is zero for an absent root, one for a Leaf root, and
the authenticated `subtree_entries` for a Branch root. Each catalogue count,
and the placement `blob_count` below, equals that value for its respective map;
arithmetic overflow fails. The profile map is authoritative: an identifier
without its verified record is unusable. Profile records and dependencies stay
live while referenced.
Revocation is signed operator policy keyed by profile and authority epoch, not catalogue state. It
survives restart, blocks new admission and preference, but never recovery; unavailable policy
fails closed for new transform admission. The profile remains until every path is replaced and
leases drain.

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

The search key is its big-endian u32 byte length followed by tagged-identity bytes; this length is
the sole exception to the general little-endian integer rule. Trie traversal is most-significant
bit first within each byte (`0x80` through `0x01`), beginning with the length prefix. The trie stores
the longest common descendant prefix; the next bit selects `zero` or `one`. Unused low bits in the
final prefix byte are zero, unary branches are forbidden, subtree counts are exact, and leaves re-derive keys. The key
set determines one shape regardless of insertion order. Point updates copy at most the key's bit
length. Empty maps have no root. Domain tags are profile `0`, representation `1`, and placement `2`.
The node identity includes its domain, so cross-map reinterpretation fails.
Physical metadata never enters logical `objects.arena`. Each generation's
`metadata.arena` uses the format-one header, magic `ASTRPM1\0`, and payload:

```text
MetadataFrameV1 = kind:u8 || identity:TaggedIdentity || value_bytes:u64 || canonical_value[value_bytes]
```
Kinds are profile `0`, representation `1`, map node `2`, catalogue root `3`, placement `4`,
and state `5`. Recovery round-trips values and re-derives IDs; exact duplicates collapse.
Unequal values under one `(kind, identity)` or missing material references fail.
`RepresentationStateV1.previous` is the sole exception: it is a lineage scalar,
not a metadata-closure edge. Recovery validates it against the journal CAS
predecessor while replaying a generation; a checkpoint may retain only the
active state and validates earlier lineage through `prior_journal_digest` and
the state generation. It never resolves `previous` as a copied metadata object.
The scan index is disposable and not authoritative; frames never depend on their paths.

Placement is a third authoritative map rooted by one placement set:

```text
placements:
    BlobId -> PlacementEntryV1
```

The leaf key must equal the embedded `PlacementEntryV1.blob`.

```text
PlacementSetV1 {
    version: u16 = 1,
    epoch: u64,
    entries_root: Option<PhysicalMapNodeId>,
    blob_count: u64,
    replica_extent_count: u64,
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
           | PackFrame { pack_generation: u64, offset: u64,
                         frame_length: u64, frame_checksum: [u8; 32] },
}
```

Placement has `replica_extent_count == checked sum of replica-list lengths`;
durability instead counts distinct `StorageNodeId`s, so same-node copies never satisfy
redundancy. Replicas sort by node, locator tag, then bytes. Arena generation zero denotes verified `objects.arena` at activation;
its locator matches the durable index tuple. Each compaction
publishes a successor generation in the same placement CAS. `StorageNodeId`
selects a signed operator-configured, already-open storage root. Beneath that
root, locator paths are canonical ASCII and never supplied by an index:

```text
ArenaFrame generation 0:  objects.arena
ArenaFrame generation N:  representations/blobs/arenas/<N:016x>.arena
PackFrame generation N:   representations/blobs/packs/<N:016x>.pack
```

`<BlobId>` is lowercase hex of the complete canonical tagged-identity envelope;
generations use exactly 16 lowercase hex digits. Resolution walks no-follow
directory handles below the selected root and rejects extra components,
symlinks, aliases, and non-canonical spelling. A missing configured storage
node or file makes that replica unavailable; it never falls back to an ambient
host path.

Nonzero blob arenas and packs are sequences of the common 52-byte format-one
physical frame. Arena magic is `ASTBLA1\0`; pack magic is `ASTBLP1\0`.
Frame version, reserved bytes, checksum context/material, and torn-tail rules
are exactly those in `crates/astrid-storage/formats/principal-store-v1.txt` section 2. Both use:

```text
BlobFrameV1 = blob:BlobId || profile:RepresentationProfileId
    || encoded_length:u64 || encoded_bytes[encoded_length]
```

There is no payload padding or trailing data. For `ArenaFrame`, `offset` names
the header byte, locator `payload_length` equals the header payload length, and
`frame_checksum` equals the header checksum. For `PackFrame`, `offset` likewise
names the header, `frame_length == 52 + payload_length` with checked arithmetic,
and the checksum equals the header. Payload blob, profile, and encoded length
must equal the `PlacementEntryV1`; the encoded bytes reproduce the BlobId.
Generation-zero arena locators instead read the existing `ASTOBJ1\0` object
frame grammar. Pack ranges are in-bounds and non-overlapping.

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
`RepresentationStateId` use `PhysicalId(context, canonical_bytes)`. Their contexts are
`astrid-physical-map-node-v1\0` for legacy binary nodes,
`astrid-physical-radix-map-node-v1\0` for dense radix nodes,
`astrid-representation-catalogue-root-v1\0`,
`astrid-placement-set-v1\0`, and `astrid-representation-state-v1\0`. The
in-band specification freezes their golden vectors before activation.

Representation state never enters principal `roots.journal`. Authority is in
`representations/CURRENT` and each
`representations/generations/<16-lowercase-hex>/{metadata.arena,state.journal}`. `CURRENT` and
the journal use the format-one header with magics `ASTCUR1\0` and `ASTREP1\0`.
`CURRENT` has one frame: `(journal_generation:u64,
checkpoint_digest:TaggedIdentity, max_tail_frames:u32, max_tail_bytes:u64)`.
A journal payload is one of:

```text
StateCasV1 = 0:u8 || journal_generation:u64 || expected:Option<RepresentationStateId> || replacement:RepresentationStateId
CheckpointV1 = 1:u8 || journal_generation:u64
    || active:Option<RepresentationStateId> || state_generation:u64 || prior_journal_digest:Option<TaggedIdentity>
```
Options use tag `0` for absent and `1` plus identity; other tags, trailing bytes,
generation mismatches, or wrong magics fail. Frame generation equals directory;
`CURRENT` and prior-journal digests use `PhysicalId("astrid-representation-journal-bytes-v1\0",
exact_journal_bytes)` over the first checkpoint or complete preceding journal. Generation one checkpoints absence
at state generation zero with no prior digest. A CAS requires expected to equal
active; replacement names it as `previous` and advances by one. Metadata and
blobs flush before the acknowledging CAS flush. Recovery validates both roots.
Non-zero operator tail budgets are fixed per generation; publication rolls over
before frame or wrapper-byte count exceeds them, and rejects an oversized frame.
`previous` authenticates journal ordering but is neither live nor a metadata reference. Under the mutation fence,
compaction copies the active metadata closure into a successor generation and
checkpoints the prior journal digest. Both files flush, reopen, and verify before
`CURRENT` changes. Replacement exclusively creates `CURRENT.tmp`, writes its frame, flushes and
reopens it, atomically renames it over `CURRENT`, then flushes the parent directory; it never edits
in place. Before that directory flush, recovery may select the valid old or new pointer; after
acknowledgement it must select new. A leftover temporary is never a candidate and is quarantined
only after valid `CURRENT` selection. The old generation survives until lease drain; audit history
does not extend startup replay.

Activation first flushes amended RÚNATAL as a terminal bootstrap frame, then writes direct records
and exact `ArenaFrame` placements for every non-bootstrap object in the recovered arena index. It
checkpoints, reopens, and closure-validates that state under implicit-direct mode before `store.meta`
atomically names the amended spec. A crash before the marker uses implicit arena recovery; afterward
every indexed object has an explicit path. Old readers reject the amended spec.

The following are disposable and may be rebuilt from the catalogue,
placement set, and self-identifying blobs:

- `ObjectId -> candidate RepresentationRecordId[]` reverse lookup;
- chunk slice offsets rebuilt from canonical File/ChunkTree records;
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

The replica-isolated corruption policy, verification boundary, and read-path
evidence requirements are normative in
[astrid-principal-store-evidence.md](astrid-principal-store-evidence.md#14-physical-representation-recovery-and-reads).

## Read and verification path

The authorized selection and verified-read state machine is specified by the
same evidence section. Implementations distinguish replica failure from
representation failure; neither is an untyped "candidate" failure.

## Costed selection

The operator policy, bounded search, and measurement contract are normative in
[astrid-storage-performance.md](astrid-storage-performance.md#representation-selection-cost-model).

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
logical object universe and root/pin reachability. Any future representation
placement would use a separate canonical snapshot; current packed arena
collection reclaims packed arena media only.

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

Current compaction streams live packed arena bytes and preserves canonical
chunk identities. Reverification, sketches, reordering, and any future
transform remain measured experiments rather than implicit writers.

## Accounting and privacy

The accounting surface has six dimensions:

```text
logical ownership bytes
resident byte-time
CPU-time
physical allocated bytes
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
chunks and metadata may contribute zero, while principal content-catalog leaf
records charge visible occurrences. Physical representation-catalogue records
never create logical ownership. The logical sum may intentionally exceed the
physical pool because sharing is not exposed through price. Physical totals
never sum principal charges.

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

A generated representation and every replay-required invocation input and
snapshot must belong to one erasure domain. Cross-domain replay dependencies
require an explicit source-domain grant into an erasure-waived retention class;
without it admission fails. Before acknowledging hard erasure, the mutation
fence finds every external recipe that depends on the condemned domain and
materializes or replaces its outputs, or removes that recipe. Another domain's
physical optimization may never delay an acknowledged source-domain erasure.

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
2. Creating an explicit representation catalogue is additive. Until the amended
   `format-spec-object` marker is durable, the arena remains the required recovery path.
3. Alternate representations may be populated without changing roots.
4. Compaction preserves the final packed arena copy; no alternate representation
   may replace it through this compatibility path.
5. Downgrade materializes, flushes, and verifies canonical arena records before
   atomically restoring the predecessor `format-spec-object`; only then may it reclaim representation state.

The format-spec marker, catalogue, and placement formats are engine-local
recovery state. They receive the same torn-tail and byte-prefix crash testing
as the arena. Before activation, the store's in-band RÚNATAL specification and
independent reader must learn their byte-exact grammar and be able to enumerate
every packed representation. Unknown recipe, profile-kind, and replica-locator
tags fail closed. Transform recipes may remain model grammar only because full
export materializes canonical records; they do not weaken RÚNATAL's canonical
materialized-export promise.

## Lifecycle summary

```text
admission
    untrusted candidate -> bounded reconstruction -> identity comparison
    -> durable staging -> catalogue/placement publication

ingest
    staged home files -> packed arena frames -> representation publication
    -> principal root CAS

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

The crash and adversarial outcomes live with the executable store obligations
in [astrid-principal-store-evidence.md](astrid-principal-store-evidence.md#15-physical-representation-failure-matrix).

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

The implementation sequence, benchmark matrix, and replacement gates live with
the rest of the store's proof obligations in
[astrid-principal-store-evidence.md](astrid-principal-store-evidence.md#16-physical-representation-implementation-gates).
