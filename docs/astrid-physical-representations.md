# Astrid Exact-Byte Physical Representations

Status: design contract; no alternate representation is active

Tracks: [#1396](https://github.com/astrid-runtime/astrid/issues/1396)

Companions:
[Principal Store](astrid-principal-store.md),
[Principal Content DAG](astrid-principal-content-dag.md),
[Durable Compaction](astrid-durable-compaction.md),
[Semantic Representations](astrid-semantic-representations.md), and
[Storage Performance and Convergence](astrid-storage-performance.md)

## Outcome

One immutable logical object may be recoverable from several physical
encodings without changing its `ObjectId`. The engine may keep canonical arena
bytes, a verified slice of an adopted file, compressed bytes, a delta, or a
deterministic recipe. These are alternative ways to reproduce the same exact
canonical `ObjectRecord`; they are not semantic equivalence.

This document defines one representation mechanism for all of them. It does
not add a capsule interface. It also does not make alternate encodings part of
format one merely by describing them: the activation gate in
[Compatibility and activation](#compatibility-and-activation) must pass before
the last canonical arena copy can be collected.

The central relation is:

```text
logical ObjectId
    -> one or more immutable RepresentationBinding records
    -> one or more identified physical blobs and reconstruction dependencies
    -> exactly one canonical ObjectRecord
```

An adopted contiguous file is the first important case. The file bytes become
one physical blob without a second data write. Its binding covers the Chunk
objects in the already-canonical File DAG by verified `(BlobId, offset,
length)` slices. File and ChunkTree records remain small canonical records.
The same binding is a direct range-read plan for the File, so the provider does
not gather chunks merely to reassemble bytes already contiguous on disk.

## Boundary and terminology

Four identifiers remain separate:

- `ObjectId` identifies one exact canonical typed logical object;
- `BlobId` identifies bytes under one exact physical encoding profile;
- `RepresentationBindingId` is the `ObjectId` of an immutable Evidence record
  proving how one blob closure recovers one object or object set; and
- `SemanticId` identifies equality under a separately registered semantic
  contract and stays above this mechanism.

None is a capability. Lookup begins only after principal/root authority has
been checked. A caller requests an authorized logical object or byte range;
the engine, not the caller, selects a physical recovery path.

The word *materialized* has two precise uses:

- a materialized representation directly contains the canonical bytes needed
  by its reconstruction profile; and
- a materialized export contains canonical `ObjectRecord` bytes for every
  object in the selected closure, irrespective of how the source engine kept
  them.

The current `objects.arena` frame is an implicit `ArenaCanonicalV1`
materialized representation. It remains valid even when no explicit binding
record exists.

## Binding invariants

1. **Exact output.** A successful recovery re-encodes one canonical
   `ObjectRecord`, recomputes its complete tagged `ObjectId`, and compares the
   full record on a candidate digest collision.
2. **At least one path.** Every live logical object is covered by at least one
   complete, durable, terminating recovery path. Coverage may come from its
   own binding or from a canonical multi-object coverage rule.
3. **Closure liveness.** A recovery path retains its blob, profile, decoder,
   dictionary, delta base, generator, immutable inputs, parameters, and every
   transitive dependency.
4. **Safe replacement.** A new path is durable and verified before the old
   final path becomes reclaimable. No crash prefix publishes zero paths.
5. **Bounded reconstruction.** Admission and selection bound depth, fanout,
   output bytes, resident bytes, fuel, I/O, and deadlines. Small-on-disk is not
   synonymous with cheap or safe.
6. **Placement is not authority.** Offset maps and locality indexes are
   disposable. Authoritative binding records and self-identifying blob
   containers can rebuild them.
7. **Export materializes.** Recipes may accompany a bundle, but recovery of a
   full archival bundle never needs the source engine, its placement index, or
   an unavailable transform.
8. **Dedup stays below the API.** Guest-visible latency classes, results,
   accounting, and admission outcomes do not disclose whether a blob or
   representation was already present.

These properties apply independently of whether two principals, a team
domain, or the operator physically share a blob.

## Blob identity and encoding profiles

`BlobId` uses the same extensible tagged-identity envelope as persistent
`ObjectId` values. Construction one is:

```text
BlobId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-blob-identity-v1" ||
        encode(PhysicalEncodingProfileId) ||
        u128_le(encoded_bytes.length) ||
        encoded_bytes
    )
)
```

`PhysicalEncodingProfileId` is the `ObjectId` of an immutable profile
specification. Including it prevents identical octets with different decode
semantics from sharing one physical name. A digest match remains a candidate:
the profile and complete bytes are compared before two admissions collapse.

A profile pins at least:

```text
PhysicalEncodingProfile {
    format_version
    output_contract                 // canonical ObjectRecord bytes
    native_operation_contract?      // for engine-native raw/arena/slice forms
    decoder_invocation_contract?    // for capsule transforms
    decoder_closure
    deterministic_runtime_profile?
    canonical_parameters
    maximum_encoded_bytes
    maximum_decoded_bytes
    maximum_expansion_ratio
    maximum_dependency_depth
    maximum_dependency_fanout
}
```

Exactly one of the native or capsule decoder contracts is present. Native
profiles name a frozen engine operation contract and fixtures; they are not
identified by a Rust type or build hash. Capsule profiles use the invocation
contract from [Conservation of Computation](astrid-conservation-of-computation.md).
Operational fuel, memory, and latency limits may be stricter than profile
ceilings without changing identity. A limit that changes accepted output is
part of the profile.

Initial profile families are:

- `ArenaCanonicalV1`: the complete existing arena payload;
- `RawSliceV1`: an exact byte range in an immutable raw blob;
- `PackedCanonicalV1`: one or more self-identifying canonical records;
- `CompressedCanonicalV1`: a pinned lossless decoder and optional dictionary;
- `ExactDeltaV1`: a pinned base plus patch decoder;
- `DeterministicGeneratorV1`: one exact invocation result; and
- future encryption or erasure profiles registered at the same boundary.

Compression, delta, and generator profiles are physical encodings only when
they reproduce the exact target record. A lossy transform creates a different
logical object or semantic derivation; it never enters this catalog as an
equal encoding.

Possessing a profile object does not register it. Registration is
operator/signature authority and binds the profile identifier, allowed
privacy domains, native operation or pinned decoder, admission status, and
deprecation epoch. An arbitrary capsule cannot advertise itself into the
recovery path. Revocation prevents new admission; an already authoritative
path is replaced by another complete path before its decoder or dependencies
can be removed. Emergency quarantine may make an affected object unavailable,
but it may not silently decode it with a different implementation.

## Authoritative representation catalog

The persistent catalog is an engine-owned component beneath the
`StateOwner::System` principal state. The system `PrincipalState` owns one
reference labelled `representations`; its target is a canonical path-copy
tree. Root publication therefore uses the existing object arena, root journal,
tagged identities, and compare-and-swap ordering rather than adding an
uncoordinated side database.

Only engine authority may update this system root. A principal can store bytes
that happen to encode a binding Evidence object, but that object is inert until
the engine independently verifies it and publishes it in the catalog.

Catalog nodes and binding records are ordinary canonical Evidence objects
with domain prefixes. They are always stored as canonical arena frames. This
bootstrap rule is absolute: the metadata that explains alternate recovery may
not itself depend solely on alternate recovery.

The abstract map is:

```text
Catalog : CoverageAnchor -> ordered Set<RepresentationBindingId>

ObjectRepresentations(object) =
    every binding whose canonical Coverage includes object
```

`CoverageAnchor` is normally the target `ObjectId`. A multi-object binding is
stored once under its canonical anchor; the binding's coverage rule derives
the complete object-level mapping. The disposable reverse index expands that
relation for point reads. This avoids writing one catalog entry per chunk for
a contiguous multi-terabyte file.

The tree grammar is deliberately separate from the placement index:

```text
RepresentationCatalogNodeV1 {
    prefix = "astrid-representation-catalog-node-v1\0"
    node_kind: leaf | branch
    entry_count
    entries in strict unsigned key order
    exact subtree entry total
    references to binding records or child nodes in matching order
}
```

Leaf keys are complete tagged `CoverageAnchor` identities and values are
strictly sorted binding identifiers. Branch keys are canonical separators.
The concrete page profile is an identified child specification, as the content
catalog does today; it is not inferred from an implementation constant.
Alternate tree shapes cannot name the same catalog root.

The catalog is authoritative for *which recipes are admitted*. Physical
placement remains discoverable from self-identifying arena/blob frames and is
accelerated by disposable indexes:

```text
RepresentationBindingId -> verified binding record
BlobId                   -> { container, offset, length, placement epoch }
ObjectId                 -> candidate binding ids       // derived reverse map
```

A corrupt or missing disposable index causes rebuild or a miss, never
acceptance of an unregistered recipe.

### Blob containers and disposable placement index

The first native realization supports two container classes:

```text
blobs/loose/<tagged-BlobId>     raw immutable file, including adopted staging
blobs.pack.<generation>         repeated self-identifying blob frames
```

Loose filenames are a canonical filesystem-safe encoding of the complete
tagged identity, not guest-controlled names. Opens are relative to an already
opened private directory, do not follow links, require an ordinary immutable
file, and verify the observed length before use. A pack frame contains its
tagged BlobId, tagged profile identifier, encoded length, frame checksum, and
encoded bytes. The raw loose form has no prepended header, which is what lets a
sealed staged file become the blob through rename rather than copy.

The rebuildable `representations.index` is a checksummed checkpoint plus
deltas, analogous to `objects.index`. Its checkpoint payload is:

```text
"astrid-representation-placement-index-v1\0"
TaggedIdentity         representation_catalog_root
u64                    blob_area_generation
u64                    covered_pack_count
u64                    covered_loose_scan_generation
u64                    entry_count
repeated in BlobId order:
    TaggedIdentity     blob
    TaggedIdentity     physical_profile
    u8                 container_kind       // loose = 0, pack = 1
    u64                container_generation
    u64                offset               // zero for loose
    u64                encoded_length
    u8[32]             frame_checksum       // zero for raw loose
```

Each delta names the exact prior and replacement catalog root and blob-area
generation, then carries added/removed entries in strict BlobId order. Frames
use a distinct magic, version, length, and checksum domain. The format is local
acceleration and may be replaced without a store migration.

An index is usable only when its catalog root and covered container
generations match authoritative state, every listed packed header agrees, and
every loose entry resolves to the canonical BlobId-derived filename with the
recorded length. A positive still receives the representation's required byte
verification. Any mismatch discards the index and scans canonical filenames
and self-identifying pack frames. A missing blob remains a missing recovery
path; an index entry cannot manufacture one.

## Binding and coverage grammar

One immutable binding Evidence record has this canonical field order:

```text
"astrid-physical-representation-binding-v1\0"
u16                    binding_format = 1
TaggedIdentity         coverage_anchor
u8                     coverage_kind
Coverage               coverage
TaggedIdentity         physical_profile
TaggedIdentity         primary_blob
u64                    primary_blob_bytes
u64                    recovered_logical_bytes
RecoveryBounds         declared_work
u64                    dependency_count
Dependency[]            dependencies in canonical order
TaggedIdentity?         admission_evidence
```

`RecoveryBounds` contains maximum depth, fanout, encoded bytes read, decoded
bytes emitted, peak resident bytes, and deterministic work/fuel units. Every
integer is little-endian. Identities use the tagged variable-digest grammar.
Optional values have a one-byte absent/present tag. The record ends after the
last field; trailing bytes are invalid.

The record carries an `Evidence` reference to its anchor for explanation but
does not own it. It carries `Owns` references to logical dependencies whose
bytes must remain live: delta bases, dictionaries, generator capsules,
immutable inputs, runtime profiles, and invocation records. Blob dependencies
are named in canonical fields and participate in physical representation
liveness.

Coverage kinds are closed in binding format one:

```text
0 ExactObject {
      target: ObjectId,
      canonical_header,
      recipe
  }

1 FileChunkClosure {
      file: ObjectId,
      expected_content_root: ObjectId,
      expected_logical_bytes: u64,
      expected_chunk_count: u64,
      recipe = ContiguousFileSlices
  }

2 ExplicitManifest {
      manifest_root: ObjectId,
      recovered_object_count: u64,
      recipe_profile
  }
```

`canonical_header` contains kind, object-format version, class, logical-byte
contribution, and the complete ordered reference sequence. A recipe emits the
canonical payload; the header and payload are reassembled and identified.

`FileChunkClosure` covers exactly the Chunk objects reached in canonical file
order through the declared File and ChunkTree ownership edges. Offsets are the
prefix sum of already identity-bearing chunk lengths. It covers neither the
File nor ChunkTree records, which remain canonical metadata representations.
The rule rejects a changed root, total, count, chunk order, or profile. The
same binding provides the exact contiguous byte view of that File.

`ExplicitManifest` is a canonical path-copy tree for a pack or generator that
recovers a heterogeneous set. Each leaf names an `ObjectId`, its canonical
header, and its recipe. It exists for cases that cannot derive coverage from a
logical DAG; it is not the default for files.

Recipe kinds are:

```text
DirectSlice       { blob, offset, length }
CompressedSlice   { blob, offset, length, decoded_length, dictionary? }
ExactDelta        { patch_blob, patch_range, base_object }
GeneratedOutput   { invocation, result_index }
PackedFrame       { blob, frame_offset, frame_length }
```

All offsets and lengths use checked arithmetic. A slice must end at or before
the identified blob length. Profiles specify how the selected bytes produce
the canonical payload; a record cannot reinterpret a recipe under another
profile.

## Well-founded recovery

Recovery is an explicit graph over `(ObjectId, RepresentationBindingId)`.
Admission rejects a binding unless every dependency already has a complete
terminating path that excludes the candidate. Batch admission topologically
orders candidates and applies the same rule to the growing accepted prefix.
This gives the graph a construction order and prevents two individually small
records from creating a delta or generator cycle.

The runtime planner independently keeps a visited set and enforces operator
bounds. The construction rule is the integrity boundary; the visited set and
bounds contain corrupt old data and future decoder faults.

Reconstruction proceeds as follows:

1. authorize the logical target through its principal/root handle;
2. obtain admitted bindings from the catalog and implicit arena candidate;
3. reject candidates outside the active privacy domain or without live
   placement and dependencies;
4. apply hard resource bounds, then choose the lowest-cost candidate;
5. acquire logical and physical leases before leaving the mutation fence;
6. read and decode through a bounded sink;
7. construct the complete canonical `ObjectRecord`;
8. recompute and compare its tagged `ObjectId`; and
9. release bytes only after the requested object or range has passed the
   applicable exact check.

Failure of one candidate may try another admitted candidate within the same
budget. Exhaustion returns a typed unavailable/corrupt result; it never returns
unverified bytes.

## Contiguous staged-file adoption

The native staging area and the blob area reside on the same filesystem.
Adoption renames the already-synced staged file; cross-device adoption falls
back to a measured copy path and cannot claim one physical write.

The one-write path is:

```text
sealed staged file
    -> one sequential read: FastCDC + chunk identities + BlobId
    -> canonical File/ChunkTree metadata and FileChunkClosure binding
    -> durable adoption intent
    -> rename content.bin to self-identifying blob placement
    -> publish representation catalog, then principal root
    -> durable publication marker
    -> conservative cleanup
```

The sequential pass does not write chunk payload frames. It emits small File
and ChunkTree records, and the binding makes each Chunk recoverable from its
verified raw slice. Duplicate chunks may still select an existing canonical
or other representation; adoption never exposes whether that happened.

The adoption intent binds:

- stage identifier, owner, content name, and close-order sequence;
- sealed length and intent checksum;
- source file identity needed to reject replacement during the operation;
- computed File `ObjectId`, BlobId, and binding identifier;
- expected principal and system catalog roots; and
- the exact publication state reached.

Durability order is:

1. the staged contents and sealed staging intent are already durable;
2. compute identities from the open, non-followed file handle;
3. append and flush canonical metadata, binding, and catalog objects;
4. flush the adoption intent;
5. rename the staged file into the blob area and flush that directory;
6. append the system catalog transition before the principal transition and
   flush the root-journal batch;
7. write and flush the ordinary staging publication marker; and
8. remove the adoption intent last.

Publishing the catalog first is safe: a crash may leave an unreferenced
binding and blob, but never a principal root without a recovery path. The two
root transitions may share one group-commit flush while preserving their
order. A retry observes identities and current roots, not an assumed step, so
every state after blob rename is idempotent.

Queue recovery checks the durable publication marker first, then an adoption
intent, before requiring `content.bin`. A missing staged file is valid only
when the checksummed intent names the exact BlobId and the immutable blob
placement verifies; recovery then resumes from that blob. Without either the
staged file or that proof, the entry fails closed. One interrupted adoption
blocks only itself and same-owner/name successors once per-entry queue
isolation is enabled; unrelated ready entries continue.

If an equal BlobId already exists, the engine performs the normal complete
collision check under its privileged path. It must not shorten the guest's
acknowledgement or report a different charge. The staged bytes remain until
the binding and principal publication are durable.

### Slice verification

Admission performs a complete sequential verification: BlobId, length, every
chunk identity, FastCDC boundaries, File/ChunkTree canonical form, and totals.
The binding is not published on partial success.

On reopen, the engine validates catalog identity, blob placement, file length,
slice bounds, and the derivable coverage map. A lazy range read recomputes each
returned Chunk identity and the boundary evidence required by the content DAG
before releasing bytes. A full read or scrub additionally recomputes the
BlobId. Process-local verified state is an accelerator and remains
principal-partitioned where its warmth could disclose another principal's
work.

Direct `mmap` or executable use cannot verify bytes after they have already
escaped through an ordinary mapping. It therefore requires a complete
verification token for the exact BlobId and placement epoch, an immutable
physical handle lease, and provider-specific mmap/exec acceptance evidence.
Otherwise the provider uses verified reads or a separately verified
materialization. A durable verification token, if added, is an authenticated
Evidence object bound to the exact blob and placement; an editable sidecar is
never trusted.

One live slice retains its complete raw blob. The accounting and compaction
policy report that retention amplification explicitly. Compaction may later
materialize the surviving chunks into independent representations and reclaim
the contiguous blob when the saved bytes exceed the rewrite cost.

## Representation lifecycle

### Admission

```text
candidate bytes/recipe
    -> stage privately
    -> identify blob and profile
    -> reconstruct and compare exact target records
    -> validate dependency closure and work bounds
    -> make blob durable
    -> append binding/catalog objects and flush
    -> publish system catalog root
    -> selectable
```

Anything before catalog publication is unreachable garbage. Anything after it
has a durable complete path. A validity failure rejects only the candidate. An
I/O or durability ambiguity poisons the engine; the next distinct operation
uses the bounded in-process recovery policy from #1387 and never retries the
ambiguous mutation.

### Replacement and compaction

```text
old path selectable
    -> write and verify new path
    -> publish catalog containing old + new
    -> new readers may select either
    -> condemn old path under GC fence
    -> wait for physical leases
    -> publish catalog without old
    -> reclaim old blob/segment
```

Removing a catalog binding and reclaiming its bytes are distinct operations.
A crash between them leaves extra bytes, not missing bytes.

### Export and import

```text
authorized root
    -> choose any recovery paths internally
    -> reconstruct canonical ObjectRecords
    -> deterministic materialized export
    -> destination verifies objects
    -> destination may create local representations
    -> destination root publication
```

Recipe import is optional optimization input. It is admitted only after local
reconstruction and exact verification under locally registered profiles.

### Garbage collection

```text
logical live roots + catalog root + physical leases
    -> expand logical closure and representation dependency closure
    -> prove every live object retains a terminating path
    -> condemn unreachable bindings and blobs
    -> recheck snapshot under mutation fence
    -> receipt-bound placement transition
```

Tensor Logic may audit the expanded relation set, but native liveness and the
mutation fence remain the deletion authority.

## Leases, fences, and resurrection

The logical handle and physical blob lease solve different races:

- a read handle pins the selected logical object closure across root changes;
- a blob lease pins the selected placement epoch and every blob needed by the
  chosen recovery path; and
- a reconstruction lease pins transitive bases, dictionaries, transforms, and
  inputs until output verification ends.

Lease acquisition, representation selection, commit closure validation,
catalog publication, and compaction liveness capture share the engine mutation
ordering boundary. A dedup or representation hit on a condemned/quarantined
blob resurrects it before a root may publish, or the operation chooses another
path. It cannot publish a root into a blob already committed to reclamation.

GC liveness is the least fixed point of:

```text
LiveObjects = OwnsClosure(current roots, pins, logical handles, system roots)

LiveBindings = bindings selected to provide at least one terminating path
               for every object in LiveObjects

LiveDependencies = transitive object/blob/profile dependencies of LiveBindings

LiveBlobs = blobs named by LiveBindings + active physical leases
```

The collector may keep economical alternatives beyond this minimum. It may
not remove the last path. A binding that covers live and dead objects remains
live as a whole until compaction splits or replaces it.

The GC fact snapshot and receipt grammar must grow explicit representation
facts before destructive representation collection is enabled: coverage,
binding dependencies, blob placement epochs, quarantine state, and leases.
That is a successor fact grammar under freeze decision D10; existing
reachability-only receipts are never reinterpreted.

## Accounting and operator policy

The engine maintains two ledgers and five resource dimensions.

Physical operator ledger:

```text
physical_bytes = unique blob/container bytes
               + canonical representation metadata
               + indexes actually resident or stored
               + replacement and compaction scratch

physical_byte_time = integral(physical_bytes, time)
```

Logical trust-domain ledger:

```text
logical_ownership(domain) = visible bytes and metadata owned by that domain

logical_recovery(domain) = full priced footprint of the recovery closures
                           its retention policy depends on

retention_byte_time(domain) = integral(logical retained bytes, time)
```

The remaining dimensions are CPU time, resident byte-time, and physical
writes. Reconstruction also records bytes read and device work. Intra-domain
sharing is billed once to the team/fleet/household domain; allocation among
its principals is the customer's policy. Cross-domain sharing never moves a
guest-visible bill. Each domain pays the same logical price it would pay if its
bytes and compute were unique; physical reuse is the operator dividend.

Dependencies are charged to every domain whose selected recovery closure
needs them. That intentional overcommit keeps billing independent of other
domains. The operator can report physical fair-share diagnostics separately,
but those numbers cannot control guest quota or reveal a dedup hit.

Creation reserves the peak, not the final optimistic size:

```text
admission reserve = staged bytes
                  + worst-case binding/manifest metadata
                  + any newly written blob bytes

replacement reserve = complete new path
                    + old path until publication and lease drain
                    + bounded intent/evidence overhead

compaction reserve = replacement placement
                  + retained old placement
                  + bounded work buffers
```

Contiguous adoption counts the staged and adopted file once because rename
does not allocate another payload. Reflink/copy fallback is accounted from
observed physical allocation, not logical file length alone.

An unsatisfied reservation rejects before publication and preserves the old
complete path. ENOSPC during a durability boundary poisons the engine; bounded
in-process recovery either restores a usable complete state or continues to
fail closed. Optional recompression, deltas, and generators shed before
principal-critical reads or writes.

## Costed selection

Hard eligibility precedes optimization. A candidate is eligible only when it:

- is admitted in the authoritative catalog or is the implicit arena form;
- lies in the caller's privacy/deduplication domain;
- has live placement and complete dependencies;
- satisfies exact output and trust requirements;
- fits the operation's hard CPU, memory, I/O, deadline, depth, fanout, and
  output bounds; and
- can acquire all required leases and reservations.

The operator then minimizes a monotonic estimate:

```text
cost(path) =
    Wread       * encoded_bytes_read
  + Wrequest    * physical_requests
  + Wcpu        * deterministic_work_units
  + Wresident   * peak_resident_bytes
  + Wlatency    * estimated_critical_path_ns
  + Wretention  * retained_bytes_due_to_path
  + Wdevice     * device_specific_work
```

Weights, device observations, cache warmth, and pressure are runtime policy,
not identity. A deterministic unsigned-byte ordering of binding identifiers is
the final tie-break. Profiles provide conservative ceilings; measured history
may improve estimates but cannot relax a hard bound or identity check.

The planner is kernel-side. Diagnostics may record candidates, chosen path,
estimate, actual cost, and fallback reason in operator Evidence. Guests see
only the authorized content result and their logical resource usage. They do
not receive representation kind, physical bytes saved, was-present status, or
cross-domain cache/dedup outcomes.

Physical cache warmth remains the same residual timing channel as the host
page cache: another domain retaining identical immutable bytes may make a read
faster. The system does not amplify it with explicit hit status, price, or
admission behavior. Operators needing a stronger boundary select separate
cache and encoding domains and accept the lost reuse.

## Compaction and the Refinery

Compaction is the only pass that removes a physical representation. The
Refinery may propose new encodings while already streaming live data, but only
the sealed engine pass publishes catalog and placement changes.

For each binding it considers:

- preserve raw contiguous blobs when observed sequential/mmap value exceeds
  their retention amplification;
- split a sparse surviving slice set when reclaimed bytes exceed rewrite and
  future read cost;
- keep compressed forms when decode cost fits their access class;
- prefer lineage-known delta bases and reject deep or fragile chains;
- retain generator recipes only with a bounded economical reconstruction path;
- reorder packs and index pages for observed locality; and
- drop an alternative only after another complete path is verified and
  durable.

Compaction may convert among these forms during the one traversal it already
owes. “Zero marginal I/O” means no second full source read; emitted blobs,
metadata, hashing, compression, and writes remain measured.

The placement receipt binds the old and new representation-catalog root,
binding set, blob placement set, resource measurements, and expanded GC fact
snapshot. Recovery installs only the exact receipted successor. Existing
format-one compaction receipts continue to describe canonical arena placement
and are not reinterpreted.

## Export, import, and longevity

A full `export_closure` emits exact canonical object records in deterministic
tagged-identity order. It may read them from any selected local path. It may
also include a separately marked recipe appendix containing profiles,
bindings, blobs, and evidence, but the appendix is never required to recover
the materialized section.

A thin export omits objects only against an authenticated declared base of
`ObjectId` values. Blob possession may optimize transfer inside a mutually
trusted representation domain, but a `BlobId` have-set never substitutes for
the declared logical base. A recipe-only bundle is not a full or thin archival
export.

Import verifies materialized records first and publishes no destination root
until the declared closure is complete. It may preserve recipe bytes as
quarantined candidates, then admit them through local profile authority and
exact reconstruction. Source registration authority, placement, cache tokens,
and cost measurements do not transfer.

Hash migration re-roots canonical objects under the successor `ObjectId`
scheme, then creates new binding records naming successor targets. Blob bytes
may be reused only through a successor `BlobId` construction or explicit
verified lineage; tags are never silently reinterpreted. The old-to-new
mapping remains Lineage/Evidence under the existing ceremony.

The frozen archival promise remains deliberately smaller than the live
economy: materialized bytes plus the in-band specification are sufficient.
No future decoder, compiler, generator, or Astrid engine is required.

## Compatibility and activation

Existing stores need no data migration. Every current arena frame is an
implicit `ArenaCanonicalV1` representation, and an absent representation
catalog means exactly that.

Activation is a crash-safe format-one amendment using the existing migration
registry:

1. install the frozen physical-representation specification as an in-band
   Evidence object;
2. create an empty canonical representation catalog under the system root;
3. verify the new system closure and independent reader fixture;
4. atomically add `representation-spec-object=<TaggedIdentity>` to
   `store.meta`; and
5. write the migration marker only after all destination state is durable.

A partial destination is quarantined and the old arena-only source remains
authoritative, following the existing RÚNATAL amendment pattern.

Two compatibility stages are distinct:

- **additive stage:** alternate blobs and bindings may exist, but every live
  object keeps a canonical arena representation. Older engines can ignore the
  new acceleration only if they explicitly tolerate the amended metadata and
  system component.
- **authoritative stage:** compaction may remove a last arena representation.
  This stage is forbidden until RÚNATAL specifies the blob containers,
  binding/catalog grammar, reconstruction algorithm, and failure behavior,
  and the independent reader reconstructs fixtures containing every active
  representation kind.

An older engine encountering an authoritative-stage store must reject the
declared representation feature before replay. It may not continue until a
later `MissingObject` makes the incompatibility look like corruption.

Changing CDC profiles does not migrate old data. Each File already carries
its profile and retains its identity; new files may choose a successor profile,
and bindings reproduce whichever exact File DAG they name.

## Crash matrix

| Interruption | Required recovery result |
|---|---|
| Blob write or rename incomplete | Binding is not published; old path or sealed stage remains |
| Blob durable, binding absent | Orphan is reusable after full verification or collectable |
| Binding objects durable, catalog root absent | Unreachable metadata and blob; no visible logical change |
| Catalog root durable, principal root absent | Extra valid representation; retry publication or collect later |
| Principal root durable, staging marker absent | Idempotent replay observes the same File and completes the marker |
| New path published, old path still present | Both are valid; selection may use either |
| Old binding removed, old blob still present | Unreachable extra bytes; reclaim after leases |
| Reclaim interrupted | Receipted old or new complete placement recovers; never a mixed unreceipted set |
| ENOSPC before reservation/publication | Reject candidate and preserve old path/stage |
| ENOSPC or fsync ambiguity during publication | Poison, bounded in-process recovery, no mutation retry |
| Crash while a reader holds an old placement | Old placement remains until lease recovery/expiry policy permits retirement |

Fault injection captures the byte-level write trace and reopens at every
prefix, including torn and reordered tail blocks. Each prefix asserts the
current logical roots have a complete path and that no unreceipted placement
is selected.

## Adversarial matrix

| Attack or fault | Required result |
|---|---|
| BlobId collision with different profile or bytes | Complete comparison rejects the second admission |
| Binding target differs from reconstructed ObjectId | Reject before catalog publication |
| Slice offset/length overflow or out of bounds | Reject canonical decode/admission |
| Slice bytes changed after admission | Lazy read/full verification fails before bytes escape |
| File DAG order or totals disagree with contiguous binding | Reject binding and direct read plan |
| Delta A depends on B while B depends on A | Well-founded admission or visited-set check rejects |
| Recipe expands beyond declared output | Bounded sink aborts; no binding/result |
| Generator reads clock, random, network, env, or mutable state | Invocation profile denies it; mismatch is an integrity event |
| Generator is deterministic but uneconomically slow | Hard cost bound makes it ineligible; another path or failure |
| Dictionary/base/generator collected while dependent path lives | GC liveness proof fails |
| Final path included in condemned set | Native fence rejects the plan regardless of auditor output |
| Dedup hit races condemned blob | Hit resurrects under the fence or chooses another path |
| Reader races catalog replacement/compaction | Logical and blob leases preserve its exact path |
| Principal commit races representation GC | Mutation ordering sees the new closure before deletion or publishes afterward |
| Disposable index lies about binding or offset | Identity/bounds check rejects and rebuilds authoritative state |
| One principal probes another's representation | No capability, timing class, accounting delta, or admission signal is returned |
| Guest requests a cheap-looking malicious recipe | Guest cannot select it; kernel bounds and exact verification still apply |
| Old engine opens authoritative alternate-only store | Explicit unsupported-feature failure before root service |

## Benchmark contract

The benchmark compares paths, not only codecs. Every result records revision,
dirty state, machine, filesystem/device, cache state, profile and binding IDs,
corpus digest, samples, concurrency, and result digest.

Path matrix:

| Path | Required workloads |
|---|---|
| Canonical arena | cached/cold 4 KiB, 64 KiB, 1 MiB, 8 MiB, sequential, reopen |
| Contiguous raw slices | adoption, first verified read, warm read, random range, sequential, mmap eligibility |
| Compressed | compress cost, cold/warm decode, ratio, peak memory, fallback |
| Exact delta | creation, depth 1..limit, base locality, reconstruction, retained closure |
| Generator | invocation cost, cache hit, exhaustion, spot-check, dependency retention |
| Mixed selection | pressure/locality changes, deterministic choice, fallback after corruption |

Corpora include incompressible random bytes, the recorded agent-state and
workspace corpus, temporal version chains, duplicated media/package data,
sparse surviving slices, and files larger than RAM. Run one, four, and eight
principals; warm and cold phases; one-shot and open-handle reads.

Report at least:

- user-visible staging acknowledgement throughput and latency;
- background publication throughput and total physical writes;
- first/warm verified read throughput, IOPS, p50/p95/p99, CPU, and peak RAM;
- encoded bytes read per logical byte returned;
- ingest, catalog, and binding metadata bytes per logical byte;
- retained-byte amplification for one live slice of a large blob;
- reconstruction compute and dependency depth;
- reopen/rebuild time with and without disposable indexes;
- compaction bytes read/written and mutation-fence hold time; and
- physical and logical byte-time across a realistic workload mix.

The current format-frozen baseline is already near verified-native throughput
for cached canonical reads. Contiguous representations are therefore judged on
provider/mmap suitability, cold and sequential I/O, retained bytes, and avoided
gather work—not by obscuring the canonical cached result. Acceptance tables
report canonical cached and contiguous results separately.

Success for adoption means one physical payload write on the same filesystem,
native-speed staging acknowledgement, an asynchronous read-bound identity
pass, and no root visibility before the representation is durable. No ratio is
claimed before the harness measures it.

## Downstream API boundary

Internal Rust surfaces eventually separate authority from mechanics:

```text
RepresentationCatalogReader
    candidates(ObjectId) -> admitted binding handles

RepresentationAdmission
    stage_and_verify(candidate, reservations) -> proposed binding
    publish(proposed, expected_catalog_root) -> binding id

RepresentationSelector
    select(authorized target, read intent, resource lease) -> recovery handle

RecoveryHandle
    read_verified(range, sink)
    materialize_verified(sink)

EngineRepresentationMutation       // sealed inside the durable engine
    replace_under_fence(plan, receipt)
```

Readers receive immutable views and leases. Admission cannot publish a
principal root. Selectors cannot register profiles or bypass capability and
privacy checks. Observer Refinery passes can propose candidates but cannot
implement `EngineRepresentationMutation`.

No WIT changes while interface PRs remain frozen. Future capsule transforms
use one generic capability-scoped bounded stream interface after an RFC; there
is no codec-, compression-, filesystem-, or generator-specific host function.
Normal file/content callers continue to see ordinary reads and writes.

## Implementation order

1. Freeze the in-band representation grammar, profile registry authority, and
   independent-reader fixtures.
2. Add the catalog/model types and arena-only compatibility oracle.
3. Admit an additional raw contiguous binding while retaining every canonical
   arena path.
4. Implement read selection and benchmarks without enabling collection.
5. Extend GC facts, receipts, leases, and compaction to representation
   closures.
6. Pass the authoritative-stage RÚNATAL and two-readers gate.
7. Permit compaction to remove an uneconomic canonical arena alternative.
8. Add compression, delta, and generator profiles through the same seam.

Change detection may skip rereading an unchanged source only as disposable
performance state; corruption or a miss falls back to full hashing. Provider
adapters consume verified recovery handles and never invent their own blob
cache or publication path.

## Decisions held by this design

- Physical representation means exact logical reconstruction, not semantic or
  perceptual equivalence.
- The catalog is authoritative, root-CAS published, and independent of the
  disposable placement index.
- Representation metadata is always canonically materialized to avoid a
  circular bootstrap.
- A contiguous file covers Chunk objects through its canonical File DAG and
  doubles as the exact direct-read plan.
- Recoverability is a GC liveness property over the complete dependency graph.
- The engine selects and meters paths; guests neither choose recipes nor learn
  cross-domain reuse.
- Full export materializes and remains independent of the live engine.
- Existing arena-only stores migrate without rewriting data.
- Alternate-only authority waits for an in-band specification and independent
  reader; old engines then fail explicitly rather than misdiagnosing missing
  objects.
- One representation system serves adoption, packs, compression, deltas,
  generators, and future physical encodings.
