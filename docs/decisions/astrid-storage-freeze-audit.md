# Principal Storage Pre-Release Freeze Audit

Status: format one is frozen for review. No release has yet made these
identity-bearing constants a public compatibility promise. This document is
the durable successor to the freeze-audit scratch record.

Each entry records a decision, rationale, implementation state, and acceptance
evidence where applicable.

## D1. BLAKE3-256 identity with mandatory SHA-384 cross-hash attestation

**Status:** complete. The verified Refinery observer emits a bounded-fanout
SHA-384 Evidence tree and Ed25519 ceremony record over one exact selected
closure. Production Rust and the independent RÚNATAL reader rebuild the same
canonical tree and reject reordered, omitted, substituted, or tampered input.

### Decision

Primary addressing remains BLAKE3-256. Astrid does not widen BLAKE3 output and
claim additional collision security. The attestation and scrub ceremony
records SHA-384 cross-hash evidence binding each attested root closure's BLAKE3
identities to SHA-384 digests as ordinary Evidence objects.

The format specification defines the successor-identity migration procedure
before the first release.

### Rationale

BLAKE3's chaining value is 256 bits; longer XOF output does not create a wider
collision-security primitive. A genuine construction-diverse 384-bit identity
would require another hash such as SHA-384 or SHA3-384 and would give up the
parallel BLAKE3 hot-path implementation on which ingest and verified-read
performance rely.

The long-horizon hedge is a pre-break cross-hash binding. A future migration
off weakened BLAKE3 is trustworthy only if the BLAKE3-to-successor relationship
was recorded while BLAKE3 was still trusted. Scrub and compaction already read
the bytes, so the Refinery computes SHA-384 on that cold path.

SHA-384 provides implementation maturity, hardware support, and construction
diversity from BLAKE3.

### Implementation

1. Re-attestation and scrub emit:

   ```text
   Evidence {
       blake3_root
       sha384_digest_tree
       ceremony_signature
   }
   ```

2. The observer covers canonical object bytes and computes the tree while
   streaming.
3. RÚNATAL specifies how a successor identity enters the tagged envelope, how
   pre-break cross-hash evidence authorizes re-addressing, and why old-to-new
   maps are immutable Lineage rather than aliases.
4. The in-memory ObjectId width, index, and format-1 addressing hash remain
   unchanged.

### Acceptance

- Attestation produces cross-hash evidence on a test store.
- The successor migration procedure is in the format specification.
- The independent RÚNATAL reader verifies a cross-hash record.

### Export manifest

`export_closure` has an optional SHA-384 manifest mode that consumes the same
cross-hash tree Evidence. It emits the selected tagged roots, canonical object
ordering, per-object/tree SHA-384 witnesses, relevant ceremony identity, and
signature material without inventing a second hashing pipeline. When required
evidence is absent, export schedules or requests the pinned Refinery
attestation pass and fails with a typed prerequisite rather than silently
claiming a compliance manifest.

This is a CNSA-sized/FIPS-family digest artifact, not a claim that the whole
product or deployment is certified. The manifest remains self-verifying and
independent of arena offsets or the live engine.

## D2. Stable opaque principal UID before the first release

**Status:** complete. The canonical genesis record, owner codec, runtime
directory, in-place alias-owner migration, and independent-reader grammar are
implemented together. Existing pre-release stores migrate without changing
root generations or commit identities; queued native staging intents migrate
under the same crash marker.

### Decision

Root journals and durable principal keying use a stable opaque 32-byte
principal UID rather than a display-name-shaped string.

The UID is minted once from a domain-separated canonical genesis identity
record containing the initial Ed25519 public key and creation metadata.
Display names and current keys are mutable identity state referencing the UID.
Key rotation is a signed chain; the UID never changes.

### Rationale

Human-chosen strings in a root journal make rename and key rotation into
permanent store migrations. Hashing the stable genesis record instead of a
current public key preserves rotation.

Astrid must have one identity system. The genesis record is reconciled with
the existing `astrid-identity` structures rather than introducing a parallel
principal concept.

### Implementation

- The genesis-record encoding and domain separation are frozen.
- The durable owner codec uses the stable UID.
- `store.meta`, RÚNATAL, and the independent reader carry the same grammar.
- The kernel identity record supplies the canonical genesis fields.
- Migration rewrites alias-keyed root snapshots and publication intents under
  the singleton runtime lock. The old root journal remains rollback evidence
  until retention policy explicitly removes it.

### Acceptance

- Rotating a principal key changes neither UID nor journal ownership.
- Renaming a principal touches no durable root-journal entry.
- Migration preserves every root generation and commit identity, rejects an
  unmapped owner, and resumes from every root-journal promotion prefix.
- The live alias directory is populated atomically from validated identity
  records before a principal-owned namespace is served.

## D3. Canonical KV transitions with immutable B+-tree checkpoints

**Status:** complete. Ordinary point mutations append constant-size canonical
transition records. Background maintenance folds them into immutable,
page-bounded B+-tree checkpoints and rebases concurrent transition tails before
the root compare-and-swap.

### Decision

Replace the persistent binary AVL projection with a transition chain over
immutable B+-tree checkpoints. Point mutations never rewrite checkpoint pages.
B+-tree pages retain approximately 2-4 KiB and fan out up to 64 children,
depending on encoded key size.

Small values are inline in leaves. Values over a frozen threshold, initially
proposed at 1 KiB, spill to owned value objects. Nodes retain cached subtree
logical and quota totals.

Transition encodings, page encodings, counters, and decoded totals are
canonical. Checkpoint page grouping is not a logical identity: multiple valid
page packings may reconstruct the same map, and maintenance chooses one
deterministically for its input snapshot.

### Rationale

The proposed direct path-copy B+-tree failed measurement. Rewriting fat
immutable pages cost 10,804 bytes at 10k entries, 14,369 bytes at 100k, and
17,420 bytes at one million for a 128-byte replacement. The existing AVL
baseline was 2,883 bytes.

The accepted transition record writes 948 authoritative bytes at all three
cardinalities. B+-trees still provide compact checkpoints and shallow reads,
but do not sit on the point-mutation write path.

### Implementation

- Sorted leaf, internal-node, transition, counter, and inline/spill encodings
  are frozen.
- Decode recomputes cached totals and rejects unsorted keys, invalid child
  bounds, and malformed occupancy.
- Checkpoint construction rebases transitions arriving during the build
  without holding the mutation lock for the full build.
- RÚNATAL and the independent reader implement the same grammar.
- The evidence harness measures amplification, operations per second, and get
  latency at 10k, 100k, and one million keys.

### Acceptance

- A 128-byte point replacement writes 948 authoritative bytes at 10k, 100k,
  and one million entries: more than threefold below the 2,883-byte baseline.
- No group-commit throughput regression.
- Recovery and crash-prefix matrices pass.

## D4. Evidence gate for the first content-defined chunker

**Status:** complete. The reproducible harness, full measurements, supply-chain
record, and decision are in
[`astrid-storage-chunker-evidence.md`](../reference/astrid-storage-chunker-evidence.md).
The byte-exact algorithm, accepted parameter grammar, and three golden vectors
are frozen in RÚNATAL and verified by both production Rust and the independent
reader.

### Decision

Format one retains FastCDC 2020 with implementation revision one,
normalization level one, 16/64/256 KiB bounds, zero gear seed, and chunk-tree
fanout 128. Files at or below 256 KiB remain whole objects.

The evidence gate rejected a chunker change: the best lower-object-cost MinCDC
candidate improved the measured combined cost by only 0.1086% while increasing
unique-object count by 41.58%. The selected construction is therefore frozen
from its behavior, not from the continued availability of a Rust crate.

### Rationale

Chunker choice becomes permanent once file identities depend on it. The gate
must compare:

- capacity convergence;
- object count;
- size distribution;
- boundary stability;
- compute throughput;
- strict bound behavior; and
- adversarially shaped content.

No chunker is a mathematical deduplication maximum. Minimum chunk size,
boundary stability, and distribution shape set the practical bound. Remaining
near-similarity belongs to later delta representations, not increasingly
clever boundary claims.

### Security doctrine

The keyed-profile algorithm tag is reserved now, but the private store keeps
public constants while chunk boundaries, sizes, and counts stay below the
guest API line.

The future public/sync layer uses a published, reviewed keyed-CDC construction.
Astrid never invents key mixing. The adversarial suite includes parameter
recovery, boundary-forcing plaintexts, degenerate min/max sequences, and
fingerprinting through chunk-length patterns.

### Wire-format rule

The File header and staging intent carry algorithm discriminator 1,
implementation revision 1, normalization 1, minimum/average/maximum sizes, and
the gear seed. Unknown algorithms, revisions, normalization levels, and
out-of-grammar parameters fail closed.

### Implementation

- The evidence harness and captured results are checked in.
- RÚNATAL pins exact masks, gear-table derivation, wrapping arithmetic, seeded
  behavior, whole-object threshold, and final-chunk behavior.
- Production Rust and the independent reader share literal golden boundary
  fixtures.
- Independent recovery validates every rooted File against the frozen
  construction.

### Acceptance

- The complete sweep and supply-chain record are checked in.
- Golden cuts and adversarial fixtures pass in both implementations.
- The profile grammar is frozen in the in-band RÚNATAL specification.

## D5. Byte-exact content names

### Decision

Catalog names remain byte-exact UTF-8. The store never case-folds or Unicode
normalizes them.

Hosted filesystem projections implement platform folding and deterministic
collision disambiguation. `astrid doctor` reports names that collide under a
target projection policy.

The frozen projection profiles are behavior contracts rather than
operating-system labels:

- `byte-exact-v1`;
- `unicode17-nfd-v1`;
- `unicode16-default-fold-v1`; and
- `unicode17-nfd-unicode16-default-fold-v1`.

Canonical comparison pins Unicode 17.0 normalization tables and applies NFD.
Caseless comparison pins Unicode 16.0 case-fold tables and applies full,
non-Turkic default case folding. The combined profile applies Unicode 17.0
NFD, Unicode 16.0 full folding, then Unicode 17.0 NFD. The differing table
versions are part of the contract: the exact audited dependencies do not
silently claim a newer fold table than they implement. Target syntax is
independently `posix-utf8-v1` or `windows-utf16-v1`, with a detected non-zero
segment-unit ceiling. This separation matters because case and normalization
behavior can vary by volume or directory on one host.

A provider selects the exact target behavior when it has a pinned comparison
implementation, or a conservative superset when the host algorithm is not
portable. Over-comparison may escape an extra display name but preserves every
source; under-comparison can miss a real collision and is forbidden.

Projection planning interprets `/` only at this compatibility boundary and
builds a trie over exact source segments. It detects both equivalent sibling
segments and file-versus-directory prefix conflicts. A safe singleton keeps
its natural spelling. Every member of a collision, and every empty, `.`, `..`,
reserved, invalid, trailing-dot/space, marker-containing, or overlong segment,
receives:

```text
readable-prefix || "~astrid-" || role || "-" || hex(
    BLAKE3-256("astrid projection name suffix v1",
               exact-source-prefix, role, exact-segment)
)
```

The derived-key input is byte-exact: `u128-le(prefix-segment-count)`, followed
by each prefix segment as `u128-le(byte-length) || UTF-8 bytes`, a one-byte
role (`0` file, `1` directory), then the final segment using the same
length-prefixed encoding. This makes every path shape self-delimiting.

The full suffix remains after syntax-aware truncation. The reserved marker is
never accepted as a natural spelling. The planner compares final output again
under the selected policy and fails closed on any digest or projected-path
collision. Planning is deterministic for a fixed catalog and independent of
input order.

Disposable mapping metadata binds every projected path to its complete exact
`ContentName`; a write handle carries that source identity. Adapters never
infer authority by parsing a display path. Publication performs one atomic
target-filesystem reservation that compares the stored exact source name.
Preflight `exists()` followed by `create()` is forbidden, and a path reserved
for another source is an error rather than an overwrite.

`astrid doctor --projection-name-policy <profile>` evaluates only the
authenticated caller's catalog, reports exact-source collision groups and
escaped segments, and makes no repair. Providers may later supply a
volume-detected policy through the same typed planner.

### Rationale

Store-side folding is irreversible semantic loss. Projection-side policy is
replaceable and platform-specific.

## D6. Similarity sketches run at scrub, not ingest

### Decision

Bottom-k resemblance sketches are deterministic Derived metadata computed by a
pinned Refinery transform during scrub or compaction. They are never
part of source-content identity and are never computed in the ingest chunking
scan.

The measured production descriptor retains the lowest 256 distinct 128-bit
scores. Scores are BLAKE3 derive-key outputs over length-framed canonical Chunk
bytes. The scheduler materializes sketches only for multi-chunk Files; the
canonical grammar still defines empty and one-chunk inputs.

### Rationale

Similarity features help later delta-partner selection but do not belong on the
write acknowledgement path. The Refinery already streams verified chunks and
can emit sketches without another full traversal.

Computing chunk boundaries and similarity features in one rolling-hash scan
has live IBM patent families. Separating sketching from ingest is both an
engineering improvement and the selected design-around.

Lineage is the first delta-partner source: a catalog replacement already knows
its predecessor. Cross-name resemblance is a secondary use of sketches.

### Implementation

- The pinned DF-1 transform and canonical sketch grammar are implemented in
  `astrid-storage::engine`.
- The shared evidence harness measures useful overlap and reconstructed
  COPY/ADD delta sizes across the registered curve.
- Sketches use non-owning references, remain evictable, and recompute
  byte-identically after interruption.

### Acceptance

- No ingest path computes or exposes similarity metadata.
- Scrub emits reproducible sketches from verified chunk bytes.
- Removing sketches changes neither identity nor authoritative reads.

### Evidence

The live 5.73 GB agent-state corpus contained 67 non-duplicate multi-chunk
targets. At 256 samples, 25 found a useful cross-name base and verified encoded
bytes fell from 2,987,909,629 raw bytes to 2,726,752,143 bytes. Gains stopped at
128 samples on this corpus.

The 1.41 GB development workspace contained 372 multi-chunk targets. At 256
samples, 22 found a useful base and verified encoded bytes fell from
995,290,622 to 987,623,522. Three of those candidates appeared between 128 and
256 samples; 512 produced no further gain. Random candidates saved zero bytes
on both corpora. The 128-bit and 256-bit score constructions selected identical
candidates and byte totals throughout the sweep, so the wider score had cost
without measured benefit. These curves select 128-bit scores and 256 samples.

Computing a sketch for every single-chunk agent-state file would retain roughly
73 MB of Derived metadata while adding no candidate information. That measured
waste is why multi-chunk eligibility is scheduler policy rather than an ingest
side effect.

## D7. Affirmed storage constants

The following remain deliberate:

- chunk-tree fanout 128 with canonical capacity-full packing;
- the documented middle-edit metadata ripple;
- 52-byte frame header with two reserved bytes;
- BLAKE3-256 frame checksums, which protect integrity but are not object
  identity;
- existing domain-separation strings;
- append-only arena and root journal;
- torn-tail recovery policy;
- two-flush object-before-root commit ordering; and
- tagged variable-length persistent identity envelopes with capacity for
  384-bit and longer successors.

## D8. Mechanical format audit

**Status:** complete. RÚNATAL section 11 classifies every inventoried constant
and records byte-exact native-staging and local compaction recovery surfaces.
Focused regressions pin numeric discriminants, profile constants, metadata,
framed magics, and the existing staging golden vector.

### Classification

The audit records whether each constant is evidence-selected behavior, a
frozen semantic discriminant, deliberately generous capacity, runtime policy,
or disposable acceleration state:

- ObjectKind values;
- ObjectFormatVersion width;
- ReferenceKind values;
- ReferenceLabel bounds;
- catalog and KV node constants;
- journal magics;
- recovery defaults that are runtime policy rather than decode semantics;
- staging-intent format;
- `store.meta` keys; and
- chunking-profile encodings.

Reference labels have no hidden byte ceiling beyond the self-delimiting wire
lengths and process addressability. Recovery allocation guards, quotas,
durability modes, batching, memory budgets, and scheduling rates remain
deployment policy. The persistent object index and projection caches remain
disposable and outside identity and archival compatibility promises.

Native staging and compaction recovery files are crash-critical local formats,
but they are not the canonical archival unit. `export_closure` carries
self-contained identified records and materialized bytes, never host paths,
arena offsets, staging files, compaction intents, or cache indexes.

## D9. Object-index scaling requirements for compaction

At a 64 KiB average chunk, one TiB is roughly 16 million chunks. A full
in-memory ObjectId-to-location index can consume multiple GiB and lose cache
locality before storage capacity becomes the limiting resource.

The persistent-index and compaction design therefore includes:

1. a Bloom, quotient, or cuckoo summary filter for fast negative lookups;
2. locality-paged persistent index entries preserving append/stream
   neighbourhoods;
3. read-back byte comparison for every candidate positive;
4. index residency charged through the common resident-memory authority; and
5. measured behavior at multi-TiB scale.

Sparse anchor-only indexing is not the default because it knowingly sacrifices
chunk-level convergence. It remains an option only if the filter and
locality-paged full index miss their measured targets.

## D10. Canonical GC fact-snapshot identity is final

Tracks: [#1409](https://github.com/astrid-runtime/astrid/issues/1409)

### Decision

Format v1 defines `GcFactSnapshotId` as the ordinary object identity of the
exact canonical fact-snapshot Evidence bytes specified in
[Durable Compaction](astrid-durable-compaction.md). That identity is independent
of whether the facts were assembled by a full scan or maintained
incrementally. Format v1 reserves no alternate snapshot-derivation
discriminator.

A future incremental implementation may maintain a materialized fact view,
immutable view generations, and an engine-local running digest. Those are
acceleration and fencing state, not durable authority. A plan continues to
carry the canonical `GcFactSnapshotId`; commit may collapse its mutation-lock
fence to an O(1) comparison against the exact materialized-view generation from
which that snapshot was produced. At any time, a full canonical re-encode must
produce byte-for-byte identical Evidence and the same `GcFactSnapshotId`.

The format-1 grammar remains reachability-only. A retention policy requiring
object kind, class, age, or another absent fact introduces an explicitly new
fact-snapshot grammar and domain prefix. It must not reinterpret existing
format-1 snapshots or receipts.

### Rationale

The current fence captures the complete object universe under the mutation
lock three times per compaction cycle. Its cost is acceptable at present but
would stall all principals for an operationally unacceptable interval near 16
million objects. The scale fix is incremental fact maintenance and an
O(1) generation fence, not a second meaning for historical receipts.

Keeping one canonical identity preserves byte-stable proof replay, audit-chain
uniformity, and independent reconstruction. It also makes the incremental
implementation continuously testable against the simple full-scan oracle.

### Future acceptance

- Arbitrary commits, root changes, retained-root leases, and resurrection
  races produce byte-identical incremental and full-scan snapshots.
- A mutation after plan capture fails the generation fence before replacement.
- Full canonical re-encoding periodically verifies the running view and
  identity; mismatch fails closed and emits an operator-visible integrity
  event.
- Mutation-lock hold time for plan verification and commit fencing is
  independent of object-universe cardinality.
- Existing format-1 plans, receipts, and audit records replay unchanged.

## Completion record

1. Cross-hash attestation and successor migration specification: complete.
2. Canonical KV transitions and immutable B+-tree checkpoints: complete.
3. Projection-only name folding and doctor behavior: complete.
4. Refinery bottom-k sketches and chunker evidence: complete.
5. Mechanical closing audit and GitHub review freeze: complete.
6. Release tag and public compatibility promise: deferred to the actual
   release workflow.
