# Principal Storage Pre-Release Freeze Audit

Status: decided work orders. The principal-store stack is merged, but no
release has made these identity-bearing constants permanent. This document is
the durable successor to the freeze-audit scratch record.

Each entry records a decision, rationale, work order, and acceptance evidence.

## D1. BLAKE3-256 identity with mandatory SHA-384 cross-hash attestation

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

### Work order

1. Extend re-attestation and scrub so each ceremony emits:

   ```text
   Evidence {
       blake3_root
       sha384_digest_tree
       ceremony_signature
   }
   ```

2. Cover canonical object bytes and compute the tree while streaming.
3. Specify how a successor identity is introduced under the tagged identity
   envelope, how pre-break cross-hash evidence authorizes re-addressing, and
   why old-to-new maps are immutable Lineage rather than aliases.
4. Do not change the current ObjectId width, index, or v1 addressing hash.

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

### Work order

- Freeze the genesis-record encoding and domain separation.
- Add the durable owner codec using the UID.
- Update `store.meta`, the RÚNATAL specification, and the independent reader.
- Reuse the kernel identity record if its canonical encoding is stable;
  otherwise stabilize it as part of this work.
- Development stores may be wiped before the first release; no permanent
  migration promise exists yet.

### Acceptance

- Rotating a principal key changes neither UID nor journal ownership.
- Renaming a principal touches no durable root-journal entry.

## D3. Path-copy B+-tree for principal KV

### Decision

Replace the persistent binary AVL KV projection with a path-copy B+-tree using
approximately 2-4 KiB nodes and fanout around 32-64, depending on encoded key
size.

Small values are inline in leaves. Values over a frozen threshold, initially
proposed at 1 KiB, spill to owned value objects. Nodes retain cached subtree
logical and quota totals.

The tree remains history-dependent. Canonical packing is not claimed for KV:
standard local split and merge behavior is the correct trade for random-key
writes.

### Rationale

A binary tree at one million keys has depth around 17 and rewrites that many
nodes per mutation. A fanout-32 tree has depth around three or four. Fat
path-copy nodes reduce write amplification, object loads, and recovery work.

### Work order

- Freeze sorted leaf and internal-node encodings.
- Freeze split, merge, and inline/spill rules.
- Recompute and validate cached totals during decode.
- Reject unsorted keys, invalid child bounds, and malformed occupancy.
- Update the RÚNATAL specification and independent reader.
- Benchmark amplification, operations per second, and get latency at 10k,
  100k, and one million keys.

### Acceptance

- At least a threefold reduction in bytes written per operation at 100k keys.
- No group-commit throughput regression.
- Recovery and crash-prefix matrices pass.

## D4. Evidence gate for the first content-defined chunker

### Decision

Run the chunker evidence gate before the first format release.

The leading candidate is the hashed robust MinCDC family, with:

- window `w = 4`;
- pinned upstream constants;
- the leftmost minimum of the hashed window between strict minimum and maximum
  chunk sizes;
- ties resolved to the earliest index;
- a strictly enforced maximum; and
- only the final chunk permitted below the minimum.

The measured 16/64/256 KiB profile is the starting point, not an assumption:
MinCDC has a different distribution and must be swept on the same corpora.

If it reproduces its claimed performance or distribution advantages, it
becomes the first Astrid profile and FastCDC never becomes durable format. If
the results are noise, the published and already-measured FastCDC profile wins
the tie.

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

The file header and staging intent carry an algorithm discriminator followed by
that algorithm's canonical parameter block. `ChunkingProfile` is a closed
tagged type. Unknown algorithms fail closed.

Candidate MinCDC parameters contain its window, strict bounds, multiplier, and
addition constants. It does not gain a synthetic average-size field.

### Work order

- Add MinCDC and Chonkers candidates to the existing sweep tool.
- Re-run both measured corpora.
- Add zeros, repetitions, boundary-forcing, and parameter-recovery fixtures.
- Pin exact constants, tie-breaking, and final-chunk behavior.
- Produce golden boundary fixtures for the Rust and independent readers.
- Verify the chosen implementation's license.

### Acceptance

- The complete sweep is attached to the gate issue.
- Golden cuts and adversarial fixtures pass.
- The profile grammar is frozen in the RÚNATAL specification.

## D5. Byte-exact content names

### Decision

Catalog names remain byte-exact UTF-8. The store never case-folds or Unicode
normalizes them.

Hosted filesystem projections implement platform folding and deterministic
collision disambiguation. `astrid doctor` reports names that collide under a
target projection policy.

### Rationale

Store-side folding is irreversible semantic loss. Projection-side policy is
replaceable and platform-specific.

## D6. Similarity sketches run at scrub, not ingest

### Decision

Bottom-k resemblance sketches are deterministic Derived metadata computed by a
pinned Refinery transform during scrub or compaction. They are never
identity-bearing and never computed in the ingest chunking scan.

### Rationale

Similarity features help later delta-partner selection but do not belong on the
write acknowledgement path. The Refinery already streams verified chunks and
can emit sketches without another full traversal.

Computing chunk boundaries and similarity features in one rolling-hash scan
has live IBM patent families. Separating sketching from ingest is both an
engineering improvement and the selected design-around.

Lineage is the first delta-partner source: a catalog replacement already knows
its predecessor. Cross-name resemblance is a secondary use of sketches.

### Work order

- Define the pinned DF-1 transform and sketch grammar.
- Measure non-duplicate chunks that find a useful overlap candidate.
- Measure actual delta sizes against those candidates.
- Keep sketches evictable and reproducible.

### Acceptance

- No ingest path computes or exposes similarity metadata.
- Scrub emits reproducible sketches from verified chunk bytes.
- Removing sketches changes neither identity nor authoritative reads.

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

Before the first release, the RÚNATAL specification records whether each
constant is evidence-backed or deliberately arbitrary and harmless:

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

## Sequence

1. Principal UID and chunker evidence gate before the first format release.
2. B+-tree format and benchmarks.
3. Cross-hash attestation and successor migration specification.
4. Projection-only name folding documentation.
5. Refinery sketch prototype with the chunker evidence tooling.
6. Mechanical closing audit.
