# Astrid Principal Content DAG

This document records the implemented boundary between principal-owned named
content and the durable object engine. It is intentionally narrower than a
filesystem: names are opaque catalog keys, symlinks and host paths have no
meaning, and no capsule interface is changed.

## Outcome

`astrid-storage-content` converts ordinary bytes into a canonical immutable
closure:

```text
File
  -> Chunk                         small content
  -> ChunkTree -> ... -> Chunk     large content
```

`PrincipalContentStore` attaches `name -> File` entries beneath the existing
`PrincipalState` object:

```text
Commit
  owns state -> PrincipalState
                   owns kv      -> NamespaceMap
                   owns content -> Directory catalog
```

KV and content therefore contend on one root compare-and-swap. A content write
cannot publish beside KV, bypass export reachability, or survive only because
an untyped identifier was hidden inside a KV value.

The object grammar and lazy reader compile with `no_std` plus `alloc`. The
default `std` feature adds the exact-pinned FastCDC builder; principal policy,
durable I/O, and authorization remain outside the primitive crate.

## Persistent chunking profile

Version one records:

- algorithm: FastCDC 2020;
- implementation revision: `fastcdc` 4.0.1;
- normalization: level one;
- minimum: 16 KiB;
- target average: 64 KiB;
- maximum: 256 KiB;
- gear seed: zero by default; and
- chunk-tree fanout: 128.

Content at or below 256 KiB is stored as one whole chunk; FastCDC engages only
above that threshold. The decoder enforces the same canonical choice, the
maximum on every chunk, and the minimum on every non-final chunk. A final chunk
may be shorter than the minimum.

The dependency is exact-pinned because boundaries influence the immutable file
root. The complete profile is encoded in each `File`, and a deterministic
one-megabyte fixture pins every expected cut length. A future profile may use a
different algorithm, seed, size distribution, or implementation revision
without making an existing file undecodable.

The gear fingerprint is not object identity. The engine's injected,
domain-separated BLAKE3 identity covers each chunk's complete bytes and every
typed structural record. Collision checking still compares canonical records.

The pinned sizes are measured rather than speculative. A real FastCDC sweep
over 5.73 GB of live Astrid state and a 2.45 GB development workspace found:

- whole-file identity alone removed 47.1% of the live-state bytes, collapsing
  230,080 files to 4,551 unique whole objects;
- total unique-byte-plus-object cost varied by only 0.5% across 8–256 KiB on
  state and by 3% on the workspace; and
- the 64 KiB target was within 0.07% and 1.2% of the respective measured
  capacity optima while using 3.5–7 times fewer objects than the smaller-chunk
  alternatives.

Object count therefore governs this profile: every object consumes index,
closure-validation, and recovery work. The result measures spatial
deduplication in one snapshot. It must be rerun over version chains once
temporal content history exists.

## Canonical objects

### Chunk

`ObjectKind::Chunk`, format one:

- canonical bytes: raw chunk bytes;
- no references;
- data accounting class; and
- zero direct logical-byte contribution.

The catalog, rather than unique chunks, accounts visible bytes. This prevents a
file containing one repeated chunk from being charged only once.

### ChunkTree

`ObjectKind::ChunkTree`, format one:

- canonical bytes: child count, subtree byte/chunk totals, and byte/chunk
  counts for each ordered child;
- owning child references labelled by big-endian child index;
- metadata accounting class; and
- at most 128 children.

Range reads use child lengths to skip non-overlapping subtrees. Identity-bearing
subtree counts let every traversed path validate byte and chunk cardinality
and canonical tree depth without loading unrelated chunks. Full reads validate
the complete closure.

### File

`ObjectKind::File`, format one:

- canonical bytes: algorithm code, implementation revision, normalization,
  minimum/average/maximum sizes, gear seed, logical length, and chunk count;
- zero references for an empty file or one `content` ownership edge; and
- zero direct logical-byte contribution.

Two identical byte sequences under the same profile produce the same `File`
identity regardless of principal or catalog name.

### Content catalog

`ObjectKind::Directory`, format one:

- each reference label is one validated opaque UTF-8 content name;
- each owning reference targets a `File`;
- canonical bytes pair references with their visible lengths and total quota;
- logical bytes sum every named value, including aliases; and
- quota bytes add every name byte to that logical total.

If Alice stores the same file twice, physical objects are reused but Alice is
charged for two visible values. If Bob stores the same bytes, his logical quota
is independent while the shared arena does not append duplicate objects.

## Mutation and concurrency

Each operation:

1. reads the current principal root;
2. validates `Commit -> PrincipalState -> content catalog`;
3. preserves KV and unrelated typed state references;
4. builds content records without admitting them;
5. computes combined KV and content quota;
6. publishes all reachable new records and one new principal root atomically;
7. retries the complete logical mutation if the root CAS conflicts.

The current `build_content` API accepts a complete source slice and copies its
chunks into a complete pending record set. Peak memory therefore includes both
the input and the built closure. It is suitable for present catalog-scale
content, not multi-gigabyte model weights; a streaming builder is required
before those workloads are enabled. The read-bound, delta-proportional ingest
pipeline and its crash marker protocol are tracked in
[#1392](https://github.com/astrid-runtime/astrid/issues/1392).

Deletes remain possible above quota. Growth is rejected when the combined
post-write total exceeds the live principal budget and exceeds the prior total.
KV applies the same combined calculation, so mutation order cannot bypass the
budget.

## Read behavior

`describe` loads only the file record. `read_range` traverses only overlapping
tree nodes and chunks. Returned bytes are copied into caller-owned memory; the
current API does not expose mapped arena storage or hand out raw engine
references.

Objects are immutable, so a concurrent catalog update cannot change the bytes
behind a descriptor. Durable garbage collection is not yet active. Once it is,
long-running readers must pin a root or use a bounded read lease.

## Security and privacy

The current native arena deduplicates equal logical objects store-wide. That
leaks equality to an operator capable of inspecting object identities or
physical reuse. It does not grant read authority: callers still require
principal-scoped access to a catalog/root.

Deduplication remains below the guest API line. No capsule-visible result,
timing class, accounting delta, or admission outcome may reveal whether an
object was newly inserted or already present. Physical insertion counts remain
kernel diagnostics and must not appear in a future content WIT.

Randomized client-side encryption prevents equality and therefore prevents
cross-principal deduplication. Convergent encryption restores deduplication but
introduces confirmation attacks. This PR does not silently choose either.
Explicit principal, organization, host, or protected no-dedup domains remain
future policy and encoding work.

Deduplication and hard erasure are mutually exclusive for the same bytes.
Erasure in a shared domain means root removal followed by garbage collection of
only the uniquely owned closure; objects referenced by any other root survive.
A per-principal hard-erasure domain requires per-principal encryption and
therefore gives up cross-principal deduplication for that domain.

### Prior-art lineage and adopted boundaries

| Lineage | Astrid boundary |
|---|---|
| 384/Snackabra (Magnusson) — deduplicated blob ledger, edge delivery, 384-bit origin-free universal identifiers | Astrid's boundary: capability-scoped principal roots over the shared store; identity is never an authorization token in the principal store. |

[Snackabra's documented object scheme][snackabra-overview] demonstrates the
useful middle ground for a future public/shared blob layer: pad plaintext into
coarse power-of-two buckets, split one SHA-512 result so the first 32 bytes
contribute the public content name and the other 32 bytes supply key material,
then encrypt and add a ciphertext hash to the full stored name. That design
retains deduplication while hiding plaintext from a storage server. It still
reveals content equality and permits confirmation attacks; padding obscures
length only within a bucket.

That scheme is acceptable in Astrid only as an explicitly selected
representation at the `ObjectId`/`BlobId` seam for future public or shared
content. It is forbidden for capability-scoped principal state:
[Tahoe-LAFS's convergence-secret design][tahoe-convergence] makes the security
consequence clear—a guessable content hash must never become the read
capability. Principal authorization remains a distinct root/capability check
even when a physical representation is message-locked.

Every admission and recovery replay must recompute identity from the complete
canonical object and compare it with the caller- or frame-supplied identity.
This is a security boundary, not an optional integrity check.
[Snackabra's storage handler][snackabra-storage-handler] is useful adversarial
evidence: the request path uses the supplied partial image identifier as its
lookup and allocation key while the intended verification call is disabled.
That permits a first writer to squat a name unless another trusted boundary
has already recomputed it. Astrid's engine therefore rejects proposals to skip
server-side recomputation for throughput.

If a future representation derives encryption keys from full-entropy content
hash material, it must use a domain-separated HKDF construction, not a
password-hardening loop. [RFC 5869][rfc5869] distinguishes extraction and
expansion of strong keying material from deliberately slow password KDFs.
Applying PBKDF2 for 100,000 iterations to an already unpredictable hash adds
latency without raising the work factor for guessing the underlying content.

### Semantic representation boundary

The current DAG recognizes exact byte equality. It deliberately does not
declare that different encodings contain the same typed value.

[Semantic Representations](astrid-semantic-representations.md) specifies the
generic extension: immutable equivalence contracts pin one archived reference
transform, `SemanticId` binds that contract to its canonical stream, and typed
representations carry provenance and trust class. This can recognize
pixel-identical images, canonical structured values, directory trees, model
tensors, or other domain values without placing codec logic in the kernel.

The reference-transform pin closes a cross-principal substitution attack:
arbitrary capsules may advertise transformation routes but cannot mint
semantic identity. Alternate implementations require complete reference
verification or a contract-pinned proof. Similarity remains a relationship
only, and arbitrary source encodings are never promoted into a shared trusted
serving pool merely because they produce the same semantic value.

No `SemanticId`, equivalence-contract registry, transform runner, or capsule
surface is activated by this increment.

[snackabra-overview]: https://snackabra.readthedocs.io/en/latest/overview.html#image-dedup-encryption-storage
[snackabra-storage-handler]: https://github.com/snackabra/snackabra-storageserver/blob/fb160601fde815f6ae16a96ed265ee205f4876dc/src/storage.js#L170-L223
[tahoe-convergence]: https://tahoe-lafs.org/trac/tahoe-lafs/browser/docs/specifications/file-encoding.rst
[rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869

## Evidence

Regression coverage includes:

- empty, small, multi-level, and repeated-chunk reconstruction;
- exact ranges crossing chunk and tree boundaries;
- proof that range reads skip unrelated objects;
- deterministic profile identity and golden FastCDC cut lengths;
- high chunk reuse after a local insertion;
- missing and malformed object rejection;
- cross-principal physical reuse with independent logical usage;
- duplicate aliases rejected by finite quota;
- combined KV/content quota in both mutation orders; and
- concurrent catalog writers retrying one shared principal CAS.

Random, compressed, and independently encrypted data are expected to approach
zero deduplication. No universal ratio is claimed.

## Deliberately separate work

This increment does not provide:

- host filesystem projection or path traversal;
- directory trees, symlinks, executable metadata, or atomic rename;
- capsule WIT/host calls before the interface freeze is lifted;
- streaming ingestion that avoids holding the source slice in memory;
- encryption and erasure-domain key management;
- semantic equivalence contracts and trusted representation selection;
- compaction or online garbage collection;
- export/import bundle integration; or
- replication, placement, and rebalancing.

Compaction and a persistent object index are prerequisites for heavy content
workloads. Until they land, logical quota does not bound append-only disk
history and store open remains proportional to the entire write history;
chunking must not be scaled merely because this format is available.

Those features can now consume a stable content primitive without changing the
authoritative principal-root model.
