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

The dependency is exact-pinned because boundaries influence the immutable file
root. The complete profile is encoded in each `File`, and a deterministic
one-megabyte fixture pins every expected cut length. A future profile may use a
different algorithm, seed, size distribution, or implementation revision
without making an existing file undecodable.

The gear fingerprint is not object identity. The engine's injected,
domain-separated BLAKE3 identity covers each chunk's complete bytes and every
typed structural record. Collision checking still compares canonical records.

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
without loading unrelated chunks. Full reads validate the complete closure.

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

Randomized client-side encryption prevents equality and therefore prevents
cross-principal deduplication. Convergent encryption restores deduplication but
introduces confirmation attacks. This PR does not silently choose either.
Explicit principal, organization, host, or protected no-dedup domains remain
future policy and encoding work.

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
- compaction or online garbage collection;
- export/import bundle integration; or
- replication, placement, and rebalancing.

Those features can now consume a stable content primitive without changing the
authoritative principal-root model.
