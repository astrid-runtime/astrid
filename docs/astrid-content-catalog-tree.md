# Astrid content catalog tree

## Status

This document specifies the named-content catalog that replaces the flat
`Directory/v1` catalog. The legacy object remains readable only by the ordered
store migration. New roots use the tree exclusively.

## Why a radix tree

The flat catalog decodes and rewrites every name for every point operation.
Measured cost is linear in catalog cardinality: about 0.26 microseconds per
entry per read and about 60 bytes of newly appended metadata per entry per
publish. At 230,000 entries that is roughly 60 milliseconds per lookup and
14 MiB of metadata for a 4 KiB save.

The replacement is a compressed binary radix tree over the canonical UTF-8
name bytes followed by one zero terminator byte. Content names cannot contain
a zero byte, so this mapping is prefix-free. Each internal node records the
first bit at which its two subtrees differ.

This shape is preferable to an AVL tree or history-shaped B-tree here:

- the logical key set determines exactly one tree, independent of insertion
  order;
- a point lookup or mutation is independent of catalog cardinality and is
  bounded by the key bit length;
- a mutation writes only the changed search path;
- in-order traversal preserves canonical byte ordering; and
- root accounting totals are available without decoding the descendants.

No fixed name-length, entry-count, or catalog-size limit is introduced. Parser
and address-space limits remain resource guards, not product quotas.

## Object grammar

Both node forms use `ObjectKind::Directory`,
`ObjectFormatVersion(2)`, and `ObjectClass::Metadata`.

### Leaf

Canonical bytes:

| Field | Encoding |
| --- | --- |
| tag | `0x00` |
| visible byte length | unsigned 64-bit little-endian |
| name byte length | unsigned 64-bit little-endian |
| name | canonical UTF-8 bytes |

The leaf has exactly one owning reference labelled `file`. Its target is the
immutable content `File` object. `ObjectRecord.logical_bytes` equals the
visible byte length.

Leaf quota is:

`visible byte length + name byte length`

### Branch

Canonical bytes:

| Field | Encoding |
| --- | --- |
| tag | `0x01` |
| distinguishing bit index | unsigned 64-bit little-endian |
| left logical bytes | unsigned 64-bit little-endian |
| left quota bytes | unsigned 64-bit little-endian |
| left entry count | unsigned 64-bit little-endian |
| right logical bytes | unsigned 64-bit little-endian |
| right quota bytes | unsigned 64-bit little-endian |
| right entry count | unsigned 64-bit little-endian |

It has exactly two owning references labelled `left` and `right`.
`ObjectRecord.logical_bytes` is zero because branches are structural; visible
bytes are contributed exactly once by leaves. Root totals are checked sums of
the corresponding child fields.
Embedding child totals lets a path copy rebuild each ancestor without loading
the unchanged sibling.

## Canonical validation

A catalog root is accepted only after a complete iterative validation:

- every object has the exact kind, version, class, payload length, and
  reference grammar above;
- identities are supplied by the verified object engine;
- branch bit indices strictly increase down every path;
- left and right key ranges are ordered and differ first at the branch's
  recorded bit;
- stored child and root accounting totals equal recomputed totals;
- no object is reused within the tree and no cycle is present; and
- every visible file length agrees with its leaf.

Validation evidence is process-local and partitioned by principal. The
immutable tree bytes may be physically shared, but one principal cannot make
another principal skip validation. A successful point mutation from a
validated root produces a validated successor by construction.

## Operations

Lookup follows distinguishing bits until a leaf, then compares the complete
name. Insert finds the existing leaf and its first differing bit, introduces
one branch at the canonical position, and path-copies only its ancestors.
Replacement path-copies the leaf path. Delete removes the leaf and its parent,
promotes the sibling, and path-copies the remaining ancestors.

The cost is `O(name bytes)` object reads and new metadata in the adversarial
bound, with no `O(catalog entries)` point-operation term. Listing remains
`O(entries)` because it intentionally returns every name.

## Migration

Store migrations and store initialization are separate. A store with the
legacy completion marker is a valid store that still requires the catalog
transform.

The ordered migration:

1. opens the already recovered engine under the singleton store lock;
2. enumerates current principal roots;
3. finds any `Directory/v1` content component;
4. validates and decodes the complete flat catalog;
5. bulk-builds the canonical radix tree from byte-sorted entries;
6. publishes an ordinary root compare-and-swap retaining every unrelated
   component and commit reference;
7. repeats after a root conflict; and
8. flushes the engine before atomically advancing the migration marker.

Each converted principal root is independently durable. A crash before the
final marker therefore resumes safely: already converted roots are no-ops and
remaining flat roots are retried. The legacy object becomes unreachable but is
not destroyed; arena compaction decides when its bytes can be reclaimed.

No permanent dual-write mode exists.

## Performance gates

The implementation is accepted only when tests or benchmarks demonstrate:

- root identity is identical across insertion permutations;
- lookup work does not grow with unrelated catalog cardinality;
- point mutation appends a bounded key path rather than the complete catalog;
- quota totals are read from and verified against the root;
- legacy migration is idempotent across interruption; and
- malformed ordering, accounting, reuse, and cycle cases fail closed.

The checked-in release-mode cardinality probe currently reports:

| Entries | Bulk build | Warm point lookup | Replacement nodes | Replacement retained metadata | Flat-catalog rewrite |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2,000 | 5 ms | 2.26 us | 11 | 1,887 B | 150,041 B |
| 230,000 | 374 ms | 2.68 us | 20 | 3,480 B | 17,250,041 B |

These are in-process catalog measurements, not storage-device throughput.
They isolate the term this change removes. At the measured live cardinality, a
replacement retains about 4,957 times less catalog metadata than serializing
the legacy object, and lookup remains in microseconds rather than inheriting
the legacy full-catalog decode. Run with:

`cargo test -p astrid-storage --release catalog_scale_probe -- --ignored --nocapture`

The non-ignored regression fixture also publishes 1,000 distinct names that
all reference one deduplicated 4 KiB file. It requires every catalog mutation
to retain less metadata than the logical file size and the complete sequence
to retain less than 4 MiB of catalog metadata. This pins the former
deduplication failure mode: content equality may eliminate data writes without
causing catalog metadata to grow as a full rewrite times cardinality.
