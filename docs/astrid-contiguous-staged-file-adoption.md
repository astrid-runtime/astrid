# Contiguous staged-file adoption

Status: format-one design contract. This document is the normative adoption
protocol referenced by [astrid-physical-representations.md](astrid-physical-representations.md).
It uses the identities, catalogue, placement, and publication rules defined
there and the common physical frame from
[astrid-principal-store-format-v1.txt](astrid-principal-store-format-v1.txt).

The native staging file is already the one physical write made on the
user-visible path. Adoption turns that sealed file into the raw-content blob
instead of copying its bytes into the object arena.

## Preconditions

- the staged generation is sealed, durable, immutable, and has canonical verified intent,
  owner, content name, generation, length, and source file identity;
- the blob store and staging area share copy-on-write clone support, or the
  engine explicitly falls back to copy publication; and
- an operation lease pins the staged generation until root publication or
  retry completes.

## Source-preserving adoption

Adoption never mutates or renames the sealed staging generation. On APFS and
Linux filesystems that support whole-file reflinks, the engine exclusively
clones the sealed generation to a private loose-blob temporary, truncates only
the clone to `logical_bytes`, flushes it, and re-verifies the BlobId. Copy-on-write
means the clone shares the content extents while the staging footer occupies at
most its own changed tail extent. The source remains a byte-exact durable retry
witness until the ordinary root publication marker authorizes staging cleanup.

This removes the destructive transition that required a separate adoption
intent. Every crash prefix has one of three simple states: the unchanged sealed
source alone; the source plus unauthoritative temporary/blob files; or the
source plus an authoritative representation state. Retrying from the source is
always possible. A filesystem without clone support copies exactly the logical
prefix into the same private temporary and follows the identical verification
and publication path.

Temporary blob names are private and non-authoritative. The final target is the
canonical loose-blob path from the representation contract. Publication uses
exclusive creation and a same-filesystem hard link as the no-replace primitive;
Unix `rename` is not used because it overwrites an occupied destination. An
occupied final path is reusable only after exact metadata, length, BlobId, and
complete-preimage comparison. Unequal occupation is fatal. Stale temporaries
may be removed or quarantined because neither representation state nor a
principal root can name them.

## Protocol

1. Validate the staging footer and require physical length to equal the
   declared logical prefix plus its encoded intent and 32-byte trailer. Stream
   exactly `logical_bytes` through FastCDC and the identity builders; the
   footer is never hashed as content. In the same pass compute the raw-content
   `BlobId`, emit File/ChunkTree records, construct coverage, and derive the
   exact profile, representation, and admission-evidence records.
2. Recheck the sealed generation and file identity. Any mutation rejects the
   attempt without publishing a root.
3. Server-identify and append every File, ChunkTree, and admission Evidence
   `ObjectRecord` to `objects.arena`, flush it, and retain their verified arena
   locations for direct paths in the candidate state. Orphaned frames are safe;
   no representation state or principal root names them yet.
4. Publish and flush the exact `ASTBLM1\0` loose-blob metadata using exclusive
   temporary creation and no-replace hard-link installation. Equal occupied
   metadata is reusable only after byte-exact comparison.
5. Clone the sealed source no-replace to a private temporary, truncate the
   clone to `logical_bytes`, flush it, and recompute length and `BlobId`. If
   whole-file cloning is unsupported, copy only the logical prefix into a
   flushed temporary. The sealed source remains unchanged in both modes.
6. Install the temporary at the final BlobId path atomically with no-replace.
   If it exists, open it no-follow below the pinned directory and never mutate
   it; reuse only after complete-preimage equality, otherwise fail fatally.
7. Re-derive the exact physical records, then stage and flush their catalogue
   nodes plus direct arena and final-blob placements.
   Recovery rebuilds any lost disposable locations from the verified arena.
8. Publish all metadata, the verified contiguous representation, and placements in one CAS. None names
   a temporary file or a file that still contains the staging trailer. Recovery
   reconstructs the disposable slice index from the authenticated maps, loose
   metadata, complete blob, canonical File/ChunkTree records, and admission
   evidence.
9. Publish the principal root. The commit fence rechecks the complete metadata
   and representation closure and the active `RepresentationStateId`.
10. Write the ordinary durable publication marker and reap the staging
   generation. A root conflict retries the catalogue/root mutation without
   rereading the blob.

The reflink path writes source bytes once plus bounded metadata and at most a
copy-on-write tail extent. The fallback performs one additional full-data
write. Mounted writes still acknowledge at native staging speed; the optimized
branch removes the second full-byte arena append measured in #1392 while
retaining the original sealed retry witness.
