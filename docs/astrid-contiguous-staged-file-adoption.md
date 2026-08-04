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
- the blob store and staging area share an atomic-rename domain, or the engine
  explicitly falls back to copy publication; and
- an operation lease pins the staged generation until root publication or
  retry completes.

## Durable intent

The durable intent lives at `representations/adoption/<OwnerNameKeyId>.intent`.
`OwnerNameKeyId = PhysicalId("astrid-adoption-key-v1\0", u64_le(owner.len) || owner ||
u64_le(name.len) || name)`, where owner is `StateOwnerCodecV1` and name is canonical
`ContentName` UTF-8. The filename is lowercase hex of the complete tagged identity. One key lock
permits one intent; an occupied unequal owner/name is fatal.

The intent file is exactly one common 52-byte format-one frame followed by its
payload and no trailing bytes:

```text
offset  size  field
     0     8  magic = ASCII "ASTADI1" followed by NUL
     8     2  physical_frame_version = 1, little-endian
    10     2  reserved = 0
    12     8  payload_length, little-endian
    20    32  checksum
    52     N  AdoptionIntentV1 payload
```

The checksum is the first 32 bytes from standard BLAKE3 `DERIVE_KEY_CONTEXT`
with the exact UTF-8 context `astrid durable physical frame checksum v1`
(without a terminating NUL), followed by `DERIVE_KEY_MATERIAL` over
`magic[8] || physical_frame_version:u16_le || payload_length:u64_le || payload`.
The reserved bytes are not checksum material.

```text
AdoptionIntentV1 = version:u16 = 1 || owner:bytes || content_name:bytes || stage_generation:u64
    || logical_length:u64 || physical_length:u64 || staging_intent:bytes
    || source_identity:bytes || blob:BlobId || profile:RepresentationProfileId
    || profile_record:bytes || representation:RepresentationRecordId
    || representation_record:bytes || admission_evidence:ObjectId
    || admission_evidence_record:bytes
    || storage_node:u32 || namespace_generation:u64 || mode:u8
```

Every `bytes` field is prefixed by its `u64` byte length. The embedded staging
intent must decode and byte-exactly re-encode as `StagingIntent` v2. Outer
owner/name equal its canonical fields; `stage_generation` equals `sequence`, `logical_length` equals
`logical_bytes`, and `physical_length == logical_length + staging_intent.len + 32`; mismatch rejects
before mutation. `profile_record` and `representation_record` are the complete
canonical physical values whose derived IDs equal `profile` and
`representation`. `admission_evidence_record` is the evidence object's complete
canonical `ObjectRecord` encoding; server-side identity must equal
`admission_evidence`, the representation must name that evidence, and all three
records must satisfy the profile, coverage, and subject rules. These bytes are
retained specifically so recovery can recreate and collision-compare the exact
candidate after the staged source has changed shape. Source identity is:

```text
SourceIdentityV1 = Unix { tag:u8 = 0, device:u64, inode:u64 }
                 | Windows { tag:u8 = 1, volume_serial:u32, index_high:u32, index_low:u32 }
```

Unix covers Linux and macOS opened-handle `st_dev/st_ino`; Windows matches its three live u32 fields.
Unknown tags, trailing bytes, or conversion overflow reject. `mode` is rename `0` or copy `1`.
The final target is the canonical loose-blob path from the representation
contract. Before that publication, the canonical storage-node-root-relative
incoming path for both modes is exactly:

```text
representations/blobs/incoming/<namespace_generation:016x>/<BlobId>.<OwnerNameKeyId>.<stage_generation:016x>.incoming
```

Generations are exactly 16 lowercase hex digits and both identities are
lowercase hex of their complete tagged envelopes. The
owner/name key and staged generation prevent concurrent equal-Blob adoptions
from sharing an incoming path. An occupied path is reusable only for the
byte-exact same intent and one of its specified recovery states; an unequal
intent is a fatal collision. A partial copy for the same intent restarts from
the retained sealed source. The rename branch resumes only after source
identity, physical length, and permitted footer/truncated state validate; it is
never overwritten from another operation. `storage_node` selects the exact
signed operator-configured root for both incoming and final paths. Recovery
never scans other storage roots; a missing mapping makes the operation
unavailable until operator configuration is restored.

Publication exclusively creates `<OwnerNameKeyId>.intent.tmp` no-follow,
writes the complete frame, flushes it, reopens and verifies it byte-for-byte,
renames it no-replace to the canonical intent path, and flushes the parent
directory before any source mutation. An incomplete or invalid temporary is
unpublished and may be quarantined. The canonical intent is not an append log:
an incomplete, checksum-invalid, non-canonical, or trailing-byte final file is
corruption that blocks only its owner/name key; recovery never truncates it
into validity. Recovery verifies the canonical filename, frame, staging
checksum, and source identity, then resumes idempotently. Roots and
representation state are always re-read under their fences, never trusted from
an intent. The intent survives until the ordinary publication marker; cleanup
checks that marker first, removes the intent, and flushes its directory.

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
4. Choose the publication mode and durably create its adoption intent before the in-file footer is
   lost. The source may not be mutated before both this intent and step 3 are durable.
5. Execute the recorded branch before mutating the source. On the same-volume
   branch, rename it to a non-authoritative incoming name, flush both namespaces,
   truncate to `logical_bytes`, flush, and recompute length and `BlobId`. On the
   fallback branch, retain the footer-bearing sealed source and copy only its
   logical prefix into a flushed, reverified incoming file.
6. Install the incoming file at the final BlobId path atomically with no-replace.
   If it exists, open it no-follow below the pinned directory and never mutate
   it; reuse only after complete-preimage equality, otherwise fail fatally.
7. Decode and re-derive the intent's exact physical records, then stage and
   flush their catalogue nodes plus direct arena and final-blob placements.
   Recovery rebuilds any lost disposable locations from the verified arena.
8. Publish all metadata, the verified contiguous representation, and placements in one CAS. None names
   the incoming file or a file that still contains the staging trailer. Crash
   recovery uses the intent's canonical records and physical length to validate
   a footer-bearing source, copied incoming file, or truncated state; anything
   else quarantines.
9. Publish the principal root. The commit fence rechecks the complete metadata
   and representation closure and the active `RepresentationStateId`.
10. Write the ordinary durable publication marker and reap the staging
   generation. A root conflict retries the catalogue/root mutation without
   rereading the blob.

The same-volume rename path writes source bytes once plus bounded metadata. The
fallback performs one additional full-data write. Mounted writes still
acknowledge at native staging speed; the optimized branch removes the second
full-byte arena append measured in #1392.
