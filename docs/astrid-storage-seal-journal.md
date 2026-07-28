# Native staging seal journal

Issue: [#1402](https://github.com/astrid-runtime/astrid/issues/1402)

## Purpose

Hosted filesystem providers must acknowledge an explicit durable close without
waiting for content chunking, hashing, or principal-root publication. The
staging area therefore has two different write boundaries:

- ordinary provider writes mutate one private native file at host-filesystem
  speed; and
- `seal` makes that file and its publication intent recoverable before
  returning.

Ordinary close may use the platform provider's native close semantics. A guest
`fsync` or an operator-selected durable-close policy maps to `seal`. This split
does not weaken explicit durability: every successful `seal` remains
recoverable after process or machine failure.

## Persistent layout

```text
content-staging/
  generations/
    <uuid>.open
    <sequence>-<uuid>.sealed
  quarantine/
  intents.v1.log
```

Open generations are not acknowledged. Sealed generations are ordinary content
bytes followed by a recoverable intent footer. The shared journal records
sealed and published lifecycle transitions. The singleton runtime lock excludes
two daemons from mutating or recovering this area concurrently.

## Seal ordering

One writer performs these steps:

1. allocate the close-order sequence and construct the intent;
2. append the checksummed intent and fixed footer trailer to the generation;
3. synchronize the complete generation file;
4. rename `<uuid>.open` to its canonical sealed name; and
5. join the current seal group.

The group leader then:

1. synchronizes `generations/`, making every participating rename durable;
2. appends all `Sealed` records to `intents.v1.log`;
3. synchronizes the journal once; and
4. resolves every successful participant.

Acknowledgement is strictly after the generation-file flush, generation
directory flush, and journal flush. A durability failure poisons the staging
instance and fails the entire group; the caller must reopen before retrying.
The same `GroupCommitPolicy` used by durable principal-root commits controls
only the short gathering window. Immediate mode changes batching latency, not
the acknowledgement boundary.

Each content file must still be synchronized individually on the portable
strict path. A later platform-specific batch-writeout policy may prepare
multiple files before one barrier, but it must be a named durability policy
with independent crash tests rather than an implicit weakening of `seal`.

## Footer format

The footer lets recovery distinguish an unjournalled-but-complete seal from an
arbitrary orphan after a torn journal tail.

```text
logical content bytes
encoded StagingIntent
32-byte trailer:
  magic            16 bytes  "ASTRID-STAGE-F1\0"
  version           u16 LE    1
  reserved          6 bytes   zero
  intent length     u64 LE
```

`StagingIntent` is independently checksummed and includes sequence, UUID,
typed owner, content name, chunking profile, and logical byte length. The
decoder requires the intent to start exactly at `logical_bytes`, so bytes
cannot be appended between the content and its authority metadata. Publication
passes only the logical prefix to the content builder.

## Journal format

Every journal frame is:

```text
magic              8 bytes  "ASTRSTG1"
version            u16 LE   1
reserved           u16 LE   zero
payload length     u64 LE
checksum           32 bytes
payload            payload length bytes
```

The checksum is BLAKE3 derive-key mode with
`"astrid native content staging journal frame v1"` over magic, version, payload
length, and payload. Payload kind `1` contains one encoded `StagingIntent`;
kind `2` contains a close-order sequence and UUID identifying a published
generation.

## Publication and cleanup

Background publication reads exactly `logical_bytes`, streams the content into
the ordinary identity-checked principal store, and publishes through its root
CAS. Only after that root is authoritative does staging append and flush a
`Published` record. The generation file is then removed and `generations/`
is synchronized. When no pending or completed entries remain, the journal is
truncated and synchronized.

A crash after root publication but before the `Published` record repeats an
idempotent content publication. A crash after the record but before cleanup
reaps the generation on reopen. Cleanup never precedes its durable publication
record.

## Recovery rules

- `.open` generations are unacknowledged and move to quarantine.
- A sealed generation named by a valid `Sealed` record must have a matching
  authenticated footer; disagreement fails closed.
- A valid sealed generation missing from the journal reconstructs its
  `Sealed` record from the footer and synchronizes that repair.
- A physically invalid final journal frame is a torn tail and is truncated.
  A valid later frame makes the damage interior corruption and open fails.
- A torn `Sealed` tail is recoverable from the generation footer.
- A torn `Published` tail is not silently inferred. If its generation is
  already gone, open fails rather than resurrecting or losing acknowledged
  state.
- A valid `Published` record permits idempotent cleanup whether the generation
  still exists or was already removed.
- Invalid or non-canonical unjournalled generations are quarantined. Redirected
  or changed journalled generations fail closed.

The legacy per-generation-directory format migrates under the singleton lock.
Migration first moves content into a flat generation, appends and synchronizes
its footer, synchronizes the generation directory, and only then appends the
shared journal record. Legacy evidence is removed last. Every crash prefix can
therefore resume from either the old evidence or the new footer.

## Measured checkpoint

The release probe performs 64 durable 4-KiB seals per writer, with three
samples per concurrency level on APFS. Medians compare the old per-entry
intent-file path with this strict journal path:

| Writers | Old seals/s | Journal seals/s | Change |
| ---: | ---: | ---: | ---: |
| 1 | 43.7 | 71.8 | 1.64x |
| 2 | 53.4 | 76.9 | 1.44x |
| 4 | 61.5 | 130.2 | 2.12x |
| 8 | 78.3 | 186.4 | 2.38x |

These are hosted-substrate results, not a filesystem-versus-filesystem claim.
The shared intent ceremony is no longer multiplied per file. The remaining
strict-path floor is dominated by synchronizing each participating content
file; provider benchmarks must separately report ordinary close and explicit
durable-close behavior.
