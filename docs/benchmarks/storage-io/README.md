# Storage I/O benchmark record

This directory preserves selected raw outputs from the storage performance
investigation behind issue #1398. The human-readable interpretation and the
benchmark contract live in
[`../../astrid-storage-io-benchmarks.md`](../../astrid-storage-io-benchmarks.md).

These files are evidence for specific code states, not one linear release
score. Several optimization branches were measured independently before they
were rebased onto the complete storage stack. Comparing two rows is valid only
when the table below names a direct before/after relationship.

The early `astrid-storage-io-benchmark-v1` schema did not include the Git
revision or command line in its JSON envelope. Revision associations below
were reconstructed from the dedicated benchmark worktrees, branch ancestry,
file names, and run timestamps. Keep the raw files, but do not promote these
associations to release attestation. The harness must add revision, dirty-tree
state, command line, cache policy, and a result digest before the next canonical
run.

## Host

All archived runs used:

- Mac Studio, Apple M2 Ultra, 24 logical CPUs, 192 GB RAM;
- macOS 26.2;
- a local journaled APFS data volume; and
- release-mode Rust builds.

The JSON records the byte counts, range sizes, sample counts, and raw
nanosecond samples. Native reads hash and check the same source bytes as Astrid
reads. Absolute cached-I/O rates vary with host cache and filesystem state, so
same-run ratios and direct before/after branches are more useful than isolated
throughput. `SHA256SUMS` fixes the exact imported result bytes independently of
their eventual Git object names.

## Run ledger

| Raw output | Code state | Purpose |
| --- | --- | --- |
| `astrid-storage-io-m2-ultra-v3.json` | benchmark branch `228a38cc`, storage baseline `756ab50c` | Initial 512 MiB, one-MiB-range baseline recorded in the main benchmark document |
| `astrid-storage-read-baseline-64k.json` | parent of `8dfd6938` plus the benchmark harness | Pre-handle 64 KiB read baseline |
| `astrid-storage-read-path-64k.json` | `8dfd6938` | Reusable positional read handles |
| `astrid-storage-verified-64k.json` | `1d2679ef` | Principal-scoped verified-boundary reuse |
| `astrid-storage-cache-final-64k.json` | `d69309ef` | Governed immutable object/header cache before tree-edge evidence |
| `astrid-storage-governed-hot-64k.json` | `e0bf4217` | Final hot 64 KiB read run with governed resident memory |
| `astrid-storage-governed-hot-1m.json` | `e0bf4217` | Final hot one-MiB read run with governed resident memory |
| `astrid-storage-publication-before.json` | code `3d44cbd6`, harness branch `ee6990d4` | Publication pipeline baseline |
| `astrid-storage-publication-after.json` | code `4193217f`, harness branch `63d0125e` | One-pass publication and copy reduction |
| `astrid-storage-publication-cache-before.json` | code `bcc45eef` | Baseline before governed duplicate-record reuse |
| `astrid-storage-publication-cache-after.json` | code `97df6492`, harness branch `09318a04` | Governed publication-record reuse |
| `astrid-storage-postcompaction.json` | `79d980d2` over merged compaction/index work | Complete 512 MiB matrix after #1407, without the independent read/publication optimization branches |

The post-compaction run is not an “after” value for the read and publication
branches. Its ancestry deliberately excludes them. It measures the integrated
storage line at that point and therefore prevents accidental claims that an
unmerged experiment was already current behavior.

## Measured progression

### Verified warm reads

| Code state | Request | Native verified | Astrid verified | Four-principal aggregate |
| --- | ---: | ---: | ---: | ---: |
| Pre-handle baseline | 64 KiB | 1,588 MiB/s | 92.9 MiB/s | 105.8 MiB/s |
| Positional handles | 64 KiB | 1,588 MiB/s | 94.4 MiB/s | 353.2 MiB/s |
| Boundary evidence | 64 KiB | 1,589 MiB/s | 227.7 MiB/s | 839.0 MiB/s |
| Object/header cache | 64 KiB | 1,607 MiB/s | 1,573.0 MiB/s | 5,416.8 MiB/s |
| Governed hot cache | 64 KiB | 1,593 MiB/s | 1,548.4 MiB/s | 5,026.7 MiB/s |
| Governed hot cache | 1 MiB | 1,612 MiB/s | 1,706.4 MiB/s | 6,512.0 MiB/s |

The final hot 64 KiB run reaches 97.2% of the same-run verified-native
throughput. The one-MiB hot run reaches 105.9%. That narrow lead is a legitimate
possible cache benefit: Astrid may reuse already verified immutable objects
while the native comparator hashes the bytes again. It is not mounted-provider
throughput and needs confirmation after the branches are integrated.

### Publication

| Code state | Unique | Duplicate | Four-principal shared |
| --- | ---: | ---: | ---: |
| Pipeline baseline | 232.8 MiB/s | 289.8 MiB/s | 573.9 MiB/s |
| One-pass pipeline | 275.0 MiB/s | 353.1 MiB/s | 578.3 MiB/s |
| Governed record reuse | 427.4 MiB/s | 646.5 MiB/s | 1,065.4 MiB/s |

Against the same experimental lineage, governed record reuse raises unique
publication throughput by 83.6%, duplicate publication by 123.1%, and
four-principal shared publication by 85.6% over the pipeline baseline.

### Other recorded branches

Some focused probes predate the JSON archive:

- `aed1b3aa` records strict durable KV group commit in
  `docs/astrid-storage-group-commit.md`: one writer remains 117.3 operations/s,
  while eight writers rise from 135 to 802.5 operations/s aggregate (5.94x).
- `32dc52fb` records the staging intent journal in
  `docs/astrid-storage-seal-journal.md`: 64-file strict seal throughput rises
  from 43.7 to 71.8 seals/s for one writer and from 78.3 to 186.4 seals/s for
  eight writers.
- merged commit `d9a1463a` records the path-copy content catalog in
  `docs/astrid-content-catalog-tree.md`: 1,000 duplicate 4 KiB publications
  append 1,906,879 bytes to the arena, about 1.9 KiB each, versus roughly
  110 KiB per publication near 2,000 entries with the flat catalog.

## Next canonical run

After the performance branches and the chunk-profile decision are integrated,
rerun the complete matrix on one clean commit. Archive both realistic and
worst-case corpora. At minimum the report must carry:

- exact Git revision and dirty-tree state;
- complete command line and benchmark schema version;
- host, filesystem, mount options, cache state, and resource-policy settings;
- raw samples, result-file digest, CPU time, peak resident memory, fsync count,
  physical bytes read/written, and logical/physical amplification; and
- direct ancestry labels for every claimed before/after comparison.
