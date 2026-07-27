# Astrid Storage I/O Benchmarks

Status: executable native-path baseline; mounted-provider measurements pending

Last reviewed: 2026-07-27

Tracking:
[#1398](https://github.com/astrid-runtime/astrid/issues/1398),
[#1399](https://github.com/astrid-runtime/astrid/issues/1399),
[#1392](https://github.com/astrid-runtime/astrid/issues/1392),
[#1391](https://github.com/astrid-runtime/astrid/issues/1391), and
[#1396](https://github.com/astrid-runtime/astrid/issues/1396)

## Claim boundary

Storage cost, storage throughput, and mounted-filesystem behavior are different
measurements.

- The FastCDC corpus sweep measures unique bytes and object counts.
- `storage_io` measures the native staging and principal-store paths that exist.
- No mounted filesystem provider exists yet, so these results are not mount
  throughput, metadata latency, `mmap` behavior, or open-handle evidence.

On a hosted platform, Astrid's arena and staging files are themselves stored by
APFS, NTFS/ReFS, or the host Linux filesystem. For the same bytes and durability
contract, the hosted target is therefore near-native overhead, not a claim that
additional work can outrun its backing filesystem. Hosted Astrid can finish a
logical workload faster when deduplication, change detection, sparse transfer,
cached representations, or grouped durability avoid work the conventional path
performs. Beating the host on raw physical storage requires Astrid to own the
lower storage path, as in the bare-metal program or a purpose-built raw-device
backend.

The benchmark never folds background publication into a foreground write
number. It records:

1. cached native write;
2. the following native `sync_all`;
3. cached write into Astrid's native staging file;
4. durable staging `seal`;
5. content construction without durable-engine work;
6. unique and duplicate publication;
7. first, warm, and post-reopen verified reads; and
8. fresh and populated engine open; and
9. concurrent publication and verified reads of shared content by multiple
   principals.

Small-file batches separately compare native write-and-close, native
write-and-sync, and Astrid write-and-seal. These operations have different
durability contracts and must never share one label.

## Reproduction

Run an optimized benchmark on the volume being evaluated:

```console
cargo +1.95 bench -p astrid-storage --bench storage_io -- \
  --bytes 536870912 \
  --block-bytes 4194304 \
  --range-bytes 1048576 \
  --samples 3 \
  --small-files 64 \
  --small-file-bytes 4096 \
  --concurrent-principals 4 \
  --output /tmp/astrid-storage-io.json
```

`--root PATH` retains the generated source, staging area, and store on a
specific volume. The path must be absent or empty; the harness refuses to
overwrite a populated directory. Without it, the harness uses and removes a
temporary directory. The JSON contains every raw nanosecond sample, the
median, range, byte or operation count, target OS and architecture, logical CPU
count, and the exact workload configuration.

`--samples` applies to unique publication, duplicate publication, engine open
and reopen, Astrid reads, native writes, seals, and the concurrent workloads.
Each store sample starts with a fresh engine so “unique” remains unique and
reopen does not silently measure a growing prior sample. When `--root` is
provided, the final single-principal and concurrent stores are retained; prior
sample stores are removed outside the timed intervals.

The source is deterministic and incompressible-looking. Source generation and
its reference digest are outside every timed interval. Native and Astrid paths
use the same source and the same user-space copy buffer. Every native and
reconstructed read is BLAKE3-checked against that reference.

The first native read is merely the first read in that process and intentionally
remains a single observation. It is not called uncached: portable,
non-privileged page-cache eviction is unavailable. Record cache state and any
platform-specific eviction procedure separately rather than relabeling a warm
read as cold.

The native read baseline hashes every byte with single-threaded BLAKE3 and
checks the resulting digest. Its roughly 1.6 GiB/s result on the machine below
is therefore a verified-read floor, not the storage device's unverified read
ceiling. A raw disk number is not an honest comparator for Astrid's mandatory
verification.

## Initial measurement

This repeated baseline was recorded from commit `756ab50` plus the benchmark
harness on:

- Mac Studio, Apple M2 Ultra, 24 CPU cores, 192 GB RAM;
- macOS 26.2;
- local journaled APFS data volume; and
- a 512 MiB deterministic source with four-MiB copy buffers and one-MiB
  published range reads.

Large-path medians:

| Operation | Median | Throughput |
|---|---:|---:|
| Native cached write | 440.27 ms | 1,163 MiB/s |
| Native sync after write | 13.31 ms | separate durability latency |
| Astrid cached staging write | 484.47 ms | 1,057 MiB/s |
| Astrid durable staging seal | 46.13 ms | separate durability latency |
| Content construction without engine admission | 644.88 ms | 794 MiB/s |
| Unique background publication | 2,095.42 ms | 244 MiB/s |
| Cached staging through unique publication | 2,318.57 ms | 221 MiB/s |
| Duplicate background publication | 1,685.04 ms | 304 MiB/s |
| Cached staging through duplicate publication | 2,187.49 ms | 234 MiB/s |
| Native warm verified-by-benchmark read | 315.36 ms | 1,624 MiB/s |
| Astrid warm one-MiB range reconstruction | 1,540.00 ms | 332 MiB/s |
| Populated engine reopen | 1,789.85 ms | not a byte-throughput metric |

Absolute cached-write rates varied with host state between runs, so same-run
ratios are the useful evidence. Astrid's cached staging write reached 90.9% of
native in this repeated run and matched it in the earlier run. That validates
the native staging acknowledgement architecture: bytes can land without
waiting for content addressing. It does not make the complete path
native-speed. Durable seal, content construction, object admission, and
verified reconstruction remain separate measured work.

Small 4 KiB file medians over batches of 64:

| Operation | Throughput |
|---|---:|
| Native write and close | 1,389 files/s |
| Native write and `sync_all` | 122 files/s |
| Astrid write and durable seal | 24.6 files/s |

Mapping every host close synchronously to today's durable seal would therefore
be a visible small-file regression. The provider contract must distinguish
ordinary close from explicit durability and define provider-process recovery
for work queued between those boundaries. This result does not authorize
weakening `seal`; `seal` remains the durable primitive.

## Concurrent principals

Four principals published and then read the same 512 MiB logical content
concurrently. Staging and seal were completed before the publication timer, so
the result isolates shared object admission, root publication, and read
contention:

| Operation | Aggregate throughput | Scaling over one principal |
|---|---:|---:|
| One-principal unique publication | 244 MiB/s | 1.00× |
| Four-principal shared publication | 562 MiB/s | 2.30× |
| One-principal warm verified read | 332 MiB/s | 1.00× |
| Four-principal shared verified reads | 481 MiB/s | 1.45× |

Sharing already improves aggregate throughput, but neither path approaches
four-way scaling. The shared read takes 2.76 times one-reader latency to serve
four readers. This directly exposes the global engine mutex and per-call
metadata reconstruction that a single-principal benchmark cannot show. The
publication result similarly establishes the before-number for group commit
and narrower appender critical sections.

## Read-size sensitivity

A diagnostic 128 MiB run varied only the `PrincipalContentStore::read_range`
request size:

| Range request | Native warm read | Astrid warm read |
|---:|---:|---:|
| 64 KiB | 1,605 MiB/s | 95 MiB/s |
| 256 KiB | 1,608 MiB/s | 219 MiB/s |
| 1 MiB | 1,599 MiB/s | 335 MiB/s |
| 8 MiB | 1,628 MiB/s | 393 MiB/s |

This diagnostic used one sample per size and is evidence of request-size
sensitivity, not a release number. Repeated small ranges re-resolve the
principal catalog and file descriptor, traverse tree paths, load neighboring
chunks, verify frame checksums, and recheck canonical boundaries. A filesystem
provider needs an open-handle read cursor with a root/object lease, cached
descriptor and traversal state, bounded read-ahead, and a representation-aware
fast path. It must not implement each VFS read callback as an independent
high-level named-content lookup.

The contiguous-representation design in #1396 is the route for hot large-file
reads. The canonical chunk DAG remains the logical identity and transfer form;
a verified contiguous representation lets the provider serve ordinary
sequential and `mmap`-compatible reads without rebuilding the file for every
request.

## Current bottleneck map

These causes are verified against the code at the measured baseline, not
inferred from throughput alone:

- **Range reads rebuild all lookup state.** Every call reloads and validates the
  principal commit, state, flat catalog, file descriptor, overlapping tree
  nodes and chunks, plus boundary-neighbor chunks. Every object load locks the
  global durable engine, seeks one shared arena file, allocates a frame buffer,
  verifies its physical checksum, and decodes a new record. No descriptor,
  tree-node, or chunk state survives the call. The 64 KiB-to-one-MiB scaling
  below is the direct signature of this fixed ceremony. The first corrective
  sequence is an immutable decoded-object cache, positional reads outside the
  engine mutex, and an open-content handle that pins root/descriptor/traversal
  state (#1399); contiguous representations then remove gather I/O for hot
  large objects.
- **Publication is serial and copy-heavy, but identity encoding is no longer
  under the mutex.** Streaming currently copies each chunk into an
  `ObjectRecord`; the sink identifies it, the durable admission boundary
  identifies it again and encodes a frame, and the appender checksums and
  copies every encoded payload into one coalesced buffer before writing. The
  first identity and frame encoding already happen before the engine lock.
  Under the lock remain duplicate-object readback, frame checksums and batch
  assembly, append, closure validation, and commit durability. Profiling must
  apportion those current costs before changing the authority boundary.
- **One seal performs at least five durability operations.** It flushes the
  content file, flushes and renames an intent temporary, flushes that
  directory, renames the staged directory, and flushes both the writing and
  ready directories. This is deliberately strong but cannot be mapped onto
  every ordinary close. Provider `close`, `fsync`, sealed-generation
  publication, and grouped intent durability need distinct contracts.
- **Reopen scans the entire arena and journal on current `main`.** It verifies
  and rebuilds the in-memory index from write history. The persistent-index
  work in #1386 changes this to a verified checkpoint plus tail; compaction and
  journal snapshots bound the history that remains.
- **One `Mutex<DurableInner>` serializes arena access across principals.**
  Current object reads hold it across seek, read, checksum, allocation, and
  decode. Publication also takes it for index/readback/append work and commit.
  The four-principal results quantify this cliff before positional reads,
  immutable caches, narrower write critical sections, and group durability.

## Scale interpretation

Linear projections are planning aids, not measurements. At the 512 MiB rates:

- staging and durable seal for 100 GiB project to roughly 1.8 minutes;
- unique background publication of 100 GiB projects to roughly 7.0 minutes;
- one-MiB verified reconstruction of 100 GiB projects to roughly 5.1 minutes;
  and
- one-TiB unique publication projects to roughly 72 minutes.

The first-ever one-TiB ingest target of minutes is therefore not met by the
current serial implementation. The measurement supports the existing work:
parallel reader/chunker/hasher execution, a single coalesced appender,
persistent indexing and compaction, a path-copy catalog, bounded builder
metadata, group publication, and representation adoption. The benchmark must
be rerun after each change instead of treating the projection as a promise.

## Mounted-provider matrix

Every supported provider eventually runs the same matrix against a native
filesystem on the same machine and volume:

| Surface | Required measurements |
|---|---|
| Large sequential I/O | cached and durable write, first and warm read, CPU, peak RAM, copies |
| Random I/O | 4 KiB and 64 KiB IOPS, queue depth, p50/p95/p99 latency |
| Small files | create, open, close, explicit sync, stat, rename, unlink, directory enumeration |
| Open handles | rename-over-open, unlink-while-open, daemon/provider restart, upgrade handover |
| Memory mapping | shared/private mapping, dirty-page writeback, linker, compiler, Wasmtime, executable policy |
| Publication | acknowledgement latency, queue lag, ingest throughput, root-CAS latency, failure recovery |
| Accounting | dirty-byte reservation, principal budget exhaustion, ENOSPC recovery |
| Integrity | read verification, doctor projection checks, crash at every write prefix |

Results must name the provider and version: FSKit, WinFsp, libfuse, Realm 9P,
or the native Astrid VFS. A provider result cannot be generalized to another
adapter.

Guest-visible timing and result fields expose only ordinary filesystem
lifecycle and resource failures. Object reuse, was-present status, insertion
counts, physical representation choice, and dedup-derived accounting remain
operator diagnostics.
