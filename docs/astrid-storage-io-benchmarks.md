# Astrid Storage I/O Benchmarks

Status: executable native-path baseline; mounted-provider measurements pending

Last reviewed: 2026-07-27

Tracking:
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

The benchmark never folds background publication into a foreground write
number. It records:

1. cached native write;
2. the following native `sync_all`;
3. cached write into Astrid's native staging file;
4. durable staging `seal`;
5. content construction without durable-engine work;
6. unique and duplicate publication;
7. first, warm, and post-reopen verified reads; and
8. fresh and populated engine open.

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
  --output /tmp/astrid-storage-io.json
```

`--root PATH` retains the generated source, staging area, and store on a
specific volume. The path must be absent or empty; the harness refuses to
overwrite a populated directory. Without it, the harness uses and removes a
temporary directory. The JSON contains every raw nanosecond sample, the
median, range, byte or operation count, target OS and architecture, logical CPU
count, and the exact workload configuration.

The source is deterministic and incompressible-looking. Source generation and
its reference digest are outside every timed interval. Native and Astrid paths
use the same source and the same user-space copy buffer. Every native and
reconstructed read is BLAKE3-checked against that reference.

The first read is merely the first read in that process. It is not called
uncached: portable, non-privileged page-cache eviction is unavailable. Record
cache state and any platform-specific eviction procedure separately rather
than relabeling a warm read as cold.

## Initial measurement

This baseline was recorded from commit `756ab50` plus the benchmark harness on:

- Mac Studio, Apple M2 Ultra, 24 CPU cores, 192 GB RAM;
- macOS 26.2;
- local journaled APFS data volume; and
- a 512 MiB deterministic source with four-MiB copy buffers and one-MiB
  published range reads.

Large-path medians:

| Operation | Median | Throughput |
|---|---:|---:|
| Native cached write | 97.61 ms | 5,245 MiB/s |
| Native sync after write | 108.78 ms | separate durability latency |
| Astrid cached staging write | 97.48 ms | 5,253 MiB/s |
| Astrid durable staging seal | 157.03 ms | 3,260 MiB/s over pending bytes |
| Content construction without engine admission | 654.18 ms | 783 MiB/s |
| Unique background publication | 2,164.50 ms | 237 MiB/s |
| Cached staging through unique publication | 2,394.79 ms | 214 MiB/s |
| Duplicate background publication | 1,746.44 ms | 293 MiB/s |
| Cached staging through duplicate publication | 2,033.85 ms | 252 MiB/s |
| Native warm verified-by-benchmark read | 320.23 ms | 1,599 MiB/s |
| Astrid warm one-MiB range reconstruction | 1,559.62 ms | 328 MiB/s |
| Populated engine reopen | 1,834.49 ms | not a byte-throughput metric |

The cached staging write is statistically indistinguishable from the native
cached-write path in this run. That is the correct foundation for a writable
mount. It does not make the complete path native-speed: durable seal, content
construction, object admission, and verified reconstruction remain separate.

Small 4 KiB file medians over batches of 64:

| Operation | Throughput |
|---|---:|
| Native write and close | 13,408 files/s |
| Native write and `sync_all` | 229 files/s |
| Astrid write and durable seal | 45 files/s |

Mapping every host close synchronously to today's durable seal would therefore
be a visible small-file regression. The provider contract must distinguish
ordinary close from explicit durability and define provider-process recovery
for work queued between those boundaries. This result does not authorize
weakening `seal`; `seal` remains the durable primitive.

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

## Scale interpretation

Linear projections are planning aids, not measurements. At the 512 MiB rates:

- staging and durable seal for 100 GiB project to roughly 51 seconds;
- unique background publication of 100 GiB projects to roughly 7.2 minutes;
- one-MiB verified reconstruction of 100 GiB projects to roughly 5.2 minutes;
  and
- one-TiB unique publication projects to roughly 74 minutes.

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
