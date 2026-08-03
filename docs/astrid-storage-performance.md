# Astrid Storage Performance and Convergence

This is the single measurement record for storage convergence, engine I/O,
publication, recovery, catalog scaling, and future filesystem-provider
performance. Component design documents define behavior and link here instead
of copying results.

Selected raw outputs are preserved in
[`benchmarks/storage-io/`](benchmarks/storage-io/README.md).

Status: convergence and native-path baselines recorded; mounted-provider
measurements pending

Last reviewed: 2026-08-03

Tracking:
[#1398](https://github.com/astrid-runtime/astrid/issues/1398),
[#1399](https://github.com/astrid-runtime/astrid/issues/1399),
[#1400](https://github.com/astrid-runtime/astrid/issues/1400),
[#1386](https://github.com/astrid-runtime/astrid/issues/1386),
[#1388](https://github.com/astrid-runtime/astrid/issues/1388),
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

For paired operations, this document reports substrate overhead as:

```text
Astrid elapsed time / native elapsed time
```

`1.00×` is hosted parity; a larger value is overhead over the same backing
filesystem. Ratios are valid only when byte count, cache state, verification,
and durability contract match. Native close, native `sync_all`, Astrid seal,
content publication, and root publication are deliberately separate because
combining unlike acknowledgement contracts manufactures a misleading number.

The current deterministic source is also a deliberate worst case for the
architecture: it is incompressible-looking, has no repeated content, remains
fully warm, and most measurements use one writer. It is useful for finding
fixed per-request and per-byte cliffs. It is not the product-level score for a
system designed to exploit repetition, version locality, concurrent principals,
and grouped durability. Both scoreboards are required.

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

## Convergence vocabulary and result

One percentage cannot describe the storage result. Every study reports:

```text
object-instance convergence
    1 - unique exact objects / logical object instances

exact-byte capacity convergence
    1 - unique whole-object bytes / logical bytes

chunk capacity convergence
    1 - unique chunked bytes / logical bytes

semantic capacity convergence
    savings added by verified cross-representation equivalence

physical capacity convergence
    1 - final stored bytes including encoding and metadata / logical bytes

marginal novelty
    additional unique physical bytes / additional logical bytes
```

The FastCDC study used 5.73 GB of live Astrid state and a 2.45 GB development
workspace. The live-state snapshot contained 230,080 file instances but only
4,551 unique whole-file objects:

```text
object-instance convergence
    = 1 - 4,551 / 230,080
    = 98.02%

whole-file byte-capacity convergence
    = 47.1%
```

Repeated small files dominate the instance count while unique large files
dominate capacity. The 98.02% result therefore proves a small repeated object
vocabulary, not 98% physical storage savings.

Across the 8–256 KiB FastCDC sweep, total unique-byte-plus-object cost varied
by only 0.5% on state and 3% on the workspace. The selected 64 KiB target was
within 0.07% and 1.2% of the respective measured capacity optima while using
3.5–7 times fewer objects than the smaller-chunk alternatives. Object count,
and its index, validation, and recovery cost, determined the profile choice.

Magnusson's 95–98% platform-scale byte-capacity convergence remains a
hypothesis. Evidence requires cumulative and marginal curves over principal
count, retained version depth, exact and chunk reuse, verified semantic
normalization, post-dedup compression, metadata, and corpus class. No combined
95–98% capacity claim is made until that experiment exists.

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
  --object-cache-bytes 1073741824 \
  --output /tmp/astrid-storage-io.json
```

`--root PATH` retains the generated source, staging area, and store on a
specific volume. The path must be absent or empty; the harness refuses to
overwrite a populated directory. Without it, the harness uses and removes a
temporary directory. The JSON contains every raw nanosecond sample, the
median, range, byte or operation count, target OS and architecture, logical CPU
count, and the exact workload configuration. It also records contract-matched
elapsed-over-substrate ratios, aggregate-to-single-principal throughput
scaling, and the exact growth in `objects.arena` plus `roots.journal` for
unique and duplicate publication. For even sample counts, the reported median
is the midpoint of the two central observations. Arena growth is authoritative
file length appended, not filesystem-allocated block count.

`--object-cache-bytes` opts the benchmark into the governed immutable-object
and verification cache. It is disabled when omitted. The example's 1 GiB is
an explicit experiment budget, not a daemon default or a recommendation for
production policy; the runtime must obtain its cache budget from the operator's
resource authority.

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

The first native-read value is merely the first measured native-read
observation and intentionally remains a single observation. The preceding
native-write, staging, and content-compute workloads have already read the
source and likely warmed the page cache. It is not called uncached: portable,
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

Large-path medians. The overhead column appears only where the current run has
a paired native operation with the same byte and verification contract:

| Operation | Median | Throughput | Substrate elapsed |
|---|---:|---:|---:|
| Native cached write | 440.27 ms | 1,163 MiB/s | 1.00× |
| Native sync after write | 13.31 ms | separate durability latency | 1.00× |
| Astrid cached staging write | 484.47 ms | 1,057 MiB/s | 1.10× |
| Astrid durable staging seal | 46.13 ms | separate durability latency | different contract |
| Content construction without engine admission | 644.88 ms | 794 MiB/s | no native pair |
| Unique background publication | 2,095.42 ms | 244 MiB/s | no native pair |
| Cached staging through unique publication | 2,318.57 ms | 221 MiB/s | no native pair |
| Duplicate background publication | 1,685.04 ms | 304 MiB/s | no native pair |
| Cached staging through duplicate publication | 2,187.49 ms | 234 MiB/s | no native pair |
| Native warm verified-by-benchmark read | 315.36 ms | 1,624 MiB/s | 1.00× |
| Astrid warm one-MiB range reconstruction | 1,540.00 ms | 332 MiB/s | 4.88× |
| Populated engine reopen | 1,789.85 ms | not a byte-throughput metric | no native pair |

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

## Measured follow-up gates

Three profiling rounds against the same storage stack turn the bottleneck map
into quantified acceptance gates:

- Warm range reads fit `0.53 ms/request + 2.41 µs/KiB` with `r² ≈ 0.999`.
  About 42% of 64 KiB read time was neighbor-chunk loading outside the requested
  range and another 13% was repeated gear-boundary validation. The
  `perf/storage-cached-positional-reads` branch moved 64 KiB single-stream reads
  from 93.1 to 228.8 MiB/s and four-principal aggregate reads from 106.0 to
  840.2 MiB/s by moving reads outside the write mutex and reusing
  principal-partitioned verification tokens. The remaining cache and
  post-reopen work stays tracked in #1399.
- Durable KV writes measured 8.6 ms, or 117 writes/s for the whole store.
  Two concurrent writers produced 111 writes/s aggregate and eight produced
  135 writes/s, confirming that current writers share no durability
  amortization. Group commit in #1388 owns this gate. Warm KV reads were about
  20 microseconds and the `spawn_blocking` adapter floor was 3.8 microseconds;
  neither is an optimization target.
- Native staging seals now batch the directory and intent-journal durability
  boundaries. The exact-parent comparison used 64 independent 4 KiB seals per
  writer, three samples per point, and reports the median sample:

  | Concurrent writers | Per-entry baseline | Batched journal | Throughput gain | Baseline p95 | Batched p95 |
  | ---: | ---: | ---: | ---: | ---: | ---: |
  | 1 | 45.6 seals/s | 74.4 seals/s | 1.63x | 23.74 ms | 13.95 ms |
  | 2 | 59.8 seals/s | 114.3 seals/s | 1.91x | 37.79 ms | 21.71 ms |
  | 4 | 61.9 seals/s | 162.0 seals/s | 2.62x | 68.68 ms | 30.24 ms |
  | 8 | 76.7 seals/s | 234.1 seals/s | 3.05x | 104.62 ms | 44.49 ms |

  A follow-up run at `5d6478c8` counted the durability calls crossed by the
  same workload. The baseline performs five filesystem flushes per seal. The
  journal implementation performs one content-file flush per seal plus one
  generation-directory flush and one journal flush per completed group:

  | Concurrent writers | Operations | Baseline flushes/seal | Median seal groups | Journal flushes/seal | Reduction |
  | ---: | ---: | ---: | ---: | ---: | ---: |
  | 1 | 64 | 5.000 | 64 | 3.000 | 40.0% |
  | 2 | 128 | 5.000 | 127 | 2.984 | 40.3% |
  | 4 | 256 | 5.000 | 131 | 2.023 | 59.5% |
  | 8 | 512 | 5.000 | 141 | 1.551 | 69.0% |

  These are successful filesystem durability calls, not inferred hardware
  cache flushes: the probe counts completed groups and combines them with the
  content-file flush executed by every seal. The raw counts and formula are in
  `docs/benchmarks/storage-io/seal-journal-main-vs-candidate.txt`.

  A lone durable seal is also faster because the flat journal removes the
  per-entry temporary-intent and directory-flush sequence; concurrency then
  amortizes the two remaining durability boundaries. Ordinary hosted close is
  still a distinct provider policy decision and need not synchronously pay
  this durable-seal cost.
- Flat-catalog read cost measured 0.26 microseconds per entry per request:
  88 microseconds at 250 entries and 1,063 microseconds at 4,000. The slope
  extrapolates, but has not yet been measured, at about 60 milliseconds per
  range read for the live 230,000-entry agent-state cardinality.
- Publishing identical 4 KiB files near 2,000 catalog entries appended about
  110 KiB of metadata per publication despite adding no content bytes. The
  catalog contributes about 60 bytes times its current cardinality to each
  write; the slope extrapolates, but has not yet been measured, at about
  14 MiB appended for one 4 KiB save at 230,000 entries. #1400 replaces this
  flat object with a persistent path-copy tree.
- A 128-byte KV set appended 2,883 bytes, or 22× logical value bytes. A probe
  with 2,400 small commits produced a 153 MiB arena and reopened in 569 ms.
  Compaction and the persistent index in #1386 must bound that historical
  amplification.

Physical bytes appended per logical byte and per operation are therefore
release metrics, not diagnostics.

### KV transition/checkpoint decision

The first replacement prototype put point mutations directly through an
immutable path-copy B+-tree. Exact wire accounting rejected it:

| Existing entries | Checkpoint build | 128-byte replacement |
| ---: | ---: | ---: |
| 10,000 | 1,817,823 B | 10,804 B |
| 100,000 | 18,169,931 B | 14,369 B |
| 1,000,000 | 181,687,551 B | 17,420 B |

Fat pages made reads shallow but made each changed immutable page expensive.
The accepted layout uses the B+-tree as an immutable checkpoint and appends
small canonical transition records between checkpoints. The same replacement
writes **948 authoritative bytes** at all three cardinalities, including object
frames and the root-journal frame and excluding objects already present. That
is 3.04 times less than the 2,883-byte AVL baseline and 11.4-18.4 times less
than the rejected direct B+-tree design.

The 4 MiB maintenance target is a batching threshold, not a format or quota
limit. It scales upward to at least the current live logical/quota size.
Checkpoint construction does not hold the mutation lock: any transition tail
that lands during the build is re-encoded over the new checkpoint and the
combined projection is root-CAS published.

The release-mode durable probe confirms that publication remains at the media
flush floor rather than growing with the owned closure:

| Existing entries | Replacement bytes | Replacement latency | Warm get | Reopen |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 948 B | 8.56 ms | 73.2 µs | 12 ms |
| 100,000 | 948 B | 8.47 ms | 91.4 µs | 100 ms |
| 1,000,000 | 948 B | 10.86 ms | 112.2 µs | 1,019 ms |

The durable engine reuses validated immutable closure evidence and stops at the
checkpoint. An in-memory reference-oracle run that deliberately revalidates the
entire closure is not representative of production publication latency.

## Integrated post-stack measurement

The first canonical format-v2 run measures the complete merged storage stack:
compaction and persistent indexes, path-copy catalogs, governed cached reads,
group commit, seal journaling, and in-process recovery. Commit `404a9d69` is
`2855d440` (`#1442` on `main`) plus the evidence-envelope-only benchmark change;
no measured storage implementation differs from that main commit. The report
records a clean tree, exact executable arguments, and independent SHA-256
commitments to both the measured executable and complete payload.

The run used the documented 512 MiB corpus, three samples, one-MiB ranges,
64 small files, four principals, and an explicit one-GiB governed cache budget
on the same M2 Ultra and APFS volume as the initial measurement:

| Operation | Median | Throughput | Relative result |
|---|---:|---:|---:|
| Native cached write | 100.41 ms | 5,098.9 MiB/s | substrate |
| Astrid cached staging write | 103.45 ms | 4,949.0 MiB/s | 1.030× elapsed |
| Astrid durable staging seal | 131.08 ms | separate durability | different contract |
| Content construction | 652.84 ms | 784.3 MiB/s | compute-only |
| Unique publication | 2,465.88 ms | 207.6 MiB/s | background |
| Duplicate publication | 2,026.84 ms | 252.6 MiB/s | background |
| Native warm verified read | 307.56 ms | 1,664.7 MiB/s | substrate |
| Astrid first verified read | 1,005.27 ms | 509.3 MiB/s | cache fill |
| Astrid warm verified read | 303.21 ms | 1,688.6 MiB/s | 0.986× elapsed |
| Astrid post-reopen verified read | 1,268.77 ms | 403.5 MiB/s | process evidence cold |
| Four-principal shared publication | 7,868.06 ms | 260.3 MiB/s aggregate | 1.254× single |
| Four-principal warm verified read | 314.47 ms | 6,512.5 MiB/s aggregate | 3.857× single |
| Populated reopen | 1,109.83 ms | not a byte rate | current checkpoint path |

The hosted foreground boundary is now effectively native: staging retained
97.1% of same-run cached-write throughput, and warm verified reads were 1.4%
faster than the comparator because immutable verification work was reused.
Four-principal warm reads scaled to 6.51 GiB/s without weakening principal-
partitioned verification or memory accounting.

Physical admission is also exact about repetition. Unique incompressible
content appended 538,140,607 authoritative bytes for 536,870,912 logical bytes
(1.002365×). Re-publishing the same 512 MiB appended only 1,092 bytes: about
491,640 times fewer authoritative bytes than the logical input. That is exact
deduplication plus root/catalog metadata, not a compression estimate.

Publication remains the integrated bottleneck. The 207.6/252.6 MiB/s unique
and duplicate results are close to the earlier governed-cache run but do not
inherit the 427/646 MiB/s result from the isolated record-reuse experiment.
That experiment remains evidence for the #1392 pipeline work, not a current-
main claim. Small strict seals reached 73.6 files/s versus 204.4 native
write-and-sync operations/s; ordinary provider close must therefore retain the
staged acknowledgement boundary rather than synchronously impersonating
`seal`.

## Optimization experiments

Several optimization branches were measured independently before integration.
The raw files preserve those experiments; they are not one linear release
score. The post-compaction run at `79d980d2`, for example, excludes the
independent read and publication branches and must not be presented as their
successor.

### Verified warm reads

| Code state | Request | Native verified | Astrid verified | Four-principal aggregate |
| --- | ---: | ---: | ---: | ---: |
| Pre-handle baseline | 64 KiB | 1,607 MiB/s | 93.1 MiB/s | 106.0 MiB/s |
| Positional handles (`8dfd6938`) | 64 KiB | 1,596 MiB/s | 94.9 MiB/s | 353.9 MiB/s |
| Boundary evidence (`1d2679ef`) | 64 KiB | 1,592 MiB/s | 228.8 MiB/s | 840.2 MiB/s |
| Object/header cache (`d69309ef`) | 64 KiB | 1,607 MiB/s | 1,573.0 MiB/s | 5,416.8 MiB/s |
| Governed cache (`e0bf4217`) | 64 KiB | 1,595 MiB/s | 1,570.0 MiB/s | 5,057.3 MiB/s |
| Governed cache (`e0bf4217`) | 1 MiB | 1,615 MiB/s | 1,739.3 MiB/s | 6,517.9 MiB/s |
| Integrated, format-frozen main (`c719da69`) | 64 KiB | 1,587 MiB/s | 1,530.2 MiB/s | 4,980.6 MiB/s |
| Integrated, format-frozen main (`c719da69`) | 1 MiB | 1,612 MiB/s | 1,705.8 MiB/s | 6,482.8 MiB/s |
| Integrated, format-frozen main (`c719da69`) | 8 MiB | 1,592 MiB/s | 1,702.5 MiB/s | 6,466.5 MiB/s |
| Review-hardened integration (`eb5f8208`) | 64 KiB | 1,581 MiB/s | 1,510.9 MiB/s | 4,928.4 MiB/s |

The pre-integration final 64 KiB run reached 98.5% of same-run verified-native
throughput and the one-MiB run reached 107.7%. Repeating the matrix after
integration onto format-frozen main produced 96.4% at 64 KiB, 105.8% at
1 MiB, and 106.9% at 8 MiB. The integrated first/cache-fill pass measured
492.0, 515.4, and 507.1 MiB/s respectively; after reopen, with process-local
verification evidence deliberately absent, it measured 319.6, 402.8, and
409.5 MiB/s. Four-principal warm aggregate throughput was 3.25-3.80 times the
single-principal result.

The final 64 KiB rerun after lifecycle, cache-accounting, and bounded-span
review fixes retained 95.6% of same-run verified-native throughput and 3.26×
four-principal scaling. Its first/cache-fill and post-reopen reads were 491.3
and 319.4 MiB/s. The 1.3% single-reader and 1.0% aggregate differences from
the preceding integrated run are within the observed host variance; the new
atomic lifecycle check did not restore the former mutex ceiling.

Astrid may legitimately lead the verified-native comparator when it reuses
immutable verified objects while the native reader hashes bytes again. These
are warm, governed-cache, verified-versus-verified engine measurements over a
128 MiB deterministic random corpus with three samples on an M2 Ultra. They
are not mounted-provider throughput, raw APFS throughput, or evidence that a
cold device read is faster than the substrate.

### Publication and durability

| Code state | Unique | Duplicate | Four-principal shared |
| --- | ---: | ---: | ---: |
| Pipeline baseline | 232.8 MiB/s | 289.8 MiB/s | 573.9 MiB/s |
| One-pass pipeline (`4193217f`) | 275.0 MiB/s | 353.1 MiB/s | 578.3 MiB/s |
| Governed record reuse (`97df6492`) | 427.4 MiB/s | 646.5 MiB/s | 1,065.4 MiB/s |

The #1388 port was remeasured against its exact current-main parent
`0ba1181c`. Each cell is the median of three release-mode runs with 64 strict
128-byte KV updates per principal through the complete async `TreeKvStore`
path:

| Principals | Main ops/s | Grouped ops/s | Throughput scaling | Main p95 | Grouped p95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 123.0 | 121.0 | 0.98× | 9.02 ms | 9.04 ms |
| 2 | 122.8 | 220.7 | 1.80× | 17.30 ms | 9.32 ms |
| 4 | 120.3 | 439.7 | 3.66× | 49.22 ms | 10.01 ms |
| 8 | 123.2 | 870.3 | 7.06× | 104.98 ms | 10.04 ms |

The isolated writer pays the intentional 250-microsecond gather delay and
remains in the same one-flush-round regime. At eight principals, one arena
flush and one root-journal flush are shared per observed group: aggregate
throughput rises 7.06 times while p95 latency falls 10.46 times. Staging uses
the same gather-policy abstraction but a separate durability journal. Its
exact-parent result in `ca1f72d8` raises strict 4 KiB seals from 45.6 to 74.4
seals/s for one writer and from 76.7 to 234.1 seals/s for eight.

Recovery-required is no longer a daemon-lifetime failure. The next engine
operation reopens the authoritative files in place under the retained store
lock and retries only the recovery scan, never the ambiguous failed mutation.
Before serving the selected root, live recovery re-flushes the recovered arena
and then its root journal; recovery is exceptional work, but it cannot turn
readable bytes from a failed flush into an unstably visible root.
Each foreground call has a configurable attempt count and backoff; later calls
may try again after an operator clears ENOSPC or another transient I/O fault.

### Catalog scaling

The path-copy catalog replaced the linear flat catalog in `d9a1463a`.

| Entries | Bulk build | Warm lookup | Replacement nodes | Replacement metadata | Flat rewrite |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2,000 | 5 ms | 2.26 µs | 11 | 1,887 B | 150,041 B |
| 230,000 | 374 ms | 2.68 µs | 20 | 3,480 B | 17,250,041 B |

The 230,000-entry replacement retains about 4,957 times less catalog metadata.
The durable 1,000-publication probe additionally measured:

| Workload | Arena growth | Root journal | Publication | Reopen |
| --- | ---: | ---: | ---: | ---: |
| Duplicate 4 KiB content | 1,906,879 B | 170,952 B | 10.62 s | 365 ms |
| Unique 4 KiB content | 6,336,445 B | 170,952 B | 11.15 s | 793 ms |

The duplicate workload averages about 1.9 KiB of total arena growth per
publication, down from roughly 110 KiB near 2,000 entries with the flat
catalog.

### Raw artifact map

| Files under `benchmarks/storage-io/` | Code state |
| --- | --- |
| `astrid-storage-io-m2-ultra-v3.json` | benchmark `228a38cc`, storage baseline `756ab50c` |
| `astrid-storage-read-baseline-64k.json` | parent of `8dfd6938` plus harness |
| `astrid-storage-read-path-64k.json` | `8dfd6938` |
| `astrid-storage-verified-64k.json` | `1d2679ef` |
| `astrid-storage-cache-final-64k.json` | `d69309ef` |
| `astrid-storage-governed-hot-64k.json`, `astrid-storage-governed-hot-1m.json` | `e0bf4217` |
| `astrid-storage-publication-before.json` | code `3d44cbd6`, harness `ee6990d4` |
| `astrid-storage-publication-after.json` | code `4193217f`, harness `63d0125e` |
| `astrid-storage-publication-cache-before.json` | `bcc45eef` |
| `astrid-storage-publication-cache-after.json` | code `97df6492`, harness `09318a04` |
| `astrid-storage-postcompaction.json` | `79d980d2` |
| `astrid-storage-main-404a9d69.json` | clean `404a9d69`; storage tree equals main `2855d440` plus evidence-only harness changes |

The historical report schema omitted Git revision and executable arguments.
Those associations are reconstructed from dedicated worktrees, ancestry,
names, and timestamps; they are historical evidence, not release attestation.
Format v2 embeds the revision, clean/dirty tree state, executable argument
vector, cache policy, and a SHA-256 commitment to the complete measured
payload. The report separately hashes the benchmark executable so the result
remains bound to the measured binary even if a checkout later moves.

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
- **Durable seals now share namespace and intent flushes.** Every seal flushes
  its own content file; a completed seal group then shares one generations
  directory flush and one intent-journal flush. The measured cost falls from
  five flush calls per seal to 1.551 at eight writers. The remaining
  per-content flush is deliberately strong and cannot be mapped onto every
  ordinary close. Provider `close`, `fsync`, sealed-generation publication,
  and grouped intent durability retain distinct contracts.
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

## Product-level workload scoreboard

The synthetic cliff-finder remains mandatory, but performance claims about the
architecture require a second suite:

- a realistic agent-state corpus with repeated files and temporal version
  chains;
- source revisions, build outputs, dependency caches, and package stores;
- Linux root filesystems, Realm/VM images, databases, and logs;
- model weights, tensor artifacts, text, media, and compressed archives;
- encrypted, uniform-random, and adversarial boundary-shifting input;
- a mixed KV/content workload across multiple principals;
- a working set larger than RAM, with cache state and any privileged cache
  eviction procedure recorded explicitly;
- the same logical create/edit/delete/sync job on native and Astrid;
- total logical bytes, physical bytes read and appended, fsync count, wall
  time, CPU, and peak memory;
- arena growth, fragmentation, and reopen cost over a long-lived mutation
  trace; and
- change-detection and sparse-transfer runs where only the delta is absent.

Every profile reports logical bytes; unique whole, chunk, metadata, and final
physical bytes; chunk count and distribution; compression separately; ingest,
export, import, cold-read, and warm-read throughput; CPU and peak memory; edit,
index, and reference amplification; durability barriers; and marginal novelty
as principals and history accumulate.

For this scoreboard Astrid may complete faster than a conventional layout by
avoiding reads, writes, transfers, and durability barriers. The report must
still show the substrate-overhead matrix separately so avoided work never
hides a slower primitive.

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
| Accounting | dirty-byte reservation, principal budget exhaustion, ENOSPC recovery, physical/logical amplification |
| Integrity | read verification, doctor projection checks, crash at every write prefix |

Results must name the provider and version: FSKit, WinFsp, libfuse, Realm 9P,
or the native Astrid VFS. A provider result cannot be generalized to another
adapter.

Guest-visible timing and result fields expose only ordinary filesystem
lifecycle and resource failures. Object reuse, was-present status, insertion
counts, physical representation choice, and dedup-derived accounting remain
operator diagnostics.
