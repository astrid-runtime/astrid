# Content chunker evidence

This document is the single human-readable record for the format-one chunker
gate. The generated machine report is
[`benchmarks/astrid-storage-chunker-evidence-v1.json`](benchmarks/astrid-storage-chunker-evidence-v1.json).
The harness that produced it is the non-published
`astrid-storage-chunker-evidence` workspace crate.

## Decision

Keep `ChunkingProfile::ASTRID_V1`: FastCDC 2020, normalization level one,
16/64/256 KiB bounds, canonical unseeded gear table.

The measured alternatives do not justify changing durable identity:

- the empirical-compromise MinCDC profile changes combined estimated retained
  cost by -0.0105%, effectively a tie;
- the lowest-cost MinCDC profile improves that estimate by 0.1086% but creates
  41.58% more unique chunk objects across the two live corpora;
- MinCDC is materially faster in the scalar CPU-only fixture, while the expanded
  local-edit study finds no material stability winner between FastCDC and the
  empirical-compromise MinCDC profile;
- Moth's caterpillar encoding collapsed 60 records in the corresponding
  live-state run and none in the workspace or captured history, a 2,400-byte
  directional metadata estimate rather than a storage-architecture win; and
- Chonkers does not currently have a licensed, byte-stream, independently
  reproducible reference profile that Astrid can freeze.

This evidence PR does not change `ChunkingProfile`, file headers, production
dependencies, or stored identity.

## What was compared

All profiles preserve the production rule that an input no larger than the
profile maximum is one whole object. Larger files are streamed. The report
keeps boundary selection separate from representation:

- `fastcdc-v2020-64k` is the production baseline;
- MinCDC `narrow` uses 48–80 KiB bounds;
- MinCDC `wide` uses 32–96 KiB bounds;
- MinCDC `empirical-compromise-96k` uses 32–160 KiB bounds, selected after the
  first pass showed that FastCDC's observed large-file mean was not 64 KiB;
- MinCDC `fastcdc-bounds` uses the same 16–256 KiB bounds as production; and
- each Moth entry uses the identical paired MinCDC boundaries, then separately
  counts its adjacent-identical-chunk run representation.

MinCDC records no invented average-size parameter. Its complete identity
candidate is its window, inclusive min/max bounds, multiplier, addend, leftmost
tie rule, and final-chunk rule.

The empirical-compromise label is deliberately not `observed-match`. FastCDC's
agent-state distribution has a 107.6 KiB mean and a 256 KiB p95/p99, while its
workspace distribution has a 74.7 KiB mean, 143.5 KiB p95, and 193.5 KiB p99.
MinCDC 32–160 KiB lands at 90.9/83.9 KiB means but cannot reproduce the agent
tail. Giving MinCDC the same 256 KiB maximum recovers the agent tail, overshoots
the workspace tail, and moves the means to 127.5/112.8 KiB. No tested bound
pair matched both corpora; the reported profiles bracket the observed
distributions instead of treating a nominal target as an empirical match.

The corpora were:

| Label | Shape | Logical size |
|---|---:|---:|
| `agent-state` | 230,088 files | 5.73 GB |
| `dev-workspace` | 47,805 files | 2.47 GB |
| `captured-code` | 32 real `Cargo.lock` revisions read directly from Git | 8.16 MB |
| `synthetic-version-chain-v1` | 16 controlled local edits | 67.1 MB |
| `synthetic-adversarial-v1` | empty, short, zeros, all-ones, periodic, monotone, repeated, pseudorandom, and boundary-pressure inputs | 58.7 MB |

Paths, file names, revision IDs, and file-level identities are not serialized.
Top-level `keys`, `secrets`, `run`, and `.Trash` directories are excluded from
directory snapshots. Symlinks are never followed. The harness captures a
length-and-BLAKE3 baseline for every file before measuring any candidate and
immediately re-hashes each timed file outside the timed interval. It aborts if
any later pass observes different bytes, including a same-length replacement.
The CDC comparison was generated from temporary point-in-time APFS copies.
The later bottom-k extension used fresh baseline-validated directory snapshots;
each input was rechecked as it was read and the run would have aborted on a
concurrent byte change. The two sections therefore retain their exact measured
file counts instead of pretending they were one observation.

## Storage results

The first pass reproduced the prior whole-file result within the explicit
floor-to-basis-points reporting rule: the agent-state corpus saves 47.07%
before chunking. Chunking raises that to 51.35–51.44% for
the candidates below. The remaining differences are small enough that object
population, recovery work, and resynchronization matter more than retained
bytes.

| Profile | Agent CDC mean | Workspace CDC mean | Agent saved | Workspace saved | Combined cost vs FastCDC | Unique objects vs FastCDC |
|---|---:|---:|---:|---:|---:|---:|
| FastCDC 16/64/256 | 107.6 KiB | 74.7 KiB | 51.38% | 26.10% | baseline | baseline |
| MinCDC empirical compromise 32–160 | 90.9 KiB | 83.9 KiB | 51.38% | 26.18% | -0.0105% | +8.46% |
| MinCDC wide 32–96 | 58.3 KiB | 57.7 KiB | 51.44% | 26.44% | -0.1086% | +41.58% |
| MinCDC same bounds 16–256 | 127.5 KiB | 112.8 KiB | 51.35% | 25.86% | +0.1323% | -8.56% |

The cost estimate is explicit and directional: unique chunk bytes plus 162
bytes per unique chunk object plus 40 bytes per physical reference record. It
is not presented as an exact arena-format byte count.

The captured code history is an important causal warning. Production FastCDC
kept every sampled version whole because each was below 256 KiB, so temporal
chunk reuse was zero. Profiles with a lower maximum chunked those files and
saved 61–71% in that chain. MinCDC with the same 256 KiB maximum also kept them
whole and saved zero. That is evidence for studying the whole-object threshold,
not evidence that MinCDC caused the gain. A future temporal study should isolate
a FastCDC 16/64/160 profile before proposing a format change.

## Boundary stability and throughput

Every candidate was run against insert, delete, and equal-length replacement
at the byte before, exactly at, and the byte after seven deterministic,
quantile-matched boundary neighborhoods. The resulting 63 cases per profile
all resynchronized. Across every candidate, each edit preserved at least
94.48% of unaffected boundaries in the deterministic 8 MiB fixture.

| Profile | Worst boundary survival | p95 resynchronization | Maximum resynchronization |
|---|---:|---:|---:|
| FastCDC 16/64/256 | 98.13% | 173,659 B | 173,916 B |
| MinCDC empirical compromise 32–160 | 97.56% | 159,401 B | 200,899 B |
| MinCDC wide 32–96 | 98.40% | 159,114 B | 164,628 B |
| MinCDC same bounds 16–256 | 96.36% | 250,549 B | 410,992 B |

The expanded measurement retracts the earlier single-midpoint claim that
MinCDC had a 2.6–3.6 times longer resynchronization tail. The empirical
compromise has a slightly shorter p95 and a 15.5% longer maximum than FastCDC;
the wide profile is slightly better on both. Stability therefore does not
decide the format. Retained cost, object population, implementation
independence, and existing production behavior do.

Each corpus/profile pair also has four order-balanced, alternating end-to-end
passes per mode. These medians include file I/O and the whole-file policy:

| Profile | Agent chunk only | Agent + BLAKE3 | Workspace chunk only | Workspace + BLAKE3 |
|---|---:|---:|---:|---:|
| FastCDC 16/64/256 | 347.51 MiB/s | 285.27 MiB/s | 945.81 MiB/s | 613.96 MiB/s |
| MinCDC empirical compromise 32–160 | 231.62 MiB/s | 207.46 MiB/s | 1,133.24 MiB/s | 682.87 MiB/s |
| Moth empirical compromise 32–160 | 229.57 MiB/s | 200.36 MiB/s | 1,100.45 MiB/s | 665.11 MiB/s |

Alternating order prevents the second mode from inheriting a systematically
warmer page cache. The results also show why CPU-only throughput is not a
corpus result: FastCDC's larger whole-file threshold wins on the agent-state
shape, while MinCDC's boundary speed wins on the development workspace.

Release-mode CPU-only medians on a deterministic 64 MiB fixture, measured on
the Apple M2 Ultra host with Rust 1.95.0:

| Profile | Chunk only | Chunk + BLAKE3 |
|---|---:|---:|
| FastCDC 16/64/256 | 1,803.91 MiB/s | 907.74 MiB/s |
| MinCDC empirical compromise 32–160 | 9,993.49 MiB/s | 1,482.58 MiB/s |
| Moth empirical compromise 32–160 | 9,922.99 MiB/s | 1,476.08 MiB/s |

MinCDC's compute result is real and worth retaining as evidence. It does not,
by itself, outweigh an identity migration for effectively unchanged retained
cost. Parallel publication can also move production chunking back below the
device-read ceiling without changing the file format.

## Bottom-k resemblance decision

The same harness also runs the production Refinery bottom-k transform over
exact format-one File DAGs and feeds the chosen candidate into a deterministic
COPY/ADD encoder. Every measured delta is decoded and required to reconstruct
the target bytes. This is candidate-selection evidence, not a new authoritative
representation format.

The selected descriptor is 256 retained 128-bit scores. The scheduler emits it
only for multi-chunk Files.

| Samples | Agent useful / 67 | Agent encoded bytes | Workspace useful / 372 | Workspace encoded bytes |
|---:|---:|---:|---:|---:|
| 16 | 18 | 2,740,491,968 | 17 | 988,699,412 |
| 32 | 20 | 2,737,297,008 | 17 | 988,699,412 |
| 64 | 21 | 2,730,497,897 | 19 | 988,389,366 |
| 128 | 25 | 2,726,752,143 | 19 | 987,972,895 |
| 256 | 25 | 2,726,752,143 | 22 | 987,623,522 |
| 512 | 25 | 2,726,752,143 | 22 | 987,623,522 |

The raw baselines were 2,987,909,629 and 995,290,622 bytes. Deterministic
random candidates saved no bytes. At 256 samples the sketches retain 229,602
bytes over the eligible agent-state Files and 308,259 bytes over the eligible
workspace Files. Moving from 128 to 256 samples costs 64,208 aggregate sketch
bytes and saves another 349,373 encoded bytes plus three avoided misses;
moving to 512 adds 106,992 sketch bytes and changes no candidate or delta.

The 256-bit construction selected exactly the same candidates and encoded byte
totals at every sample size. At the selected sample size it retained 352,144
more aggregate bytes, while a 128-bit score collision can at worst propose
work that still fails exact reconstruction and ObjectId verification. The
wider score therefore has no measured or correctness benefit in this advisory
index.

The production pass body sustained 577.65 MiB/s on eligible agent-state DAGs
and 557.41 MiB/s on eligible workspace DAGs at the selected descriptor. These
timings begin after the exact File DAG is available and exclude the independent
verification pass. The pass keeps at most 8 KiB of score slots; the evidence
harness separately verifies that its vector never grows beyond the initial
bounded reservation.

History fixtures preserve the causal ordering. The synthetic edit chain and
the 32-version CHANGELOG chain found useful resemblance candidates, but none
beat the immediate predecessor. The selected execution policy is therefore
lineage first, sketches only for residual cross-name or cross-lineage search.

An initial all-file measurement also quantified the scheduler rule: emitting
one-score records for every agent-state file would retain roughly 73 MB of
Derived metadata and add no search information. Multi-chunk-only scheduling
reduces that selected-profile footprint to 230 KB without changing any useful
candidate in the measured corpus.

## Reproducibility and trust boundary

`Cargo.lock` pins the registry versions and package checksums used for the run.
The corresponding upstream tag revisions inspected for provenance are recorded
separately in the JSON and below; the lockfile does not authenticate those Git
revisions:

| Component | Version | Source revision | License | Role |
|---|---|---|---|---|
| `fastcdc` | 5.0.0 | `eeb3cbe8ed4eeef020aa346707bbdb29abd814ad` | MIT | production baseline for even profiles |
| `fastcdc-v4` | 4.0.1 | `2e47aa3146c6dbae34896997eebd162b280a7052` | MIT | legacy odd-profile compatibility edge |
| `mincdc` | 0.1.0 | `638840e6809274e3e8e9916951d3c3ae4f3f5191` | Zlib | accelerated evidence oracle |
| `mothcdc` | 0.7.2 | `3900c1e4e6c311bf832cb5099b2e0170e070970f` | Zlib | representation evidence oracle |

The harness includes a deliberately scalar MinCDC implementation that shares
no SIMD or reader-buffer machinery with the crate. Tests require byte-for-byte
boundary agreement on adversarial fixtures and pin the four-byte window,
`0x915f77f5` multiplier, `0x34636463` addend, leftmost-minimum tie rule,
inclusive non-final bounds, and short-final-chunk behavior. Moth and MinCDC
must produce identical logical cuts before caterpillar records are measured.

The Chonkers paper and inspected reference revision
`4fff91bae8eceaf209850544a00ecaa67e5ffb6b` describe a hierarchy over
caller-supplied proto-chunks, not one canonical byte-stream preprocessing
profile. The repository has no license grant, independent reader, golden cuts,
or conformance suite. The harness records it as unavailable rather than
inventing missing behavior.

Run the public fixtures:

```console
cargo run --release -p astrid-storage-chunker-evidence -- \
  --target-kib 64 --output chunker-evidence.json
```

Run only the bottom-k curve when CDC comparisons are not being revisited:

```console
cargo run --release -p astrid-storage-chunker-evidence -- \
  --sketch-only \
  --corpus agent-state="$ASTRID_STATE" \
  --corpus dev-workspace="$ASTRID_WORKSPACE" \
  --output sketch-evidence.json
```

Add private corpora without placing paths in the result:

```console
cargo run --release -p astrid-storage-chunker-evidence -- \
  --target-kib 64 \
  --corpus agent-state="$ASTRID_STATE" \
  --corpus dev-workspace="$ASTRID_WORKSPACE" \
  --git-history captured-code="$ASTRID_REPO"::Cargo.lock \
  --output chunker-evidence.json
```

The report contains wall-time measurements, so reruns are not byte-identical.
Its `benchmark_environment` records the OS, architecture, host and target
triples, CPU, exact Rust compiler, and Cargo build profile that bound those
timings.
Corpus counts, boundaries, identities, deduplication totals, representation
counts, and stability outcomes are deterministic. CPU-only throughput uses
three in-memory samples per profile. Corpus throughput uses four
order-balanced, alternating end-to-end samples per mode; directory snapshots
include file I/O, while memory-backed synthetic and Git-history corpora do not.
Both must be interpreted within the recorded host/toolchain boundary.

## Reopening the decision

Do not change the profile from this data. Reopen only with new evidence that
includes multiple real version chains and isolates:

1. whole-object threshold from boundary algorithm;
2. retained bytes from object count and recovery/index cost;
3. single-thread compute from the parallel ingest pipeline; and
4. a production-grade independently specified implementation with golden cuts
   and a compatible license.

Moth remains evidence-only. Its representation seam may be revisited
independently if a corpus with large adjacent identical chunk runs demonstrates
a material win.
