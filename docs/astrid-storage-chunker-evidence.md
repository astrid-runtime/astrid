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

- the best matched MinCDC profile changes combined estimated retained cost by
  -0.0105%, effectively a tie;
- the lowest-cost MinCDC profile improves that estimate by 0.1086% but creates
  41.59% more unique chunk objects across the two live corpora;
- MinCDC is materially faster in this scalar pipeline, but its local-edit
  resynchronization tail is 2.6–3.6 times the FastCDC result;
- Moth's caterpillar encoding collapsed 60 records in the matched live-state
  run and none in the workspace or captured history, a 2,400-byte directional
  metadata estimate rather than a storage-architecture win; and
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
- MinCDC `observed-match-96k` uses 32–160 KiB bounds, selected after the first
  pass showed that FastCDC's observed large-file mean was not 64 KiB;
- MinCDC `fastcdc-bounds` uses the same 16–256 KiB bounds as production; and
- each Moth entry uses the identical paired MinCDC boundaries, then separately
  counts its adjacent-identical-chunk run representation.

MinCDC records no invented average-size parameter. Its complete identity
candidate is its window, inclusive min/max bounds, multiplier, addend, leftmost
tie rule, and final-chunk rule.

The corpora were:

| Label | Shape | Logical size |
|---|---:|---:|
| `agent-state` | 230,086 files | 5.73 GB |
| `dev-workspace` | 47,746 files | 2.47 GB |
| `captured-code` | 32 real `Cargo.lock` revisions read directly from Git | 8.14 MB |
| `synthetic-version-chain-v1` | 16 controlled local edits | 67.1 MB |
| `synthetic-adversarial-v1` | empty, short, zeros, all-ones, periodic, monotone, repeated, pseudorandom, and boundary-pressure inputs | 58.7 MB |

Paths, file names, revision IDs, and file-level identities are not serialized.
Top-level `keys`, `secrets`, `run`, and `.Trash` directories are excluded from
directory snapshots. Symlinks are never followed. The harness captures a
length-and-BLAKE3 baseline for every file before measuring any candidate and
aborts if any later pass observes different bytes, including a same-length
replacement.

## Storage results

The first pass reproduced the prior whole-file result within the explicit
floor-to-basis-points reporting rule: the agent-state corpus saves 47.07%
before chunking. Chunking raises that to 51.35–51.44% for
the candidates below. The remaining differences are small enough that object
population, recovery work, and resynchronization matter more than retained
bytes.

| Profile | Agent CDC mean | Workspace CDC mean | Agent saved | Workspace saved | Combined cost vs FastCDC | Unique objects vs FastCDC |
|---|---:|---:|---:|---:|---:|---:|
| FastCDC 16/64/256 | 110.1 KiB | 76.5 KiB | 51.38% | 26.10% | baseline | baseline |
| MinCDC observed-match 32–160 | 93.1 KiB | 86.0 KiB | 51.38% | 26.18% | -0.0105% | +8.47% |
| MinCDC wide 32–96 | 59.7 KiB | 59.1 KiB | 51.44% | 26.44% | -0.1086% | +41.59% |
| MinCDC same bounds 16–256 | 130.5 KiB | 115.5 KiB | 51.35% | 25.86% | +0.1323% | -8.56% |

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
at the byte before, exactly at, and the byte after an observed boundary.
All reused at least 97.63% of unaffected boundaries in the deterministic
8 MiB fixture.

| Profile | Worst boundary survival | Longest resynchronization |
|---|---:|---:|
| FastCDC 16/64/256 | 99.06% | 58,222 B |
| MinCDC observed-match 32–160 | 98.78% | 152,644 B |
| MinCDC wide 32–96 | 98.40% | 159,114 B |
| MinCDC same bounds 16–256 | 98.18% | 208,706 B |

Release-mode CPU-only medians on the measured Apple M2 Ultra host, Rust 1.95.0:

| Profile | Chunk only | Chunk + BLAKE3 |
|---|---:|---:|
| FastCDC 16/64/256 | 1,818.73 MiB/s | 912.35 MiB/s |
| MinCDC observed-match 32–160 | 10,888.28 MiB/s | 1,565.22 MiB/s |
| Moth observed-match 32–160 | 10,860.11 MiB/s | 1,548.39 MiB/s |

MinCDC's compute result is real and worth retaining as evidence. It does not,
by itself, outweigh an identity migration for effectively unchanged retained
cost. Parallel publication can also move production chunking back below the
device-read ceiling without changing the file format.

## Reproducibility and trust boundary

The exact evidence-oracle revisions are recorded in the JSON and locked in
`Cargo.lock`:

| Component | Version | Source revision | License | Role |
|---|---|---|---|---|
| `fastcdc` | 4.0.1 | `2e47aa3146c6dbae34896997eebd162b280a7052` | MIT | production baseline |
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
Corpus counts, boundaries, identities, deduplication totals, representation
counts, and stability outcomes are deterministic. Throughput is compared by
median and must be interpreted within the recorded host/toolchain boundary.

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
