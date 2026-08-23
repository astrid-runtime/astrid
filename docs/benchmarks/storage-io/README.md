# Storage I/O raw results

The canonical interpretation, code-state ledger, claim boundaries, and
reproduction contract live in
[`../../astrid-storage-performance.md`](../../astrid-storage-performance.md).
This directory contains evidence only:

- selected `astrid-storage-io-benchmark-v1` historical JSON outputs with raw
  nanosecond samples and complete workload configuration;
- `astrid-storage-io-benchmark-v2` evidence envelopes for canonical runs. Each
  envelope binds the exact Git revision, clean/dirty tree state, executable
  argument vector, executable bytes, cache policy, and measured payload with
  SHA-256; and
- focused probe transcripts whose headers pin the compared revisions, command,
  host, and workload; and
- `SHA256SUMS`, which fixes the imported result bytes.

Any result named `contiguous` or `LooseBlob` below is an archived pre-release
experiment. It describes code that never shipped and must not be used as a
runtime or performance contract. Current content publication uses packed arena
ingest (`put_streaming_batch`); recovery rejects legacy contiguous metadata.

The `94e7cea7` main, `d6bc3d06`/`0d5a42b3`/`603d260b`
physical-catalogue, and `ce756e1e` dense-radix envelopes form one lineage. They
establish the pre-change baseline, expose the initial physical-metadata
amplification, measure final-node-only batch admission, and finish with the
audited work-conserving and denser canonical implementations under an
otherwise identical workload.

## Current headline result

Clean commit `ce756e1e` used a deterministic 512 MiB incompressible corpus,
three samples, one-MiB read ranges, four principals, and a governed one-GiB
object cache on an M2 Ultra/APFS host.

| Operation | Median result | Same-run context |
|---|---:|---|
| Astrid staging write | 4,443.2 MiB/s | native-speed acknowledgement path |
| Astrid warm verified read | 1,778.5 MiB/s | 0.898× native BLAKE3-verified elapsed |
| Unique publication | 179.5 MiB/s | 1.013715 authoritative/logical bytes |
| Duplicate publication | 256.5 MiB/s | 18,032 authoritative bytes for 512 MiB |
| Four-principal shared publication | 380.9 MiB/s | 2.122× single-principal throughput |
| Four-principal warm verified read | 6,285.1 MiB/s | 3.534× single-principal throughput |
| Populated reopen | 1.276 s | dense physical catalogue enabled |
| Direct-catalogue activation | 2.243 s | one-time populated-store migration |

The machine-readable source is
`astrid-storage-dense-radix-ce756e1e.json`. These are engine/substrate
measurements, not mounted-provider results or a compressibility estimate.

## Bulk-ingest and admission checkpoint

Clean commit `0d6a8366` was compared directly with parent `3d61052b` over the
same deterministic 512 MiB incompressible corpus, divided into 128 independently
fingerprinted 4 MiB sources. Each value is the median of three samples with
eight explicitly granted workers and a governed 512 MiB object cache.

| Operation | Parent | Prepared admission |
|---|---:|---:|
| Single-worker first ingest | 2.941 s, 174.1 MiB/s | 2.893 s, 177.0 MiB/s |
| Eight-worker first ingest | 1.961 s, 261.1 MiB/s | 1.415 s, 361.8 MiB/s |
| Worker scaling | 1.500× | 2.044× |
| Duplicate publication | 2.027 s, 252.6 MiB/s | 2.077 s, 246.5 MiB/s |
| Four-principal shared publication | 390.5 MiB/s | 390.6 MiB/s |

Preparing frame checksums and direct physical identities before entering the
single-appender critical section raises eight-worker throughput 38.6% without
changing single-worker or dedup throughput materially. A cheap authoritative
probe comes first, so an all-dedup batch never performs that preparation.
Vectored append avoids rebuilding all prepared frames into another contiguous
buffer, while preserving the frozen frame bytes exactly.

The earlier `astrid-storage-bulk-ingest-eca9c20a.json` remains the first
delta-proportional source-work record. In both generations, unchanged sources
read zero bytes and a one-file mutation reads only its partition. The new exact
comparison is recorded in `astrid-storage-admission-before-3d61052b.json` and
`astrid-storage-admission-after-0d6a8366.json`.

The next clean checkpoint, `02968196`, was compared with exact parent
`279c9342` using the same corpus and worker grant. Moving the prepared values
through a bounded, engine-bound handoff preserves parallel ingest at 388.3
MiB/s and raises scaling from 2.080 to 2.105 times. Its operator-only phase
matrix records a 250.7 ms pipeline, 163.6 ms of authoritative object admission,
and 1,067.7 ms of root publication, of which 979.1 ms is exact closure
validation. Pending prepared values peak at 4,207,436 bytes with one worker and
a median 58,853,269 bytes with eight workers. The evidence is in
`astrid-storage-pipeline-before-279c9342.json` and
`astrid-storage-pipeline-after-0296819.json`.

The closure-evidence checkpoint at clean commit `a4a492b5` reuses the
identity and complete owning-closure proof earned during authoritative staging.
On the same 512 MiB corpus, eight-worker publication rises from 388.3 to
1,251.0 MiB/s (3.22 times), and single-worker publication rises from 184.5 to
268.4 MiB/s. Root publication falls from 1,067.7 to 90.8 ms because exact
closure validation falls from 979.1 ms to 0.146 ms. Physical-map work remains
essentially flat at 78.0 ms versus 74.5 ms, so the removed work was not shifted
to another publication phase. Median eight-worker pending memory rises from
58,853,269 to 67,303,811 bytes and remains bounded by the configured worker
window. The evidence is in
`astrid-storage-closure-after-a4a492b.json`.

## Archived contiguous-adoption artifacts

The contiguous-adoption checkpoint at clean commit `da8e3cd0` keeps the sealed
staging generation as the retry witness and publishes a verified whole-file
representation. Unique publication reaches 271.3 MiB/s and appends 1.000971
authoritative bytes per logical byte. Republishing the same 512 MiB reaches
388.2 MiB/s and appends 8,387 bytes (0.001562%). Eight-worker first ingest
reaches 1,556.4 MiB/s; four-principal shared publication reaches 928.6 MiB/s;
and four-principal warm verified reads reach 6,485.4 MiB/s. Representation
metadata excludes `.blob` payloads and measures 61,042 bytes for the unique
publication. The evidence is in `astrid-storage-contiguous-da8e3cd.json`.

Clean commit `6384aaec` hardens canonical-blob reuse against substituted source
bytes and symlink replacement, then measures the mandatory copy fallback as a
separate workload. The forced fallback copies and verifies the 512 MiB corpus
at 674.7 MiB/s. Unique publication remains 270.4 MiB/s, warm verified reads
reach 1,774.6 MiB/s, and four-principal shared publication reaches 935.8 MiB/s.
Duplicate publication is 295.8 MiB/s because reuse now reads and verifies the
supplied complete preimage instead of trusting an occupied canonical path. The
same run appends 8,387 authoritative bytes for that duplicate. The evidence is
in `astrid-storage-contiguous-6384aae.json`.

The historical schema did not embed Git revision, executable arguments,
dirty-tree state, or cache policy. The canonical document records reconstructed
ancestry and explicitly prevents independent experiment branches from being
presented as one integrated result. Format v2 carries that provenance in the
report itself. Its `payload_digest` is SHA-256 over the exact UTF-8 bytes in
`payload_json`. The decoded `payload` object is a convenience copy and must be
semantically equal to parsing `payload_json`; either mismatch invalidates the
artifact. This avoids relying on a second JSON implementation to reproduce
floating-point spellings. Derived medians, rates, comparisons, and
amplification ratios in the archived files were recalculated from the unchanged
raw samples after the even-sample median rule was corrected to average both
central observations.
