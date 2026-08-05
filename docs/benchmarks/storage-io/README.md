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

The `94e7cea7` main and `d6bc3d06`/`0d5a42b3`/`603d260b`
physical-catalogue envelopes are a four-point lineage. They establish the
pre-change baseline, expose the initial physical-metadata amplification,
measure final-node-only batch admission, and finish with the audited work-
conserving implementation under an otherwise identical workload.

## Current headline result

Clean commit `603d260b` used a deterministic 512 MiB incompressible corpus,
three samples, one-MiB read ranges, four principals, and a governed one-GiB
object cache on an M2 Ultra/APFS host.

| Operation | Median result | Same-run context |
|---|---:|---|
| Astrid staging write | 4,734.7 MiB/s | 1.078× native cached-write elapsed |
| Astrid warm verified read | 1,798.5 MiB/s | 0.887× native BLAKE3-verified elapsed |
| Unique publication | 179.1 MiB/s | 1.016492 authoritative/logical bytes |
| Duplicate publication | 258.3 MiB/s | 24,426 authoritative bytes for 512 MiB |
| Four-principal shared publication | 386.3 MiB/s | 2.158× single-principal throughput |
| Four-principal warm verified read | 6,337.0 MiB/s | 3.523× single-principal throughput |
| Populated reopen | 1.368 s | physical catalogue enabled |
| Direct-catalogue activation | 2.328 s | one-time populated-store migration |

The machine-readable source is
`astrid-storage-physical-catalogue-603d260b.json`. These are engine/substrate
measurements, not mounted-provider results or a compressibility estimate.

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
