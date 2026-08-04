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

The `94e7cea7` main and `d6bc3d06`/`0d5a42b3` physical-catalogue envelopes are
a paired three-run series. They establish the pre-change baseline, expose the
initial physical-metadata amplification, and measure the final-node-only batch
admission correction under an otherwise identical workload.

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
