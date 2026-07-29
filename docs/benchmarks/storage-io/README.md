# Storage I/O raw results

The canonical interpretation, code-state ledger, claim boundaries, and
reproduction contract live in
[`../../astrid-storage-performance.md`](../../astrid-storage-performance.md).
This directory contains evidence only:

- selected `astrid-storage-io-benchmark-v1` JSON outputs with raw nanosecond
  samples and complete workload configuration; and
- `SHA256SUMS`, which fixes the imported result bytes.

The early JSON schema did not embed Git revision, command line, dirty-tree
state, or cache policy. The canonical document records reconstructed ancestry
and explicitly prevents independent experiment branches from being presented
as one integrated result. The next canonical run must embed that provenance in
the report itself. Derived medians, rates, comparisons, and amplification
ratios in the archived files were recalculated from the unchanged raw samples
after the even-sample median rule was corrected to average both central
observations.
