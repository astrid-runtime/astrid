# Astrid 2026.9.5

Maintenance release following v2026.9.4. Includes the interrupted Wasmtime
instance recovery fix from #2010 (34bfab971cb780815b50ae9a51dc23d6646161d9).
Published tags and artifacts remain immutable.

## Runtime recovery

An exhausted fuel budget, guest trap, epoch deadline, or cancelled call discards
the interrupted guest instance. The next call uses a fresh instance, including
when the pool has a single slot. Successful calls retain their warm instance.
Interrupted guards deny the triggering operation; recovery must not bypass the
guard or continue its dispatcher chain. Recovery does not increase fuel quotas
or guarantee that an over-budget capsule can complete its work.

## Qualification

Run `cargo test --locked -p astrid-capsule --lib
engine::wasm::interruption_tests` on the release source, on Linux and macOS.
The suite covers fuel, epoch expiry, cancellation, guest traps, single-slot
replacement, successful warm reuse, and denial through the real dispatcher.
Also run `bash scripts/ci/test-release-contracts.sh` and the ordinary release CI.

Use matching CLI and daemon binaries. Preserve the six-target release matrix,
immutable signed release metadata and musl extension, macOS signing and
notarization, and existing FSKit certification requirements. AOS must verify
the published metadata and archives before changing its runtime pins.

This is release preparation. It does not authorize a tag, publication, channel
promotion, or a repair of the failed Codewall endpoint. Artifact digests will
come from the actual signed release, not this source preparation.
