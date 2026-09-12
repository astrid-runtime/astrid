# Supervised macOS release certification

The Release workflow builds the signed/notarized Darwin archive, identifies its
SHA-256, then waits at the existing protected `release` environment. No GitHub
runner software runs on the operator's Mac. This is an operator-attested native
test, not a claim that the hosted Linux approval job executed FSKit.

The dedicated clean-Mac workflow remains available for future infrastructure.
This supervised path currently certifies Apple Silicon. It does not assert a
second physical Intel-Mac run. Hosted builds still validate both Darwin archives.

## Before changing the Mac

1. Download **this Release run's** `binary-aarch64-apple-darwin` artifact into
   its own directory and `supervised-fskit-manifest-<attempt>` separately.
   Compare source commit, run ID and attempt with the GitHub run. Do not use a
   rebuilt archive or a preceding prepare run.
2. Validate the staged app's Developer ID, team, version, notarization and
   companion with `macos/validate-macos-fskit.sh` from the extracted archive.
   The local certification script repeats those checks.
3. Inventory existing Astrid mounts, their backing homes and daemon ownership.
   Sync and unmount only explicitly identified mounts during a supervised
   maintenance window. Never run the dedicated runner's blanket cleanup here.
4. Preserve the existing app and companion, including permissions and extended
   attributes, in an operator-owned backup outside the installation destination.
   Record their hashes and the previous extension selection. Preserve backing
   volumes; do not delete application homes or terminate unrelated daemons.
5. Use the archive's manager to update the intended installed app and enable it.
   Its transactional update validates the candidate before replacement. macOS
   may require operator approval. Do not disable Gatekeeper or substitute an
   unsigned app. Keep the explicit backup until restoration or acceptance of
   the new installation has been verified.

The actual app swap is deliberately **not automated** by the certification
script. A separate macOS account does not isolate `/Applications` or FSKit
registration. A failed installation or incomplete restoration stops the
supervised operation and must be reported before proceeding.

## Execute and retain evidence

Run from the exact release source checkout, with Python 3.12 or newer:

The runner checks that HEAD equals the release source and that both certification
Python files match that commit, before execution and before emitting a receipt.
Do not copy or edit a failing runner to obtain a PASS. A diagnostic run with
different assertions is not the canonical certification; changes to acceptance
criteria require review before they can authorize a future release.
This is a local guard against accidental runner drift, not remote execution
attestation: a protected approval is still the operator's statement, and the
hosted receipt verifier cannot prove which program was executed on the Mac.

The native dirty-state assertions remain strict. A desktop may issue background
writes or synchronization between a filesystem operation and a CLI status query.
If those assertions fail, retain the logs and investigate; do not infer corruption
or automatically replace the required result with a different check.

```sh
python3 scripts/certify_fskit_local.py \
  /absolute/archive-directory/astrid-2026.9.0-aarch64-apple-darwin.tar.gz \
  /absolute/manifest-directory/fskit-manifest.json \
  --app /Applications/AstridFS.app
```

The script hashes the archive, safely extracts it, compares every installed app
file's bytes/mode, validates Apple trust and bound provider identity, then tests
a fresh runtime: real `astridfs` mount, write/rename/read, dirty/sync status,
delete/sync, unmount and stop leaving exactly `astrid.volume`. It never installs
or uninstalls an app, changes extension election, or kills foreign processes.
It retains commands, checks and the PASS receipt in the printed `/tmp/fsc.*`
evidence directory. Failure produces no PASS receipt. Preserve that directory.

Restore the previous app/companion and any deliberately paused mounts, or
explicitly accept retaining the tested version. Verify the chosen host state
before approving publication; the native test receipt alone does not certify
restoration of the operator's separate development environment.

## Approve the exact result

Only after the native test passes and the Mac is in the agreed state, paste the
complete `receipt.json` as the protected release approval comment. The gate
requires Joshua's `joshuajbouw` approval for environment `release`, with exact
source, archive hash/name, target, run ID, run attempt, and all required checks
literally `true`. Generic approval, missing checks, different bytes or a stale
attempt fail. Do not manufacture a receipt from a planned test.

The hosted job uploads the accepted receipt to the same Release run and reports
the named certification check. GitHub publication still depends on that check
and retains its existing signature, immutable-release and protected-environment
controls. A new run attempt requires a fresh receipt. Normal publication approval
may be requested separately; it is not permission to skip the local test.
