# PIO/IDE journal media evidence

Isolated q35 evidence harness for a dedicated second raw disk attached with
`isa-ide` + `ide-hd`. It is not product selector wiring, not a durable native
kernel medium claim, and not a ServiceDriver.

The guest uses ATA PIO (`READ/WRITE SECTORS EXT` plus `FLUSH CACHE EXT`) to
store a padded 4736-byte `ASTRABJ2` payload and a keyed HMAC-SHA-256 commit
sector (`PIOJAUT2`). The commit MAC binds the raw ATA IDENTIFY serial, the
complete padded layout, commit metadata, and the fixture key. Recovery is
fail-closed: a serial mismatch, forged frame, invalid metadata, wrong size,
pending or invalid commit, or frames without a matching commit is never a
candidate.

## Run

```sh
cargo fmt --all --check
cargo test -p pio-media-host --locked
cargo +1.95.0 build -p pio-media-guest --profile guest --target x86_64-unknown-uefi --locked
cargo +1.95.0 build -p pio-media-host --bin build-fat --locked
python3 scripts/run_qemu.py --name onesector
python3 scripts/run_qemu.py --name recover --mode recover --reuse-journal target/qemu-runs/onesector/journal.img
python3 scripts/run_qemu.py --name torn --crash before-commit --kill-after-serial "CRASH-BARRIER BEFORE-COMMIT"
python3 scripts/run_qemu.py --name torn-recover --mode recover --reuse-journal target/qemu-runs/torn/journal.img
python3 scripts/run_matrix.py
```

The QEMU journal disk uses the unique serial `PIO1691-JOURNAL-0001`. The named
matrix records each observed serial and the SHA-256 of the journal image before
and after each run. QEMU artifacts under `target/qemu-runs/` are local evidence
only.

## Claim boundary

This harness is supporting q35/TCG UEFI emulator evidence only. It is not
selector or native-kernel wiring, does not exercise KVM, does not qualify bare
metal or physical power-loss behavior, and does not establish A/B recovery.
Killing the emulator host process with `cache=none` and a guest write cache is
not a physical power-loss oracle.
