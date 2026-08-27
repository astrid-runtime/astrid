# PIO/IDE journal media evidence

Isolated q35 evidence harness for a dedicated second raw disk attached with
`isa-ide` + `ide-hd`. It is not product selector wiring, not a durable native
kernel medium claim, and not a ServiceDriver.

The guest uses ATA PIO (`READ/WRITE SECTORS EXT` plus `FLUSH CACHE EXT`) to
store a padded 4736-byte `ASTRABJ2` payload and a keyed HMAC-SHA-256 commit
sector (`PIOJAUT2`). Recovery is fail-closed: frames without a matching commit
are torn, never a candidate.

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
```

QEMU artifacts under `target/qemu-runs/` are local evidence only.
