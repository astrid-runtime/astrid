# Astrid native-kernel — M1

Recovered isolated `kernel/` workspace. M1 boots to Rust ring 0 on the
experimental emulator machine, emits structured serial evidence, runs
negative-first self-tests, and halts with a machine-checkable outcome.

This workspace is isolated from `crates/astrid-kernel`. Nested
`[workspace]` membership keeps core CI from ingesting these crates.

## Citation (do not rename)

Quote the architecture freeze; do not invent a TCG-named machine:

- Experimental contract: x86-64 QEMU/KVM with UEFI, fixed memory, one CPU,
  serial diagnostics, APIC timer, and an explicit virtio/IOMMU topology.
- QEMU, TCG, and KVM runs establish only the named emulator
  machine-contract enforcement boundary. They are functional and
  conformance evidence for that emulator contract.
- They never establish bare-metal, no-host, or hypervisor machine
  authority, DMA containment against a malicious hypervisor, or
  physical-machine ownership.
- First-owner remains unresolved and is not an M1 gate.

M1 evidence class is **TCG** (`-accel tcg`). This child does not select
KVM, virtio, or IOMMU, and therefore does not prove that topology.

## Layout

- `crates/astrid-native-kernel/` — `#![no_std] #![no_main]` ring-0 binary.
- `tools/kimage/` — wraps a kernel ELF into a bootable UEFI disk image.
- `tools/ktest/` — QEMU serial-assertion harness and host unit tests.

## Run

```
./run.sh            # or: cargo run -p ktest --release
```

The harness builds the kernel, builds the UEFI image twice (determinism
measurement), boots QEMU (`q35`, explicit `tcg`, UEFI pflash, 1 CPU,
256 MiB, COM1, `-display none`, `isa-debug-exit`), captures JSONL serial,
and asserts M1 evidence. QEMU is killed after two minutes.

Firmware discovery used on this host: executable-relative QEMU share,
package prefixes (Homebrew is one), well-known OVMF paths, and env
overrides. QEMU 11.0.2 does **not** support `-print-datadir`; ktest
probes that flag only when the binary accepts it. This run does not
claim datadir portability. Override with:

- `ASTRID_QEMU_FIRMWARE_CODE` and `ASTRID_QEMU_FIRMWARE_VARS`
- `ASTRID_QEMU_FIRMWARE_DIR`

`kimage` still needs a nightly toolchain because bootloader 0.11 runs
`-Zbuild-std`. Override with `KTEST_TOOLCHAIN`. The ring-0 kernel stays
on stable 1.95.0. Do not run `cargo clippy --workspace` on stable; that
fails here because bootloader 0.11 requires nightly `-Zbuild-std`.
Use `./check.sh` for the supported split checks.

kimage host artifacts go in `target/kimage-host`. Nested bootloader
`cargo install` uses `target/bootloader-nested` via `CARGO_TARGET_DIR`.
Those directories are distinct so the nested install cannot deadlock on
the parent target lock.

## What is asserted

- `seq` values are contiguous and strictly increasing from 0.
- required M1 events appear exactly once.
- `boot.entry` is the first kernel event.
- `mem.map`, `paging.wx`, `heap.ready`, `idt.ready`, `halt` appear in
  order.
- `halt` is terminal (`halt` is the last event).
- `paging.wx` reports `rodata_nx_w=false`, `text_w=false`.
- at least 8 `apic.timer.tick` events.
- exactly one `test.pass` for `int3_handled`, `wx_rodata_write`,
  `nx_data_exec`, `heap_exhaustion`, `frame_unique`, `frame_exhaustion`.
- any `test.fail` fails the run, including unknown names such as
  `future_gate`.
- `halt` with `outcome:"ok"` and QEMU exit code 33.

## What is NOT claimed

No KVM, virtio/IOMMU, DMA, bare-metal/no-host, physical ownership,
dual-closure, A/B, first-owner, Wasmtime, filesystem, Linux, or Hermes
claim. Timing is not evidence. Image determinism is reported honestly:
`DETERMINISM: FAIL` does not fail boot assertions and is not coerced to
PASS.

## Checks

`./check.sh` is the supported host sequence. It does **not** run
`cargo clippy --workspace`.

- stable `ktest`: `cargo test -p ktest --locked` and
  `cargo clippy -p ktest --all-targets --locked -- -D warnings`
- stable `astrid-native-kernel` for `x86_64-unknown-none`:
  `cargo clippy -p astrid-native-kernel --target x86_64-unknown-none --locked -- -D warnings`
- nightly `kimage`: `rustup run nightly cargo clippy -p kimage --all-targets --locked --target-dir target/kimage-host -- -D warnings`
  with `CARGO_TARGET_DIR=target/bootloader-nested` so nested
  `cargo install -Zbuild-std` cannot deadlock on the parent lock.

`./run.sh` is the QEMU evidence. Image determinism is reported honestly
and remains FAIL.

## Toolchain

Pinned to stable Rust 1.95.0. Interrupt handlers use stable naked-function
ISR stubs via `x86_64`'s `Entry::set_handler_addr`.
