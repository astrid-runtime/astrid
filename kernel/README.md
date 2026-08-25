# Astrid native-kernel — M1 plus dual-closure stub

Recovered isolated `kernel/` workspace. M1 boots to Rust ring 0 on the
experimental emulator machine, emits structured serial evidence, runs
negative-first self-tests, and halts with a machine-checkable outcome.
This child adds a dual-closure stub: the loader signs a kernel/bootstrap
closure and a distinct empty System Generation as separate artifacts;
ring 0 verifies the table and binds the measured identities.

Ring 0 verifies the table against a compiled emulator-fixture public-key
policy with independent kernel and System Generation floors. The table
cannot choose trust keys or rollback policy. Authenticated loader handoff
is not available: fixture *private* keys stay in `kimage` (`sign` feature).
This is not firmware root of trust and not self-measurement.

This workspace is isolated from `crates/astrid-kernel`. Nested
`[workspace]` membership keeps core CI from ingesting these crates.

## Citation (do not rename)

Quote architecture freeze `ad3162492c47515f83f3e5230c9cec4d3b269ccd`.
Do not invent a TCG-named machine:

- One experimental machine-contract fixture is x86-64 QEMU/KVM with
  UEFI, fixed memory, one CPU, serial diagnostics, APIC timer, and an
  explicit virtio/IOMMU topology.
- QEMU, TCG, and KVM runs establish only the named emulator
  machine-contract enforcement boundary. They are functional and
  conformance evidence for that emulator contract.
- They never establish bare-metal, no-host, or hypervisor machine
  authority, DMA containment against a malicious hypervisor, or
  physical-machine ownership. Standalone machine-authority claims are
  reserved for named physical board, firmware, and device evidence.
- First-owner remains section 14.5 and is not the Stage B emulator gate.

M1 evidence class is **TCG** (`-accel tcg`). This child does not select
KVM, virtio, or IOMMU, and therefore does not prove that topology.

## Layout

- `crates/astrid-native-closure/` — `#![no_std]` dual-closure codec,
  external `TrustedPolicy`, ramdisk region validator, verify, and
  loader-only signing.
- `crates/astrid-native-kernel/` — `#![no_std] #![no_main]` ring-0 binary.
- `tools/kimage/` — wraps a kernel ELF into a bootable UEFI disk image
  and embeds the dual-closure table as a bootloader ramdisk (memory
  table, not a guest filesystem).
- `tools/ktest/` — QEMU serial-assertion harness and host unit tests.

## Run

```
./run.sh            # or: cargo run -p ktest --release
```

The harness builds the kernel, builds the UEFI image twice (determinism
measurement), boots QEMU (`q35`, explicit `tcg`, UEFI pflash, 1 CPU,
256 MiB, COM1, `-display none`, `isa-debug-exit`), captures JSONL serial,
and asserts one combined serial sequence (boot, both closure
identities/floors, bound, M1 milestones, halt). QEMU is killed after two
minutes.

Firmware discovery used on this host: executable-relative QEMU share,
package prefixes (Homebrew is one), well-known OVMF paths, and env
overrides. QEMU 11.0.2 does **not** support `-print-datadir`; ktest
probes that flag only when the binary accepts it. This run does not
claim datadir portability. Override with:

- `ASTRID_QEMU_FIRMWARE_CODE` and `ASTRID_QEMU_FIRMWARE_VARS`
- `ASTRID_QEMU_FIRMWARE_DIR`

`kimage` still needs a nightly toolchain because bootloader 0.11 runs
`-Zbuild-std`. The supported channel is the dated pin `nightly-2026-07-21`
(rustc 1.99.0-nightly `87e5904f5`, 2026-07-20). Override with
`KTEST_TOOLCHAIN`. Floating `nightly` is not CI evidence: GitHub rolling
nightly failed to link bootloader 0.11.16's nested `x86_64-unknown-uefi`
build (`undefined symbol: wcslen`). The ring-0 kernel stays on stable
1.95.0. Do not run `cargo clippy --workspace` on stable; that fails here
because bootloader 0.11 requires nightly `-Zbuild-std`. Use `./check.sh`
for the supported split checks.

kimage host artifacts go in `target/kimage-host`. Nested bootloader
`cargo install` uses `target/bootloader-nested` via `CARGO_TARGET_DIR`.
Those directories are distinct so the nested install cannot deadlock on
the parent target lock.

## What is asserted

- `seq` values are contiguous and strictly increasing from 0.
- required events appear exactly once.
- `boot.entry` is the first kernel event.
- combined order: `boot.entry`, `idt.ready`, `closure.kernel`,
  `closure.sysgen`, `closure.bound`, `mem.map`, `paging.wx`,
  `heap.ready`, `halt`.
- GDT/IDT are installed before any ramdisk copy.
- `halt` is terminal (`halt` is the last event).
- `paging.wx` reports `rodata_nx_w=false`, `text_w=false`.
- at least 8 `apic.timer.tick` events.
- exactly one `test.pass` for `int3_handled`, `wx_rodata_write`,
  `nx_data_exec`, `heap_exhaustion`, `frame_unique`, `frame_exhaustion`.
- any `test.fail` fails the run, including unknown names such as
  `future_gate`.
- `halt` with `outcome:"ok"` and QEMU exit code 33.
- host `verify_table(bytes, TrustedPolicy::emulator_fixture())` accepts
  the ramdisk table. Serial `closure.kernel` / `closure.sysgen` /
  `closure.bound` carry independent `kernel_floor` and `sysgen_floor`
  and match the measured ELF identity and the empty System Generation
  identity.
- `verify_table` rejects arbitrary self-signed keys, a lowered mutable
  header floor used to admit stale artifacts, independently stale kernel
  or sysgen, swapped keys/artifacts, and missing/truncated/unmapped
  regions (host unit tests).

## What is NOT claimed

No KVM, virtio/IOMMU, DMA, bare-metal/no-host, physical ownership, A/B
persistence, first-owner, services, Wasmtime, filesystem, Linux, or
Hermes claim. Timing is not evidence. Image determinism is reported
honestly: `DETERMINISM: FAIL` does not fail boot assertions and is not
coerced to PASS.

Ring 0 compiles emulator-fixture **public** keys and `CURRENT_FLOOR` as
independent minima. Fixture **private** keys are host-only (`kimage`,
`feature = "sign"`) and are not present in ring 0. This child does
**not** prove firmware authenticated the loader, does not prove ring 0
re-hashed the in-memory kernel image, and does not claim a firmware root
of trust or self-measurement. Dual-closure here is a distinct pair of
signed artifacts plus identity binding against an external policy, not a
supported machine or an owner ceremony. Table header keys and
`min_floor` are untrusted advertisements.

## Checks

`./check.sh` is the supported host sequence. It does **not** run
`cargo clippy --workspace`.

- stable `astrid-native-closure`: `cargo test -p astrid-native-closure --locked`,
  host `cargo clippy -p astrid-native-closure --all-targets --all-features --locked -- -D warnings`,
  and `x86_64-unknown-none` lib clippy (no `--all-targets` on none)
- stable `ktest`: `cargo test -p ktest --locked` and
  `cargo clippy -p ktest --all-targets --locked -- -D warnings`
- stable `astrid-native-kernel` for `x86_64-unknown-none`:
  `cargo clippy -p astrid-native-kernel --target x86_64-unknown-none --locked -- -D warnings`
- pinned nightly `kimage`: `rustup run nightly-2026-07-21 cargo clippy -p kimage --all-targets --locked --target-dir target/kimage-host -- -D warnings`
  with `CARGO_TARGET_DIR=target/bootloader-nested` so nested
  `cargo install -Zbuild-std` cannot deadlock on the parent lock.

`./run.sh` is the QEMU evidence. Image determinism is reported honestly
and remains FAIL.

### CI

The dedicated `.github/workflows/native-kernel.yml` workflow runs for pull
requests targeting `os/universal`. It installs stable 1.95.0 plus
`nightly-2026-07-21`, sets `KTEST_TOOLCHAIN` to that dated pin, and
invokes `./check.sh` plus `./run.sh`. It does not install rolling
`nightly`. Root `ci.yml` still targets `main` and does not ingest this
nested workspace. Do not run `cargo clippy --workspace` here.
`DETERMINISM: FAIL` is reported by the QEMU job and is not a
boot-assertion gate. That job is emulator evidence only and preserves
the non-claims above.

## Toolchain

Pinned to stable Rust 1.95.0. Interrupt handlers use stable naked-function
ISR stubs via `x86_64`'s `Entry::set_handler_addr`.

`x86_64-unknown-none` builds set `curve25519_dalek_backend="serial"` so
ring-0 Ed25519 does not take the x86 SIMD codegen path. That is a compile
choice, not a cryptography or timing claim.
