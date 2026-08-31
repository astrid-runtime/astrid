# Astrid native-kernel — M1 plus authenticated handoff fixture

Recovered isolated `kernel/` workspace. M1 boots to Rust ring 0 on the
experimental emulator machine, emits structured serial evidence, runs
negative-first self-tests, and halts with a machine-checkable outcome.
This child adds a fixed 1282-byte loader bundle: a 379-byte `ASTRIDPH`
root-signed policy handoff, a 355-byte `ASTRIDDC` dual-closure table, and a
548-byte canonical signed `ASTRIDSG` descriptor. Ring 0 validates the mapped
ramdisk, copies the descriptor into kernel-owned memory, checks a bounded
receipt produced by the pre-relocation UEFI loader, re-verifies the signed
handoff/table bindings, binds the descriptor identity to those exact copied
bytes, and verifies the manifest against compiled fixture policy inputs. The
loader measures the original `Kernel.elf.input` before writable PT_LOAD
mappings; ring 0 never hashes the mutable `BootInfo::kernel_addr` backing span.

The root verifier is an emulator fixture key with independent minimum
generation/floors; the signed handoff authorizes subordinate keys and keeps
kernel/System Generation floors independent. The table cannot choose trust
keys or rollback policy. Explicit hex key files are required by `kimage`; the
committed files under `tools/kimage/fixtures/` are development-only material
and are never environment defaults. The handoff does not authenticate
firmware or a production loader root.

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

- `crates/astrid-native-closure/` — `#![no_std]` fixed handoff/dual-closure
  codecs, external root/policy inputs, region validator, verify, and
  loader-only signing.
- `crates/astrid-native-kernel/` — `#![no_std] #![no_main]` ring-0 binary.
- `tools/kimage/` — wraps a kernel ELF into a bootable UEFI disk image,
  requires explicit root/kernel/sysgen key files, and embeds the exact
  handoff+table+descriptor bundle as a bootloader ramdisk (not a guest
  filesystem).
- `tools/ktest/` — QEMU serial-assertion harness and host unit tests.
- `tools/bootloader/` — minimal vendored bootloader 0.11.16 UEFI/API/common
  sources with the pre-relocation verification hook and bounded `BootInfo`
  receipt. Upstream MIT/Apache notices are retained; BIOS/test-kernel sources
  are not part of this fixture.

## Run

```
./run.sh            # or: cargo run -p ktest --release
```

The harness builds the kernel, builds the UEFI image twice (determinism
measurement), boots QEMU (`q35`, explicit `tcg`, UEFI pflash, 1 CPU,
256 MiB, COM1, `-display none`, `isa-debug-exit`), captures JSONL serial,
and asserts one combined serial sequence (boot, handoff binding, both closure
identities/floors, bound, M1 milestones, halt). It also boots a deliberately
tampered signed bundle and requires loader rejection before `boot.entry`; that
negative run is killed after a bounded 15-second timeout. Normal QEMU runs are
killed after two minutes.

Firmware discovery used on this host: executable-relative QEMU share,
package prefixes (Homebrew is one), well-known OVMF paths, and env
overrides. QEMU 11.0.2 does **not** support `-print-datadir`; ktest
probes that flag only when the binary accepts it. This run does not
claim datadir portability. Override with:

- `ASTRID_QEMU_FIRMWARE_CODE` and `ASTRID_QEMU_FIRMWARE_VARS`
- `ASTRID_QEMU_FIRMWARE_DIR`

The image builder requires explicit `--root-key`, `--kernel-key`, and
`--sysgen-key` files on every invocation. `ktest` passes the three committed
development fixture files explicitly; no environment secret or implicit
signing fallback is accepted.

`kimage` still needs a nightly toolchain because bootloader 0.11 runs
`-Zbuild-std`. The supported channel is the dated pin `nightly-2026-07-21`
(rustc 1.99.0-nightly `87e5904f5`, 2026-07-20). Override with
`KTEST_TOOLCHAIN`. Floating `nightly` is not CI evidence: GitHub rolling
nightly failed to link bootloader 0.11.16's nested `x86_64-unknown-uefi`
build (`undefined symbol: wcslen`). The ring-0 kernel stays on stable
1.95.0. Do not run `cargo clippy --workspace` on stable; that fails here
because bootloader 0.11 requires nightly `-Zbuild-std`. Use `./check.sh`
for the supported split checks.

`check.sh` inherits Cargo's configured target directory instead of creating a
target per worktree. kimage host artifacts go in `<cargo-target>/kimage-host`.
Nested bootloader `cargo install` uses `<cargo-target>/bootloader-nested` via
`CARGO_TARGET_DIR` and the exact path is passed through
`ASTRID_BOOTLOADER_TARGET_DIR`; the vendored build script never creates a
`tools/bootloader/target` fallback. Those directories are distinct so the
nested install cannot deadlock on the parent target lock. An explicit caller
`CARGO_TARGET_DIR` remains supported when incompatible concurrent builds require
isolation, and direct kimage builds derive the same nested sibling when the
override is absent.

## What is asserted

- `seq` values are contiguous and strictly increasing from 0.
- required events appear exactly once.
- `boot.entry` is the first kernel event.
- combined order: `boot.entry`, `idt.ready`, `handoff.bound`, `closure.kernel`,
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
- host pre-relocation falsifiers reject altered length, root, subordinate key,
  floor, generation, context, kernel digest, and table bytes; receipt falsifiers
  reject forged status/digests/bundle bytes. A deliberate mutation of the raw
  ELF backing after loader verification leaves the receipt acceptance stable.
- host `verify_policy_handoff` accepts the exact handoff against independent
  root/context inputs, then `verify_table` accepts the table using the
  root-authorized subordinate policy. Serial `handoff.bound` carries the
  pre-relocation raw ELF and closure-table measurements. Serial `closure.kernel` /
  `closure.sysgen` / `closure.bound` carry independent `kernel_floor` and `sysgen_floor`
  and match the measured ELF identity and the signed descriptor identity.
- `verify_table` rejects arbitrary self-signed keys, a lowered mutable
  header floor used to admit stale artifacts, independently stale kernel
  or sysgen, swapped keys/artifacts, and missing/truncated/unmapped
  regions (host unit tests).

## What is NOT claimed

No KVM, virtio/IOMMU, DMA, bare-metal/no-host, physical ownership, A/B
persistence, first-owner, services, Wasmtime, filesystem, Linux, or
Hermes claim. Timing is not evidence. Sequential emulator-image
packaging determinism is reported as an independent result:
`DETERMINISM: PASS` does not strengthen boot assertions and is not
coerced into them.

The pre-relocation hook and ring 0 compile only the emulator-fixture **root
public key** and minimum generation/floors. The loader measures the original
raw ELF bytes before writable PT_LOAD mappings; ring 0 checks that signed
evidence and never hashes the relocated image, bootloader, firmware, or
`BootInfo::kernel_addr`. Fixture **private** keys are supplied explicitly to
host-only `kimage` and are not present in ring 0. This child does **not** prove
firmware authenticated the loader, a production root of trust, hardware
self-measurement, or an owner ceremony. Table header keys and `min_floor`
remain untrusted advertisements.

## Checks

`./check.sh` is the supported host sequence. It does **not** run
`cargo clippy --workspace`.

- stable `astrid-native-closure`: default and `--no-default-features` tests,
  no-default `x86_64-unknown-none` check,
  host `cargo clippy -p astrid-native-closure --all-targets --all-features --locked -- -D warnings`,
  and `x86_64-unknown-none` lib clippy (no `--all-targets` on none)
- stable `ktest`: `cargo test -p ktest --locked` and
  `cargo clippy -p ktest --all-targets --locked -- -D warnings`
- stable `astrid-native-kernel` for `x86_64-unknown-none`:
  `cargo clippy -p astrid-native-kernel --target x86_64-unknown-none --locked -- -D warnings`
- pinned nightly `kimage`: `rustup run nightly-2026-07-21 cargo clippy -p kimage --all-targets --locked --target-dir <cargo-target>/kimage-host -- -D warnings`
  with `CARGO_TARGET_DIR=<cargo-target>/bootloader-nested` so nested
  `cargo install -Zbuild-std` cannot deadlock on the parent lock.
- target-layout regression: `./test-shared-cargo-target.sh` exercises an
  external Cargo target root with `CARGO_TARGET_DIR` unset and an explicit
  caller override, then rejects `kernel/target` and
  `tools/bootloader/target` output.

`./run.sh` is the QEMU evidence. Sequential native emulator-image
packaging determinism reports `PASS`.

### CI

The dedicated `.github/workflows/native-kernel.yml` workflow runs for pull
requests targeting `os/universal`. It installs stable 1.95.0 plus
`nightly-2026-07-21`, sets `KTEST_TOOLCHAIN` to that dated pin, and
configures an external shared Cargo target root while leaving
`CARGO_TARGET_DIR` unset, then invokes `./check.sh` plus the target-layout
regression and `./run.sh`. It does not install rolling
`nightly`. Root `ci.yml` still targets `main` and does not ingest this
nested workspace. Do not run `cargo clippy --workspace` here.
The QEMU job reports `DETERMINISM: PASS` for sequential native
emulator-image packaging and does not treat it as a boot-assertion gate.
That job is emulator evidence only and preserves the non-claims above.

## Toolchain

Pinned to stable Rust 1.95.0. Interrupt handlers use stable naked-function
ISR stubs via `x86_64`'s `Entry::set_handler_addr`.

`x86_64-unknown-none`, `aarch64-unknown-none`, and
`riscv64gc-unknown-none-elf` builds set
`curve25519_dalek_backend="serial"`. SIMD cannot activate on the AArch64 and
RISC-V arches; this is a compile choice, not a crypto claim.
