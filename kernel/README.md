# Astrid native-kernel — M1 skeleton

The first executable milestone of the Astrid native kernel: boot to Rust ring 0
on the frozen machine contract, emit structured serial evidence, run
negative-first self-tests, and halt with a machine-checkable outcome.

This workspace is isolated from the surrounding `core/` workspace. It builds the
ring-0 binary for `x86_64-unknown-none` and two host tools.

## Layout

- `crates/astrid-kernel/` — `#![no_std] #![no_main]` ring-0 binary.
- `tools/kimage/` — wraps a kernel ELF into a bootable UEFI disk image.
- `tools/ktest/` — the QEMU serial-assertion harness.

## Run

```
./run.sh            # or: cargo run -p ktest --release
```

The harness builds the kernel, builds the UEFI image twice (determinism check),
boots it under QEMU (`q35`, UEFI/EDK2 pflash, single CPU, 256 MiB, COM1 serial,
`-display none`, `isa-debug-exit`), captures the JSONL serial stream, and
asserts the evidence. QEMU is always run under a 120 s hard timeout and killed by
the harness.

## What is asserted

- `boot.entry` is the first kernel event.
- `mem.map`, `paging.wx`, `heap.ready`, `idt.ready` appear in order.
- `paging.wx` reports the live page tables honestly: `rodata_nx_w=false`,
  `text_w=false` (W^X holds for the kernel image).
- at least 8 `apic.timer.tick` events.
- every self-test emits `test.pass`: `int3_handled`, `wx_rodata_write`,
  `nx_data_exec`, `heap_exhaustion`, `frame_unique`, `frame_exhaustion`.
- final `halt` with `outcome:"ok"` and QEMU exit code 33.

## What is NOT claimed

Per the kernel support policy, this is an **experimental machine** target, not a
supported host. Nothing here is a supported-host claim: no isolation-completeness,
recovery, or stability promise. The host is Apple Silicon, so QEMU runs under TCG
(no KVM) — **timing is not evidence** and no performance number is claimed. The
determinism check is a reported measured-result; image divergence is printed as
`DETERMINISM: FAIL` but does not fail the boot assertions.

## Toolchain

Pinned to stable Rust 1.95.0. Interrupt handlers use stable naked-function ISR
stubs registered via `x86_64`'s `Entry::set_handler_addr`, because the nightly
`extern "x86-interrupt"` ABI is unavailable on the pinned stable toolchain.
