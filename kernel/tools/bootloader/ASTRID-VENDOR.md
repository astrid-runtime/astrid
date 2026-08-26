# Bootloader fixture vendor

This directory is a minimal, local copy of the upstream `bootloader` 0.11.16
UEFI workspace (`api`, `common/config`, `common`, and `uefi`). The upstream
MIT/Apache-2.0 notices are retained in this directory. BIOS stages and the
upstream test kernels are intentionally not vendored because this workspace
builds the explicit UEFI/QEMU fixture only.

Astrid changes are limited to the fixed pre-relocation policy-handoff check,
the bounded `BootInfo` verification receipt, and the UEFI-to-common handoff of
the loaded ramdisk bytes. The loader receives only public verification keys;
fixture signing material remains in the host-side `kimage` invocation. The
vendored build script selects curve25519's equivalent serial backend for the
nested `x86_64-unknown-uefi` image on every host, avoiding a known pinned
nightly LLVM SIMD codegen failure (including native x86_64 builds). This is a
compile choice, not a cryptography, timing, or performance claim.
`kimage --tamper-handoff` is a
test-only signed-envelope mutation used by the QEMU fail-before-entry check.
