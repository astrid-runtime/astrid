# Astrid fuzz targets

This package holds coverage-guided fuzz targets for `core`. It is intentionally
excluded from the root Cargo workspace so normal workspace builds do not compile
`libfuzzer-sys`.

## Running

Install `cargo-fuzz`, then run targets from `core/`:

```sh
cargo fuzz run ip_blockset
cargo fuzz run topic_patterns
cargo fuzz run crypto_wire
cargo fuzz run capability_patterns --features capabilities-target
cargo fuzz run ssrf_helpers --features ssrf-target
```

Short smoke runs are useful before longer campaigns:

```sh
cargo fuzz run topic_patterns -- -runs=10000
```

## Target policy

Fuzz targets should assert Astrid invariants, not only "does not panic":

- malformed input fails closed;
- authorization predicates do not widen;
- CLI and HTTP adapters preserve shared kernel semantics;
- path, archive, and local-egress checks cannot be bypassed by alternate
  encodings;
- every minimized finding gets a deterministic regression test in the owning
  crate.

The default target set covers cheap, deterministic Tier 1 predicates from
issue #1084. `capability_patterns` is feature-gated because the full
`astrid-capabilities` crate pulls storage dependencies, and `ssrf_helpers` is
feature-gated because it compiles the Wasmtime-backed `astrid-capsule` crate.
Parser, archive, admin-state, HTTP, CLI, and Wasm/WIT targets should be added
in follow-up slices.
