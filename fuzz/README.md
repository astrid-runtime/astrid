# Astrid fuzz targets

This package holds coverage-guided fuzz targets for Astrid. It is intentionally
excluded from the root Cargo workspace so normal workspace builds do not compile
`libfuzzer-sys`.

`fuzz/Cargo.lock` is intentionally untracked. The root workspace lockfile stays
the release/audit lockfile; the standalone fuzz package resolves its own
tooling dependencies when fuzz targets are run.

## Running

Install `cargo-fuzz`, then run targets from the repository root:

```sh
cargo fuzz run ip_blockset
cargo fuzz run topic_patterns
cargo fuzz run crypto_wire
cargo fuzz run admin_json
cargo fuzz run config_toml
cargo fuzz run capability_patterns --features capabilities-target
cargo fuzz run manifest_toml --features capsule-target
cargo fuzz run gateway_request_json --features gateway-target
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
issue #1084 plus the cheap parser/wire-format targets. `capability_patterns`
is feature-gated because the full `astrid-capabilities` crate pulls storage
dependencies, `manifest_toml` and `ssrf_helpers` are feature-gated because they
compile the Wasmtime-backed `astrid-capsule` crate, and
`gateway_request_json` is feature-gated because it pulls the HTTP gateway
dependency graph. Archive, admin-state, full HTTP boundary, CLI, and Wasm/WIT
targets should be added in follow-up slices.
