# Hosted Astrid verification

CI checks the Rust arithmetic called by `FuelRateLimiter::try_reserve` and
`FuelRateLimiter::settle_reserved`. The verifier entry point imports the
production source file directly. Cargo builds that same file on Astrid's normal
toolchain.

For bounded budgets, admission succeeds exactly when spent fuel, outstanding
reservations and the requested amount sum to at most the limit over mathematical
integers. An overflowing machine sum cannot admit a request. Settlement uses
saturating arithmetic. When the reservation exists and actual fuel is at most
the amount released, settlement cannot increase the sum of spent and reserved
fuel. Dropping an unsettled reservation passes its full amount as actual fuel.

The proof covers the two arithmetic functions. The caller is responsible for
serializing each principal's updates, maintaining reservation ownership, rolling
the window and obtaining the actual fuel count. The zero-budget exemption is
handled in the caller. IPC publication, cancellation ordering and restart are
outside these contracts.

Use [Verus 0.2026.11.22.1ce6a59](https://github.com/verus-lang/verus/releases/tag/release%2F0.2026.11.22.1ce6a59)
and its bundled Z3 and standard library. From the repository root:

```sh
rustup toolchain install 1.100.0 --profile minimal
verus --edition=2024 --crate-type=lib --no-cheating verification/fuel_ledger.rs
cargo test --locked -p astrid-capsule-types --lib fuel_ledger
```

The proof trusts Verus, its integer primitive specifications and Z3. The
production executable also depends on the normal Rust compilation toolchain.
