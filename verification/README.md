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
verus --edition=2024 --crate-type=lib --no-cheating verification/hosted_authority.rs
cargo test --locked -p astrid-capsule-types --lib fuel_ledger
```

The proof trusts Verus, its integer primitive specifications and Z3. The
production executable also depends on the normal Rust compilation toolchain.

## Principal lifecycle and IPC

The verifier also checks the per-principal tracker transitions used under the
existing tracker mutex. A retired entry rejects a new operation without changing
its outstanding count. Successful admission increments without overflow. Finish
preserves the retirement state and decrements the count. Resume is explicit,
and the tracker can discard only an open entry with no active operations.

The shared guest publish path acquires the effective invocation principal's
operation guard after the bus capacity wait and keeps it across publication.
The tracker mutex orders admission against principal retirement. A previously
admitted operation can finish while quiescence waits for it. A regression test
exercises the point where retirement has closed the tracker but cancellation
has yet to reach the invocation.

The transition proofs do not certify the tracker adapters, token replacement,
authenticated ingress for forwarded requests, bus implementation, or global
coverage of privileged effects. The cancellation check and adapter tests remain
part of the assurance argument for this path.

## Static capability patterns

Verus checks the production static capability matcher against a segment
specification. A middle wildcard consumes one segment and a trailing wildcard
consumes one or more. Exact segments compare byte for byte. This covers the
shared matcher used for principal and device policy decisions. URI-based
runtime capability tokens use a different matcher.

Scoped device issuance also checks every requested allow pattern for semantic
containment in an issuer allow pattern. Verus proves that a positive containment
decision implies every concrete capability accepted by the child pattern is
accepted by the covering issuer pattern. The pairing adapter still checks the
principal decision and inherits explicit issuer denies. This proof covers the
pattern relation, with the policy adapter, persistence, and use-time checks
remaining separate obligations.
