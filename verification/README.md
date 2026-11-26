# Hosted Astrid verification

The [hosted security contract](hosted-security-contract.md) defines the full authority claim, identifies production entry points and records the outstanding refinement obligations.

For hosted guest KV, Verus checks owner selection, root transition bytes, the WAL record position and body, and publication bookkeeping. The production scanner checks a record's active transaction sequence and ordinal before dispatch. The recovery proof checks the marker's canonical bytes against the observed counters and digest. A matching marker releases exactly the collected descriptors, while a torn tail releases none. On a stable byte image the verification loop follows frame boundaries through Commit and derives its counts and digest input from those bytes. The live dispatch loop in `wal/scan.rs` remains outside the verifier. Its agreement with the verified loop is a refinement obligation. The production buffer loop assembles short reads, checks the filled payload and restores the payload cursor after measuring file length. The host read and seek primitives must implement the stated stable-image contracts. A writer-to-reader theorem produces a Begin, Root and Commit and recovers its Root span when scanning from offset zero with an unrestricted payload limit. The checked map fold encodes the journal before recording the replacement root. Live commit and WAL replay use a checked traversal of the root's owning references. Its result covers new objects and the boundaries of previously validated subgraphs. Indexed arena reads check that the embedded digest and the computed identity of the returned record both match the requested name. The header and payload helpers used by the frame codec separately preserve the object kind, format version, accounting class, logical size, canonical bytes, reference count and first reference position. Unsealed and foreign transactions must check every supplied identity. Only a matching engine seal can carry a KV checkpoint into publication. Duplicate declarations in the incoming map must agree. The checked lookup prefers incoming records over the pending WAL overlay and the arena index. The worklist consumes the concrete reference target decoded from the wire. Proving record construction, map provenance and cache validity remains open, alongside physical reads, crash recovery and caller receipts.

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

## Durable guest KV addresses

The verifier checks two stages of durable point addressing. The namespace selector
returns the admitted UID exactly when the requested namespace and observed UID
match the binding. The production entry encoder appends a zero byte and the
complete key to the namespace bytes. Its injectivity theorem shows two distinct
namespace/key pairs cannot share an entry address when both namespaces exclude
zero bytes, as required by the tree adapter. The proof applies equally to
non-ASCII UTF-8 and keys of different lengths.

For listing and deletion, the tree adapter uses that same encoder for the
inclusive lower bound. The verified upper-bound constructor increments the
last byte with a successor and discards trailing maximal bytes. The separator
always has a successor, including for an empty prefix. The interval theorem
uses unsigned lexicographic byte order and proves membership in both directions
for every encoded entry in a validated namespace. Checkpoint leaf selection, branch pruning and the two overlay iterator
comparisons now use a production comparator verified against that byte order.
A child containing any requested key between its declared fences must pass
the checked pruning decision, including the final child with no upper fence.
The point lookup used to suppress superseded checkpoint entries is checked on
the actual immutable overlay nodes. For a strictly ordered overlay, it returns
the stored value or explicit deletion marker for the requested key exactly
when that entry occurs anywhere in the tree. A missing key returns no entry.
The default overlay has an empty root. Its production insertion function now
proves that an ordered root stays ordered, including both rebalancing rotations.
For every query key, lookup on the new root returns the supplied value or
explicit tombstone for the written key and preserves the old result for every
other key. The proof concerns logical contents and ordering. Checkpoint decoding,
the declared child fences and full range traversal remain open. Applying the resulting deletion
replacements and publishing their new root remain open obligations.

The synchronous Wasmtime KV host call holds its operation guard across semaphore
acquisition and the backend future. On the native tree write path that future
waits for the blocking worker. The address theorem covers the bytes passed to
storage. Establishing when a mutation becomes visible relative to retirement,
cancellation or restart still requires a proof of the surrounding execution.

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

## Durable token authority and restart

Verus checks the token status functions used by the capability store. Any
revocation marker denies admission. A consumption marker denies single-use
admission. A consume attempt succeeds only for a live unused token and a
winning persistence result. Recovery folds the durable markers for the same
token ID through monotone transitions. The replay lemma proves that an
arbitrary order or duplication of records preserves each observed marker.

The adapter orders final admission and revocation using one authority lock.
The live revocation fence closes before persistence. If persistence fails or
the task is canceled, the live fence stays closed. An acknowledged durable
revocation survives restart, even if physical token cleanup is incomplete.
Previously admitted operations can finish. Single-use consumption uses a
durable insert-if-absent, so retry after an ambiguous or canceled write cannot
win a second CAS.

Startup loads both marker namespaces before exposing the store. Verus checks the two-element recovery schedule, the exact namespace used for each marker kind, and preservation of the supplied token key when constructing the write address. UUID formatting and parsing and complete enumeration by the backend remain assumptions. It also uses
the authoritative ownership snapshot to restore capability and allowance
fences for pending principal deletions. The authenticated kernel and admin
IPC preambles check those fences. Principal derivation checks under the
same management write lock as deletion. Invite and device redemption use
their own durable reservation paths. A kernel regression exits a subprocess
without calling shutdown, reopens the hosted backend, and checks revocation,
single use, incomplete principal retirement, and a live control token.

The token proof assumes one active capability-store authority per hosted
instance, correctly keyed complete storage reads, and the hosted backend's
atomic and durable CAS contract. Operation binding is checked on the actual
signed token admitted by the MCP adapter. The proof covers the token state
transitions and marker fold. It does not establish the cryptographic verifier,
storage engine crash model, distributed revocation, or complete mediation of
every hosted effect.

## Authority model

`hosted_authority_model.rs` is the specification side of the security contract.
A trace follows one grant through the transitions that change who may act
under it, the operations of one principal's tracker, or the fuel charged to
one principal under a fixed budget. Verus checks a theorem about every trace
of each kind:

- Once a revocation's durable write completed, the grant stays revoked for the
  rest of the trace, across retries and restarts, which closes every admission
  under it.
- A single-use grant admits at most one consumption in a trace.
- Once a consumption's durable write completed, the grant stays consumed for
  the rest of the trace, which closes single-use admission under it.
- A revocation keeps the grant revoked until the next recovery, whether or
  not its durable write completed, which closes every admission under it
  until then. A checked witness shows that a recovery which reads no marker
  for the grant reopens one whose write did not complete. That is the
  boundary of the restart guarantee.
- After retirement, a principal admits no operation until a resume that
  follows the retirement. Each engine instance has its own tracker.
- Charged and promised fuel never exceed the budget by more than the fuel that
  settlements charged beyond what they released. When no settlement charges
  beyond what it released, committed fuel stays within the budget.

The theorems are conditional on obligations the model cannot observe:

- Recovery reads every marker whose write completed earlier. Durable markers
  are only ever added, so the storage adapter must report them completely.
- The caller resumes a retired principal only once the kernel's retirement of
  that principal has ended.
- A settlement releases no more fuel than was promised. Production does not
  bound the fuel it charges: a metered call can consume more than it was
  promised before the meter traps at its next hook, and the settlement charges
  all of it. The fuel theorem bounds that overshoot by the excess charged.
  The within-budget statement holds only when no settlement charges beyond
  its promise.
- Rolling the window drops charged fuel and keeps promises, which the model's
  roll transition expresses.
- The budget is fixed along a trace. Production resolves it per call, so a
  decrease while promises are outstanding is outside the model.
- A zero budget means unlimited. Admission is exempt and settlement still
  charges the observed fuel to the window. Both are outside the model.
- The trace applies transitions one at a time. Production serializes each
  principal's fuel transitions with its window lock: `try_reserve` holds it
  from the admission check through the reservation, and settlement holds it
  across its load, arithmetic and store.
- `FuelRateLimiter::record` charges the window with no reservation. The
  hosted invocation path settles a reservation instead. `record` has no
  production caller there and is outside the model.

Production calls the transitions directly. Each carries the verified
postcondition that the `apply_*` and `fuel_*` functions restate in the model's
terms. Those functions record the grant and tracker transitions, decide
admission and compute settlement, and do not update the limiter's counters.
Startup replays each token's markers through
the verified `TokenStatus::recover_markers`. The store's `revoke`, `consume`,
`is_available` and `use_checked` adapters, and the limiter's window and
reservation counters, remain the unverified callers of these transitions.

Run `python3 scripts/verification_defect_checks.py` with the pinned verifier on
the path. It applies deliberate defects to a scratch copy and fails unless the
verifier reports an error at the expected source path. Weakening a callback
binding must fail in its trace consumer. Ordinary implementation mutations
must fail in the edited file. One defect puts a false
assertion at the start of every listed theorem, consumer and witness, which
shows that body is checked. The others edit the production transitions, every
bridge and the conditions of the proofs. Consumers derive reusable denial from
the two revocation theorems and the consumed component over its whole range
from the consumption theorem, so narrowing any of the three back to
single-use denial fails a check. CI runs it after the main check.

A defect check cannot detect a statement that is weakened but still true
unless a listed proof derives its conclusion from the stronger statement.
`retirement_closes_after_an_earlier_resume` derives its conclusion from the
retirement theorem on an abstract trace, so restoring the earlier vacuous
condition of that theorem fails a check. The two revocation consumers are the
same guard for the revocation theorems, and the two consumption consumers
are that guard for the consumption theorem's component and its first index.
