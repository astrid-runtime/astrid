# Capsule Index repository conformance fixtures

These trees exercise the host-only `astrid-index-tool` validator.  Release
records are the JSON serialization of a sealed
`astrid_capsule_index::PublicationRecord`; lifecycle records are sealed
`event-envelope-v1` values with a contiguous sequence and prior-digest chain.
Unsigned legacy `IndexEvent` values are migration input only and are rejected
in deployable `events/`.  Event files use
`events/{20-digit-sequence}-{64-lowercase-event-digest}.json`; the validator
treats the directory as untrusted input and rejects symlinks, traversal
components, aliases, and files larger than its configured limit.

Each fixture is a complete candidate tree, with `base/` representing the last
accepted merge and the sibling `candidate-*` trees representing one proposed
PR.  The expected diagnostic code is in the fixture directory name:

| fixture | expected result |
| --- | --- |
| `candidate-idempotent` | `idempotent` (same coordinate and publication digest) |
| `candidate-equivocation` | `EQUIVOCATION` |
| `candidate-delete` | `APPEND_ONLY_DELETE` |
| `candidate-alias` | `INVALID_IDENTITY` or `PATH_IDENTITY_MISMATCH` |
| `candidate-stale-event` | `STALE_EVENT_TARGET` (for a sealed envelope; unsigned legacy JSON is `INVALID_EVENT_SCHEMA`) |
| `candidate-cross-index` | `CROSS_INDEX_COLLISION` |
| `candidate-traversal` | `path traversal` repository error |
| `candidate-symlink` | `symlinks are not allowed` repository error |

The actual protocol records are generated in tests rather than copied from a
publisher URL.  This keeps the fixtures independent of mutable release assets
and makes their publication digests reproducible.

The generator's `_tuf-input/` directory is staging-only.  It contains
unsigned target/snapshot inputs and is never a deployable TUF role.  A separate
signer must emit tough's consistent-snapshot roles (`v1/<version>.root.json`,
`v1/timestamp.json`, versioned snapshot, and targets) plus SHA-256-prefixed
target aliases before a Pages tree can be published.
