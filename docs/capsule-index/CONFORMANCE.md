# Capsule Index protocol and conformance contract

Status: normative contract, protocol revision `1`.

This document is the implementation-neutral contract for an Astrid Capsule
Index.  Astrid, AOS, and a third-party Index may implement the protocol
independently.  A client MUST treat an Index as a configured trust domain; the
protocol does not imply that one Index is authoritative for another.

The JSON vectors in `tests/capsule-index/conformance/fixtures/` exercise the
rules below.  `scripts/capsule_index_conformance.py` checks the structural and
state-machine rules.  Signature verification, key rotation, and threshold
policy remain the responsibility of the implementation's TUF library; the
vectors deliberately contain no invented signatures.

## 1. Terminology and scope

* **Index** is a curated, append-only publication log plus its signed static
  metadata.  The official Astrid Index and the AOS Index are different trust
  domains even when they point at the same bytes.
* **Source** is a client configuration for one Index: an immutable `index_id`,
  base URL, and trusted TUF root fingerprint.
* **Coordinate** is `(namespace, capsule, version)`.  The sealed publication
  digest includes `index_id`, and `(index_id, coordinate)` is its scoped
  identity.
* **Publication record** is the immutable description of one accepted capsule
  publication.  A record is never edited or deleted.
* **Event** is an append-only state transition addressed to a publication
  digest.  Events derive lifecycle state; they never rewrite the record.
* **Mirror** is an additional byte locator for the exact artifact digest.  A
  mirror event cannot replace, mutate, or introduce an artifact.
* **Publisher authority** is the authority to declare the requested manifest,
  WIT, dependencies, provenance, and capabilities.  **Local capability
  authority** is the installing operator's policy; it may deny a publisher
  request, but it may not grant a capability absent from the record.

The protocol is content-addressed.  A GitHub Release URL, Pages URL, commit
URL, or any other locator is transport only; a digest is the identity of the
bytes.

## 2. Names, versions, and digests

`namespace` and capsule `name` are lower-case ASCII names matching
`[a-z][a-z0-9-]{0,62}` and not ending in `-`.  They MUST NOT be empty, contain
`.`, `_`, `/`, `\\`, or an uppercase character.  Names are compared byte-for-byte
after validation; no Unicode or case folding is performed.  An `index_id` is a
lower-case ASCII token whose first byte is alphanumeric and whose remaining
bytes are alphanumeric, `-`, `_`, or `.` (except `.` and `..`).

`version` is canonical SemVer 2.0.0 without build metadata:
`MAJOR.MINOR.PATCH` with optional hyphenated prerelease identifiers.  Numeric
identifiers have no leading zero.  A `+build` suffix is rejected in v1 so every
implementation compares and serializes the same coordinate.

Every tagged digest is lower-case and uses one of `sha256` (64 hex), `sha384`
(96 hex), `sha512` (128 hex), or `blake3` (64 hex).  TUF/root fingerprints use
tagged `sha256`; publication identity uses tagged `blake3`.

## 3. Publication record

A record has exactly these keys (unknown keys are rejected):

```json
{
  "schema": "publication-v1",
  "index_id": "astrid",
  "coordinate": {"namespace": "astrid", "name": "hello"},
  "version": "1.2.3",
  "artifact": {
    "digests": ["sha256:<64 lower-case hex>", "blake3:<64 lower-case hex>"],
    "size": 4096,
    "media_type": "application/vnd.astrid.capsule",
    "locations": ["https://…"]
  },
  "package": {
    "embedded_identity": {
      "coordinate": {"namespace": "astrid", "name": "hello"},
      "version": "1.2.3",
      "package_digest": "blake3:<64 lower-case hex>"
    },
    "manifest_digest": "blake3:<64 lower-case hex>",
    "component_digest": "blake3:<64 lower-case hex>",
    "wit_digest": "blake3:<64 lower-case hex>",
    "capability_digest": "blake3:<64 lower-case hex>",
    "ipc_digest": "blake3:<64 lower-case hex>",
    "runtime_abi_digest": "blake3:<64 lower-case hex>",
    "dependency_digest": "blake3:<64 lower-case hex>",
    "capabilities": ["astrid:read"],
    "dependencies": [{
      "coordinate": {"namespace": "astrid", "name": "dep"},
      "requirement": "*", "optional": false
    }],
    "runtime": {
      "runtime": "wasmtime", "abi": "component-model-0.2",
      "digest": "blake3:<64 lower-case hex>"
    }
  },
  "publisher": {
    "identity": "github:astrid-runtime/hello",
    "signing_key": "blake3:<64 lower-case hex>"
  },
  "source": {
    "repository_url": "https://github.com/org/repo",
    "github_owner_id": 123456,
    "github_repository_id": 987654,
    "commit": "<40 or 64 lower-case hex>",
    "tree": "<40 or 64 lower-case hex>",
    "tag": "v1.2.3",
    "subdirectory": "capsules/hello",
    "source_digest": "blake3:<64 lower-case hex>"
  },
  "provenance": {
    "predicate_type": "https://slsa.dev/provenance/v1",
    "statement_digest": "blake3:<64 lower-case hex>",
    "builder_identity": "https://github.com/org/repo/actions",
    "attestation_identity": "sigstore:rekor:entry-1"
  },
  "metadata": {"channel": "stable"},
  "publication_digest": "blake3:<64 lower-case hex>"
}
```

The artifact locations and repository URL MUST use `https`; credentials,
queries, fragments, percent escapes, ports, and path traversal are not
permitted.  `size` is a non-negative integer.  `digests` is a non-empty,
unique array of tagged digests in the Rust `Digest` order (`sha256`, `sha384`,
`sha512`, `blake3`); locations are unique and sorted by UTF-8 byte order.  The
package fields are the typed `EmbeddedPackageIdentity`, manifest, Component
Model, WIT, capability declaration, effective IPC, runtime/ABI, and dependency
commitments plus their claims arrays.  `runtime_abi_digest` MUST equal
`package.runtime.digest`.  Publisher identity and signing key, source
repository IDs and revision/tree/tag/subdirectory/source digest, metadata, and
provenance/attestation identities are all immutable.

The publication digest is the tagged BLAKE3 digest of the domain-separated,
length-prefixed binary projection of every immutable field, in this exact Rust
order: schema, index ID, coordinate namespace/name, version, artifact
size/media type, sorted locations and digest vector, publisher actor/signing
key, source URL/owner ID/repository ID/commit/tree/tag/optional subdirectory/
source digest, runtime/ABI/digest, embedded identity coordinate/version/
package digest, manifest/component/WIT digests, capability array and its
declaration/effective-IPC digests, runtime/ABI/digest again, dependency edges
and dependency digest, provenance predicate/statement/builder/attestation,
then sorted metadata key/value pairs.
The domain prefix is the UTF-8 bytes
  `astrid:capsule-index:publication:v1\\0`.  Text is length-prefixed by its UTF-8
byte length (little-endian `u64`); digests carry their algorithm tag, byte
length, and raw bytes.  An optional subdirectory is encoded as a one-byte
presence flag followed by text when present; dependency `optional` is one byte
(`0`/`1`).  This is the cross-language canonicalization boundary, not RFC 8785
JSON.  A mirror URL, event actor, or lifecycle reason MUST NOT enter this
projection.

## 4. Same-coordinate and idempotence rules

Within one Index, `(namespace, capsule, version)` is write-once forever:

* The first accepted record reserves the coordinate and its publication
  digest.
* A resubmission with the same canonical immutable projection and digest is an
  idempotent success (`already_published` is not an error).
* A resubmission with any different immutable field, including artifact,
  package, publisher/signing identity, source revision, provenance, or
  locator, is equivocation and MUST be rejected permanently.  There is no
  administrator override and no in-place correction; publish a new version.
* The same coordinate may exist in another Index.  A client MUST scope lookup,
  locks, caches, and events by `index_id`; a matching coordinate in AOS cannot
  satisfy an Astrid source.  The sealed `index_id` inside the record MUST match
  the Index identity in which it is stored.

## 5. Events and lifecycle

`IndexEvent` is the append-only publication body.  Its compatibility wire uses
Serde's externally tagged enum: each body object has exactly one variant key
(`Yank`, `Unyank`, `Deprecate`, `Revoke`, `Tombstone`, `OwnerChange`,
`AddMirror`, `AddAttestation`, or `Annotation`) whose value is that variant's
object.  Every payload carries an `actor` and a `publication` key (`index_id`,
coordinate, and version).

The authoritative v1 wire is `EventEnvelope` (`schema: "event-envelope-v1"`)
with exactly `schema`, `index` (`id` and `trust_root`), `sequence`,
`recorded_at`, `actor`, `authorization` (`actor`, `evidence`,
`signature_digest`), `prior_event_digest`, `body`, and `event_digest`.  `body`
is externally tagged as `{"Publication": <IndexEvent>}` or
`{"NamespaceTransfer": <typed transfer>}`.  Sequence starts at one and is
contiguous; sequence one has no prior digest and later envelopes require one.
`recorded_at` is canonical RFC 3339 UTC, and the envelope actor MUST match the
body actor and authorization actor.  `event_digest` is domain-separated BLAKE3
over the Rust length-prefixed projection with prefix
`astrid:capsule-index:event:v1\\0`; signatures and threshold verification for
`authorization.signature_digest` remain delegated to the Index/TUF layer.
The projection order is schema/index ID/trust-root/sequence/time/actor,
authorization actor/evidence/signature digest, prior-digest presence and value,
then the body discriminator (`publication` or `namespace-transfer`) and the
typed body projection.  Optional strings and keys use a one-byte presence flag;
publication event variant labels are lower-case (`yank`, `add-mirror`, etc.).

The lifecycle variants are:

* `Yank` removes a version from new resolution; an existing lock may continue
  to install it with a warning.
* `Unyank` restores only the original sealed publication and is invalid unless
  the current state is yanked and not revoked/tombstoned.
* `Revoke` blocks new and locked installation.  A forensic override, if an
  implementation exposes one, MUST be explicitly digest-bound and outside
  normal resolution.
* `Deprecate` keeps a version resolvable and carries optional replacement and
  note fields.
* `Tombstone` suppresses ordinary discovery while retaining the minimum
  transparency record.  It is terminal for normal resolution.
* `AddMirror` adds one HTTPS locator for the publication's already sealed
  artifact.  It has no effect on lifecycle or publication identity.
* `OwnerChange`, `AddAttestation`, and `Annotation` are append-only metadata
  events; they do not change the publication digest.

Events after a tombstone are invalid except `AddMirror` needed for retention.
A revoked publication cannot be unrevoked.  Duplicate mirrors or attestations,
retargeted events, and transitions that violate these rules are rejected.  The
derived state is deterministic from the sealed record and the event prefix.
readers MUST NOT infer state from mutable GitHub labels or URLs.  The body
lifecycle rules below apply whether a body is read from a compatibility
array or from an envelope; readers MUST derive state from the verified envelope
prefix and MUST NOT infer it from mutable GitHub labels or URLs.

## 6. TUF roles and freshness

An Index is served as static, sparse Pages content and is treated as an
untrusted mirror.  The client ships a trust root and verifies TUF signatures
and thresholds using its TUF implementation.  The protocol roles are:

* `root`: offline trust anchors and role thresholds; rotation is a signed root
  transition and is never inferred from Pages content.
* `timestamp`: short-lived metadata referring to one exact snapshot version,
  digest, and length.
* `snapshot`: a consistent set of target metadata versions, digests, and
  lengths.
* `targets` (including package-record metadata): signed references to records,
  event logs, and artifact metadata.

Clients MUST reject expired metadata, timestamp/snapshot reference mismatches,
snapshot/targets mismatches, rollback to a version below the last trusted
  version, and a response that mixes generations.  Freshness is checked at the
  caller's current time; conformance fixtures provide `checked_at` so tests are
  deterministic.  The timestamp role's expiry is the anti-freeze boundary.
Signature bytes and cryptographic threshold vectors are intentionally delegated
to the TUF implementation.

## 7. Sparse Pages layout and mirrors

An Index MAY publish only the files needed for lookup.  A conforming sparse
layout is:

```text
<base>/v1/<root-version>.root.json
<base>/v1/timestamp.json
<base>/v1/<snapshot-version>.snapshot.json
<base>/v1/<targets-version>.targets.json
<base>/v1/objects/<algorithm>/<digest-prefix>/<digest>.json
<base>/v1/shards/<identity-shard>.json
<base>/v1/search.json
<base>/v1/<sha256>.<target-path>
```

The signed snapshot/targets objects map coordinates and event shards to
content-addressed objects; a client MUST NOT infer an object from an unsigned
path.  The versioned role filenames and `timestamp.json` are emitted by the
`astrid-index-tool sign-pages` command; `_tuf-input/` is an unsigned, temporary
generation input and MUST NOT be published.  A client obtains the stable
`index_id` and pinned root fingerprint from its configured trust source, not
from an unsigned `index.json`.

Every path component is a validated name, SemVer, or digest.  Clients MUST
reject path traversal, symlinked fixture/content files, and a response that is
not covered by the signed metadata.  Pages/CDN may be stale or eventually
consistent; clients verify the signed snapshot and retry a bounded number of
times.  A successful publish means the merge/append is durable in the Index's
authoritative repository, not that every Pages edge is immediately fresh.

The official Index SHOULD mirror accepted artifact bytes into an
Index-controlled, content-addressed release store.  A mirror is usable only
after an `AddMirror` event for the publication; fetched bytes MUST still match
the sealed digest set, size, and media type.  The event carries only the HTTPS
locator because those immutable claims already live in the record.  Release URLs are locators, never identity.  If an Index does not
mirror a record, it MUST state that historical upstream availability is not
guaranteed.

## 8. Sources, locks, and resolution

A source is:

```json
{
  "index_id": "astrid",
  "base_url": "https://astrid-runtime.github.io/capsules/v1",
  "root_fingerprint": "sha256:<64 lower-case hex>"
}
```

The source's `index_id`, base URL, and root fingerprint are lock-bound.  The
Rust `LockRecord` wire stores exactly `index_id`, `trust_root`, `coordinate`,
`version`, `publication_digest`, `artifact_digests`, `artifact_size`,
`artifact_media_type`, `manifest_digest`,
`component_digest`, `wit_digest`, `capability_digest`, `ipc_digest`,
`runtime_abi_digest`, `dependency_digest`, `provenance_digest`, and
`source_digest`.  These fields bind every artifact and package/source
commitment needed to reproduce the selected bytes; publisher identity and
provenance identity remain available through the publication digest.  Artifact
locations are intentionally absent: they are transport, and effective mirror
locations are derived from signed `AddMirror` state.  A lock is valid only if
every field matches the selected record and trusted root
(`trust_root` is the tagged SHA-256 root fingerprint).  Cache keys include
`index_id` and publication digest.

Resolution is exact within one source: filter that source's records by the
requested SemVer range, omit yanked/revoked/tombstoned records as required by
their lifecycle, and select according to the client's documented SemVer
precedence.  A client MUST NOT silently fall back to another configured source,
merge candidate sets from different sources, or substitute a same-coordinate
record from AOS for Astrid.  Cross-Index fallback requires an explicit user
choice and a new source-bound lock.

## 9. Publisher and local capability authority

The publisher controls the signed record's requested capabilities, manifest,
WIT, dependency graph, provenance, and source commit.  The local operator (or
fleet policy) controls whether those requests are granted in the installation
environment.  Local policy may deny, constrain, or require approval; it MUST
NOT elevate the record or silently rewrite its publication digest.  The kernel
enforces the resulting local grant, while the Index records only publisher
claims.

## 10. Eventual-consistency and failure contract

Readers MUST verify a complete signed generation before using any record.  A
Pages 404, stale generation, timeout, or incomplete shard is a retryable
transport result only when the trusted metadata remains valid; it is never a
reason to use another Index implicitly.  Writers report the authoritative PR/
append result separately from edge propagation.  Implementations SHOULD expose
the observed snapshot version and publication digest so operators can diagnose
stale edges without changing identity.

The conformance runner returns one deterministic JSON result for every fixture.
It bounds fixture size, recursion, file count, subprocess time, and subprocess
output; rejects symlinks and traversal; and reports stable error codes and JSON
paths.  An optional implementation command is invoked with `--json`, receives
one fixture JSON document on stdin, and MUST return `{"accepted": bool}` as a
single JSON object.  The command is advisory to the structural checks and does
not replace TUF cryptographic verification.
