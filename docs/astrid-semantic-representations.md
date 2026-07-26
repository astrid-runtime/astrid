# Astrid Semantic Representations

This document specifies how Astrid may recognize that different exact byte
objects represent the same typed value without confusing equivalence with byte
identity, similarity, authority, or safe interchangeability.

It is a design contract, not an activated capsule interface. The current
principal content store identifies exact canonical object records only. A
future capsule-facing transformation interface changes WIT and therefore
requires an RFC after the interface freeze is lifted.

## The problem

Content-addressed storage recognizes equal bytes. It does not recognize that:

- a PNG and a lossless WebP decode to the same pixels;
- two JSON encodings contain the same value under an agreed number and key
  ordering grammar;
- a tar archive and a directory DAG contain the same entries;
- several model encodings represent the same typed tensors; or
- an installable capsule and a native cache contain the same component.

Treating all of these as unrelated leaves substantial reuse unavailable.
Treating them as equivalent based on an arbitrary transform is worse: it lets
the transform author redefine another principal's content.

Astrid therefore separates four claims:

```text
ObjectId
    Exact canonical object bytes are equal.

SemanticId
    Values are equal under one immutable equivalence contract.

Representation
    Exact encoded bytes represent one SemanticId with stated provenance,
    profile, and trust class.

Similarity
    Values are related under a metric. Similarity never collapses identity.
```

There is no universal canonical form. Equivalence is always scoped to a typed,
versioned contract. Behavioral equivalence of arbitrary programs is
undecidable; a narrower contract such as component-interface equality may be
valid without claiming equal execution.

## Stated adversary: semantic substitution

Mallory controls a principal, source bytes, and a transform that claims to
implement a known contract. Alice has already admitted a private object whose
canonical value is `C`.

If Astrid accepts Mallory's claimed result, Mallory can:

1. choose malicious bytes `M`;
2. claim that `M` canonicalizes to `C`;
3. cause the shared store to bind `M` to Alice's semantic identity; and
4. induce a representation selector to return `M` where Alice requested her
   value.

Hashing the claimed output does not prevent this attack. The security boundary
is the authority to decide which canonical stream follows from an input.
Semantic reuse across principals is permitted only after that decision has
been made by the contract's pinned reference transform.

Even a true equivalence claim does not make every source representation safe
to serve. A crafted image can decode to the expected pixels while exploiting a
bug in a consumer's metadata parser. Untrusted source encodings therefore do
not become globally trusted representations merely because their decoded value
matches.

## Identity construction

An equivalence contract is an immutable canonical object:

```text
EquivalenceContract {
    format_version
    display_name
    input_type
    canonical_output_type
    canonical_stream_grammar
    reference_transform
    reference_transform_closure
    deterministic_runtime_profile
    permitted_imports
    semantic_input_bounds
    optional_proof_verifier
    frozen_specification
    conformance_fixtures
}

ContractId = ObjectId(EquivalenceContract)
```

`display_name`, such as `canonical-image-pixels/v1`, is explanatory. It is not
the identity boundary. `ContractId` binds the complete object, including one
archived reference transform capsule and everything required to run it.

The resulting identity is:

```text
SemanticId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-semantic-identity" ||
        encode(ContractId) ||
        canonical_stream
    )
)
```

Persistent `SemanticId` encodings use the same algorithm-tagged,
variable-digest envelope as persistent `ObjectId` values. The initial
construction may use BLAKE3-256, but the wire representation must admit tagged
384-bit and longer successors.

The contract identifier prevents outputs from two divergent implementations
or contract revisions from occupying one equivalence domain. A changed
reference transform, runtime semantic, input grammar, or canonicalization rule
creates a new `ContractId` and therefore new semantic identities.

The canonical stream may be hashed incrementally and need not be stored as an
uncompressed physical object.

As with `ObjectId`, a digest match is only a candidate equality. Admission must
compare the complete canonical streams before collapsing two bindings. The
comparison may stream both values without buffering them. If the existing
stream is not materialized, Astrid reproduces it through the reference
transform from an authoritative retained representation. A semantic value
whose canonical stream can no longer be reproduced is not admissible as an
authoritative binding.

## What the contract pins

Pinning only the transform's component bytes is insufficient. Its behavior can
also depend on imports, data tables, decoding profiles, or runtime semantics.
The contract therefore binds:

- the installable reference capsule's exact object closure;
- the typed input and canonical-output schemas;
- the deterministic transform-runtime profile and host ABI;
- every permitted host import;
- identity-affecting parameters and semantic acceptance bounds;
- a byte-exact canonical-stream specification;
- adversarial and boundary conformance fixtures; and
- an optional proof verifier and proof grammar.

Reference transforms are pure with respect to identity. They may read the
supplied source and immutable contract closure and may emit a canonical stream,
diagnostics, and execution evidence. They may not observe the clock, random
state, network, mutable principal state, locale, host filesystem, scheduling,
or undeclared environment values.

Operational metering remains deployment policy. Running out of fuel, memory,
or time produces no semantic binding; it never produces a different value.
Contract-defined input and recursion bounds are identity-bearing when they
change which inputs the contract accepts.

## Registration and authority

Possessing or storing an `EquivalenceContract` object does not register it.
Registration is system/operator authority recorded in a signed, auditable
registry outside principal-owned state. A principal or arbitrary capsule
cannot create a store-wide equivalence domain by publishing an object or
advertising a compatible interface.

Registration binds:

- the accepted `ContractId`;
- the authority and authority epoch that admitted it;
- its permitted privacy/deduplication domains;
- whether semantic source retention may ever replace exact-byte retention;
- approved representation producers; and
- revocation or deprecation state.

Contract objects are immutable. Corrections create a new contract and a
separate migration. Recomputing under a successor may record verified lineage
between old and new identities, but never silently rewrites existing
`SemanticId` values.

## Reference transforms and accelerators

Only the pinned reference transform mints a `SemanticId`.

An alternate implementation may propose a canonical result as an optimization,
but its result becomes persistent only after:

1. the reference transform fully reproduces and verifies it; or
2. the alternate supplies a sound proof accepted by the proof verifier pinned
   in the contract.

Spot checks, conformance suites, signatures from the alternate author, and
historical agreement are useful monitoring signals but cannot authorize
identity. One falsely accepted result is sufficient to create a cross-principal
substitution.

This rule does not make accelerators useless. They can reject invalid input
early, prepare candidate encodings, amortize a reference check through a shared
verified cache, or use a contract-defined proof system. If an operator intends
another implementation to be normative without reference verification, it
must register a new contract that pins that implementation.

The reference transform runs as an archived capsule inside Astrid's sandbox.
The kernel meters it, enforces its imports, and records execution evidence; the
kernel does not learn its content semantics. The admission service validates
the result against the registered contract.

## Bindings and representation trust

`EvidenceId` below is the `ObjectId` of an immutable execution-evidence record;
it is notation, not an authority token.

A verified semantic binding records:

```text
SemanticBinding {
    source: ObjectId
    contract: ContractId
    semantic: SemanticId
    reference_execution: EvidenceId
}
```

The binding is rebuildable while its source or an authoritative retained
representation remains. Its evidence may be pinned independently for audit.
Its existence grants no read capability and does not import the source into
another principal's owned closure.

A representation binding additionally records:

```text
RepresentationBinding {
    semantic: SemanticId
    representation: ObjectId | BlobId
    representation_type
    encoding_profile
    producer_transform
    derivation_evidence
    trust_class
}
```

Trust classes distinguish at least:

- **source** — exact caller-supplied bytes, never promoted automatically;
- **verified** — proven to decode to the semantic value, but not necessarily
  safe for arbitrary consumers;
- **sanitized** — emitted by an approved representation producer from verified
  canonical content; and
- **platform** — additionally approved for a named execution or device
  boundary.

Consumers request a typed representation and minimum trust class, not merely a
`SemanticId`. A shared serving pool contains approved derived representations,
not arbitrary cross-principal source bytes. Exact-byte requests always resolve
the requested `ObjectId`.

`SemanticId` is not a capability. Principal-root authority is checked before
semantic lookup, and guest-visible behavior must not reveal whether another
principal already established the same identity. Equality also does not force
physical sharing: protected privacy or erasure domains may store separate
encodings for one semantic identity.

## Retention and accounting

Normalization does not silently discard exact source bytes.

Three retention choices are meaningful:

- exact retention keeps the source `ObjectId`, semantic binding, and any useful
  derived representation;
- semantic retention permits collection of the source only after a sanitized,
  contract-valid representation becomes authoritative and retained; it
  explicitly accepts the contract as the preservation boundary; and
- derived-only cache retains no authority and may be evicted at any time.

`Derived` references remain outside a principal's owned closure because their
targets are rebuildable. That does not make derived storage or computation
free. Shared representations consume an operator-controlled cache budget,
transform execution consumes the principal's compute budget, and admission is
rate-limited. Cache eviction may remove a representation but never an owned
source, the final authoritative representation of semantically retained
content, or an authoritative principal root.

Physical reuse is scoped by the existing deduplication, privacy, encryption,
and erasure policy. Semantic equivalence expands the set of reusable values; it
does not override those policies.

## Portability and longevity

An export that relies on semantic retention contains the registered contract
object, frozen specification, reference transform closure, exact retained
representation, and required derivation evidence. It does not export the
source system's registration authority. A destination may preserve and inspect
the bytes immediately but performs semantic collapse only if local authority
registers the same contract.

Hash or contract migration creates successor semantic identities by rerunning
the successor reference transform. Old-to-new mappings are immutable lineage
or evidence, not identity aliases. The archived reference capsule remains
normative; the plain-text contract specification and fixtures make independent
reimplementation and disaster recovery possible without allowing a new
implementation to redefine existing identities.

## Typed transformation graph

Capsules may eventually advertise typed transformations:

```text
image/jpeg                -> canonical-image-pixels/v1
canonical-image-pixels/v1 -> image/webp;lossless
canonical-image-pixels/v1 -> gpu-texture/bc7
directory-tree/v1         -> archive/tar
archive/tar               -> directory-tree/v1
model/tensors/v1          -> device-model/metal
```

The graph separates route discovery from identity authority:

- any installed transform may advertise a typed edge;
- policy determines whether the edge is eligible for one invocation;
- only a registered contract's reference transform or proof verifier can
  establish semantic identity; and
- only an approved producer can publish a shared trusted representation.

A deterministic planner can initially choose a route by type compatibility,
authority, trust class, loss policy, locality, measured cost, and resource
budget. A later Tensor Logic planner may rank the same typed graph without
changing its authority rules. Learned similarity and route preference remain
advice; neither can mint identity.

Every route has fuel, memory, output-size, fanout, and derivation-depth bounds.
A planner must detect cycles and cannot turn attacker-influenced transform
advertisements into unbounded work.

## Domain examples and limits

### Images

A contract may canonicalize dimensions, orientation, color space, alpha,
sample depth, pixels, and animation timing. Pixel-identical encodings may share
a `SemanticId`. Resized, cropped, or recompressed images with different pixels
remain distinct even when a perceptual metric relates them.

### Structured documents

Canonical JSON requires explicit rules for duplicate keys, numbers, Unicode,
and object ordering. A vague claim that key order is irrelevant is not a
contract.

### Directories and archives

A directory equivalence contract defines path-byte grammar, ordering, modes,
timestamps, symlink treatment, sparse extents, and executable metadata.
Ignoring one field is an explicit semantic choice, not an implementation
shortcut.

### Programs

Astrid does not claim general behavioral equivalence. Honest contracts can
identify narrower values: exact component bytes, a canonical WIT interface,
validated imports/exports, or a reproducible build result under a pinned build
contract. Similar interfaces may be related without declaring executable
substitution safe.

## Required evidence before activation

Implementation is gated on tests that demonstrate:

- a capsule cannot register its own equivalence contract;
- changing any contract field changes `ContractId` and `SemanticId`;
- an alternate transform cannot persist a binding without complete reference
  verification or an accepted proof;
- claimed canonical output substitution is rejected;
- a valid but untrusted source representation is never selected for another
  principal;
- exact-byte lookup never returns a merely equivalent representation;
- a forced semantic-digest collision is detected by canonical-stream
  comparison;
- similarity edges change no identity, authority, retention, or accounting;
- privacy domains can prevent physical sharing without changing semantic
  equality;
- transform failure, timeout, exhaustion, and oversized output create no
  binding;
- cyclic and over-depth routes terminate within declared bounds; and
- derived-cache eviction changes no principal root or authoritative read and
  never removes the final representation of semantically retained content.

The current content DAG remains the exact-byte substrate beneath this design.
Compaction and the persistent object index remain prerequisites before
semantic representations are admitted at heavy-content scale.
