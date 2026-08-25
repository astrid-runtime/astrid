# Astrid Semantic Representations

This document specifies how Astrid may recognize that different exact byte
objects represent the same typed value without confusing equivalence with byte
identity, similarity, authority, or safe interchangeability.

It is a design contract, not an activated capsule interface. The current
principal content store identifies exact canonical object records only. A
future capsule-facing transformation interface changes WIT and therefore
requires an RFC after the interface freeze is lifted.

Deterministic transform invocation, reuse, and maintenance are specified by
[Conservation of Computation](astrid-conservation-of-computation.md),
[Muninn](astrid-muninn.md), and the
[Astrid Refinery](astrid-refinery.md). Those designs consume this contract;
they do not weaken its reference-transform or registration authority.

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
been made by the registered representation decoder and semantic canonicalizer.

Even a true equivalence claim does not make every source representation safe
to serve. A crafted image can decode to the expected pixels while exploiting a
bug in a consumer's metadata parser. Untrusted source encodings therefore do
not become globally trusted representations merely because their decoded value
matches.

## Two contract layers

The semantic domain and the source codec cannot be one contract. If
`canonical-image-pixels/v1` pinned a PNG decoder directly, a WebP decoder would
produce a different contract identifier and the two formats could never
converge. Adding AVIF later would also redefine every image identity.

Astrid therefore uses two immutable contract types.

An equivalence contract defines one stable typed value domain:

```text
EquivalenceContract {
    format_version
    display_name
    canonical_value_type
    canonical_stream_grammar
    reference_canonicalizer
    reference_canonicalizer_closure
    deterministic_runtime_profile
    permitted_imports
    semantic_value_bounds
    optional_proof_verifier
    frozen_specification
    conformance_fixtures
}

SemanticContractId = ObjectId(EquivalenceContract)
```

A representation contract defines how one exact encoding produces a value in
that semantic domain:

```text
RepresentationContract {
    format_version
    source_type
    semantic_contract: SemanticContractId
    decoded_value_type
    reference_decoder
    reference_decoder_closure
    deterministic_runtime_profile
    permitted_imports
    representation_bounds
    optional_proof_verifier
    frozen_specification
    conformance_fixtures
}

RepresentationContractId = ObjectId(RepresentationContract)
```

Display names such as `canonical-image-pixels/v1` and `image/png/v1` are
explanatory. They are not identity boundaries. Each contract identifier binds
the complete canonical object, archived reference capsule, and everything
required to run it.

Admission follows one explicit path:

```text
exact source bytes
    -> pinned representation decoder
    -> typed value stream
    -> pinned semantic canonicalizer
    -> canonical stream
    -> SemanticId
```

The resulting identity contains only the stable semantic contract:

```text
SemanticId = TaggedIdentity(
    algorithm,
    construction_version,
    digest_length,
    H(
        "astrid-semantic-identity" ||
        encode(SemanticContractId) ||
        canonical_stream
    )
)
```

PNG, lossless WebP, and a future codec can therefore converge when their
independently pinned reference decoders produce the same value stream under one
semantic contract. Adding a representation contract does not change an
existing `SemanticId`.

Persistent `SemanticId` encodings use the same algorithm-tagged,
variable-digest envelope as persistent `ObjectId` values. The initial
construction may use BLAKE3-256, but the wire representation must admit tagged
384-bit and longer successors.

Changing the semantic canonicalizer, runtime semantics, typed value grammar, or
canonicalization rule creates a new `SemanticContractId` and new semantic
identities. Correcting one codec creates a new `RepresentationContractId` and
requires its sources to be reverified, but does not change the semantic domain
when the corrected decoder emits the same canonical values.

The canonical stream may be hashed incrementally and need not be stored as an
uncompressed physical object.

As with `ObjectId`, a digest match is only a candidate equality. Admission must
compare the complete canonical streams before collapsing two bindings. The
comparison may stream both values without buffering them. If the existing
stream is not materialized, Astrid reproduces it from an authoritative retained
representation through its pinned decoder and the semantic canonicalizer. A
semantic value whose canonical stream can no longer be reproduced is not
admissible as an authoritative binding.

## What the contracts pin

Pinning only a transform's component bytes is insufficient. Behavior can also
depend on imports, data tables, decoding profiles, or runtime semantics. Each
contract therefore binds:

- the installable reference capsule's exact object closure;
- typed input and output schemas;
- the deterministic transform-runtime profile and host ABI;
- every permitted host import;
- identity-affecting parameters and semantic acceptance bounds;
- a byte-exact specification;
- adversarial and boundary conformance fixtures; and
- an optional proof verifier and proof grammar.

The equivalence contract additionally binds the canonical stream grammar. The
representation contract binds one source encoding to that semantic contract.
An approved encoder is registered as a producer from a semantic contract to a
representation contract; its output is still checked through the pinned
decoder before publication. It is a representation of the same `SemanticId`
only when decoding reproduces the exact canonical value. A transform that
intentionally changes that value creates a new semantic object and a typed
derivation instead.

Reference decoders and canonicalizers are pure with respect to identity. They
may read the supplied source and immutable contract closure and may emit a
typed stream, canonical stream, diagnostics, and execution evidence. They may
not observe the clock, random state, network, mutable principal state, locale,
host filesystem, scheduling, or undeclared environment values.

Operational metering remains deployment policy. Running out of fuel, memory,
or time produces no binding; it never produces a different value.
Contract-defined input and recursion bounds are identity-bearing when they
change which values the contract accepts.

## Registration and authority

Possessing or storing either contract object does not register it.
Registration is system/operator authority recorded in a signed, auditable
registry outside principal-owned state. A principal or arbitrary capsule
cannot create a store-wide equivalence domain or trusted decoder by publishing
an object or advertising a compatible interface.

Registration binds:

- the accepted semantic and representation contract identifiers;
- the authority and authority epoch that admitted them;
- their permitted privacy/deduplication domains;
- whether semantic source retention may ever replace exact-byte retention;
- approved representation producers and their maximum trust classes; and
- revocation or deprecation state.

Contract objects are immutable. Correcting an equivalence contract creates a
new semantic domain and an explicit migration. Correcting a decoder creates a
new representation contract and revalidation path. Recomputing under a
successor may record verified lineage, but never silently rewrites existing
identities or treats two domains as aliases.

## Reference transforms and accelerators

Only the pinned representation decoder and semantic canonicalizer establish a
`SemanticId` binding.

An alternate implementation may propose an intermediate or canonical result,
but its result becomes persistent only after:

1. the relevant pinned reference transform fully reproduces and verifies it;
   or
2. the alternate supplies a sound proof accepted by the proof verifier pinned
   in that contract.

Spot checks, conformance suites, signatures from the alternate author, and
historical agreement are useful monitoring signals but cannot authorize
identity. One falsely accepted result is sufficient to create a cross-principal
substitution.

This rule does not make accelerators useless. They can reject invalid input
early, prepare candidate encodings, amortize a reference check through a shared
verified cache, or use a contract-defined proof system. If an operator intends
another implementation to be normative without reference verification, it
must register a successor contract that pins that implementation.

Reference transforms run as archived capsules inside Astrid's sandbox. The
kernel meters them, enforces their imports, and records execution evidence; the
kernel does not learn their content semantics. The admission service validates
the pipeline against the registered contracts.

## Bindings and representation trust

`EvidenceId` below is the `ObjectId` of an immutable execution-evidence record;
it is notation, not an authority token.

A verified semantic binding records:

```text
SemanticBinding {
    source: ObjectId
    representation_contract: RepresentationContractId
    semantic_contract: SemanticContractId
    semantic: SemanticId
    decoder_execution: EvidenceId
    canonicalizer_execution: EvidenceId
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
    representation_contract: RepresentationContractId
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

An export that relies on semantic retention contains the semantic and
representation contract objects, frozen specifications, reference transform
closures, exact retained representation, and required derivation evidence. It
does not export the source system's registration authority. A destination may
preserve and inspect the bytes immediately but performs semantic collapse only
if local authority registers the same contracts.

Hash or semantic-contract migration creates successor semantic identities by
rerunning the successor pipeline. A representation-contract migration
revalidates affected sources without changing semantic identities when the
canonical values agree. Old-to-new mappings are immutable lineage or evidence,
not identity aliases. Archived reference capsules remain normative; plain-text
specifications and fixtures make independent reimplementation and disaster
recovery possible without allowing a new implementation to redefine existing
identities.

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
- only registered representation and semantic contracts can establish a
  binding through their pinned reference transforms or proof verifiers; and
- only an approved producer can publish a shared trusted representation.

A deterministic planner can initially choose a route by type compatibility,
authority, trust class, loss policy, locality, measured cost, and resource
budget. A later Tensor Logic planner may rank the same typed graph without
changing its authority rules. Learned similarity and route preference remain
advice; neither can mint identity.

Every route has fuel, memory, output-size, fanout, and derivation-depth bounds.
A planner must detect cycles and cannot turn attacker-influenced transform
advertisements into unbounded work.

## Activation and host boundary

The feature is automatic from an agent or human's normal file/content view, but
it is not implementation magic. A content service orchestrates the registered
capsules behind that view:

1. exact source bytes commit first under their `ObjectId`;
2. policy chooses whether semantic admission runs immediately, lazily on first
   use, or as bounded background work;
3. the service invokes the pinned decoder and canonicalizer;
4. the host streams and verifies their output, records evidence, and admits the
   binding;
5. a representation request uses an existing trusted encoding or invokes an
   approved producer and verifies its result; and
6. the caller receives ordinary content bytes, not a deduplication protocol.

No background policy rewrites or deletes the source silently. Exact retention
remains the default until an explicit retention policy accepts semantic
preservation.

Current IPC can coordinate those steps but should not carry large content
buffers. Activation needs one generic, capability-scoped WIT streaming world,
not media-specific host functions. Conceptually it supplies:

```text
source resource
    read bounded byte chunks from one host-selected ObjectId

value/output sink resource
    accept bounded chunks, apply backpressure, and finalize or abort

transform context
    names host-selected contract, types, and execution bounds

execution result
    reports success or diagnostics; never a caller-chosen identity
```

The host selects the source and contracts, computes identities, compares
canonical streams, enforces output bounds, and stamps evidence. The capsule
cannot open arbitrary paths, choose another principal, claim a `SemanticId`, or
publish directly into the trusted representation pool. Existing fuel, memory,
deadline, and principal compute accounting apply to the run.

This is a future generic WIT/RFC surface because current contracts are frozen.
The engine and storage model can first expose equivalent internal Rust traits.
There is no `decode-png`, `encode-webp`, or codec registry host function, and
the kernel remains format-blind.

## Domain examples and limits

### Images

An image semantic contract may canonicalize dimensions, orientation, color
space, alpha, sample depth, pixels, and animation timing. Pixel-identical
encodings may share a `SemanticId`. Resized, cropped, or recompressed images
with different pixels remain distinct even when a perceptual metric relates
them.

The capsule family stays deliberately small and codec-specific:

```text
image-pixels canonicalizer
    defines canonical-image-pixels/v1

PNG reference decoder
    image/png -> canonical-image-pixels/v1

WebP reference decoder
    image/webp -> canonical-image-pixels/v1

approved lossless WebP/AVIF encoders
    canonical-image-pixels/v1 -> verified equal representation

lossy WebP/AVIF encoders
    image SemanticId -> new image SemanticId + lossy-derived-from relation

image similarity analyzer
    image SemanticId pair -> scored relation only

Metal texture producer
    canonical-image-pixels/v1 -> device-scoped derived representation
```

Adding an AVIF decoder adds a representation contract; it does not redefine
the pixel semantic domain. Decoder libraries remain inside sandboxed capsules
with no filesystem or network access. Declared dimensions, checked arithmetic,
fuel, memory, and output accounting contain decompression bombs. Encoders may
be replaced without changing the image identity, while a new canonical color
or animation policy intentionally creates a new semantic contract.

Lossy encodings and GPU texture compression do not remain representations of
the source pixel identity when decoded pixels differ. They receive their own
`SemanticId` and a typed derivation recording source, profile, and execution
evidence. A perceptual threshold is a similarity relation, not equivalence:
tolerance-based equality is generally non-transitive. Metadata omitted by a
pixel contract remains available through the exact source and may have its own
typed semantic contract; omission never destroys it implicitly.

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

## Convergence measurement

Semantic equivalence contributes one separately reported term to convergence;
it never changes the byte-identity or authorization rules in this document.
The metric vocabulary, measured whole-file results, platform-scale hypothesis,
and required corpus axes live in
[Storage Performance and Convergence](../reference/astrid-storage-performance.md).

## Required evidence before activation

Implementation is gated on tests that demonstrate:

- a capsule cannot register its own semantic or representation contract;
- changing an identity-bearing semantic-contract field changes
  `SemanticContractId` and `SemanticId`;
- adding or replacing a representation contract changes no existing
  `SemanticId` when canonical output is equal;
- each source binding executes its pinned decoder and semantic canonicalizer;
- an alternate transform cannot persist a binding without complete reference
  verification or an accepted proof;
- claimed canonical output substitution is rejected;
- a valid but untrusted source representation is never selected for another
  principal;
- an encoder whose decoded canonical value differs creates a new semantic
  identity and derivation rather than an equal representation;
- exact-byte lookup never returns a merely equivalent representation;
- a forced semantic-digest collision is detected by canonical-stream
  comparison;
- similarity edges change no identity, authority, retention, or accounting;
- privacy domains can prevent physical sharing without changing semantic
  equality;
- transform failure, timeout, exhaustion, and oversized output create no
  binding;
- transform capsules can access only host-selected stream handles and cannot
  select a principal, path, contract, or identity;
- bounded chunk streaming applies backpressure without buffering complete
  large inputs or outputs;
- cyclic and over-depth routes terminate within declared bounds; and
- derived-cache eviction changes no principal root or authoritative read and
  never removes the final representation of semantically retained content.

The current content DAG remains the exact-byte substrate beneath this design.
Compaction and the persistent object index remain prerequisites before
semantic representations are admitted at heavy-content scale.
