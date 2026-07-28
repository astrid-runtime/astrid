# Conservation of Computation

Status: architectural contract. This document defines the identity and
authority rules that must exist before Astrid persists or reuses deterministic
computations.

Related documents:

- `astrid-principal-store.md` defines the exact-byte and principal-root
  substrate.
- `astrid-semantic-representations.md` defines contract-scoped equivalence and
  pinned transforms.
- `astrid-muninn.md` defines the fleet derivation index and its verification
  policy.
- `astrid-huginn.md` applies the model to context assembly.
- `astrid-refinery.md` applies it to bounded cold-path work.

## Thesis

In a content-addressed operating system, a pure deterministic computation with
a complete content-addressed invocation can be executed once, verified once,
and reused anywhere that policy permits.

Astrid therefore treats verified computation as another immutable relation:

```text
InvocationId --derives-with-evidence--> Result ObjectId(s)
```

The result remains ordinary content governed by principal authority. The
relation does not make an identity into a capability, authorize a caller, or
turn an external effect into a cache hit.

This is the conservation of computation:

> Store irreducible entropy, name complete computations, derive reproducible
> structure, and remember verified work.

Conservation of computation must not become conservation of side effects.

## Work Order 0: the invocation contract

The shorthand `(transform ObjectId, input ObjectId)` is not an identity
construction. A derivation identity binds every semantics-visible value that
can affect the result.

Conceptually:

```text
DerivationInvocation {
    format_version
    execution_class
    transform_contract
    ordered_inputs
    canonical_parameters
    runtime_semantic_profile
    output_contract
    optional_snapshot
    optional_seed
}

InvocationId = ObjectId(DerivationInvocation)
```

The durable encoding uses the same canonical ObjectRecord discipline as the
principal store. Every field has an explicit tag, width, and ordering rule.
Unknown format versions fail closed. Maps are encoded as ordered entry
sequences under a pinned key ordering. Optional fields have an explicit
presence byte. No ambient JSON, language serializer, locale, map iteration
order, native integer width, or platform float formatting participates in
identity.

`canonical_parameters` is an ObjectId naming a typed canonical parameter
object, not an opaque caller-provided byte string. The transform contract
defines that object's schema, bounds, and canonical encoding.

`ordered_inputs` contains explicit labels and ordinals. A set of equal inputs
in a different semantic order is a different invocation unless the transform
contract itself defines a canonical commutative input grammar.

If a value can change the result, it is an input or belongs to an immutable
contract named by the invocation.

## Runtime semantic profiles

Keying the invocation by an engine build hash is safe but destroys reuse on
every runtime release. Omitting runtime semantics is reusable but unsound.
Astrid therefore names the semantics-visible execution surface independently
from an engine build:

```text
RuntimeSemanticProfile {
    format_version
    wasm_core_spec
    component_model_semantics
    enabled_proposals
    host_function_semantic_versions
    integer_and_trap_semantics
    float_and_nan_profile
    thread_and_scheduling_profile
    deterministic_resource_failure_rules
}

RuntimeSemanticProfileId = ObjectId(RuntimeSemanticProfile)
```

The profile pins exactly the behavior a transform can observe:

- the relevant WebAssembly and component-model semantic versions;
- the sorted set of enabled proposals;
- every reachable host import by semantic contract version, not merely its
  display name;
- floating-point, NaN, reduction-order, and canonicalization guarantees;
- whether threads, atomics, or scheduler-visible behavior are reachable; and
- deterministic rules for fuel, memory, output, recursion, and deadline
  failure.

It deliberately does not contain an engine build identifier, optimization
level, compiler revision, or operating-system version when those cannot affect
observable behavior.

Each engine build records its own identity in execution evidence and may claim
support for an existing semantic profile only after running that profile's
conformance fixtures. A behavior-changing release registers a new profile. A
behavior-preserving release continues to use the existing profile, preserving
fleet memo durability.

Registration is operator authority. A capsule cannot announce that an
incompatible runtime is equivalent to an existing profile.

## Execution classes

Every invocation declares one closed execution class. The class is checked
against the transform contract and permitted imports.

### Pure

The transform observes only its identified inputs, immutable contract closure,
canonical parameters, and deterministic runtime profile. It is safe to reuse
within an allowed computation-sharing domain.

Examples include canonicalization, verified decoding, deterministic
compilation, content reconstruction, Tensor Logic at `T=0`, and fixed-seed
analysis.

### Snapshot-bound

The transform observes mutable or external information only through an
identified provenance snapshot. The snapshot ObjectId and any validity policy
are part of the invocation.

A web response, package index, source repository, mutable principal view, or
model registry is fetched first and retained with provenance. Deterministic
processing of those bytes is reusable. The acquisition itself is not silently
replayed from a derivation cache.

### Effectful

The operation changes authority or an external system. The effect is never
skipped because a matching invocation exists.

Sending a message, charging an account, publishing a release, granting a
capability, and actuating hardware remain fresh authorized operations. Pure
preparation, validation, encoding, or receipt parsing around the effect may be
memoized independently.

An old execution receipt is evidence that an effect occurred once. It is not
authorization to claim that the effect occurred again.

### Nondeterministic

The operation depends on undeclared entropy, time, environment, scheduling,
network state, floating-point reduction order, or another unpinned source. It
is not reusable.

Some operations can become pure or snapshot-bound by making the seed,
environment, source snapshot, and runtime guarantees explicit. Others, such as
intentionally stochastic tests or hardware-dependent inference, remain
nondeterministic by design.

## Derivation admission

Only the kernel-governed derivation service admits a reusable relation:

1. authorize the caller's access to every input and requested output class;
2. resolve registered contracts and the runtime semantic profile;
3. compute the canonical `DerivationInvocation` and its `InvocationId`;
4. execute through the pinned sandbox profile on a miss;
5. compute result identities from bytes written to host-selected sinks;
6. validate output type, bounds, closure, and any reference transform or proof;
7. emit immutable execution evidence; and
8. publish the derivation relation through the ordinary root-CAS path.

Computed, never accepted, remains the rule. A guest may request execution. It
cannot supply a trusted result identity, evidence record, invocation identity,
runtime equivalence claim, or fleet memo entry.

## Authority and sharing domains

An `InvocationId`, result ObjectId, or memo presence is never a capability.
Authorization is evaluated before lookup and again before returning a result.
The derivation relation cannot import private inputs or outputs into another
principal's owned closure.

Fleet-wide reuse means reuse within an operator-declared computation-sharing
domain. Public build inputs may use a broad domain. Private prompts, protected
datasets, erasure domains, and enterprise tenants may require narrower domains
or separate physical encodings.

Cross-domain physical reuse may occur only below the guest API line. It never
changes admission, result shape, or guest-visible accounting based on another
domain's prior computation.

Cache warmth is an accepted residual timing signal in the same class as a
shared operating-system page cache. Deployments requiring a stronger boundary
use separate reuse domains and encodings.

## Accounting

Computation uses the same double-ledger rule as deduplicated storage:

- the physical ledger records actual CPU time, resident byte-time, device
  work, reads, writes, and retained derived bytes;
- the logical ledger charges each principal or trust domain for the full
  declared computation it requested, independent of physical reuse.

A cross-domain memo hit is billed at the same logical compute price as a miss.
The saved work is the operator's dividend, never a guest-visible discount or
cross-domain equality oracle.

Inside one customer-controlled trust domain, aggregate billing is the default.
Internal per-principal allocation is an explicit policy because it can create
bill fluctuation and intra-domain observation channels.

Spot checks and maintenance execution are charged to an operator maintenance
budget through the common resource authority, not to the principal whose
historical invocation happened to be sampled.

## Evidence and portability

An admitted derivation records at least:

```text
DerivationEvidence {
    invocation: InvocationId
    transform_contract: ObjectId
    runtime_semantic_profile: RuntimeSemanticProfileId
    actual_engine_build: ObjectId
    inputs: [ObjectId]
    outputs: [ObjectId]
    execution_measurements
    verifier_or_reference_evidence
    authority_epoch
}
```

Muninn's live index is disposable. The immutable evidence and result objects
are sufficient to rebuild it.

`export_closure` materializes authoritative result bytes. It may also include
the invocation, transform closure, runtime profile, and evidence so a
destination can inspect or re-execute the derivation. A destination does not
inherit the source system's registration authority merely by importing the
objects.

## Required tests before activation

- Changing any semantics-visible invocation field changes `InvocationId`.
- Reordering labeled inputs changes identity unless the contract explicitly
  defines commutativity.
- Alternative serializers cannot produce a second accepted encoding of the
  same invocation.
- Two engine builds conforming to one runtime semantic profile reuse the same
  invocation and produce identical results.
- A behavior-changing runtime cannot claim the old profile.
- Clock, random, mutable environment, undeclared filesystem, network, and
  scheduling observations are unreachable from a pure derivation.
- Snapshot-bound results change identity when their provenance snapshot
  changes.
- An effectful operation is performed on every authorized invocation even when
  its pure preparation has a memo hit.
- A nondeterministic operation cannot enter Muninn.
- A caller without input authority cannot probe memo presence or receive a
  result.
- Cross-domain hit and miss accounting are logically identical.
- Corrupt or absent memo state falls back to correct execution rather than
  failing a valid operation.

## Program sequence

1. Freeze this invocation and determinism contract.
2. Build Muninn over durable derivation evidence and a disposable index.
3. Add Refinery scheduling and pass seams before arena compaction.
4. Freeze the Tensor Logic GC fact schema and linked plan/commit receipts.
5. Amend Forge, local-model, distro, Realm, audit, export, sync, and public
   content charters as consumers of the same primitive.
