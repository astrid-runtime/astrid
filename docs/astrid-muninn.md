# Muninn: Verified Computation Memory

Status: design contract. No guest-facing interface is activated by this
document.

Muninn is Astrid's fleet derivation memory: a disposable lookup index over
durable, independently verified derivation evidence.

Verification memoization in the principal content read path is its first
measured instance. Once immutable bytes have been validated under a complete
contract, later authorized reads can reuse that work instead of proving the
same fact again.

## Boundary

Muninn remembers computation. It does not:

- authorize a caller;
- accept a guest's claimed result or evidence;
- turn an identity into a read capability;
- replay external effects;
- redefine semantic equivalence;
- make nondeterministic execution reusable; or
- become the only durable copy of a derivation.

The principal store remains authoritative for objects and roots. Registered
contracts remain authoritative for transform meaning. The sandbox remains
authoritative for execution boundaries. Muninn accelerates the path between
them.

## Durable relation, disposable index

The durable record is an immutable derivation Evidence object:

```text
InvocationId --evidence--> Result ObjectId(s)
```

The live index is conceptually:

```text
MuninnEntry {
    invocation
    results
    evidence
    computation_sharing_domain
    determinism_class
    trust_state
    last_spot_check
}
```

The index can be dropped and rebuilt by walking retained Evidence and Derived
relations. Losing it loses speed, never correctness or authority.

An entry may be:

- `verified`: admitted by the governed derivation service;
- `suspect`: excluded from reuse pending investigation;
- `revoked`: contract, runtime profile, or transform authority was revoked; or
- `expired`: snapshot or policy validity ended.

These states are closed domain types, not strings. Transitions are auditable.

## Lookup

For one requested derivation:

1. authorize the caller and resolve its computation-sharing domain;
2. construct the canonical invocation defined by
   `astrid-conservation-of-computation.md`;
3. look for a verified entry eligible in that domain;
4. validate that its contracts, evidence, result closure, and policy epoch
   remain usable;
5. return authorized result bytes on a hit; or
6. execute, validate, publish evidence, and populate the index on a miss.

A missing, corrupt, full, disabled, or evicted Muninn index never fails a valid
operation. It falls back to execution.

## Spot-checking as continuous attestation

At an operator-defined sampling rate, Astrid re-executes an eligible pure or
snapshot-bound derivation under its exact recorded invocation and byte-compares
all result objects.

The sample selector must be unpredictable to the transform. A transform must
not be able to behave deterministically only when it expects verification.
Selection policy and aggregate sampling evidence remain auditable without
revealing another principal's invocation set.

A mismatch can indicate an undeclared nondeterministic input, sandbox or
runtime-profile failure, transform or loader tampering, implementation drift,
memo/evidence corruption, or a hardware fault. Every category is
security-relevant.

On mismatch Astrid:

1. emits a security audit event;
2. marks the entry suspect;
3. prevents the mismatching result from serving future hits;
4. identifies the transform, runtime profile, engine build, inputs, expected
   outputs, observed outputs, and sampling policy;
5. schedules bounded reference diagnosis under operator policy; and
6. never silently replaces the old result and calls the incident repaired.

The audit event schema is:

```text
DerivationMismatch {
    invocation: InvocationId
    evidence: ObjectId
    transform_contract: ObjectId
    runtime_semantic_profile: ObjectId
    original_engine_build: ObjectId
    checking_engine_build: ObjectId
    expected_outputs: [ObjectId]
    observed_outputs: [ObjectId]
    sampled_at_audit_sequence
    sampling_policy: ObjectId
}
```

Time is audit metadata, not an input to the replayed pure computation.

## Determinism tests

The sandbox profile used for memoizable derivations has acceptance tests that
prove:

- clock, random, network, mutable environment, locale, and undeclared
  filesystem imports are absent;
- deterministic host imports have semantic versions named by the runtime
  profile;
- iteration order, traps, integer behavior, and resource exhaustion are
  stable;
- forbidden threads, atomics, races, GPU reductions, and scheduler
  observations are unreachable;
- two fresh processes produce byte-identical outputs and evidence identities;
  and
- an injected nondeterministic capsule is caught by the sampling verifier.

Float- or accelerator-dependent contracts must define a backend-scoped
determinism profile or remain outside fleet memoization.

## Privacy and economics

Verification status, accounting, authority, and reuse policy are partitioned
by principal or trust domain. Immutable result bytes may share physical cache
entries when privacy policy permits, just as the host page cache shares
physical pages.

Guests never observe whether another domain populated an entry through:

- a different admission result;
- result metadata;
- an `already_present` field;
- reduced logical compute charges; or
- operator physical-accounting values.

Cross-domain hits pay the same logical compute price as misses. Physical saved
work belongs to the operator ledger.

Cache warmth is an accepted residual timing signal. Deployments that reject
that residual use distinct sharing domains and cache partitions.

## Resource authority

Muninn has no fixed hidden memory allowance. Its resident index, result cache,
decoded records, and spot-check workers use leases from Astrid's common
resource authority:

- physical resident bytes are charged to the operator pool;
- logical cache weight is attributed to the requesting trust domains;
- CPU time, resident byte-time, reads, writes, and device work are measured;
- eviction releases physical leases without changing any durable result; and
- pressure degrades to the uncached execution path.

Spot-check execution consumes the Refinery maintenance budget. Reservation is
leased in slabs or work batches so a global accounting lock does not return to
the hot read path.

## Revocation and migration

An engine update that preserves a runtime semantic profile retains matching
entries. A semantics-changing update creates a new profile and therefore new
invocations.

Revoking a transform or runtime profile prevents new hits immediately but does
not erase historical Evidence. Evidence records what the system previously
executed and believed; revocation records why it is no longer trusted.

Successor transforms create successor invocations. Old and new results may be
related through Lineage or Evidence but are never silently aliased.

## Initial consumers

1. content verification and canonical-boundary validation;
2. Forge capsule builds keyed by complete source and toolchain closure;
3. deterministic tests keyed by code closure and test contract;
4. Refinery transforms such as cross-hashing and sketches;
5. semantic representation decoding and canonicalization;
6. distro and Realm image generation; and
7. Huginn context and local-model prefix-state construction.

The slogans are conditional on complete invocation identity:

- unchanged reproducible builds become lookups;
- unchanged deterministic tests become evidence lookups, with sampled reruns;
- agents reuse verified content and context work they are authorized to see.

## Acceptance

- Muninn rebuilds from retained evidence after deleting its live index.
- A corrupt index entry cannot return an unverified result.
- Eviction changes performance only.
- A spot-check catches an injected nondeterministic transform.
- Mismatch emits the defined event and quarantines reuse without silent repair.
- Contract or runtime-profile revocation blocks matching hits.
- Two engine builds sharing one conformance-tested semantic profile reuse an
  entry.
- Cross-domain hits and misses have identical logical charges.
- Unauthorized callers cannot probe entry presence.
- Pure cache hits never replay effectful operations.
