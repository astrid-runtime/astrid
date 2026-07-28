# Forge as a Muninn Consumer

Status: charter amendment. This document changes the identity and evidence
model for future Forge work; it does not activate a new capsule or WIT surface.

Forge builds and deterministic tests are derivations, not a second cache
system.

## Build identity

A reproducible capsule build uses the complete invocation contract:

```text
source closure
toolchain closure
target and build profile
canonical build parameters
runtime semantic profile
packaging contract
    -> canonical capsule artifact and build manifest
```

The source closure includes every source, generated input, lockfile, vendored
dependency, build script, and declared environment object visible to the
build. The toolchain closure includes compiler, linker, `astrid-build`,
canonical WIT inputs, target libraries, and packaging implementation. Ambient
host paths, time, locale, network state, and undeclared environment are absent
from a reusable build.

The exact transform closure and contracts participate in `InvocationId`.
Changing compiler bytes, target semantics, feature flags, packaging grammar,
or any declared input produces a different invocation. A build lookup is
permitted only after ordinary source/input authorization.

## Test identity

A deterministic test outcome is keyed by:

```text
(code-and-fixture closure, test contract, runtime semantic profile,
 canonical parameters)
```

The evidence records pass/fail, canonical output artifacts, measurements, and
the executing engine build. Unchanged deterministic tests become Muninn
lookups, but operator sampling re-runs a selected subset. A mismatch becomes a
security event and makes the entry suspect; it is never silently blessed as a
new expected result.

Tests that observe clock, random, external services, undeclared filesystem
state, races, or backend-dependent numerics remain snapshot-bound or
nondeterministic. Forge does not label a flaky test pure to improve its hit
rate.

## Side-effect boundary

Compilation, packaging, and deterministic verification can be reused.
Installing a capsule, granting authority, signing a release, publishing an
artifact, changing a channel, and charging an account remain fresh effectful
operations. A memo hit supplies verified preparation; it never replays or
claims an external effect.

## Evidence and economics

Build and test results use `DerivationEvidence`; the live lookup is Muninn.
The durable result remains an ordinary principal-authorized object. Cross-domain
hits receive the same logical compute charge as misses, while saved physical
work is the operator's dividend.

The fleet goals are therefore precise:

- an unchanged reproducible build is a verified lookup;
- an unchanged deterministic test is an evidence lookup subject to sampling;
- deleting the disposable index changes speed only; and
- a source or toolchain change invalidates exactly the affected invocations.

## Acceptance

- Two fresh processes produce byte-identical capsule and manifest ObjectIds
  from one complete invocation.
- Every semantics-visible source, toolchain, target, and packaging change
  changes `InvocationId`.
- An undeclared clock, random, network, environment, or filesystem read makes
  the build ineligible for pure reuse.
- Install, signing, and publication execute on every authorized request.
- Deleting Muninn rebuilds the index from retained evidence.
- A sampled divergent build/test quarantines the entry and emits audit
  evidence.
- Cache presence cannot be probed across computation-sharing domains.
