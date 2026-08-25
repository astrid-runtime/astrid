# Astrid Resource Ownership Model

Status: WP0 architecture freeze. This document is a locked architecture
contract and implementation plan, not an assertion that the resource table,
native kernel, Realm, or first-owner ceremony has landed. No section is a
standalone completion claim.

Canonical namespace: `astrid-runtime`. Redirects from `unicity-astrid` are not
authority.

Implementation epic: [astrid#1564](https://github.com/astrid-runtime/astrid/issues/1564)

Last reviewed: 2026-08-25

Evidence snapshot: `astrid-runtime/astrid` `origin/main`
`6e43da5f68f4ca10899236598988fe3ebadd7a39`.

Landed storage:
[astrid#1535](https://github.com/astrid-runtime/astrid/pull/1535) `3f82d81e`
(2026-08-19);
[astrid#1562](https://github.com/astrid-runtime/astrid/pull/1562) `0aca3f40`
(2026-08-20);
[astrid#1601](https://github.com/astrid-runtime/astrid/pull/1601) `a7d50f55`
(2026-08-22). `AstridVolume` is media/projection; WAL is the
`transactions.wal` region, default off, not a host `PathBuf` authority.

Types foundation:
[astrid#1565](https://github.com/astrid-runtime/astrid/issues/1565)
`codex/resource-types-foundation` `800cee5a4731c38a912ebc72f053c5165f8cd9b4`,
no pull request. Independent local quality evidence on that SHA is 17 tests,
`no_std`/`wasm32` checks, `clippy -D warnings`, and `fmt`. It is not merged
and is not a behavior change.

Named systems such as Hermes, BusyBox, Linux Realm, QEMU/q35, NVIDIA, and
other workloads, vendors, or devices are non-normative fixtures or
falsifiers. They are not canonical product identity, dependencies, or
sequencing authority. No provider, resource, device, or application
contract specializes to them. Fixture ordering does not order architecture
tracks. Linux Realm is one compatibility personality, not the native OS
or the application model. A machine or device example proves only its
named conformance boundary.

A recoverable RV64-in-WASM oracle plus a BusyBox argv fixture is one
compatibility-backend falsifier, not the definition of Realm.
[unicity-aos/aos-ce#77](https://github.com/unicity-aos/aos-ce/pull/77)
(`b64d8d94`, draft, conflicting) is inventory only.

Related documents:

- [Astrid Universal Application Substrate](astrid-universal-application-substrate.md)
- [Astrid Kernel Charter](astrid-kernel-charter.md)
- [Astrid Native Component Kernel](astrid-native-kernel.md)
- [Astrid Principal Store](astrid-principal-store.md)
- [Astrid Principal Store Runtime Realization](astrid-principal-store-runtime.md)
- [Astrid User, Fleet, and Principal Ownership](astrid-user-fleet-ownership.md)
- [Astrid Driver Domain Contract](astrid-driver-domain-contract.md)

## 1. Locked decision

Astrid applies Rust's central systems-design discipline to operating-system
resources:

> Every consequential resource has an owner, every usable reference carries
> bounded authority, sharing and transfer are explicit, validity has a
> lifecycle, and unsafe compatibility is confined behind a checked boundary.

This is the native Astrid model. Linux, POSIX, language standard libraries,
filesystems, paths, processes, sockets, and agent harnesses are projections or
compatibility personalities over it. They do not define ownership or authority.

The direction is locked. New work may refine representations and prove better
mechanisms, but it must not reverse these decisions:

1. `PrincipalUid`, not a mutable alias or guest-provided name, is the durable
   principal identity.
2. Authority is intersection-only and can attenuate, expire, be consumed, or
   be revoked; it never grows implicitly.
3. Resource names, paths, ports, object digests, manifests, and descriptors are
   not authority.
4. Mutable resource state has exactly one explicit owner class. Physical
   sharing does not create shared mutable ownership.
5. Handles are opaque, typed, owner-bound, rights-bound, epoch-bound, and
   lifecycle-bound.
6. Sharing, delegation, transfer, checkpoint, restore, promotion, and
   installation are explicit transitions with separately checked authority.
7. Compatibility code cannot mint Astrid authority or fall back to ambient
   host operations.
8. The kernel owns enforcement primitives, not filesystem, POSIX, application,
   package-manager, agent, or policy intelligence.
9. The same resource semantics must hold on the hosted runtime and the native
   `no_std` kernel.
10. Existing public interfaces remain stable while typed internal edges are
    introduced and proven.
11. Presentation never implies authority. Astrid issues admitted action
    handles; host labels, icons, and layout cannot mint or widen them.
12. Physical sharing and dedup obey the substrate privacy ceiling. Logical
    owner, accounting, and non-enumeration remain separate; they do not
    close storage contention, dedup observability, shared-device, cache,
    microarchitectural, or equivalent leakage by themselves. Default is
    hostile-principal isolation unless a named evidence-backed threat model
    permits each sharing class.
13. QEMU, TCG, and KVM evidence establishes only a named emulator
    machine-contract enforcement boundary. It is not bare-metal, no-host,
    or hypervisor machine authority, and not proof that host or hypervisor
    authority is absent. Hosted success is the same class of functional
    evidence. First-owner enrollment is the unresolved ceremony in
    substrate section 14.5.
14. Named systems such as Hermes, BusyBox, Linux Realm, QEMU/q35, NVIDIA,
    and other workloads, vendors, or devices are non-normative fixtures or
    falsifiers. No provider, resource, device, or application contract
    specializes to them. Fixture ordering does not order architecture
    tracks. Linux Realm is one compatibility personality, not the native
    OS or the application model.

Changing one of these decisions requires a focused ADR or RFC that identifies
the violated invariant, supplies adversarial evidence, and explains why a less
disruptive refinement is insufficient. An attractive implementation shortcut
is not enough.

## 2. What “Rust-like” means

The analogy is a design constraint, not branding and not a literal language
borrow checker inside the kernel.

```text
Rust concept                 Astrid resource meaning
------------                 -----------------------
owned value                  owner-bound resource
move                         explicit authority transfer
shared borrow                bounded read/use lease
mutable borrow               exclusive mutation lease
lifetime                     authority epoch and lifecycle generation
type                         resource kind and protocol
trait                        provider contract with advertised semantics
Send / Sync                  explicit cross-domain transfer/share property
Drop                         release, reap, or revoke non-durable reservation
Result                       explicit failure; no ambient fallback
unsafe                       named compatibility or device trust boundary
crate closure                immutable application/system closure
compiler check               build validation plus admission verification
runtime safety check         kernel handle-table and provider enforcement
```

Rust succeeded because it retained native performance and interoperability
while changing which mistakes were expressible. Astrid must likewise preserve
Linux application ergonomics while changing which authority and lifecycle
mistakes are expressible.

### 2.1 Three enforcement moments

Not every OS fact can be decided statically. Astrid therefore divides checking
without weakening it:

1. **Build and install:** validate schemas, closure identity, protocol
   compatibility, requested resource kinds, provenance, and authority
   expansion. This produces no runtime authority.
2. **Admission:** intersect exactly one host-stamped authenticated invocation
   or admitted service lease with the principal, device where applicable,
   application, provider, portal, and job ceilings. Successful admission mints
   opaque handles under the current authority and lifecycle epochs.
3. **Operation:** validate the handle table entry, operation rights, current
   epochs, provider generation, quotas, and revocation state before each
   consequential effect.

Static declarations can only request. Admission can only narrow. Runtime can
only enforce the admitted result or invalidate it.

### 2.2 What is deliberately not copied from Rust

- Astrid does not require all resource lifetimes to be statically knowable.
- A cloned process-local Rust `Arc` is not proof that a cross-boundary resource
  is shareable.
- WIT `own<T>` and `borrow<T>` govern component resource-table mechanics; they
  do not by themselves prove durable ownership, delegation, or revocation.
- Drop is not sufficient for durable resources or crash recovery. Durable
  state follows committed transitions and recovery roots.
- A Rust type is not a security boundary when untrusted bytes can deserialize
  directly into it without validation.
- `unsafe` is not a general escape hatch. Each unsafe OS boundary has a named
  provider, capability ceiling, audit identity, and conformance claim.

## 3. Semantic model

### 3.1 Resource authority tuple

Every live handle resolves in a host-owned table to this semantic tuple:

```text
ResourceAuthority {
    handle_id
    resource_kind
    resource_identity
    object_generation
    owner
    holder_context
    initiator_binding
    acting_principal
    application_or_service_identity
    application_generation
    rights
    authority_epoch
    lifecycle_generation
    provider_identity
    provider_generation
    accounting_scope
    resource_scope
    budget
    durability_class
    transfer_class
    parent_delegation
    expiry
    revocation_selector
    causal_request
}
```

The tuple is the normative semantic contract. Exact Rust and wire
representations remain private until their migration and conformance tests are
ready.

Serializable descriptors and receipts may describe this tuple but are not a
live `ResourceAuthority`. Live authority also depends on non-serializable
holder/table state in the enforcing domain, including authority-bearing
`resource_scope`, `budget`, and reservation/envelope bindings;
deserializing the fields can never manufacture a usable handle.

- `handle_id` is an unguessable or table-local opaque reference. Knowledge of
  the value is not sufficient if the caller/table binding differs.
- `resource_kind` selects a typed operation set.
- `resource_identity` names the object inside its provider without conveying
  authority.
- `object_generation` rejects reuse of a stale table slot or object identity.
- `owner` is `System`, `Principal(PrincipalUid)`, or `Fleet(FleetUid)` for
  durable state. Invocation-scoped resources additionally bind the acting
  principal and parent job.
- `holder_context` binds the domain/session/table in which the opaque handle is
  meaningful.
- `initiator_binding` is a typed `Session(id)` or `ServiceLease(id)` binding;
  background work never synthesizes a human session.
- `acting_principal` is host-stamped and cannot be selected in the operation
  payload.
- application/service identity prevents authority admitted to one executable
  closure or service from being replayed by another.
- application generation binds the exact selected immutable closure, not only
  a mutable application or service name.
- `rights` is the admitted operation subset, never a free-form policy prompt.
- `authority_epoch` invalidates grants after revocation, ownership change,
  credential retirement, or administrative security transition.
- `lifecycle_generation` invalidates handles after instance restart,
  replacement, stop, checkpoint restore, or principal deletion.
- provider identity and generation prevent silent backend substitution.
- accounting scope binds reservations and usage even when physical bytes are
  shared.
- `resource_scope` is a bounded, host-only description of the admitted object
  subset. It is not a guest-supplied path or a serializable grant.
- `budget` binds the reserved resource envelope, or a precise linked
  reservation identity, so child attenuation can prove a subset of remaining
  parent budget. Authority-bearing scope, budget, and envelope live in
  non-serializable holder/table state; descriptors may name them but cannot
  mint them.
- durability class controls crash/restart behavior.
- transfer class states whether a handle is local-only, movable, shareable,
  delegable, or non-transferable.
- parent delegation links the attenuated authority chain and receipt. The
  receipt is evidence, never a bearer grant; validation resolves the live
  parent table entry or authenticated derivation/lineage record.
- expiry and revocation selector define time and lineage invalidation without
  requiring one global epoch.
- causal request binds admission, effect, accounting, and outcome without
  trusting a guest correlation string.

Fields may be represented by compact indices in a native handle table. They
must remain observable in structured diagnostics and receipts where disclosure
policy allows.

The ring-0 capability entry stays smaller than the full product tuple: it binds
domain-local slot, object generation, rights, and derivation/revocation facts.
The admitted user-space/service table binds owner, principal, application,
provider, lifecycle, accounting, `resource_scope`, budget/envelope, and
policy evidence. Kernel legibility relates these layers without moving product
policy or strings into ring 0.

Owner, holder, issuer, provider, operator, and accounting payer are distinct
roles. A principal may hold an attenuated handle to a fleet-owned object; a
provider may implement it without owning it; an operator pool may pay for
physical residency while each principal pays its logical charge.

Physical sharing does not merge owners or logical charges. The privacy ceiling
in the universal-application substrate applies here: the default is
hostile-principal isolation; logical accounting and non-enumeration do not
close storage contention or timing, dedup equality or existence
observability, shared device queues, cache or microarchitectural channels,
or equivalent leakage. Each sharing class requires a named evidence-backed
threat model.

### 3.2 Generation and epoch vocabulary

The word `generation` must not conceal different invalidation domains:

- **ObjectGeneration:** rejects a stale handle-table slot after object reuse;
- **DerivationId/lineage:** identifies a delegation subtree for scoped
  revocation;
- **AuthorityEpoch:** identifies the current policy/grant snapshot for a
  principal, service, portal, or other revocation domain;
- **LifecycleGeneration:** identifies one service/Realm/runtime incarnation;
- **SystemGeneration/ApplicationGeneration:** selects an immutable closure;
- **ProviderGeneration:** identifies one provider incarnation; and
- **RootGeneration:** is the owner-root CAS generation and advances on every
  root transition, including rollback; and
- **PlacementEpoch:** identifies a storage placement/configuration generation.

They are separate newtypes with separate advance and refresh rules. A single
global epoch would turn local revocation into a machine-wide availability
weapon. Wasmtime interruption epochs are scheduling mechanisms and must not be
accepted as any of these security types.

### 3.3 Owner and durability classes

The durable owner model remains:

```text
System
Principal(PrincipalUid)
Fleet(FleetUid)
```

Resources additionally declare one durability class:

- **ephemeral:** destroyed on job/instance termination;
- **session:** survives individual calls but not authenticated session expiry;
- **service:** survives jobs and is restored by the service lifecycle policy;
- **durable:** committed in the Principal Store and recovered independently of
  a process or compatibility Realm; or
- **immutable:** content-identified closure data, never modified in place.

Durability does not imply authority persistence. On restore, durable state is
reopened through current authority. Live sockets, secret handles, wall-clock
assumptions, process identifiers, DMA mappings, and invocation handles are not
resurrected from old authority.

### 3.4 Rights and attenuation

Rights are defined per resource kind and represented canonically. A delegation
may only produce:

```text
child.rights             subset of parent.rights
child.expiry             no later than parent.expiry
child.resource_scope     no broader than parent.resource_scope
child.budget             no greater than remaining delegated budget
child.transfer_class     no more permissive than parent.transfer_class
child.authority_epoch    current parent authority epoch
child.parent_delegation  authenticated lineage record or live parent reference
```

`resource_scope` and `budget` are fields of the live `ResourceAuthority`
tuple. They are host-only and non-serializable where authority-bearing.
Delegation proves subset attenuation against those live bindings, not
against a guest descriptor.

Revokes win. Missing registry entries, target kinds, providers, semantic
profiles, identities, epochs, or accounting authorities fail closed.

Ownership transfer is not ordinary handle transfer. It is a separately
authorized durable transition that updates owner records, authority epochs,
recovery roots, quotas, and audit evidence atomically.

### 3.5 Sharing and transfer

Astrid distinguishes operations that Unix frequently collapses:

- `borrow_read`: create a bounded concurrent read/use lease;
- `borrow_exclusive`: create an exclusive mutation lease;
- `share`: admit another independently accounted handle to explicitly
  shareable state;
- `move`: invalidate the source handle and create a destination binding;
- `delegate`: retain the parent while creating a strictly attenuated child;
- `publish`: make a typed service endpoint discoverable in an admitted
  namespace;
- `promote`: move an immutable artifact into an installable or executable
  trust state; and
- `checkpoint`: commit recoverable state without preserving stale live
  authority.

These are separate verbs and audit events. A generic `clone_handle` operation
is forbidden unless the resource kind explicitly defines its semantics.

### 3.6 Lifecycle transitions

Every resource service implements a subset of a common transition algebra:

```text
declare -> verify -> install -> admit -> activate -> use
                                      |          |
                                      |          +-> delegate/share/move
                                      |          +-> checkpoint
                                      |          +-> drain
                                      +-> deny

drain -> stop -> release
use/checkpoint -> restore under new lifecycle generation
installed generation -> promote -> select -> rollback
any live state -> revoke/retire/delete -> invalidate handles -> reclaim
```

Transitions are idempotent where retry is required and carry operation IDs.
Partial completion is recoverable or explicitly terminal. Selection of a
system/application generation never silently rolls back principal data.

### 3.7 Namespaces and discovery

A principal namespace is a projection of resources already authorized for the
session. Enumeration cannot reveal inaccessible resource names. Resolving a
name returns no authority unless the admission intersection succeeds.

Aliases remain ergonomic and mutable. Durable records use stable UIDs and
content-bound references. Guest payloads never choose the authoritative owner
by supplying an alias, path, mount name, service name, or principal string.

## Continued chapters

Normative text after section 3 continues in these chapter files. Numbered headings below stay on this path so existing `#` anchors still resolve.

- [4 through 5. Existing code and target structure](architecture/resource-ownership-model/code-and-structure.md)
- [6 through 12. Sequence, prior work, corpus, and review](architecture/resource-ownership-model/programme-and-review.md)

## 4. Existing code: retain, extend, or replace

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#4-existing-code-retain-extend-or-replace).

### 4.1 Identity and ownership: retain

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#41-identity-and-ownership-retain).

### 4.2 Authority systems: converge semantically, preserve surfaces

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#42-authority-systems-converge-semantically-preserve-surfaces).

### 4.3 Host-stamped execution context: extend

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#43-host-stamped-execution-context-extend).

### 4.4 Runtime identity and generations: extend

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#44-runtime-identity-and-generations-extend).

### 4.5 Resource handles and ledgers: generalize by contract, not one class

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#45-resource-handles-and-ledgers-generalize-by-contract-not-one-class).

### 4.6 Storage: consume the current programme

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#46-storage-consume-the-current-programme).

### 4.7 Hosted path gates: retire as authority, retain as adapters

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#47-hosted-path-gates-retire-as-authority-retain-as-adapters).

## 5. Target code structure

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#5-target-code-structure).

### 5.1 Portable resource types

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#51-portable-resource-types).

### 5.2 Host-only authorization context

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#52-host-only-authorization-context).

### 5.3 Admitted resource table

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#53-admitted-resource-table).

### 5.4 Authority epochs

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#54-authority-epochs).

### 5.5 Effect evidence classes

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#55-effect-evidence-classes).

### 5.6 Provider traits

Full text continues in [Code and structure](architecture/resource-ownership-model/code-and-structure.md#56-provider-traits).

## 6. Implementation sequence

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#6-implementation-sequence).

### Step 0: freeze vocabulary and inventory

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-0-freeze-vocabulary-and-inventory).

### Step 1: portable types without behavior changes

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-1-portable-types-without-behavior-changes).

### Step 2: authoritative execution context

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-2-authoritative-execution-context).

### Step 3: one admitted resource vertical slice

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-3-one-admitted-resource-vertical-slice).

### Step 4: storage and workspace adoption

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-4-storage-and-workspace-adoption).

### Step 5: accounting and delegation

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-5-accounting-and-delegation).

### Step 6: compatibility-Realm semantics

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-6-compatibility-realm-semantics).

### Step 7: native `no_std` host

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-7-native-no_std-host).

### Step 8: public contracts and ecosystem

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#step-8-public-contracts-and-ecosystem).

## 7. Prior work disposition

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#7-prior-work-disposition).

### `origin/codex/storage-mounted-filesystem`

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#origincodexstorage-mounted-filesystem).

### `feat/kernel-skeleton` / `origin/feat/kernel-skeleton`

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#featkernel-skeleton--originfeatkernel-skeleton).

### Preserved Linux Realm and `origin/feat/linux-realm-runtime`

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#preserved-linux-realm-and-originfeatlinux-realm-runtime).

### `origin/feat/connection-workspace-attachment`

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#originfeatconnection-workspace-attachment).

### Resident-memory and compute branches

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#resident-memory-and-compute-branches).

### Capability, principal-stamping, and semantic-registry work

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#capability-principal-stamping-and-semantic-registry-work).

### Remote contexts, SSH, distro reconciliation, and live removal

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#remote-contexts-ssh-distro-reconciliation-and-live-removal).

## 8. Ideas explicitly rejected

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#8-ideas-explicitly-rejected).

## 9. Required conformance corpus

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#9-required-conformance-corpus).

### Authority and identity

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#authority-and-identity).

### Handles and lifecycle

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#handles-and-lifecycle).

### Accounting

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#accounting).

### Storage and compatibility

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#storage-and-compatibility).

### Hosted/native equivalence

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#hostednative-equivalence).

## 10. Review and acceptance policy

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#10-review-and-acceptance-policy).

## 11. Independent review record

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#11-independent-review-record).

### Kernel and resource-model review

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#kernel-and-resource-model-review).

### Authority and adversarial-security review

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#authority-and-adversarial-security-review).

### Storage and recovery review

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#storage-and-recovery-review).

### Linux Realm and compatibility review

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#linux-realm-and-compatibility-review).

### Prior-work archaeology review

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#prior-work-archaeology-review).

## 12. Definition of locked-plan completion

Full text continues in [Programme and review](architecture/resource-ownership-model/programme-and-review.md#12-definition-of-locked-plan-completion).
