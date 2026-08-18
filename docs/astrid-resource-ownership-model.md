# Astrid Resource Ownership Model

Status: locked architectural direction and code-grounded implementation plan

Implementation epic: [astrid#1564](https://github.com/astrid-runtime/astrid/issues/1564)

Last reviewed: 2026-08-18

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
holder/table state in the enforcing domain; deserializing the fields can never
manufacture a usable handle.

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
provider, lifecycle, accounting, and policy evidence. Kernel legibility relates
these layers without moving product policy or strings into ring 0.

Owner, holder, issuer, provider, operator, and accounting payer are distinct
roles. A principal may hold an attenuated handle to a fleet-owned object; a
provider may implement it without owning it; an operator pool may pay for
physical residency while each principal pays its logical charge.

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

## 4. Existing code: retain, extend, or replace

This plan was originally grounded on `origin/main` at `0452b6a0` and an
earlier snapshot of `origin/codex/storage-mounted-filesystem`. Those hashes and
historical green runs are archaeological evidence, not merge evidence. Before
implementation or merge, re-read the exact heads and required checks of storage
PR #1535 and performance PR #1562. Land and certify #1535 first; then rebase and
forward-port only the still-required #1562 WAL/cache semantics. Do not merge or
cherry-pick the divergent storage stacks wholesale. Paths and symbols below are
code anchors, not claims that every intended semantic is already complete.

### 4.1 Identity and ownership: retain

- `crates/astrid-core/src/identity/principal.rs`
  - `PrincipalUid` is the durable opaque identity derived from canonical
    `PrincipalGenesis`.
  - `PrincipalId` remains the human-facing alias.
- `crates/astrid-core/src/identity/ownership.rs`
  - `PrincipalOwnership` binds the durable principal to user/fleet ownership.
- `crates/astrid-storage/src/principal_state.rs`
  - `StateOwner::{System, Principal, Fleet}` is the existing durable owner
    vocabulary.
- `crates/astrid-storage/src/ownership.rs`
  - deletion reservations and `PrincipalDeletionGuard` already model guarded
    destructive transitions.

Do not introduce a competing principal identifier or infer durable ownership
from `PrincipalId`, a filesystem path, runtime slot, authentication key, or
application session.

### 4.2 Authority systems: converge semantically, preserve surfaces

- `crates/astrid-capabilities/src/token.rs`
  - signed `CapabilityToken` binds resource pattern, permissions, principal,
    scope, expiry, issuer, approval evidence, and single-use state.
- `crates/astrid-capabilities/src/store.rs` and `validator.rs`
  - token lookup, trusted issuer checks, consumption, revocation, persistence,
    and principal matching remain enforcement inputs.
- `crates/astrid-capabilities/src/policy.rs`
  - `CapabilityCheck` implements static management capability evaluation with
    revoke precedence and per-device attenuation.
- `crates/astrid-core/src/capability_registry.rs`
  - `CapabilityRef`, registry revisions/digests, target kinds, delegability,
    privilege, and signed extension provenance provide the semantic registry
    foundation.
- `crates/astrid-capsule-types/src/manifest/capabilities.rs`
  - exhaustive manifest capability expansion is retained as a request and
    install-review surface.

The static management capability namespace, runtime tokens, and manifest
requests must not be collapsed into one serialized token format. Introduce a
common internal `AuthorizationContext` and `AuthorityDecision` produced from
them. Preserve their distinct issuance and persistence rules.

Manifest union is request aggregation only. Admission binds the exact
requested-manifest digest and an immutable approved-grant snapshot ID/epoch,
then intersects that snapshot with current principal, device, session/service,
provider, and portal authority. Reloading or modifying a manifest cannot
expand a live instance.

`CapabilityToken` currently signs the human alias `PrincipalId`, not durable
`PrincipalUid`. A future token format must bind the UID with an explicit
version and migration. Existing signed v2 bytes cannot be silently
reinterpreted.

### 4.3 Host-stamped execution context: extend

- `crates/astrid-types/src/ipc.rs`
  - `IpcMessage` already carries host-derived `principal`, `device_key_id`, and
    `MessageOrigin` plus bus sequence data.
- `crates/astrid-capsule/src/engine/wasm/host_state.rs` and
  `host_state_invocation.rs`
  - invocation context, effective principal, publish stamping, and balanced
    lifecycle are existing enforcement seams.
- `crates/astrid-capsule/src/dispatcher.rs`
  - kernel-stamped caller identity reaches orchestration and access
    resolution.
- `crates/astrid-kernel/src/audit_sink.rs`
  - audit emission already requires principal attribution.

Add authority epoch, session identity, lifecycle generation, and admitted
resource-set identity to a host-only execution context. Do not expose setters
to guest code. Preserve the current public IPC wire shape until versioned
migration exists; use a validated internal envelope rather than adding more
guest-serializable optional strings indiscriminately.

The boundary is explicit:

```text
UntrustedEnvelope -> authenticate/resolve/stamp once -> StampedInvocation
```

Only `StampedInvocation` may enter an authority-bearing bus, portal, admission,
or provider operation. It is not serializable as authority and has no public
constructor. Background work receives the same type from a durable,
revocable, principal-bound `ServiceLease`, not from a default-principal
fallback.

### 4.4 Runtime identity and generations: extend

- `crates/astrid-capsule/src/registry/runtime_id.rs`
  - `RuntimeScope::{Principal, SystemResident}`, `RuntimeKey`, immutable
    `WasmHash`, and `RuntimeId::generation` already separate artifact,
    authority scope, and incarnation.
- `crates/astrid-capsule/src/registry/replacement.rs`
  - replacement verifies expected runtime identity and advances generation.
- `crates/astrid-capsule/src/engine/wasm/pool.rs`
  - pool epoch policy and instance lifecycle provide revocation/cancellation
    mechanisms, but Wasmtime interruption epochs are not authority epochs.

Promote lifecycle generation into the common admitted-handle check. Keep
Wasmtime epoch deadlines distinct from security epochs.

`SystemResident` remains an enumerated kernel-service designation, not a
sharing shortcut. Such a service must have neutral default state, explicit
fan-in behavior, per-message stamped context, and hostile cross-principal
tests. Hermes, a Realm, and ordinary applications are never made
`SystemResident` merely to share code or one process.

### 4.5 Resource handles and ledgers: generalize by contract, not one class

- WIT staging already defines owned resources for filesystem handles, streams,
  sockets, subscriptions, processes, HTTP streams, and pollables under
  `crates/astrid-capsule/wit-staging/deps/`.
- `crates/astrid-storage/src/resources/` implements separately accounted
  physical and logical resident-memory leases with RAII release and pressure
  reconciliation.
- `crates/astrid-capsule-types/src/fuel_ledger.rs` and
  `memory_ledger.rs` provide per-principal CPU and memory accounting.
- `crates/astrid-capsule/src/engine/wasm/host/fs/`, `host/net/`,
  `host/process/`, and `host/ipc.rs` own current resource-table operations.

`crates/astrid-capabilities/src/handle.rs` UUID wrappers are serializable hosted
registry keys, not the native capability type. Some host filesystem handle
operations and declared process resource limits remain incomplete. These are
gaps to close through the admitted resource table, not semantics to freeze.

Do not replace these with a single generic resource implementation. Define the
common authority tuple, lifecycle checks, accounting contract, and transition
receipts; let each resource kind retain its performance-appropriate provider
and ledger.

### 4.6 Storage: consume the current programme

The storage branch introduces or completes the required volume, owner-bound
filesystem, mount, provider, migration, audit, registry, secret/configuration,
and workspace transitions. The final merged types are authoritative.

The model depends on these separations:

```text
AstridVolume
  != logical Principal Store
  != owner-bound filesystem protocol
  != FSKit/FUSE/WinFsp mount adapter
  != Linux Realm filesystem semantics
```

The resource model adds authority/lifecycle bindings to storage leases. It
does not create another persistence engine or make a host path authoritative.

Current volume, mount, and provider APIs contain hosted `std`, path, process,
and async-runtime types. Their semantics and formats are inputs, not the frozen
native ABI. Extract portable `no_std + alloc` owner/root/lease identifiers,
bounded region/media operations, canonical formats, and errors; implement
those contracts through hosted adapters and a future native block provider.

Current mounted-storage work requires a deletion interlock before it is a safe
resource lease: principal deletion must revoke and drain every owner-bound
mount before purging the directory/root, and every callback must revalidate
the owner authority epoch. An in-memory lease retaining an old UID must not be
able to publish data and recreate a deleted principal root.

Rollback generations, exports, and checkpoints require durable GC-visible
retention roots. Current durable compaction accepts point-in-time retained
roots but has no production durable pin registry. Implement owner-scoped
`pin-before-promise` and transactional unpin semantics; after restart, every
advertised durable reference must still protect its closure.

Open read handles instead use ephemeral GC-visible leases; they must not be
recovered after their process dies. Registration must be atomic with root
observation from GC's point of view. A reader cannot snapshot an old root,
race a writer/compactor, and register its lease only after GC captured its fact
set. Either registration is inside the engine fence or GC revalidates a
monotonic lease-registry generation inside its mutation fence.

### 4.7 Hosted path gates: retire as authority, retain as adapters

`crates/astrid-capsule/src/security/manifest_gate.rs` currently resolves
`cwd://` and `home://` into host paths and checks path prefixes. This remains a
hosted compatibility adapter during migration, but it is not the native
resource model.

The destination is an admitted workspace/home handle whose provider resolves
paths inside an owner-bound namespace. Literal host paths remain available
only for explicit external attachments under separate operator authority.

## 5. Target code structure

### 5.1 Portable resource types

Create `crates/astrid-resource-types` as an internal-first crate:

- `#![no_std]` with optional `alloc`;
- no Tokio, filesystem, environment, process, socket, wall-clock, random UUID,
  or host synchronization dependency;
- optional `serde` support behind a feature;
- canonical fixed-width encodings for durable/wire identifiers; and
- compile checks for `--no-default-features` and `wasm32-unknown-unknown`.

Initial modules:

```text
owner.rs       OwnerId and owner-class tags
kind.rs        ResourceKind and semantic-version reference
rights.rs      canonical rights set and subset/attenuation operations
epoch.rs       AuthorityEpoch and LifecycleGeneration newtypes
handle.rs      opaque handle identifiers and transfer classes
authority.rs   ResourceAuthority tuple and validation-independent value types
transition.rs  operation IDs, transition kinds, and outcomes
accounting.rs  accounting scope and resource quantity vocabulary
encoding.rs    versioned canonical encodings
```

`astrid-core` re-exports public types where compatibility requires it. Existing
public field shapes do not change merely to make internal code aesthetically
uniform.

Do not move crypto issuance, token storage, policy evaluation, provider
objects, async locks, or host tables into this crate.

### 5.2 Host-only authorization context

Add an internal module initially under `astrid-kernel` or a private core crate:

```text
AuthorizationContext {
    principal_uid
    principal_alias_for_display
    device_identity
    session_identity
    message_origin
    authority_epoch
    application/runtime identity
    lifecycle_generation
}
```

Construct it only at authenticated ingress or a kernel-originated transition.
Capsules receive selected read-only facts through existing host imports; they
never deserialize an authoritative context from their own payload.

For scheduled/background work, construction consumes a current `ServiceLease`
that already binds principal UID, service identity, rights, authority epoch,
lifecycle generation, expiry/revocation domain, and budget account. There is
no implicit default principal.

`AuthorityDecision` records the exact registry revision, grant/token evidence,
revokes, requested-manifest digest, immutable approved-grant snapshot and
epoch, device floor, requested operation, admitted rights, resource scope,
budget, provider, and decision reason. Denials are first-class outcomes.

### 5.3 Admitted resource table

Introduce a host-owned `AdmittedResourceTable` beside the Wasmtime component
resource table. An entry contains the normative authority tuple and a
provider-specific object. Operations perform one shared preflight:

1. locate the caller-owned table entry;
2. compare acting principal, holder table/domain, and the typed initiator
   binding: authenticated invocations match session/device state, while
   background operations match the current service lease and its epoch;
3. compare authority and lifecycle epochs;
4. validate the requested typed right;
5. validate provider generation and availability;
6. reserve or verify accounting capacity;
7. invoke the provider; and
8. commit usage and audit/receipt outcome.

The component resource handle indexes the host table. It is not itself a
bearer capability outside that table. Cross-instance transfer uses an explicit
authority/admission operation that re-admits and rebinds authority. On native
Astrid, live capability derivation across domains uses kernel IPC handle
transfer; product-level re-admission and cross-machine delegation remain above
ring 0.

Start with one narrow resource kind rather than rewriting every host import.
The recommended proof is owner-bound storage or an in-memory test resource,
followed by network streams and process/execution handles.

### 5.4 Authority epochs

Define an authority epoch store keyed by the smallest revocation domain needed
for correctness. The initial implementation requires at least:

- principal security epoch;
- authenticated session or admitted service-lease epoch;
- application/service authority epoch; and
- provider generation.

An effective epoch stamp is either the exact typed tuple or a domain-separated,
collision-resistant canonical digest over it.

Revocation advances the relevant in-memory epoch/tombstone immediately, so
audit or receipt failure can never preserve authority. No operation may begin
after that linearization point. Durable revocation acknowledgement requires
the authoritative invalidation marker to be committed before any grant record
is removed; receipt persistence is coupled where supported and otherwise uses
reserved recovery capacity or a deferred receipt without restoring authority.

An operation that acquired its invocation guard before the linearization point
either completes under its captured authority or is cancelled/drained at the
resource kind's declared commit boundary. It must revalidate the epoch before
committing a consequential effect where the provider can support that fence.
Revoke-complete, domain-death, and owner-deletion are not reported until all
derived handles, mappings, queues, DMA, provider operations, and reservations
are drained or reclaimed.

Principal deletion, credential retirement, grant revocation, service
replacement, checkpoint restore, and provider restart must identify which
epochs they advance. Wasmtime interruption counters and storage placement
epochs remain separate types.

### 5.5 Effect evidence classes

Consequential effects are classified before implementation:

1. **Receipt-required:** external writes, authority increases, installation,
   promotion, ownership changes, durable state transitions, secret release,
   ingress publication, and other effects whose product claim requires durable
   attribution. Admission/effect intent is durably ordered before the effect,
   and completion is committed afterwards. If required evidence cannot be
   established, an authority-increasing or externally consequential effect does
   not proceed. Emergency denial, revocation, disable, kill, credential
   retirement, and provider quarantine invalidate authority immediately and
   are never blocked by receipt availability; durable completion follows the
   revocation rules above.
2. **Observability-only:** telemetry and diagnostic events whose loss does not
   change authority or committed state. They may follow an explicitly defined
   continue-and-alert policy and must never be presented as complete receipts.

The current audit path can continue after some persistence failures and some
host effects record only manifest-gated system proof. That behavior is not
sufficient for Hermes H1 or a general “every effect receipted” claim. The
transactional effect-journal boundary must be implemented before those claims.

If a process crashes after a non-transactional external effect but before its
completion record, recovery records `outcome_unknown`. It reconciles through a
provider idempotency key/status operation when available; otherwise replay is
forbidden without explicit policy because success cannot be inferred.

Future receipt/audit formats bind durable `PrincipalUid`; aliases are display
metadata only. Existing signed chains that bind `PrincipalId` remain
versioned and verifiable as historical bytes and are never silently
reinterpreted under a reused alias.

### 5.6 Provider traits

Provider traits describe operations and semantic profiles, not authority.
Authority is checked before provider dispatch. Each provider exposes:

- stable provider identity and generation;
- supported resource kind/protocol versions;
- semantic feature profile;
- durability and recovery guarantees;
- checkpoint/restore support;
- accounting measurements;
- cancellation and close behavior; and
- conformance-suite identity.

A provider cannot return a wider handle than requested or silently substitute
host behavior. Provider loss is explicit and fail-closed.

Providers do not decide product policy, but they run with attenuated backing
capabilities enforced by their host domain or kernel. Dispatch passes scoped
objects/handles, never broad provider authority plus caller-selected resource
identifiers. Compromise of a provider therefore remains bounded by its own
admitted ceiling.

## 6. Implementation sequence

### Step 0: freeze vocabulary and inventory

1. Adopt this document and the universal-application substrate as the joining
   architectural contract.
2. Generate a crate dependency/feature inventory identifying `std`, `alloc`,
   host path, wall-clock, environment, process, socket, and async-runtime use.
3. Inventory every WIT resource and host resource-table entry with owner,
   rights, lifecycle, drop, transfer, accounting, and recovery semantics.
4. Inventory every principal-bearing wire field and prove where it is
   host-stamped versus client-controlled.
5. Record the current capability namespaces and their issuance, persistence,
   revocation, and precedence rules.
6. Classify every consequential host operation as receipt-required or
   observability-only and record its current failure ordering.

Exit gate: no existing authority or handle mechanism is silently replaced, and
each has an explicit retain/adapt/supersede decision.

### Step 1: portable types without behavior changes

1. Add `astrid-resource-types` and its compile matrix.
2. Introduce epoch, generation, owner, kind, rights, transfer, accounting, and
   transition newtypes.
3. Re-export through stable paths where necessary.
4. Add canonical encoding round-trip, malformed input, version rejection, and
   no-allocation tests where required.
5. Add compile-fail or constructor-visibility tests preventing construction of
   admitted handles without host validation.

Exit gate: hosted behavior is unchanged, public API compatibility is checked,
and the portable crate builds under `no_std`.

### Step 2: authoritative execution context

1. Build `AuthorizationContext` from verified socket/gateway/kernel ingress.
2. Resolve alias to `PrincipalUid` once and retain alias only for display.
3. Bind device scope, session, message origin, authority epoch, runtime scope,
   and lifecycle generation.
4. Carry it across nested IPC, fan-out, approval, egress, network, and drop
   paths without accepting guest replacements.
5. Add hostile tests for unstamped, cross-principal, cross-device,
   cross-session, stale-generation, and unknown-origin messages.
6. Remove authority-bearing fallback to load owner/default principal; internal
   work must carry a valid stamped invocation or service lease.

Exit gate: every consequential host import receives the same validated context
and cannot derive authority from payload fields.

### Step 3: one admitted resource vertical slice

1. Implement `AdmittedResourceTable` and preflight checks.
2. Adapt one resource kind end to end.
3. Exercise read borrow, exclusive borrow, explicit delegation, revocation,
   lifecycle replacement, drop, crash, and accounting.
4. Bind every outcome to its declared receipt-required or observability-only
   evidence class; emergency invalidation cannot depend on receipt health.
5. Differentially test the legacy hosted path and the new provider semantics.

Exit gate: stale or cross-principal handles fail before provider invocation,
and cleanup releases all non-durable reservations.

### Step 4: storage and workspace adoption

1. Land and stabilize the host-independent storage/mounted-filesystem work on
   its own evidence.
2. Bind owner-scoped storage/mount leases into the admitted resource table.
3. Replace `home://`/`cwd://` host-path authority with owner/workspace handles
   for migrated call sites.
4. Preserve explicit external host attachments as a separately authorized
   resource kind.
5. Add crash-prefix, migration-from-release, quota, compaction, physical
   reclamation, stale mount, rename/open-handle, and provider restart tests.
6. Revoke and drain owner mounts before principal root purge, revalidate the
   owner epoch on every callback, and add a regression proving a deleted
   principal cannot be resurrected through an old mount.
7. Add durable owner-scoped retention roots for rollback, export, and
   checkpoint promises. Separately close the ephemeral read-open/GC
   registration race without recovering dead-process leases.
8. Extract portable storage model/format/media contracts from hosted adapters
   without changing the released storage format silently.
9. Define application-consistent checkpoint prepare/commit/restore over pinned
   roots; never serialize live handles, secrets, sockets, or authority.

Exit gate: paths only select objects inside an already admitted namespace;
they never select the owner or storage authority.

### Step 5: accounting and delegation

1. Adapt resident-memory leases and fuel reservations to the common accounting
   scope and transition receipts without forcing one generic ledger.
2. Define child/sub-agent budget delegation and unused-budget return.
3. Separate physical host consumption from logical per-principal charges for
   shared immutable objects.
4. Add descriptor, socket, process, stream, storage, and operation-count
   authorities incrementally.
5. Prove crash, cancellation, timeout, deletion, and provider-loss reclamation.

Exit gate: no child or shared cache can escape principal and ancestor ceilings,
and logical accounting is independent of cache warmth.

### Step 6: application and Linux Realm

1. Define the internal execution-provider contract using the common context,
   resource table, lifecycle generations, and portal handles.
2. Forward-port the preserved principal-owned Linux Realm; do not rebuild it
   as an ambient sidecar.
3. Map virtual/block filesystem, network, secrets, clock, entropy, terminal,
   ingress, and tool access to admitted portals. Linux retains its internal
   fork/exec, PID, UID, thread, signal, pipe, and descriptor semantics; Astrid
   supplies compute admission, budgets, lifecycle/cancellation, terminal
   attachment, and external effects. The host `astrid:process` capability is
   not Realm execution.
4. Bind Realm system image and application closure independently of principal
   state.
5. Run Linux/POSIX and Hermes conformance gates before advertising semantics.

Hermes's SQLite/WAL-bearing state must use a block-local filesystem or another
provider that passes the required POSIX durability and locking corpus. 9P is
limited to workspace/import-export and other semantics it proves. The first
filesystem implementation remains a measured provider choice; no filesystem
is promoted into the native authority model.

Exit gate: two hostile principals use the same immutable Hermes closure with
isolated state, authority, lifecycle, and accounting, with no host fallback.

### Step 7: native `no_std` host

1. Freeze the minimal native ABI only after the resource vertical slices prove
   required operations.
2. Reclaim the native-kernel boot, domain, capability, IPC, syscall, fault, and
   audit mechanisms behind the portable resource types.
3. Run a restartable user-space resource service and Principal Store over a
   native block provider.
4. Start a component through the freestanding AOT/Pulley host.
5. Run the same resource conformance corpus against hosted and native Astrid.

Exit gate: the same admitted operation and durable principal state survive a
hosted/native move without changing authority semantics.

### Step 8: public contracts and ecosystem

1. Promote only independently implementable cross-capsule boundaries to WIT.
2. Add typed SDK wrappers that make invalid combinations difficult to build.
3. Add application closure tooling, provider certification, receipts, system
   generations, remote administration, and optional SSH adapters.
4. Consider an Astrid Rust `std` target only after the native ABI is stable and
   a measured workload justifies bypassing both WASM and Linux compatibility.

Exit gate: external providers and applications can implement the contracts
without obtaining ambient authority or depending on hosted internals.

## 7. Prior work disposition

Snapshot decisions are deliberately conservative. Stale branches are evidence
and source material, not merge instructions.

| Work | Reference | Locked disposition |
|---|---|---|
| Kernel charter, threat model, ADRs, evidence | Astrid PRs #1299, #1301, #1305, #1307 | Retain as normative floor |
| Native ABI sketch | Astrid PR #1309 / `docs/kernel-abi-sketch` | Amend after resource vertical slice; do not freeze yet |
| Native kernel executable proof | Draft Astrid PR #1317 / `origin/feat/kernel-skeleton` | Selectively forward-port mechanisms and tests |
| Portable Principal Store | Astrid PRs #1377 and #1390 | Retain current implementation; older #1373/#1375 stacks are superseded |
| Generic compute/workspace attachments | Draft Astrid PR #1365 / `origin/feat/connection-workspace-attachment` | Split and forward-port contracts; do not merge wholesale |
| Resident-memory authority | Astrid PR #1438 | Retain evolved mainline implementation |
| User/fleet/principal ownership | Astrid PR #1470 | Retain current mainline model |
| Standalone local administration | Astrid PR #1473 | Retain as admin-provider seed |
| Host-independent storage and mounts | Astrid PR #1535 / `origin/codex/storage-mounted-filesystem` | Land first after its own CI/correctness gates |
| Actual principal Linux Realm | Preserved draft PR #77 / `b64d8d9` bundle in its source repository | Forward-port after storage and execution-provider contracts |
| Distro compatibility validation | Astrid PR #1024 | Retain as validation floor, not generation architecture |
| Package `supersedes` | Closed Astrid PR #583 and issue #1184 | Reject as system-generation mechanism |
| Remote CLI/contexts | Astrid issues #658 and #688 | Defer as consumers of stamped sessions |
| Dynamic service namespaces | Astrid issue #1406 | Forward design after provider/resource identity is fixed |

### `origin/codex/storage-mounted-filesystem`

**Decision: reclaim and land independently; foundation, not superseded.**

Consume its final volume, owner, mount, migration, registry, audit, workspace,
secret/configuration, and provider boundaries. Do not make the resource-model
branch a second implementation of storage or absorb a 79-commit substrate into
an authority-type PR.

### `feat/kernel-skeleton` / `origin/feat/kernel-skeleton`

**Decision: preserve and selectively forward-port after ABI proof.**

Reclaim boot, domains, page tables, capabilities, IPC/syscalls, trap/fault
delivery, audit order, and test harness. Do not merge the branch wholesale or
add product/compatibility semantics to ring 0. Resolve its existing review and
determinism gaps before promotion.

In particular, replace wrapping object-generation reuse with checked
exhaustion and permanent slot retirement; scope legibility per relation rather
than exposing all relations through one broad capability; and complete
supervisor fault delivery, reclamation, and multi-core evidence before calling
the proof a production kernel.

### Preserved Linux Realm and `origin/feat/linux-realm-runtime`

**Decision: preserve the working Realm; forward-port by contract.**

The authoritative preserved source/artifact work remains in its owning
repository/bundle. The core branch contains useful principal-affine runtime,
memory, filesystem, and service work but is substantially behind main; harvest
tests and mechanisms after re-evaluating them against current runtime identity,
resource ledgers, and storage.

Do not convert the Realm into a host shell, global VM, or hidden foundation for
native capsules.

### `origin/feat/connection-workspace-attachment`

**Decision: supersede as a merge unit; reclaim typed ideas and tests.**

The branch is broad and diverged. Re-evaluate its `WorkspaceAttachment`,
effective-host-state, compute WIT, immutable worker assets, session binding,
workspace identity, and negative tests against current main and final storage
leases. Forward-port narrow commits only where semantics still match.

### Resident-memory and compute branches

**Decision: use evolved mainline authorities; do not resurrect stale branch
heads.**

Current main already contains resident-memory authorities, per-principal fuel
and memory ledgers, principal-affine runtime identity, and substantial storage
accounting work. Extend those types through the common accounting contract.
Reclaim unmerged compute fixtures only after checking patch equivalence and
authority semantics.

### Capability, principal-stamping, and semantic-registry work

**Decision: retain as established floor.**

The current code already includes principal-bound tokens, host-stamped caller
identity, per-device attenuation, principal-owned IPC subscriptions, runtime
authority isolation, exhaustive manifest capability merging, and semantic
capability grants. The resource model composes them; it does not reopen their
security direction.

### Remote contexts, SSH, distro reconciliation, and live removal

**Decision: defer implementation but preserve as dependent requirements.**

Remote authentication/contexts must mint the same principal-bound session
context. SSH/SFTP remain protocol adapters. Distro switching/removal must use
generation and lifecycle transitions so an artifact removed from a selected
closure cannot keep loading from residue.

## 8. Ideas explicitly rejected

The following ideas conflict with the locked direction:

1. **Make Linux the real kernel and put Astrid policy above it.** This leaves
   host identities and ambient Linux authority below Astrid.
2. **Reimplement full POSIX or Rust `std` in ring 0.** Compatibility belongs in
   user-space providers; only native security/recovery primitives belong in
   the kernel.
3. **Treat WIT `own`/`borrow` as the complete security model.** Component-table
   lifetime is necessary but lacks durable owner, epoch, delegation, provider,
   and accounting semantics.
4. **Put the principal in every guest operation payload.** The host-stamped
   invocation context is authoritative; payload selectors invite confused
   deputy failures.
5. **Use path prefixes as durable authority.** Paths operate only inside an
   admitted namespace. External host paths are explicit attachments.
6. **Unify every ledger and provider behind one generic implementation.** Share
   semantics and evidence, not hot-path data structures or failure modes.
7. **Merge all capability systems into one token immediately.** Preserve
   issuance domains and public interfaces while converging on a common
   internal decision and registry model.
8. **Let handles survive restore because state survived.** Restore re-admits
   state under current authority and a new lifecycle generation.
9. **Give every principal a private copy of immutable applications.** Share
   verified immutable bytes and account logical use separately; isolate all
   mutable state.
10. **Run one mutable Hermes process for all principals.** One closure may be
    shared, but logical service instances and mutable authority remain
    principal-affine.
11. **Freeze a public WIT/native ABI before proving a vertical slice.** Freeze
    invariants now; freeze encodings after conformance and migration evidence.
12. **Merge stale branches wholesale to preserve effort.** Reclaim contracts,
    tests, and verified mechanisms against current main.
13. **Silently fall back from a failed Realm/provider to host execution.**
    Provider loss is explicit and fail-closed.
14. **Use an LLM or prompt as the authority evaluator.** Policy assistance may
    explain or propose; cryptographic identity, typed rules, and kernel checks
    decide.
15. **Use one global authority epoch.** Revocation domains are scoped so a
    local change cannot invalidate unrelated principals and services.
16. **Treat all audit events as durable receipts.** Best-effort observability
    and transactionally ordered effect evidence are separate contracts.
17. **Use the interpreted RV64 Realm as the only production backend.** It is a
    semantic oracle and portable recovery lane. Hardware virtualization or
    native-architecture providers may serve production workloads behind the
    same contract and conformance suite.
18. **Persist or serialize raw live handles as authority.** Cross-domain or
    cross-machine use requires re-admission or an explicit signed delegation;
    table slot values are local implementation details.

## 9. Required conformance corpus

### Authority and identity

- guest principal forgery and alias collision;
- cross-principal, cross-device, cross-session, and anonymous operations;
- revoke-before-use, revoke-during-use, single-use replay, issuer loss, and
  registry-revision mismatch;
- attenuation monotonicity and delegation-chain verification;
- principal deletion and recreation under the same alias; and
- inaccessible namespace enumeration.

### Handles and lifecycle

- wrong resource kind and wrong operation right;
- guessed, copied, stale, closed, double-dropped, and cross-instance handles;
- restart, replacement, checkpoint/restore, rollback, provider restart, and
  authority-epoch advance;
- concurrent share versus exclusive mutation;
- cancellation during admission and provider operation; and
- crash before/after each transition commit boundary.

### Accounting

- shared physical object with independent logical charges;
- child attenuation and unused-budget return;
- CPU, memory, storage, descriptor, process, socket, stream, and operation
  exhaustion;
- pressure reclaim acknowledgement and dishonest provider behavior; and
- deletion/crash releasing every non-durable reservation.

### Storage and compatibility

- released-state migration and rollback;
- crash-prefix recovery, compaction, reclamation, quota, and mount revocation;
- filesystem feature profile including rename, durability, locks, mapping,
  open-after-unlink, links, modes, and attributes where claimed;
- Linux syscall/POSIX differential cases for advertised Realm semantics;
- Hermes SQLite, sessions, skills, subprocess, MCP, network, streaming,
  cancellation, and service recovery; and
- absence of host filesystem, process, credential, network, and device escape;
- old mount callback after principal deletion cannot recreate the owner root;
- SQLite WAL/crash, atomic rename plus fsync, advisory locking, memory mapping,
  open-after-unlink, sparse file, link, and corruption-recovery behavior for
  any provider advertised to Hermes; and
- guest UID 0 remains Realm-local and cannot imply Astrid operator, principal,
  owner, or host authority.

### Hosted/native equivalence

- canonical admission and denial vectors;
- identical stale-handle and lifecycle results;
- identical durable-state and migration results;
- provider-semantic profile negotiation; and
- receipts that bind the same logical identities while naming the actual host
  provider.

## 10. Review and acceptance policy

Independent reviews are incorporated as explicit rulings:

- **Accept** when a suggestion tightens an invariant, identifies an existing
  code seam, supplies a missing negative test, or improves migration without
  changing the direction.
- **Amend** when the concern is valid but the proposed mechanism overreaches,
  breaks compatibility, or freezes a public contract prematurely.
- **Reject** when it introduces ambient authority, host-path identity, hidden
  Linux dependence, unioned rights, global mutable tenancy, ring-0 product
  policy, or a second storage authority.
- **Defer** when measurement or a vertical slice is required and the locked
  invariant is sufficient meanwhile.

The review record belongs in this document so later implementation cannot cite
an isolated suggestion while ignoring its ruling and conditions.

## 11. Independent review record

Five read-only reviews inspected current code, relevant remote branches, the
preserved Linux Realm bundle, and the draft plan on 2026-08-18.

### Kernel and resource-model review

- **Accept:** three enforcement moments, the authority tuple, typed epoch
  taxonomy, portable `no_std` resource types, and selective reuse of the native
  cap/object/derivation proof.
- **Amend:** keep the full product tuple above ring 0; the kernel cap table
  carries only mechanism-level object generation, rights, and derivation.
- **Reject:** literal global borrow checking, one universal generation type,
  UUID-string handles as native capabilities, and wholesale kernel-branch
  merge.

### Authority and adversarial-security review

- **Accept:** one typed `UntrustedEnvelope -> StampedInvocation` boundary,
  scoped authority epochs, explicit derivation, immutable approved-request
  snapshots, hierarchical reservations, and negative stale-handle tests.
- **Amend:** distinguish receipt-required effects from best-effort
  observability and migrate alias-bound tokens explicitly to UID-bound future
  formats.
- **Reject:** a global epoch, universal token flag day, runtime union of grants,
  guest-selected principals, `SystemResident` as a tenancy shortcut, and audit
  tracing presented as durable proof.

### Storage and recovery review

- **Accept:** current storage programme as the immediate substrate; volume,
  logical store, filesystem protocol, and mount adapters remain distinct.
- **Amend:** add deletion-driven lease revocation/drain, per-operation owner
  epoch validation, a durable retention-root registry, atomic read-lease/GC
  coordination, and a separately certified Realm filesystem.
- **Reject:** paths/content IDs as authority, current content filesystem as
  general POSIX, every generation retained forever, and existing hosted
  `std`/path/provider types frozen as the native ABI.

### Linux Realm and compatibility review

- **Accept:** principal-owned Realm, explicit service leases for background
  work, Realm/job/descriptor attenuation, block-local database storage, and
  provider-neutral conformance.
- **Amend:** require POSIX behavior rather than freezing ext4 or another
  filesystem before measurement; keep execution-provider Rust contracts
  private until a second implementation establishes the abstraction.
- **Reject:** 9P for Hermes SQLite/WAL, `astrid:process` host execution as Realm
  execution, guest UID 0 as Astrid authority, one mutable cross-principal
  Realm, and the preserved RV64 interpreter as the only production backend.

### Prior-work archaeology review

- **Accept:** land storage first; reuse current mainline ownership, memory,
  runtime-generation, authority, and admin work; split and forward-port compute
  and workspace contracts; forward-port the Realm; then rebase the kernel
  proof.
- **Supersede:** old reference/KV stores, old Core Linux-Realm scaffolding,
  broad workspace/compute and kernel branches as merge units, package-level
  `supersedes`, and host CoW as canonical workspace state.
- **Defer:** SSH, remote contexts, dynamic namespaces, complete system
  generations, and an Astrid Rust `std` target until their prerequisite
  resource contracts are proven.

No review proposed a competing architectural direction that survived the
locked invariants. Accepted findings tighten the same ownership model; amended
findings preserve semantic requirements without prematurely fixing one
provider or public ABI.

A second pass re-read the integrated document. It closed the remaining
priority findings: emergency revocation no longer depends on audit health;
revocation completion requires teardown; session versus service-lease
initiators are explicit; application, object, root, provider, authority, and
lifecycle generations are distinct; durable pins are separated from ephemeral
read leases; provider domains retain their own kernel-enforced ceiling; and
Linux process semantics remain internal to the Realm. No reviewer requested a
new architectural direction after these amendments.

## 12. Definition of locked-plan completion

The plan is ready for implementation when:

- every proposed primitive maps to current code or a named new module;
- prior branches have retain/reclaim/supersede/defer decisions;
- storage remains the immediate dependency;
- public compatibility is preserved;
- `no_std` scope is confined to portable types, native kernel, ABI, and native
  services that require it;
- Linux/POSIX remains a compatibility provider rather than Astrid's native
  authority model;
- security, storage, kernel, compatibility, and recovery reviews have explicit
  rulings; and
- the first vertical slice and its negative/conformance tests are named.

Implementation proceeds in the sequence above. New proposals are evaluated
against the locked invariants before they enter the workplan; they are not
accumulated merely because they are novel.
