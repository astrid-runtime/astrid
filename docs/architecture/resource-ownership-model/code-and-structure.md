This chapter continues [Astrid Resource Ownership Model](../../astrid-resource-ownership-model.md).

## 4. Existing code: retain, extend, or replace

This plan was originally grounded on `origin/main` at `0452b6a0` and an
earlier snapshot of `origin/codex/storage-mounted-filesystem`. Those hashes and
historical green runs are archaeological evidence, not merge evidence. Storage
PRs #1535, #1562, and #1601 have merged to current main (`6e43da5f`). Consume
the landed `AstridVolume`, owner, mount, and recovery contracts. Do not reland
those PRs, invent a second ingest, or treat a host `PathBuf` as owner
authority. Volume WAL is the `AstridVolume` region `transactions.wal` and is
default off. Paths and symbols below are code anchors, not claims that every
intended semantic is already complete.

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

The landed storage programme supplies the required volume, owner-bound
filesystem, mount, provider, migration, audit, registry, secret/configuration,
and workspace transitions. The merged types on current main are the storage
substrate. `AstridVolume` is media/projection for the one catalog CAS/blob
path, not a second ingest and not an owner. WAL, when enabled, is the volume
region `transactions.wal`; default policy leaves it off.

The model depends on these separations:

```text
AstridVolume
  != logical Principal Store
  != owner-bound filesystem protocol
  != FSKit/FUSE/WinFsp mount adapter
  != Linux Realm filesystem semantics
```

The resource model adds authority/lifecycle bindings to storage leases. It
does not create another persistence engine, a second ingest, or a host-path
owner.

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

Create `crates/astrid-resource-types` as an internal-first crate. The
quality-clean types foundation on `codex/resource-types-foundation`
`800cee5a` ([astrid#1565](https://github.com/astrid-runtime/astrid/issues/1565))
is the intended starting point. It has no pull request and is not merged;
rebasing it onto current main is types work, not a behavior change.

Create the crate with:

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
no implicit default principal. `ServiceLease` is a typed initiator binding
into live `ResourceAuthority`; it is not a serializable substitute for that
tuple. Requested `resource_scope` and reserved `budget` are validated
against the live host tuple in preflight, not reconstructed from the lease
alone.

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
6. validate requested `resource_scope` and reserved `budget` against the
   live host bindings (bounded scope plus resource-envelope or linked
   reservation identity), not merely `accounting_scope` or remaining
   capacity;
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
sufficient for a named application-fixture claim such as Hermes H1, or for a
general “every effect receipted” claim. The transactional effect-journal
boundary must be implemented before those claims. Fixture claim gates do not
specialize the receipt contract.

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
