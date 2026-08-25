This chapter continues [Astrid Universal Application Substrate](../../astrid-universal-application-substrate.md).

## 15. Security invariants

The implementation must preserve these properties:

1. A guest cannot select or forge its effective principal.
2. A path cannot select an owner outside its admitted mount or portal.
3. A name, descriptor, manifest, endpoint, or object digest is not authority.
4. A child process or sub-agent cannot exceed delegated parent budgets.
5. Shared immutable bytes never make mutable principal state shared.
6. A compatibility workload receives no ambient host process, filesystem,
   network, credential, device, or control-plane access.
7. Portal loss, revocation, provider failure, and stale lifecycle generations
   fail closed without fallback.
8. Checkpoint restore refreshes principal, authority, workspace, network,
   secret, time, and lifecycle bindings.
9. Installation, execution, promotion, ingress publication, and authority grant
   are separate actions.
10. Ring-0 compromise authority stays minimal; filesystems, Linux, application
    policy, package managers, and agent logic remain outside it.
11. Recovery state is reserved and cannot be exhausted by ordinary principals.
12. Every externally consequential effect is attributable to principal,
    application generation, provider, authority epoch, and causal request.
13. Presentation never implies authority; only Astrid-issued admitted action
    handles are invocable.
14. Firmware, loader, distribution, recovery, and first-owner enrollment are
    distinct trust boundaries; none of the first four mints machine-owner
    identity.

## 16. Economic proof

The economic case must be measured against ordinary containers and VMs rather
than asserted from architecture. The benchmark suite records:

- physical bytes for one application versus 10, 100, and 1,000 principals;
- logical per-principal charge and physical deduplication separately;
- cold, warm, and checkpoint-restored startup latency;
- dormant bytes per principal;
- resident memory and CPU under idle, burst, and sustained workloads;
- storage write amplification, compaction, reclamation, and backup cost;
- Realm execution overhead versus native Linux and a conventional container;
- portal latency for files, network, secrets, and tools;
- scale-to-zero recovery time and first-token latency for each selected
  or claimed application fixture;
- update download size and rollback time; and
- operator effort for install, upgrade, recovery, migration, and incident
  inspection.

Claims must state hardware, provider, application generation, workload,
concurrency, durability policy, cache state, and measurement interval. Shared
page-cache warmth and stored green fixtures are not independent economic proof.
Hostile-principal page or cache sharing is not an economic optimization that
overrides the section 5.1 privacy ceiling. Logical charges are reported even
when physical bytes are shared, and they do not close the named leakage
classes.

## 17. Reclaiming previous work

Previous implementation work should be reclaimed by contract and evidence, not
merged wholesale or rewritten from memory.

### 17.1 Host-independent storage and mounts

Treat the landed storage/mounted-filesystem programme
([astrid#1535](https://github.com/astrid-runtime/astrid/pull/1535),
[astrid#1562](https://github.com/astrid-runtime/astrid/pull/1562),
[astrid#1601](https://github.com/astrid-runtime/astrid/pull/1601)) as the
immediate substrate. This specification consumes its `AstridVolume`, owner,
filesystem, mount-lease, workspace, registry, audit, and migration boundaries
rather than creating a parallel application store. `AstridVolume` is
media/projection, not a second ingest.

Dependent work still reconciles remaining public types, filesystem semantic
profile, physical reclamation, and the native block-provider seam against
current main. Historical storage-branch hashes are not merge instructions.

### 17.2 Linux Realm

Recover the preserved Linux Realm source and installable artifact from its
owning repository/branch as inventory, not as a merge unit.
[unicity-aos/aos-ce#77](https://github.com/unicity-aos/aos-ce/pull/77)
(`b64d8d94`, draft, conflicting) is inventory only. A recoverable
RV64-in-WASM oracle plus a BusyBox argv fixture is one compatibility-backend
falsifier; it does not order Hermes, hardware virtualization, or Track N.
Inventory each capability and test against the execution-provider and portal
contracts above. Preserve
principal-resident, no-`host_process`, bounded `realm_shell`, durable home,
workspace, signed worker, and intersection-authority properties.

Forward-port rather than recreate:

- authenticated workspace attachment and lifecycle epochs;
- immutable system generation and checkpoint binding;
- application-consistent durable storage;
- long-lived service supervision;
- network, secret, and ingress portals;
- PTY only when the underlying process semantics are complete; and
- backend-neutral receipts and conformance cases.

Do not promote the current Realm to a production general Linux claim until its
advertised Python, package, network, PTY, filesystem, and service semantics pass
the relevant workload gates.

### 17.3 Native kernel skeleton

Recover the isolated native-kernel branch as the executable proof of boot,
memory protection, domains, capabilities, IPC, legibility, and audit ordering.
Keep it isolated until the current draft's failures, determinism, supervisor
fault delivery, and reclaim behavior are resolved.

The older `astrid-native-kernel.md` implementation programme is retained as a
historical research record, not a normative milestone plan. Its conventional
driver-host, ring-0 virtio bootstrap, System Distro, and Dock milestones are
superseded by this specification, the kernel charter, and the hardware-provider
model. Reclaim mechanisms and tests individually; do not inherit its product or
distribution ownership.

Do not add filesystems, Linux, Hermes, policy engines, or application semantics
to ring 0. The next reclaim increment should connect a small native block/IPC
ABI and a restartable user-space service, then run the hosted/native conformance
corpus.

### 17.4 Earlier unikernel and `no_std` reconnaissance

Retain the useful seams:

- injected `KernelResources` and provider traits;
- portable task/time/storage/capability libraries;
- Wasmtime custom-platform/AOT/Pulley analysis;
- Hermit and other kernels as mechanism references; and
- load-time-bound device handles instead of arbitrary MMIO.

Reject the collapsed premise that a Hermit appliance, a hosted daemon, and the
Astrid trusted kernel are interchangeable projects. They are different hosts
for related contracts with different TCBs and evidence.

## 18. Implementation programme

### Stage A: adopt the contract and consume landed storage

- Review and adopt this specification as the umbrella architecture.
- Consume the landed host-independent storage/mount programme
  ([astrid#1535](https://github.com/astrid-runtime/astrid/pull/1535),
  [astrid#1562](https://github.com/astrid-runtime/astrid/pull/1562),
  [astrid#1601](https://github.com/astrid-runtime/astrid/pull/1601)) rather than
  relanding it.
- Land or rebase the portable resource-types foundation
  ([astrid#1565](https://github.com/astrid-runtime/astrid/issues/1565)
  `800cee5a`) as types only; it is not a behavior or storage change.
- Publish exact storage, filesystem-semantic, mount-lease, owner, and native
  volume contracts from the landed types.
- Fix distro reconciliation so removed artifacts stop loading.
- Inventory crate portability and classify every host dependency.

Exit gate: authoritative Astrid state no longer depends on host directory
layout, no dependent design invents a second persistence authority, and the
portable resource vocabulary is available without claiming runtime behavior.

After Stage A, native machine authority and Realm semantics proceed as
independent tracks. Neither is a hidden prerequisite that freezes the other.

- **Track N, native machine authority:** Stages B and C. Boot, protection,
  DMA mediation, recovery, and one Capsule on the freestanding kernel.
- **Track R, compatibility-Realm semantics:** portable execution-provider,
  portal, isolation, accounting, and recovery contracts for guest ABIs.
  A recoverable RV64-in-WASM oracle plus a BusyBox argv fixture is one
  falsifier for those contracts, not the definition of Realm and not a
  prerequisite for Track N, Hermes, or hardware virtualization. AOS-CE
  PR #77 is inventory only.

Named application or device fixtures such as Hermes or NVIDIA do not order
these tracks. Stage E is a fixture campaign, not architecture sequencing.

### Stage B: standalone boot and machine authority

- Freeze one experimental machine contract and its canonical firmware/loader
  handoff.
- Build deterministic signed boot images containing the kernel, plan-bounded
  init/recovery, and the initial provider bundle.
- Bring up memory protection, domains, scheduling, IPC, timers, interrupt
  routing, IOMMU/DMA mediation, reset/quarantine, capability tables, fault
  delivery, and recovery reserves.
- Prove that no device-specific protocol or conventional driver stack exists in
  ring 0.
- Start one preloaded provider Capsule or isolated device Realm from the signed
  boot plan and publish only its typed service.

Emulator exit gate: QEMU, TCG, or KVM evidence establishes only that the
named experimental machine contract in section 14.4 enforces protection,
capability, IPC, a hostile native domain, and authenticated sealed-bundle
recovery on that emulator. It never establishes bare-metal, no-host, or
hypervisor machine authority, and it does not prove DMA containment against
a malicious hypervisor.

Standalone machine-authority claims are reserved for separately named
physical board, firmware, and device evidence. First-owner enrollment
remains the unresolved ceremony in section 14.5 and is not this gate.

### Stage C: native system services and Capsule host

- Make ABI, identifiers, bounded codecs, authority, and storage-format crates
  compile under their declared `no_std`/`alloc` profiles.
- Bootstrap and supervise distribution-selected implementations of the required
  init/recovery, audit, identity/key, admission, resource-table, time/entropy,
  storage, update, administration, and component-host service classes.
- Run Principal Store through an isolated storage provider over mediated device
  resources.
- Start one existing Capsule through the freestanding component host.
- Run the hosted deployment as a supported adapter and differential oracle for
  the same portable contracts.

Exit gate: the standalone machine recovers durable state and serves one
principal Capsule operation without relying on a host daemon.

### Stage D: native universal-application control plane

- Define and implement application generations, execution providers,
  lifecycle, streams, cancellation, health, checkpoint, receipt, projection,
  action, attachment, and pending-confirmation types.
- Implement principal namespace publication, stale-handle invalidation, and
  typed storage, workspace, network, configuration, secret, and ingress portal
  bindings.
- Prove the projection/action boundary with non-graphical fixtures; graphical
  presentation remains distribution/consumer-owned. Action handles are
  Astrid-issued; host presentation cannot mint or widen them.
- On Track R, prove the portable compatibility contracts. A recoverable
  RV64-in-WASM oracle plus BusyBox argv fixture is one falsifier; it does
  not wait for native HV or Hermes, and those fixtures do not wait for it.

Exit gate: two principals run one immutable application closure on standalone
Astrid with isolated state and resources; revocation and replacement fail
closed.

### Stage E: named compatibility and application fixtures

Linux Realm and Hermes are fixtures, not architecture tracks. They do not
order Track N or Track R, and those tracks do not wait on them. Hermes is
not a native-kernel completion claim.

- Supply compute, storage, clock, entropy, and portal providers from native
  domains.
- Boot Linux Realm as one principal-owned compatibility personality against
  the portable Track R contract. BusyBox argv is a separate falsifier, not
  a prerequisite for that personality.
- If a distribution selects the Hermes fixture, produce its hermetic closure
  and execute H0/H1 through an admitted compatibility provider.
- Store, crash, recover, and receipt the resulting principal state.
- Run the application conformance corpus and record exact cost evidence.

Exit gate: released native artifacts and a reproducible standalone test prove
only the named fixture claim, such as “Hermes runs on standalone Astrid.”
Hosted Hermes may separately satisfy an explicitly hosted-Astrid claim. That
claim still does not prove native machine authority or first-owner
enrollment, and it does not specialize portable contracts to Hermes.

### Stage F: services, administration, distribution, and recovery

- Add application-service tools, supervision, scale-to-zero, attachment,
  reconnect, and current-authority refresh. Hermes may be one fixture for
  those paths; the contracts do not specialize to it.
- Complete authenticated CLI contexts, principal shell/attach, storage mounts,
  and optional SSH/SFTP adapters.
- Let distributions and consuming hosts select product composition and
  presentation without widening Astrid authority.
- Build and test distribution-neutral bootstrap, slot activation,
  System-Generation selection, interrupted-update, rollback, state-migration,
  authenticated-recovery, and destructive-reset primitives and contracts. A
  distribution-owned installer supplies workflow, policy, and presentation.

Exit gate: an authorized operator can install, provision, update, roll back,
recover, administer, and leave a standalone Astrid machine without ambient or
stale authority.

### Stage G: broader machine and application ecosystem

- Qualify additional machine contracts and hardware providers behind the frozen
  resource interfaces.
- Add compatibility personalities only for demonstrated workloads.
- Add graphics, audio, accelerator, input, and other device services through
  typed provider Capsules or isolated device Realms.
- Establish third-party distribution, application, provider, certification,
  and update tooling.

Exit gate: distributions and application authors can target Astrid-native
services or bring existing application closures while Astrid retains one
coherent boot, authority, storage, lifecycle, hardware-resource, and recovery
model.

## 19. Contract and RFC ownership

This document belongs in `astrid` because it governs internal architecture and
cross-repository implementation order. Public capsule-visible WIT changes must
be proposed separately in `astrid-rfcs` and land in canonical `wit` before SDK
and implementation activation.

Expected contract work includes:

- execution provider and application lifecycle;
- lifecycle-stamped service handles and namespace deltas;
- typed stream, terminal, signal, cancellation, and status surfaces;
- stable workspace attachment identity and epoch;
- filesystem semantic profiles and optional operations;
- block-volume portal where compatibility workloads require it;
- network connect/listen and ingress route resources;
- configuration and secret resource delivery;
- checkpoint prepare/commit/restore hooks; and
- application generation, migration, promotion, and receipt types.

Start with internal Rust protocols where possible. A public WIT contract is
justified only when independently released capsules must implement or consume
the boundary.

## 20. Required evidence

No stage is complete from documentation or fixture success alone. This
document is not evidence. The evidence set must include:

- exact source and artifact digests;
- reproducible build instructions;
- negative authority and cross-principal tests;
- crash and power-loss injection at named boundaries;
- cancellation, timeout, quota, and exhaustion cases;
- stale-handle, restart, upgrade, rollback, and revocation cases;
- filesystem and application conformance workloads;
- hosted/native differential results;
- migration from released state, not synthetic state alone;
- hostile manifest, image, checkpoint, and portal inputs;
- measured performance and economics with stated baselines; and
- a claim ledger distinguishing captured, prototyped, verified, and production
  properties.

Execution-scope claims are falsifiable. Each names a subject, a claim,
evidence, and a non-claim:

- **Native kernel.** Claim: boots and enforces protection, capability, and IPC
  on a named machine contract. Evidence: signed image digest, boot log,
  isolation and recovery tests on that contract. Non-claim: QEMU, TCG, or KVM
  evidence establishes only the named emulator machine-contract enforcement
  boundary; it is not bare-metal, no-host, or hypervisor machine authority,
  and not physical ownership.
- **System image.** Claim: authenticates a signed System Generation and
  selected slot. Evidence: signature verification, slot activation,
  rollback/recovery. Non-claim: image presence is not first-owner enrollment.
- **Provider.** Claim: supplies only the advertised semantic profile.
  Evidence: the conformance corpus for that profile. Non-claim: provider
  success is not kernel or owner authority.
- **Storage.** Claim: owner-scoped Principal Store over `AstridVolume` media.
  Evidence: crash/reopen, quota, mount revocation, migration from released
  state. Non-claim: host path or `PathBuf` placement is not owner authority;
  volume is not a second ingest.
- **Realm.** Claim: a named compatibility backend enforces the portable
  execution-provider, portal, isolation, accounting, and recovery contracts.
  Evidence: exact artifact digest and tests on that named backend. A
  recoverable RV64-in-WASM oracle plus BusyBox argv fixture is one such
  falsifier and proves only that named conformance boundary. Non-claim:
  Hermes, NVIDIA, native hardware virtualization, or AOS-CE PR #77 is not
  this proof, and the fixture is not the Realm definition.

## 21. Open decisions

The following decisions require prototypes, measurements, or a later HQ
ruling. Frozen ceilings in this document are not reopened by the list:

1. the first stable execution-provider wire shape and whether it begins as
   internal IPC or canonical WIT;
2. the filesystem/block provider used for SQLite-heavy Realm applications;
3. the network portal boundary: virtual NIC, socket proxy, protocol connector,
   or a measured combination;
4. checkpoint granularity and application-consistency hooks;
5. which hardware-virtualized Realm backend, if any, is proven against the
   portable contract; BusyBox argv does not order that choice;
6. remaining measurements of physical-sharing implementations under the
   section 5.1 privacy ceiling; the ceiling itself is frozen; logical charges
   remain separate and do not close the named leakage classes;
7. remaining cache-implementation evidence under that same ceiling;
8. system-generation migration and rollback behavior when application state
   schemas change;
9. whether an Astrid Rust `std` target provides enough value after the native
   ABI stabilizes;
10. which Hermes feature subset, if a distribution selects that fixture,
    constitutes a released closure; that choice does not specialize the
    application contract;
11. the minimum host-neutral object/action projection contract needed by
    presentation owners without adopting their component grammar; and
12. the first-owner enrollment ceremony. Until it is specified and proven,
    standalone machine-owner claims are unauthorized.

An open decision does not authorize an ambient host fallback, a host-issued
action handle, or a QEMU non-claim as a completion proof.

## 22. Definition of success

This programme succeeds when all of the following are true:

- a signed Astrid image independently boots an authenticated System Generation
  on at least one qualified machine contract without a host operating system or
  conventional privileged driver stack; emulator QEMU/KVM/TCG evidence cannot
  satisfy this no-host machine-authority claim;
- distribution-neutral Astrid primitives let a distribution-owned installer
  provision, update, roll back, and recover that machine while preserving
  ownership, revocation, audit, and principal state;
- an existing non-WASM program runs without treating the host OS as its
  authority;
- every external effect maps to an authenticated, principal-scoped Astrid
  resource;
- one immutable application closure safely serves many isolated principals;
- principal state survives application, Linux distribution, host OS, and
  machine replacement;
- hosted and standalone Astrid pass the same portable semantic conformance
  suite, with deployment-specific claims naming their actual lower boundary;
- a human can authenticate, enter, administer, mount, recover, and leave a
  principal computer with familiar tools;
- a consuming host can safely project Astrid's typed state and admitted
  actions without making Astrid own the graphical interface;
- the native kernel remains `no_std`, small, and free of application/POSIX
  policy;
- compatibility providers supply only the semantics they can prove; and
- measured density, startup, storage, recovery, and operational cost establish
  the economic claim against conventional containers and VMs.

The result is not “Linux inside a WASM capsule.” Astrid is the independently
bootable kernel and universal operating substrate. Distributions select the
signed system composition and product experience above it. Applications may
believe they are running on Linux while Astrid owns the identity, authority,
storage, compute, hardware resources, network, lifecycle, and evidence beneath
them.
