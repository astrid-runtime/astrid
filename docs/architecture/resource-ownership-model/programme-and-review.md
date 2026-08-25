This chapter continues [Astrid Resource Ownership Model](../../astrid-resource-ownership-model.md).

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

1. Rebase and land `astrid-resource-types` from
   [astrid#1565](https://github.com/astrid-runtime/astrid/issues/1565)
   `800cee5a` onto current main. Keep it types-only.
2. Introduce epoch, generation, owner, kind, rights, transfer, accounting, and
   transition newtypes.
3. Re-export through stable paths where necessary.
4. Add canonical encoding round-trip, malformed input, version rejection, and
   no-allocation tests where required.
5. Add compile-fail or constructor-visibility tests preventing construction of
   admitted handles without host validation.

Exit gate: hosted behavior is unchanged, public API compatibility is checked,
and the portable crate builds under `no_std`. Local quality evidence on
`800cee5a` is not a merge or completion claim.

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

1. Consume the landed host-independent storage/mounted-filesystem work
   (#1535/#1562/#1601). Do not reland it or treat `AstridVolume` as a second
   ingest.
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
   shared immutable objects. Apply the substrate privacy ceiling: default
   hostile-principal isolation; no sharing class is permitted unless a named
   evidence-backed threat model covers that exact class, including storage
   contention/timing, dedup observability, shared device queues, and cache
   or microarchitectural channels. Logical charges and non-enumeration do
   not close those leakage classes.
4. Add descriptor, socket, process, stream, storage, and operation-count
   authorities incrementally.
5. Prove crash, cancellation, timeout, deletion, and provider-loss reclamation.

Exit gate: no child or shared cache can escape principal and ancestor ceilings,
logical accounting is independent of cache warmth, and physical sharing has
not relaxed owner isolation or closed the named leakage classes by
accounting alone.

After Steps 1-5, native machine authority and Realm semantics are independent
tracks. Neither waits for the other. The substrate Track N/Track R split and
this Step 6/Step 7 split are the same two tracks, not a native-then-Realm or
Realm-then-native total order.

### Step 6: compatibility-Realm semantics

Track R proves portable execution-provider, portal, isolation, accounting,
and recovery contracts for guest ABIs. A recoverable RV64-in-WASM oracle
and a BusyBox argv fixture is one falsifier for those contracts. It does
not define Realm, does not order Linux Realm, Hermes, hardware
virtualization, or Track N, and does not prove native machine authority or
absence of host or hypervisor authority.
[unicity-aos/aos-ce#77](https://github.com/unicity-aos/aos-ce/pull/77) remains
inventory only. Do not merge it as the Realm backend.

1. Define the internal execution-provider contract using the common context,
   resource table, lifecycle generations, and portal handles. The contract
   is workload-neutral and does not specialize to Linux, Hermes, BusyBox,
   NVIDIA, or any named vendor or device.
2. Prove one named compatibility-backend falsifier, such as the RV64-in-WASM
   oracle and BusyBox argv fixture, against that contract.
3. Inventory the preserved principal-owned Linux Realm as one compatibility
   personality; do not rebuild it as an ambient sidecar, do not treat AOS-CE
   PR #77 as landed, and do not wait on BusyBox to inventory it.
4. Map virtual/block filesystem, network, secrets, clock, entropy, terminal,
   ingress, and tool access to admitted portals. Linux retains its internal
   fork/exec, PID, UID, thread, signal, pipe, and descriptor semantics; Astrid
   supplies compute admission, budgets, lifecycle/cancellation, terminal
   attachment, and external effects. The host `astrid:process` capability is
   not Realm execution.
5. Bind Realm system image and application closure independently of principal
   state.
6. Run advertised Linux/POSIX gates as personality fixtures. Hermes, if
   selected, is a named application fixture and is not a native-kernel
   completion claim.

A SQLite/WAL-bearing application fixture such as Hermes must use a
block-local filesystem or another provider that passes the required POSIX
durability and locking corpus. That requirement is a falsifier for the
advertised filesystem profile; it does not specialize the storage or
provider contract to Hermes. 9P is limited to workspace/import-export and
other semantics it proves. Filesystem implementation remains a measured
provider choice; no filesystem is promoted into the native authority model.

Exit gate: a named compatibility-backend falsifier recovers and executes
without host-process fallback. A later named application fixture such as
Hermes, if claimed, still requires two hostile principals using the same
immutable closure with isolated state, authority, lifecycle, and accounting,
and with no host fallback. Those fixture gates do not order architecture
tracks.

### Step 7: native `no_std` host

Track N is independent of Track R after the types/storage foundation.

1. Freeze the minimal native ABI only after the resource vertical slices prove
   required operations.
2. Reclaim the native-kernel boot, domain, capability, IPC, syscall, fault, and
   audit mechanisms behind the portable resource types.
3. Run a restartable user-space resource service and Principal Store over a
   native block provider.
4. Start a component through the freestanding AOT/Pulley host.
5. Run the same resource conformance corpus against hosted and native Astrid.

QEMU, TCG, and KVM boot evidence establishes only a named emulator
machine-contract enforcement boundary. It cannot prove bare-metal, no-host,
or hypervisor machine authority, DMA containment against a malicious
hypervisor, or first-owner enrollment.

Exit gate: the same admitted operation and durable principal state survive a
hosted/native move without changing authority semantics. That gate is not a
standalone-machine ownership claim.

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
| Host-independent storage and mounts | Astrid PRs #1535, #1562, #1601 on current main | Landed; consume as media/projection, not a second ingest |
| Portable resource types | Astrid issue #1565 / `codex/resource-types-foundation` `800cee5a` | Quality-clean types foundation, not merged; rebase as Step 1 |
| Actual principal Linux Realm | Preserved draft unicity-aos/aos-ce PR #77 / `b64d8d94` | Inventory only; Linux Realm is one compatibility personality; RV64-in-WASM plus BusyBox argv is one falsifier |
| Distro compatibility validation | Astrid PR #1024 | Retain as validation floor, not generation architecture |
| Package `supersedes` | Closed Astrid PR #583 and issue #1184 | Reject as system-generation mechanism |
| Remote CLI/contexts | Astrid issues #658 and #688 | Defer as consumers of stamped sessions |
| Dynamic service namespaces | Astrid issue #1406 | Forward design after provider/resource identity is fixed |

### `origin/codex/storage-mounted-filesystem`

**Decision: landed; consume, do not reland.**

PRs #1535, #1562, and #1601 are on current main. Consume the landed volume,
owner, mount, migration, registry, audit, workspace, secret/configuration, and
provider boundaries. `AstridVolume` is media/projection, not a second ingest.
Do not make the resource-model branch a second implementation of storage.

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

**Decision: inventory only as a merge unit. Linux Realm is one compatibility
personality, not the native OS. RV64-in-WASM plus BusyBox argv is one
falsifier, not the Realm definition and not a sequencing gate.**

The authoritative preserved source/artifact work remains in its owning
repository/bundle, including draft unicity-aos/aos-ce PR #77 (`b64d8d94`).
That PR is conflicting inventory, not a backend to merge. The core branch
contains useful principal-affine runtime, memory, filesystem, and service work
but is substantially behind main; harvest tests and mechanisms after
re-evaluating them against current runtime identity, resource ledgers, and
storage.

Do not convert the Realm into a host shell, global VM, or hidden foundation for
native capsules. Do not treat QEMU or hosted Realm success as native machine
authority.

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
17. **Use the interpreted RV64 Realm as the only production backend.** It is
    one semantic oracle and a portable recovery lane, plus a BusyBox argv
    fixture. Hardware virtualization or native-architecture providers may
    serve production workloads behind the same contract and conformance
    suite; the fixture does not order them.
18. **Persist or serialize raw live handles as authority.** Cross-domain or
    cross-machine use requires re-admission or an explicit signed delegation;
    table slot values are local implementation details.
19. **Treat QEMU, TCG, or KVM success as bare-metal, no-host, or hypervisor
    machine authority, or as proof that host or hypervisor authority is
    absent.** Those runs establish only a named emulator machine-contract
    enforcement boundary.
20. **Let a host mint or widen action handles through labels, icons, or
    layout.** Presentation is not authority; Astrid issues admitted action
    handles.
21. **Treat a default root account, local console, or first network caller as
    machine owner.** First-owner enrollment is an unresolved ceremony and is
    not implied by firmware, loader, distribution, or recovery.
22. **Merge AOS-CE PR #77 as the Realm backend.** It is inventory only.

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
- named application-fixture cases such as Hermes SQLite, sessions, skills,
  subprocess, MCP, network, streaming, cancellation, and service recovery,
  when that fixture is claimed; and
- absence of host filesystem, process, credential, network, and device escape;
- old mount callback after principal deletion cannot recreate the owner root;
- SQLite WAL/crash, atomic rename plus fsync, advisory locking, memory mapping,
  open-after-unlink, sparse file, link, and corruption-recovery behavior for
  any provider advertised to a SQLite/WAL application fixture; and
- guest UID 0 remains Realm-local and cannot imply Astrid operator, principal,
  owner, or host authority.

### Hosted/native equivalence

- canonical admission and denial vectors;
- identical stale-handle and lifecycle results;
- identical durable-state and migration results;
- provider-semantic profile negotiation; and
- receipts that bind the same logical identities while naming the actual host
  provider.

Execution-scope claims are falsifiable and use the same subject/claim/evidence/
non-claim ledger as the universal-application substrate: native kernel, system
image, provider, storage, and Realm. QEMU/KVM/TCG establishes only a named
emulator machine-contract enforcement boundary; it cannot prove absence of
host authority or standalone machine ownership. Hosted success cannot prove
standalone machine ownership.

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
- **Reject:** 9P for a SQLite/WAL application fixture, `astrid:process` host
  execution as Realm execution, guest UID 0 as Astrid authority, one mutable
  cross-principal Realm, and the preserved RV64 interpreter as the only
  production backend.

### Prior-work archaeology review

- **Accept:** consume landed storage; rebase #1565 types; reuse current
  mainline ownership, memory, runtime-generation, authority, and admin work;
  split and forward-port compute and workspace contracts; take AOS-CE PR #77
  as inventory; Linux Realm is one compatibility personality; RV64-in-WASM
  plus BusyBox argv is one falsifier, not a sequencing gate; native machine
  authority is a parallel track, not a later hidden prerequisite.
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
- landed storage is consumed rather than relanded;
- public compatibility is preserved;
- `no_std` scope is confined to portable types, native kernel, ABI, and native
  services that require it;
- Linux/POSIX remains a compatibility provider rather than Astrid's native
  authority model;
- security, storage, kernel, compatibility, and recovery reviews have explicit
  rulings; and
- the first vertical slice and its negative/conformance tests are named.

This list is a start-work gate, not a standalone completion claim.
Implementation proceeds in the sequence above, with Track N and Track R
independent after types and storage. New proposals are evaluated against the
locked invariants before they enter the workplan; they are not accumulated
merely because they are novel.
