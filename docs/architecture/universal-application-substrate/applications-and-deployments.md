This chapter continues [Astrid Universal Application Substrate](../../astrid-universal-application-substrate.md).

## 11. Agents are applications

Astrid does not make the agent. An agent may run inside Astrid as:

- an existing harness such as Hermes inside a compatibility Realm;
- a native Capsule composition whose replaceable parts provide a loop, model
  access, memory, tools, ingress, and presentation; or
- another application graph selected by a distribution or user.

The composition mechanism stays small: verified component identities, typed
links, resource attachments, state roots, authority requests, and lifecycle
selection. Astrid does not assign special kernel meaning to “agent”, “ReAct”,
“model”, “memory”, “tool”, or “prompt”.

A distribution may expose a composition as maximally inspectable and hackable:
parts can be replaced, rewired, or developed locally, with each executable
change producing a new application generation and fresh admission. It may
instead publish a frozen, reproducible, signed closure whose parts change only
through reviewed generation replacement. Hackable and frozen are policies over
the same composition format; neither requires a second runtime or authority
model. Mutable principal state remains separate in both cases.

Hermes is a non-normative fixture and falsifier because it combines Python,
native wheels, HTTP model access, MCP, subprocesses, skills, persistent
memory, SQLite, long-lived gateway operation, messaging ingress, and human
terminal UX. That combination does not make Hermes product identity, a
required dependency, or sequencing authority for provider, resource,
device, or application contracts. Fixture slices below do not order
Track N, Track R, or any other architecture track.

Hermes is not the Astrid agent, a mandatory system service, or the template
every native agent must copy.

### 11.1 Sharing and isolation

When a distribution selects a Hermes fixture, Astrid stores one immutable
Hermes closure and one or more compatible Realm system generations. Each
authorized principal receives a separate Hermes service instance and private
`HERMES_HOME`. Immutable Python packages and image pages may be reused;
configuration, sessions, databases, memory, skills, credentials, processes,
and workspaces may not. The same share-bytes-not-authority rule applies to
any other application closure; the contract does not specialize to Hermes.

### 11.2 Initial compatibility closure

A Hermes fixture closure, if selected, must contain:

- an exact upstream Hermes revision;
- Python within Hermes's declared supported range;
- all direct and transitive dependencies with hashes and provenance;
- prebuilt guest-architecture native extensions or reproducible source-build
  derivations;
- CA roots and timezone data;
- a fixed launcher and configuration schema;
- no online `pip`, `uv`, package-hook, or `curl | sh` step at activation; and
- an SBOM and vulnerability-review receipt.

The current Realm Python and Hermes Python constraints must be reconciled in the
image derivation rather than bypassed with an unsupported interpreter.

### 11.3 Vertical slices

#### H0: dependency and filesystem proof

- Import the immutable Hermes closure without network installation.
- Place one private `HERMES_HOME` on an application-consistent durable provider.
- Run Hermes import, configuration, SQLite, skill discovery, and session-store
  probes without a model call.
- Crash at named storage boundaries and prove recovery.

#### H1: one governed turn

- Admit one principal and one workspace.
- Deliver one model-provider capability through a governed connector or
  domain-scoped HTTPS portal.
- Run one headless Hermes turn with a minimal tool set.
- Bind result, model, application generation, principal, workspace generation,
  egress policy, resource use, and state transition into a receipt.

#### H2: Astrid tool plumbing

- Expose the principal's live Astrid capability namespace to Hermes through a
  stable adapter.
- Prefer typed remote tools/connectors over guest-local replicas.
- Map approvals and cancellation across the boundary.
- Prove that a tool visible to Alice is neither enumerable nor callable by Bob.

#### H3: supervised service

- Run the Hermes API/gateway as a supervised principal service.
- Publish readiness atomically and support streaming, cancellation, draining,
  restart, and checkpoint-aware recovery.
- Scale an idle instance to cold state and restore it without changing service
  identity or losing committed sessions.

#### H4: human ergonomics

- Attach a terminal when PTY semantics are available.
- Support messaging ingress through Astrid routes and connector capsules.
- Support authorized SSH attachment to the principal computer without exposing
  a host shell.

### 11.4 Hermes claim gate

Astrid may claim “Hermes runs on Astrid” only when H1 passes on a released
standalone Astrid System Generation. It may claim “Hermes is an Astrid service”
only when H3 passes natively. It may claim “multi-principal Hermes” only after
the concurrent hostile isolation, accounting, restart, and revocation corpus
passes on standalone Astrid. Hosted results remain differential evidence.
Those gates falsify Hermes claims only. They do not gate portable provider,
resource, device, or application contracts, and they do not order architecture
tracks.

## 12. Human and operator access

### 12.1 Higher-layer experience enabled by Astrid

Astrid does not own or render a graphical desktop, Home, component tree, or
personal interface. Higher-layer hosts may build those experiences over the
substrate defined here. This section describes a forcing consumer experience,
not an Astrid-owned product surface or kernel service.

A graphical host may present a small number of immediately legible
concepts:

- **Spaces:** personal or collaborative compositions of work, people, agents,
  services, and explicitly attached resources;
- **ongoing work:** durable activities that can be resumed where they were
  left;
- **collaborators:** humans and agents such as Hermes acting inside the current
  admitted context;
- **owned things:** semantic objects the person can inspect or use directly;
  and
- **changes:** an attributable timeline of consequential effects, receipts,
  and available compensating or rollback operations.

Such an experience answers “where am I?”, “what is happening?”, “what can I
continue?”, and “what can I ask?” without exposing principals, capabilities,
mounts, Realms, providers, or generations as normal product vocabulary. Those
mechanisms remain available through progressive disclosure for administration,
recovery, and exact authority inspection.

A Space is a higher-layer presentation and navigation composition with
explicit Astrid resource attachments.
It is not a principal, owner, capability set, policy realm, filesystem
namespace, or ambient context switch. Entering or sharing a Space never changes
the kernel-stamped principal or widens the accessible resource set. Missing or
stale attachments become non-enumerating unavailable placeholders and never
silently retarget. Cross-Space drag/drop proposes a typed copy, move, share, or
delegation operation; it does not itself transfer authority.

### 12.2 Host-facing semantic state and action boundary

Astrid exposes principal-scoped typed objects, relationships, current state,
and proposed actions through a host-neutral boundary. A consuming host may
translate that boundary into A2UI, graphical, terminal, accessibility, or other
native experiences. Astrid does not own layout, components, rendering,
personalization, or the visual metaphor.

The normative invariant is:

> A host projection of Astrid state is never Astrid identity, authority,
> consent, or policy. Presentation and personalization remain host concerns.

The architecture separates three concerns:

1. an **Astrid projection boundary** exposing bounded typed state, object
   identities, eligible action descriptors, and Astrid-issued admitted action
   handles;
2. a **host-owned experience** controlling scenes, components, layout, density,
   modality, accessibility, theme, and personalization; and
3. an **Astrid enforcement boundary** controlling authenticated context,
   authority validation, action dispatch, lifecycle, and receipts.

Astrid's boundary contains no HTML, JavaScript, CSS, webviews, layout tree, or
executable presentation instructions. Any A2UI-like component grammar and its
rendering limits belong to the consuming host.

Astrid issues every actionable element's opaque admitted action handle. The
handle is an Astrid table entry, not a host token. Its entry binds the
canonical action-descriptor digest, view revision, target semantic-object
identities, typed arguments, authority delta, confirmation policy, expiry, and
relevant principal/session/application/provider/lifecycle/attachment epochs.
A host may present labels, icons, ordering, layout, and component state derived
from the descriptor. Presentation never mints, copies, widens, or substitutes
an action handle, and a visible control is not authority. Every invocation
revalidates current authority through the ordinary admission path.

For authority expansion Astrid emits typed pending-operation data and a
single-use challenge bound to the exact operation and authenticated context. A
trusted host decides how to present that decision and returns the bound
response; Astrid validates and consumes it. Astrid does not own the graphical
chrome, but arbitrary application or agent content cannot substitute for the
host's confirmation path. Generic semantic `Confirm`, clicks, drag/drop, or
elicitation responses are not consent.

Type metadata may be cached globally, but the visible semantic catalog is
filtered by the current stamped principal, admitted application/Space
attachments, and exact generations. Knowing a schema, topic, name, or receipt
grants no right to enumerate, subscribe, publish, invoke, or view data. Schema
collisions reject rather than overwrite. WIT descriptions and agent prose are
untrusted descriptive content, not security language.

The earlier in-runtime agent-owned A2UI/TUI design in issues #629 and #630 is
not revived. Build internal Rust projection/action domain types first. A
presentation owner may separately prove an A2UI-like protocol and
multiple renderers without making Astrid itself the UI framework.

### 12.3 Authentication and principal selection

Remote access authenticates a user/device or machine credential first. The
session then requests a principal view. The authority service verifies that the
authenticated subject owns, operates, or holds an explicit delegation for that
principal.

```text
device or user authentication
  -> authorized principal selection
  -> principal-bound session capability
  -> capability namespace and optional workspace attachments
  -> shell, service, filesystem, and management operations
```

The selected principal cannot be changed by a later command argument. An admin
“act as” operation is an explicit, scoped, time-bounded delegation with an audit
record. User identity, fleet role, principal ownership, and operator authority
remain distinct.

### 12.4 Native administration

The primary interface is the Astrid CLI/API, with context switching across
hosts. It should provide at least:

```text
astrid context add|list|use|current
astrid auth login|status|logout
astrid principals list|show
astrid services list|show|start|stop|restart
astrid exec --principal <p> -- <command>
astrid attach --principal <p> <service-or-session>
astrid logs --principal <p> --follow
astrid usage --principal <p>
astrid grants inspect|trace|revoke
astrid storage mount|status|sync|unmount
astrid system generations|switch|rollback|doctor
```

The API returns typed state. Terminal rendering is a client concern.

### 12.5 SSH compatibility gateway

An optional SSH gateway may preserve familiar `ssh`, terminal forwarding, and
SFTP ergonomics. It is a protocol adapter to the same authenticated Astrid
session and never an ambient Unix login service.

- SSH public keys bind devices/users, not unrestricted host accounts.
- Requested user/principal names are authorization requests.
- A shell attaches to a principal-owned Realm or native management session.
- SFTP projects an owner-bound storage lease.
- Port forwarding requires separate ingress/egress capabilities.
- Agent forwarding, host filesystem access, and host process access are denied
  unless separately modeled and explicitly granted.
- Session close revokes invocation-scoped attachments and handles.

Local recovery retains a minimal console path that can inspect boot slots,
storage health, authority epochs, audit integrity, and service failures without
requiring the normal application stack.

## 13. Distro and Nix-inspired generation model

Astrid should adopt the useful Nix properties without making Nix its kernel or
authority model:

- content-identified immutable inputs and outputs;
- complete closure verification;
- reproducible derivations;
- atomic profile/generation switching;
- rollback by root selection;
- shared physical artifacts under the section 5.1 privacy ceiling;
- garbage collection from declared live roots; and
- a strict separation between immutable system and mutable state.

Two meanings of “distro” must remain explicit:

1. An **Astrid distribution** is a signed composition of capsules, applications,
   services, compatibility Realms, configuration schemas, and authority
   requests. It is a distribution built on Astrid, analogous to a Linux
   distribution rather than an operating system beneath Astrid. It owns product
   selection, defaults, channels, installer policy, and presentation; Astrid
   owns the boot, authority, resource, storage, Capsule, generation, and
   recovery contracts it must satisfy.
2. A **Linux distribution generation** is an optional compatibility image
   selected by an Astrid application or system generation.

Reprovisioning a distro must transactionally reconcile the installed set.
Artifacts removed from the new signed closure cannot continue loading merely
because old directories remain. Side-loaded artifacts have separately recorded
provenance and are not silently pruned as if they belonged to the distro.

A distribution decides which compositions are editable, which inputs may be
overridden, and which closures are frozen. Astrid supplies one transparent
generation mechanism for both: edits never mutate an already identified
closure; they derive a new candidate, make its authority delta visible, and
switch only after admission. A frozen distribution may disable local
derivation entirely.

## 14. Standalone and hosted deployments

### 14.1 Hosted Astrid

The current daemon is a supported hosted deployment and remains useful for
incremental adoption, development, migration, CI, and differential conformance.
It may use Tokio, Wasmtime, host files, sockets, platform mounts, and OS
sandboxes internally. Those dependencies live behind provider traits and do not
define Astrid resource identity. Its security statement names the inherited
host boundary explicitly. A hosted result can complete a hosted claim, but not
a standalone boot, machine-authority, DMA, recovery-independence, or physical
hardware claim.

### 14.2 Standalone Astrid

The freestanding system uses:

- a minimal `no_std` capability kernel in ring 0;
- restartable ring-3 init/recovery, runtime, storage, identity, admission,
  network, audit, update, hardware-provider, and application domains;
- a `no_std`/`alloc` component host using verified AOT or Pulley artifacts;
- the same Principal Store formats and logical protocols over a native block
  provider;
- the same signed system/application generation model; and
- the same principal namespace, execution-provider, portal, and receipt
  semantics.

Linux runs as a Realm in user space. It is one compatibility personality,
not the native OS. A recoverable RV64-in-WASM oracle plus a BusyBox argv
fixture is one compatibility-backend falsifier for that personality. A
hardware-virtualized backend may implement the same portable contract where
available; BusyBox does not order that choice. Either backend must reproduce
the same authority, storage, portal, lifecycle, checkpoint, and accounting
contract. Neither QEMU nor a hosted Realm proves native machine authority.

### 14.3 Conformance corpus

The same corpus must run against hosted and native providers:

- capability visibility and stale-handle rejection;
- owner-scoped file/object/KV operations and crash recovery;
- application generation admission and rollback;
- execution, cancellation, resource exhaustion, and process-tree cleanup;
- network destination/listener policy and revocation;
- secret isolation and rotation;
- checkpoint authority refresh;
- receipt completeness for receipt-required effects plus declared behavior for
  observability loss; and
- concurrent hostile principals.

Provider-specific performance is reported separately from semantic conformance.

### 14.4 Mandatory boot and recovery chain

```text
firmware / UEFI
  -> firmware authenticates the Astrid loader
  -> loader separately verifies the Astrid kernel/bootstrap closure and the
     distribution-supplied immutable System Generation, then preloads both
  -> ring 0 establishes CPU, memory, protection, scheduling, IPC, discovery
     facts, interrupt routing, IOMMU/DMA mediation, reset, and capabilities
  -> plan-bounded init/recovery realizes the selected A/B system generation
  -> hardware claims are transferred to isolated provider Capsules or dedicated
     compatibility/device Realms
  -> audit, storage, Principal Store, identity/key, time/entropy, component-host,
     admission, network/uplink, update, and administration services become ready
  -> principals, Capsules, compatibility Realms, and applications may start
```

The sealed boot bundle contains enough authenticated provider artifacts to
reach storage and recovery without conventional device-specific code in ring
0. One experimental machine-contract fixture is x86-64 QEMU/KVM with UEFI,
fixed memory, one CPU, serial diagnostics, APIC timer, and an explicit
virtio/IOMMU topology. That named emulator example does not specialize
portable provider, resource, or device contracts, and it does not order
architecture tracks. QEMU, TCG, and KVM runs establish only the named
emulator machine-contract enforcement boundary. They are functional and
conformance evidence for that emulator contract. They never establish
bare-metal, no-host, or hypervisor machine authority, DMA containment
against a malicious hypervisor, or physical-machine ownership. Standalone
machine-authority claims are reserved for named physical board, firmware,
and device evidence. First-owner enrollment remains the unresolved
ceremony in section 14.5 and is not this contract. The contract becomes a
supported machine only after install, interrupted-update, rollback,
recovery, isolation, and hardware-provider gates pass on its exact named
claims. Physical-hardware support requires a separately named board,
firmware, and device contract with continuous hardware evidence.

### 14.5 Trust-boundary handoff and first-owner enrollment

Machine authority is a chain of named handoffs, not a successful boot log.
Each stage authenticates the next and cannot mint owner identity for the one
after it:

```text
board firmware
  -> authenticates the Astrid loader; firmware identity is board evidence,
     not Astrid owner identity
  -> loader verifies the kernel/bootstrap closure and the distribution
     System Generation as separate signed artifacts
  -> ring 0 accepts only those verified closures and establishes protection,
     DMA mediation, and capability transfer
  -> recovery/init realizes the selected generation from the sealed bundle
  -> first-owner enrollment binds a user/device credential to machine
     ownership through a dedicated ceremony
  -> ordinary principal login, remote administration, and application start
     consume that enrolled ownership; they never create it
```

Distribution signing selects and authenticates the System Generation. It does
not enroll the machine owner and does not make the first installer process an
administrator.

The first-owner ceremony is an unresolved contract. Until it is specified and
proven, no product claim of the form "this standalone machine has an owner" is
authorized. The freeze already rejects these substitutes:

- a default root or first-user account;
- local console presence as administrator authority;
- first network caller, first CLI context, or first SSH key as owner;
- TOFU of an unauthenticated daemon as machine ownership; and
- recovery-console reachability as enrollment.

The unresolved ceremony must bind an authenticated user/device credential to
machine ownership, be distinct from ordinary principal login, survive
interrupted update and recovery, and fail closed if no owner has been
enrolled. This document does not choose the ceremony mechanism.
