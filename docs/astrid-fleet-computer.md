# Astrid fleet computer and principal views

Status: proposed architecture

Last reviewed: 2026-08-15

Related documents:

- [Astrid user and fleet ownership](astrid-user-fleet-ownership.md)
- [Astrid Principal Store](astrid-principal-store.md)
- [Astrid Principal Store Runtime Realization](astrid-principal-store-runtime.md)
- [Astrid Native Component Kernel](astrid-native-kernel.md)
- [AOS Principal Linux Realm](https://github.com/unicity-aos/aos-ce/blob/main/docs/principal-linux-realm.md), an optional Linux capsule consumer

## 1. Product ruling

Astrid should host lightweight fleet computers for multiple users. Every user
has a home fleet. That fleet contains the user's agent and service principals
and owns their shared computer authority, filesystem, browser identity,
applications, and budget. Every agent receives an independent view and session
over that shared computer; services receive only the views their compositions
need.

The ordinary experience is:

1. A person starts Astrid and receives a durable `UserUid`, a home fleet, and
   one agent principal.
2. The person creates additional specialized agents in that fleet. Each may use
   a different capsule-composed harness while retaining an Astrid principal
   identity. External AI hosts attach through AOS connectors.
3. Every agent uses the same fleet computer: common files, installed software,
   browser sign-ins, cookies, and ambient fleet authority. Linux is available
   when the optional Linux Realm capsule is installed.
4. Every agent has its own overlay, process/session view, desktop, working
   context, history, and attribution, so concurrent agents do not accidentally
   overwrite or commandeer one another's active work.
5. Agents communicate through a kernel-stamped team service and may cooperate
   directly through fleet-owned files and applications.
6. An authorized person can open a terminal, mount a filesystem view, or attach
   to the desktop belonging to a selected agent.

Within one user's cooperative fleet, "one computer" is literal at the product
level: agents may share browser identity, writable fleet roots, application
state, and an ambient computer-authority profile. A Linux provider may project
that profile as one shared Unix user. Principal views prevent collisions and
preserve identity; they are not falsely claimed as adversarial isolation.
Separate users' home fleets remain separate tenant security domains.

The referenced Grok Bot desktops establish the desired user-visible experience,
not their internal implementation. Shared cookies and ambient computer authority
are accepted here as reported target behavior; Astrid must define and verify its
own storage, concurrency, recovery, and tenant boundaries.

The tenancy model therefore has two nested cardinalities:

```text
one Astrid installation
  -> many UserUid tenants
  -> one stable home FleetUid per user
  -> many PrincipalUid actor tenants per home fleet
```

The user fleet is the security and ownership tenant. Principals are independent
actors and views inside that tenant.

## 2. Identity and ownership boundaries

The existing concepts retain distinct jobs:

| Concept | Role in the fleet computer |
| --- | --- |
| `UserUid` | Durable human authority and authentication subject |
| `FleetUid` | One user's home-computer tenant, team policy, shared authority, shared resources, and aggregate budget boundary |
| `PrincipalUid` | Durable executable actor identity of one agent or service within the fleet computer |
| `GroupName` | Reusable capability role; never an ownership container |
| application identity | Identity and lifecycle of installed software below its owning fleet or principal |
| invocation or job | One bounded execution under an acting principal |

A principal does not imply a brain, model, prompt, or conversational agent. It
is the durable identity of something that acts with separately attributable
authority. A principal may run an AI harness, a vault, an indexer, a scheduler,
a browser service, or another capsule-composed service. A vault merits its own
principal when it actively receives requests, holds capabilities, owns state,
and needs independent revocation, accounting, or audit. Passive vault data may
instead remain a fleet- or principal-owned resource served by an existing
principal; not every object needs another actor identity.

A specialized durable bot is a separate principal owned by the fleet. It is not
a sub-agent sharing a parent principal's identity. "Sub-agent" may describe a
temporary orchestration relationship, but it cannot define durable ownership,
storage, audit attribution, revocation, or resource accounting.

An ephemeral worker may remain inside one principal only when it requires no
independent durable identity, policy, state, or revocation boundary. Promotion
from worker to durable teammate creates a new principal explicitly.

Every user has one home fleet for their own computer and agents. A user may also
receive a role or bounded collaboration grant in another user's fleet without
losing their home fleet. One principal has at most one owning fleet.
Transferring a principal between fleets is an explicit ownership transition,
not a filesystem move or alias change.

The home fleet's default cooperative profile intentionally gives its agents the
same baseline computer authority and common data. Separate rights still govern
human administration, remote desktop observation, recovery, fleet transfer,
principal impersonation, and access to non-filesystem secrets. Cross-fleet
access is always an explicit, audited delegation.

## 3. The filesystem is a composed view

Astrid already has a canonical, Linux FHS-aligned version-one hierarchy. Layout
version two extends it rather than replacing it. The final visible contract is:

```text
Astrid/
├── etc/                         deployment configuration and policy
│   ├── config.toml
│   ├── servers.toml
│   ├── gateway.toml
│   ├── groups.toml
│   ├── hooks/
│   ├── profiles/{principal}.toml
│   └── layout-version           contains 2 after committed migration
├── var/                         persistent system state
│   ├── principal-store/         authoritative typed multi-owner store
│   ├── content-staging/         private acknowledged-write staging
│   ├── migrations/              durable layout intents and receipts
│   └── state.db/                retained v0.10.4 legacy import source
├── run/                         ephemeral runtime endpoints, mounts, sessions
├── log/                         system logs
├── keys/                        runtime and local identity keys
├── secrets/                     capability-mediated secret backing
├── bin/                         content-addressed compiled components
├── lib/                         shared component libraries
├── wit/                         canonical and content-addressed WIT
│   └── store/
├── srv/                         fleet-owned data served by Astrid
│   └── fleets/
│       └── {fleet_uid}/
│           ├── shared/          durable common files
│           └── workspaces/      explicit attachment points, not copied roots
├── home/
│   └── {principal}/
│       ├── .local/
│       │   ├── capsules/
│       │   ├── kv/
│       │   ├── log/
│       │   ├── audit/
│       │   ├── tokens/
│       │   └── tmp/
│       └── .config/env/
└── cow/                         host-managed workspace copy-on-write state
```

`srv/fleets/{fleet_uid}/shared` is the one canonical fleet-common filesystem
root. The FHS `/srv` class is used because this is durable data served by the
fleet computer, not a human login home and not private engine state. A
principal's existing `home/{principal}` remains its independent home and
overlay boundary. `srv/fleets/{fleet_uid}/workspaces` contains admitted mount
points for external or object-backed workspaces; attachment never moves the
workspace's authoritative backing data into `AstridHome`.

Browser cookies, team inboxes, vault records, capability tokens, indexes, and
other service databases are not made ordinary editable files under `srv/`.
They remain typed state in the authoritative store and are reached through
their owning services. Supported exports, downloads, and artifacts may be
published into `shared/` as normal fleet-owned files.

On Unix the physical host root currently defaults to `~/.astrid`; Windows uses
the user's `LocalAppData`; `$ASTRID_HOME` may select another physical root. Those
host locations are placement details. The mounted administrative root preserves
the canonical hierarchy and names on every OS.

The Linux inspiration is deliberate and remains useful. Familiar path classes
give people, shell tools, and otherwise unrelated agent harnesses a discoverable
administrative model: inspect the tree, read supported configuration, find logs,
and understand what is durable. Astrid should preserve those names and ordinary
filesystem behavior where practical without treating POSIX mode bits, a Unix
UID, or path reachability as its authorization model. Linux familiarity is the
interface affordance; typed Astrid ownership and capabilities remain the
authority.

Different agents do not receive different invented hierarchies. They receive
different capability-filtered namespace views of this hierarchy. A normal
principal may see shared executable/interface resources and its own
`home/{principal}`. A fleet-cooperative profile may add explicitly shared roots.
A sysadmin-authorized principal may receive the broader administrative view.
Paths never grant authority by themselves.

| View | Canonical visibility |
| --- | --- |
| Ordinary principal | Shared admitted `bin/`, `lib/`, and `wit/`; its own `home/{principal}`; explicit workspace attachments |
| Cooperative fleet agent | Ordinary principal view plus its owning `srv/fleets/{fleet_uid}/` subtree and services |
| Sysadmin principal | Supported `etc/`, `var/`, `run/`, `log/`, `home/`, lifecycle, and policy projections according to system capabilities |
| Recovery operator | Separately admitted repair views; never implicit raw-store write authority |

An agent can therefore be the sysadmin without ceasing to be a principal. Its
system capabilities select a broader view of the same hierarchy, and every
operation remains principal-attributed and audited.

### 3.1 Shared system view

`bin/`, `lib/`, and `wit/` are the normal shared software/interface projection.
Their immutable bytes and caches may be shared physically across principals and
fleets. `etc/`, `var/`, `run/`, `log/`, `keys/`, and `secrets/` are
administrative namespaces whose visibility and mutability depend on explicit
system capabilities.

`StateOwner::System` contains kernel-owned state such as identity and ownership
records. A sysadmin view may expose supported logical administration files at
their canonical paths, but raw arena frames, indexes, journals, locks, key bytes,
and staging internals are not made safely editable merely because their backing
directories exist. Unsupported raw mutation remains refused.

### 3.2 Fleet view

Fleet-owned shared files are the deliberate collaboration boundary. They support
ordinary file operations, durable staging, generation-checked publication,
conflicts, quota, audit, and recovery. Agents in the user's home fleet may also
share browser and application state through their owning services.

Fleet ownership does not currently exist in `StateOwnerCodecV1`, whose frozen
grammar contains only `System` and `Principal(PrincipalUid)`. Fleet-owned roots
therefore require `StateOwnerCodecV2` or an equivalently explicit versioned
owner grammar. Layout version two fixes the canonical visible path at
`srv/fleets/{fleet_uid}/`. A fleet must never be encoded as a synthetic
principal or hidden beneath `StateOwner::System`. The path is a projection of
the fleet-owned root in the typed store; it is not a second authoritative copy.

### 3.3 Principal overlay view

`home/{principal}` remains the canonical principal path. The object store may
compose fleet-common base state with a principal-owned writable overlay behind
that path, but the visible layout does not change. The overlay gives an agent
stable working context without making a complete copy of shared state.

The overlay is primarily a collision and lifecycle boundary, not a claim that a
cooperative fleet peer lacks the ambient authority to reach equivalent shared
resources. Agent memory, scratch changes, window state, downloads-in-progress,
and process/session metadata can remain overlay-local. Agents deliberately
publish work into the common fleet root when it should become team-visible.

Secrets that require principal isolation do not live as ambient files in the
shared computer view. They remain capability-mediated resources outside the
fleet filesystem and are leased only to the intended invocation.

### 3.4 Workspace attachment

The project workspace is not silently moved into `AstridHome`. Its existing
per-project `.astrid/` state and opaque workspace identity remain separate. A
workspace attached to a job or desktop session may be:

- the fleet's default shared project root;
- a principal-owned project root;
- a user-selected host directory exposed through a bounded portal; or
- a disposable copy-on-write worktree.

An attachment carries an opaque identity, owner, generation or epoch, access
mode, and lifetime. A guest path never selects a host directory. Stale handles
fail after detach or generation change rather than silently resolving against a
different workspace.

### 3.5 Application state

Application state declares whether it is fleet-common, principal-overlay, or an
isolated capability-mediated volume. Applications do not silently choose the
scope. Two instances may share fleet state only when the application contract
and fleet policy select it; session-local state still receives an instance and
generation boundary. Existing principal-installed capsules and their data retain
the canonical `home/{principal}/.local/` and `.config/` placement until a
versioned layout change says otherwise.

The complete execution key is at least:

```text
(fleet, acting principal, application, instance, execution generation)
```

The current Astrid runtime does not yet supply every application and instance
component of this key. The Linux Realm capsule is one consumer that currently
binds residency and durable home state to a principal.

## 4. One store, several authorities

Astrid may use one physical content store and still expose distinct logical
owners. Sharing bytes is an implementation economy, not a grant.

The target owner model is versioned and domain-typed:

```text
SystemOwner
FleetOwner(FleetUid)
PrincipalOwner(PrincipalUid)
ApplicationOwner(application identity, owning FleetUid or PrincipalUid)
```

`UserUid` is normally an authorization subject rather than the direct owner of
agent state. The user's home fleet supplies their computer ownership boundary.
User-private settings or credentials may gain a separate user-owned root later;
they must not be smuggled into a principal or fleet root for convenience.

Logical accounting follows the owner whose root retains the object:

- signed system artifacts are operator/system cost;
- common home, browser, application, and workspace state are charged to the
  home fleet budget;
- principal overlays and memory are charged to the principal under its fleet
  ceiling;
- application state is charged to its declared owner and application slice;
- external workspace portals retain their external accounting policy.

Physical deduplication, reflinks, shared page cache, and principal-free prewarm
checkpoints may reduce host cost. They never reveal whether another owner has
the same bytes and never reduce the caller's logical charge in a way that forms
a cross-owner equality oracle.

## 5. Execution providers and the Linux Realm adapter

The fleet computer is an Astrid ownership, storage, authority, and resource-view
contract. It does not require Linux and is not itself a Realm.

Astrid providers may materialize a fleet computer through:

- hosted macOS, Windows, or Linux filesystem and process adapters;
- native Astrid components and applications;
- a graphical desktop or browser provider;
- a remote attested execution provider; or
- the optional AOS Linux Realm capsule.

Every provider receives an admitted view rather than choosing its owner or
authority from a path or payload. Each command, application, browser action, or
desktop session retains the kernel-stamped acting `PrincipalUid`, even when the
provider supplies a cooperative fleet-wide environment.

### 5.1 Linux Realm projection

Realm is the Linux capsule's compatibility abstraction. It may render an
Astrid-owned fleet computer as a Linux filesystem, process environment, browser,
or desktop, but it does not own the canonical fleet, principal, storage, or mount
semantics.

A Grok-like Linux profile may use one fleet-affine resident Realm per active home
fleet/profile. Same-fleet principals may share:

- the signed kernel and immutable system image;
- principal-free prewarm checkpoints;
- content-addressed physical objects and page cache;
- fleet-owned writable files and browser identity;
- compute workers and scheduling infrastructure;
- network, graphics, storage, and device provider implementations; and
- an ambient Linux authority profile and ordinary Unix user environment.

The Realm constructs a principal view with its overlay, workspace attachment,
process/session namespace, resource slice, and audit context. Independent views
prevent accidental interference; shared ambient fleet authority means they are
not a hostile-tenancy boundary.

Different users' home-fleet Realms must not share writable RAM, Unix credentials,
session buses, browser identity, home generations, writable file handles, or
capability tokens. They may share verified immutable pages and physical content
below the authority line. UID 1000 in separate fleet Realms names unrelated
guest users and confers no cross-fleet authority.

The existing Linux Realm capsule is principal-affine. A fleet-affine cooperative
mode is therefore separate AOS capsule work, not an Astrid core rename or a
prerequisite for the provider-neutral storage mount. A principal-isolated Realm
profile should remain available for agents or applications that are not trusted
with fleet-wide ambient Linux authority.

## 6. Team communication

Easy cooperation requires a first-class fleet service, not reliance on agents
polling a shared directory.

The team service should provide:

- fleet member and principal discovery limited by policy;
- kernel-stamped direct messages and topic channels;
- task offers, acceptance, cancellation, and completion receipts;
- object and workspace-handle delegation with attenuation and expiry;
- shared activity and artifact references without copying bytes;
- backpressure, quotas, retention, and audit; and
- explicit bridges to a human operator.

The sender principal is derived from the authenticated connection. A payload
cannot claim another sender. Receiving a message does not add authority beyond
the common fleet profile. Any delegated handle for a narrower or external
resource names its exact resource, rights, generation, and lifetime.

Files remain useful for human-readable collaboration and ordinary tools. The
team service remains the authority-preserving coordination plane.

### 6.1 Principal compositions, harnesses, and AOS connectors

A principal runs an identified, versioned composition of capsules. When those
capsules operate together as an agent system, that composition is a harness.
Its capsules may provide the agent loop, model or external cognition edge,
context assembly, memory, skills, tools, policy, and team behavior. A
non-cognitive service such as a vault may instead run a service composition with
no harness, model, prompt, or agent loop. Different principals in the same fleet
may use entirely different compositions. The composition is part of the
principal's admitted runtime shape; it is not itself an owner or security
identity.

Codex, Claude Code, Grok, and similar external AI hosts sit at a different
boundary. Their AOS host connectors attach a host-native agent session to an
Astrid principal and, when present, its capsule harness. A connector translates
host-native tools, events, approvals, and lifecycle into the common governed
surface. It does not become the harness and does not own the principal. A local
capsule-only agent or non-cognitive service may run without one of these
external connectors.

The durable principal runtime binding should carry at least:

```text
(UserUid, home FleetUid, PrincipalUid,
 capsule composition and generation)
```

Each external attachment adds a separately admitted connector session:

```text
(PrincipalUid, connector identity, device identity,
 connector session and generation)
```

The user and device authenticate at the connector boundary. Astrid selects the
fleet and principal from admitted ownership state and loads the principal's
identified capsule composition. No connector or capsule may self-assert a
principal or fleet in an IPC payload, environment variable, mount path, model
prompt, or tool argument.

Every AOS connector has the same small set of responsibilities:

- authenticate its host connection and bind a stable acting principal;
- attach to the admitted principal composition rather than selecting capsules
  through untrusted host input;
- obtain generation-bound filesystem, terminal, browser, desktop, and team
  handles instead of deriving authority from paths;
- preserve kernel-stamped actor context on commands, messages, and artifacts;
- translate those handles into the external host's native tool protocol; and
- reconnect or fail boundedly when its session, provider, or generation expires.

The common semantic surface should be available through the Astrid event bus
and typed AOS surfaces, with MCP, CLI, HTTP, or WebSocket bridges where useful.
Principal compositions and connectors do not need identical internal loops,
user interfaces, or prompt formats. They need identical identity, resource,
delegation, receipt, and failure semantics at the shared boundary.

The admitted actor context needs to become explicit and kernel-stamped. The
current message envelope carries a validated principal plus host-derived device
and origin information, but it does not carry the complete user, fleet,
composition, connector, session, application, instance, and generation context
required here. A future versioned context should resemble:

```text
ActorContext {
    user_uid,
    home_fleet_uid,
    principal_uid,
    composition_ref,
    composition_generation,
    connector_id,
    device_key_id,
    host_session_id,
    application_id,
    instance_id,
    execution_generation,
    origin,
}
```

Not every field must appear on every public wire message. The kernel or trusted
host boundary must nevertheless be able to recover and stamp the applicable
context, and receipts must retain enough of it to attribute actions after
restart. The composition reference identifies the admitted capsule closure and
the optional connector identifies an external attachment. Neither replaces
`principal_uid` as the actor.

### 6.2 Fleet directory and shared services

Each home fleet has a policy-filtered directory of its durable teammates. A
directory entry contains a stable principal identity, user-facing alias,
composition reference and service kind, declared capabilities or specialties,
availability, active connector/session references, and admitted inbox topics.
It does not expose another principal's private prompt, model context, overlay,
or credentials.

The fleet computer composes four state scopes:

| Scope | Shared details |
| --- | --- |
| System | Admitted immutable software and interfaces; supported administrative projections only for system-capable principals |
| Home fleet | Common files, installed applications, browser identity, selected profile state, team directory, inboxes, tasks, artifact references, shared service endpoints, policy, and fleet budgets |
| Principal | Capsule namespaces, service state, optional agent memory and preferences, working overlay, process/session state, desktop/window state, and audit identity |
| Invocation | Selected workspace attachments, temporary state, task inputs and outputs, attenuated handles, limits, and expiry |

The common filesystem is one fleet-owned root, not a copy per composition or
connector. A principal view composes that root with the principal's overlay and
explicit workspace attachments. View handles are bound to at least the fleet,
acting principal, admitted root generation, overlay generation, and workspace
epoch.
Same-fleet common paths resolve to the same published objects; overlay-local
paths resolve to the acting principal's working delta. Publication into shared
state is generation-checked and emits a fleet event so teammates can react
without polling.

Team communication is similarly composition-neutral. Principals can discover
admitted teammates, send direct or topic messages, offer and accept tasks,
delegate attenuated handles, report status, and reference artifacts. An agent
harness or its connector may render those operations as native sub-agents,
chats, tools, or jobs; a vault may expose a narrower request/reply interface.
The underlying sender, recipient, fleet, task, resource, and receipt identities
stay the same. A temporary orchestration child stays within its parent's
principal unless it is explicitly promoted to a durable fleet principal.

The browser follows the same split: browser identity, cookies, and selected
profile policy are fleet services; tabs, windows, active automation, screenshots,
and action attribution belong to a principal session. The browser service
serializes mutations to the shared profile rather than allowing independent
capsule or connector-hosted browser processes to corrupt the same profile
database.

## 7. Desktop and browser views

A desktop is an Astrid projection of one principal session over the fleet
computer. It may be implemented by a hosted-native provider, Linux Realm
capsule, future native Astrid desktop, or remote provider. The contract does not
assume Linux.

Principals may share browser identity, cookies, application authority, and—in a
Linux provider—the same ambient Unix account, while retaining independent
windows, process/session views, overlays, work contexts, and audit attribution.

Each desktop session binds:

```text
(authenticated UserUid, FleetUid, PrincipalUid,
 application/profile, desktop session, provider generation)
```

The selected principal receives its own display/session, terminal processes,
working overlay, and window state. The home fleet may deliberately share
clipboard, downloads, browser sign-ins, cookies, history, extensions, and other
profile state.

Two Chrome processes must not be pointed concurrently at one mutable
SQLite/LevelDB profile directory and called safe sharing. A fleet browser
service should own the common browser profile and serialize its mutation while
exposing independent principal windows or sessions. A simpler provider may
snapshot a verified fleet profile at session start and merge only supported
state through a typed service. The chosen semantics must be visible and
crash-tested.

Graphics, input, clipboard, screenshots, downloads, notifications, camera, and
microphone cross typed portals. A screenshot capability returns pixels from a
named desktop surface; it does not grant filesystem or general display access.
Clipboard and file-picker grants are scoped resources rather than ambient host
integration.

Remote desktop attaches through an authenticated gateway to one named principal
desktop session in the user's home fleet. Its lease is short-lived, revocable,
and audited. A user can open their own agents' desktops as the ordinary product
flow. A user entering another user's fleet requires a separate delegated
observation or control grant.

Provider or daemon failure must produce bounded errors and reconnect behavior.
It must not strand acknowledged filesystem writes or indefinitely hang the
remote desktop client.

## 8. Human mounts and system administration

The hosted-OS filesystem provider should mount the canonical Astrid hierarchy
under an admitted view. Illustrative commands are:

```text
astrid storage mount --as <principal> [--read-only]
astrid storage mount --fleet <fleet> [--read-only]
astrid storage mount --admin [--read-only]
astrid storage sync <mount>
astrid storage status <mount>
astrid storage unmount <mount>
```

Command names are not yet a frozen CLI contract.

Mounting never provisions an owner or store. User setup creates the home fleet
and its empty root; agent creation creates the principal and its overlay; an
explicit application or workspace operation creates those resources. A mount
only admits and projects resources that already exist, and fails if its selected
owner or view is absent or unauthorized.

Every mode preserves the same canonical relative paths. A principal view exposes
the shared resources admitted to that principal and `home/{principal}`. A future
fleet view exposes fleet-owned shared state without selecting an agent overlay.
An administrative view exposes the supported system hierarchy according to the
acting user's and principal's system capabilities; it is read-only by default.

This is what permits an agent to be the sysadmin. The agent does not receive a
different filesystem API or a magic bypass. It receives an administrative
namespace view and explicit rights over paths such as `etc/`, `log/`, supported
`var/` projections, principal homes, and lifecycle endpoints. Particularly
sensitive operations over `keys/`, `secrets/`, raw store state, and runtime
endpoints remain narrower capabilities even for an administrator.

Filesystem writes update crash-durable working state. `fsync` means the staged
bytes and namespace mutation are durable; it does not falsely claim that the
authoritative content root has advanced. Publication seals an immutable
generation, verifies identity and closure, charges quota, and advances the root
with compare-and-swap. `storage sync` waits for that publication outcome.

An invalid, conflicting, or over-quota edit remains staged and visible with a
typed blocked state. Doctor and repair tooling must never discard acknowledged
dirty bytes merely because they differ from the last published root.

Administrative access uses a mount lease such as:

```text
MountLease {
    authenticated_user,
    authenticated_device,
    selected_fleet,
    target_owner,
    view_kind,
    access_mode,
    granted_rights,
    admitted_generation,
    expires_at,
}
```

The operating-system account, `root`, or Windows Administrator status may allow
the local provider to run; it does not replace Astrid authentication or mint an
Astrid data-access grant.

## 9. Authorization rules

Mount, shell, desktop, and team authorization all use the same intersection:

```text
authenticated user and device
∩ home-fleet ownership or cross-fleet delegated role
∩ selected acting principal
∩ cooperative fleet profile or narrower target resource grant
∩ provider declaration
∩ per-session attenuation and limits
```

No path, guest UID, process environment variable, principal alias, fleet alias,
or payload field can add authority.

Recommended rights are deliberately separate:

```text
fleet.resource.read
fleet.resource.write
principal.storage.read
principal.storage.write
principal.desktop.observe
principal.desktop.control
principal.recovery
system.storage.inspect
system.storage.repair
```

Exact capability grammar is future contract work. Agents in the user's home
fleet may receive the cooperative fleet-computer profile by default. Broader
human administration, cross-fleet access, isolated-principal resources, system
repair, and impersonation remain explicit grants.

## 10. Provisioning and lifecycle

Fresh setup performs one recoverable ownership transaction:

```text
create or authenticate UserUid
  -> create or recover exactly one home FleetUid
  -> create first PrincipalUid
  -> assign principal to fleet
  -> allocate fleet and principal budgets
  -> create empty authoritative roots
  -> install signed system/application closure
  -> optionally start the first principal view
```

Creating another agent or service creates another principal, assigns it to the
home fleet, allocates its resource slice, creates an empty overlay root, and
installs its admitted capsule composition. An agent may select a harness that
differs completely from every other agent's harness. A service principal such
as a vault may select a non-cognitive composition instead. Both immediately see
the fleet resources admitted to them without copying another principal's
overlay, running processes, session state, or audit identity.

Changing a principal's capsule composition advances an explicit composition
generation while retaining the same durable principal. Capsule namespace state
is preserved or migrated only through declared lifecycle contracts. Replacing
an external AOS connector is a separate operation: expire the old connector
session, admit the new connector to the same principal, and reconstruct its
view. Neither operation silently changes ownership, roots, inbox, task history,
or audit identity.

Provider RAM, desktop processes, and temporary state are lazy and evictable. The
principal identity, roots, published state, application identity, service
identity, ownership graph, and audit evidence survive shutdown. Restart
reconstructs execution from those durable objects rather than preserving an
ambient machine as authority.

Removing an agent revokes its sessions and handles, stops its processes and
desktop, publishes or preserves blocked overlay state according to policy,
detaches it from the fleet, and then retires its roots under explicit retention
or erasure rules. The fleet computer and shared objects survive while the user
or other agents still retain them.

### 10.1 Upgrade from Astrid v0.10.4

The latest published release at the time of this design is
[`v0.10.4`](https://github.com/astrid-runtime/astrid/releases/tag/v0.10.4).
It writes layout version one, uses `var/state.db/` as its authoritative
SurrealKV state, and stores principal files under `home/{principal}/`. The
version-two migration must start from those released bytes and paths, not only
from synthetic current-main state.

Version one resolves `$ASTRID_HOME` or `$HOME/.astrid`. Version two retains that
default on macOS and Linux. Astrid v0.10.4 did not publish Windows binaries, so
there is no supported public Windows release migration from that version. A
clean Windows version-two installation uses
`%LOCALAPPDATA%\Astrid\Runtime` when `$ASTRID_HOME` is absent. Importing state
created by an unreleased Windows development build is a separate explicit
developer operation; it never participates in automatic release migration or
silently merges a legacy `$HOME/.astrid` with the new root.

The migration is an exclusive, crash-resumable ownership transaction:

1. Acquire the daemon singleton lock before opening either store. Reject active
   mounts, unknown layout versions, redirected paths, insufficient free space,
   and invalid host permissions. Persist a versioned migration intent containing
   the source and target physical roots, source layout, source inventory, target
   format, and binary identity.
2. Import `var/state.db/` into a fresh typed store, verify entry counts and
   domain-separated digests per owner, then advance through every registered
   store-format migration. An incomplete destination is quarantined or resumed;
   it is never mistaken for authoritative state.
3. Create or validate the stable user, home fleet, and principal identities.
   A released version-one home had one local operator authority and no hard
   user/fleet tenant partition, so its admitted legacy principals are assigned
   to that operator's home fleet with explicit receipts. A development home that
   already contains a valid ownership graph preserves that graph instead of
   reassigning principals.
4. Convert the imported store to the version-two owner grammar, create one empty
   fleet root, and project it at `srv/fleets/{fleet_uid}/shared`. Existing
   `home/{principal}/`, `etc/`, `keys/`, `secrets/`, `bin/`, `lib/`, `wit/`,
   and `cow/` content remains in place. Principal homes are never merged into
   the fleet root.
5. Preserve existing principal-scoped browser and capsule state. A fleet browser
   profile starts empty unless the operator explicitly selects one principal
   profile for typed import; multiple browser databases are never merged by
   copying files.
6. Synchronize the new roots and directories, write a durable migration receipt,
   and atomically replace `etc/layout-version` with `2` as the final commit
   point. Only then may the daemon serve principals or mounts.
7. Retain `var/state.db/` read-only as the authenticated rollback/export source
   until an explicit later cleanup after backup. Once version-two writes have
   been acknowledged, running a version-one binary against the home is refused;
   rollback requires a supported export or restoration of the pre-migration
   snapshot.

Migration restart is idempotent. Before the version-two sentinel is committed,
the intent and verified target determine whether to resume, quarantine, or
restart the import while leaving version-one source bytes intact. After the
sentinel is committed, the receipt and typed roots are authoritative and the
legacy database is never reopened for live writes.

Release evidence must include actual homes produced by the published v0.10.4
binaries on macOS and Linux. It covers empty, single-principal, and
multi-principal installations; an already partially migrated development home;
and fault injection at every durable migration boundary. It must also prove
repeat execution, corrupt-source refusal, low-disk refusal, permission repair or
refusal, byte preservation of every existing principal home, stable owner
derivation, cross-fleet denial, and a correct first mount of the new `srv/`
subtree. Windows separately proves a clean version-two installation and mount;
an unreleased developer-home importer has its own non-release evidence track.

Current main already contains a digest-verifying SurrealKV importer, preserves
the legacy source, quarantines an incomplete typed-store destination, and
migrates alias-keyed roots to stable principal UIDs. Those are useful pieces,
not completion of this contract. `LAYOUT_VERSION` is still `1`, `ensure()` only
creates a missing sentinel, the owner codec has no fleet tag, `srv/` does not
exist, and no exact v0.10.4 home fixture proves the complete macOS/Linux
upgrade. The release remains blocked until these gaps close together.

## 11. Product story

The simple truthful story is:

> Every Astrid user gets a fleet computer and a first agent. Add specialists as
> your work grows. Your agents share that computer's files, applications,
> browser sign-ins, cookies, and ambient authority. Linux is one available
> compatibility environment, not the computer's identity. Each agent keeps an
> independent view, overlay, active processes, desktop, working context, and
> identity. Each agent may use a different capsule-composed harness and external
> AI connector. The same fleet may also contain non-cognitive principals such as
> vaults and schedulers. Open any agent's terminal or desktop and let the team
> work together without stepping on one another's active state.

The shorter phrase is:

> Your computer. Your fleet of agents. An independent view for each.

The security qualification is:

> Principals preserve attribution and independent views inside the cooperative
> fleet; the hard tenant boundary is between users' home fleets.

## 12. Implementation order

1. Freeze layout version two, strict version admission, and the canonical
   `srv/fleets/{fleet_uid}/` projection. Check in real v0.10.4 migration
   fixtures and their source identities.
2. Implement the exclusive version-one-to-version-two macOS/Linux migration,
   including durable intent and receipt, verified store import, ownership
   adoption, restart recovery, and refusal by old binaries. Keep any Windows
   development-home importer explicit and outside the public migration promise.
3. Define `StateOwnerCodecV2`, the fleet-owned root, and fleet accounting without
   changing `StateOwnerCodecV1` in place.
4. Expose read-only ownership inspection and authenticated user/fleet context.
5. Define the versioned kernel-stamped actor context, capsule-composition
   contract, and AOS connector contract. Admit unlike harness and service
   compositions to stable principals without giving a capsule or connector
   authority to self-select its identity.
6. Implement the provider-neutral path/inode, staging, publication, mount-lease,
   and doctor contracts.
7. Project supported system, fleet, principal-overlay, application, browser, and
   team resources through the canonical `AstridHome` hierarchy. Keep workspaces
   as explicit attachments.
8. Add the fleet directory, team service, inboxes, tasks, receipts, wakeups, and
   attenuated handle delegation.
9. Implement one hosted mount, browser, and desktop adapter used concurrently by
   unlike harness compositions and external connectors, with crash, `mmap`,
   compiler, provider-death, daemon-upgrade, and repair evidence.
10. Add the remaining macOS, Linux, and Windows mount/desktop adapters against the
   same behavioral contract.
11. Adapt the Linux Realm capsule to consume the same view. Add a fleet-affine
   cooperative mode without removing its principal-isolated mode.
12. Optimize density through shared immutable pages, checkpoints, physical
   objects, workers, and provider-specific fleet residency without weakening
   cross-fleet isolation or principal attribution.

The first release slice should prove two users with distinct home fleets and at
least three principals using at least two different capsule compositions in one
user's fleet. At least one composition is an agent harness, one is a
non-cognitive service such as a vault, and an external AOS connector is present:

- every user recovers the same stable home fleet and never another user's fleet;
- every mount preserves canonical `AstridHome` paths across macOS, Windows, and
  Linux while applying the admitted principal or sysadmin view;
- same-fleet principals share the ambient computer-authority profile, common
  files, browser sign-ins, and cookies;
- same-fleet principals retain independent overlays, working contexts, process
  sessions, desktops, and audit attribution;
- unlike principal compositions discover one another, exchange kernel-stamped
  messages, complete an admitted request or task, and reference the same shared
  artifact;
- changing a capsule composition or replacing an external connector preserves
  the principal's identity, files, inbox, task history, and receipts according
  to the declared migration policy;
- a shared browser service remains correct under concurrent agent sessions and
  provider crash;
- different home fleets cannot access one another's writable files, cookies,
  processes, tokens, or displays;
- exchange delegated file handles without allowing a capsule or connector to
  claim another sender, fleet, or generation;
- survive provider and daemon restart with acknowledged writes intact; and
- can each be mounted or remotely viewed by an independently authorized user.

The Linux Realm adapter separately proves that the same roots, acting-principal
attribution, overlays, cookies, and cross-fleet denials survive projection into
its Linux environment. That adapter evidence does not define the Astrid core
contract.

## 13. Stop conditions

Do not ship the fleet-computer claim if any of the following remains true:

- the layout changes while `etc/layout-version` remains `1`, or an unknown
  layout version is silently accepted;
- a version-one binary can open a committed version-two home;
- migration has not been exercised against exact macOS and Linux v0.10.4 homes;
- migration mutates or deletes the version-one source before the version-two
  receipt and sentinel commit;
- existing principal homes or browser databases are implicitly merged into
  fleet-shared state;
- specialized durable agents share one `PrincipalUid`;
- a capsule, connector, process, prompt, or connection can self-select a
  `PrincipalUid` or `FleetUid`;
- a principal is required to contain a model, prompt, or agent loop;
- changing a composition or connector silently replaces the durable principal
  or loses its owned state and team history;
- a user can be provisioned without one stable home fleet;
- a fleet or group name is treated as authentication;
- a fleet-owned root is encoded as a synthetic principal or system-owned state;
- the cooperative profile is described as adversarial isolation between its
  same-fleet principals;
- a principal view can accidentally overwrite another agent's overlay or active
  session state;
- multiple Chrome processes concurrently mutate one unsupported profile
  directory;
- shared cookies, ambient computer authority, or provider-specific Linux
  authority cross a home-fleet boundary;
- an application silently chooses fleet-common rather than overlay or isolated
  state;
- a guest path or UID selects an authority-bearing host resource;
- desktop observation is implied by ownership-management authority;
- an ordinary principal view exposes administrative `etc/`, `var/`, `keys/`,
  `secrets/`, or `run/` state without the corresponding system capability;
- raw principal-store engine files are the human administration interface;
- provider failure can lose acknowledged staged bytes or hang clients without a
  bounded error;
- physical deduplication becomes an authorization or cross-owner equality oracle;
  or
- a shared Linux guest becomes the only isolation boundary between different
  users' home fleets.
