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
has a home fleet. That fleet contains the user's agent principals and owns their
shared computer authority, filesystem, browser identity, applications, and
budget. Every agent receives an independent view and session over that shared
computer.

The ordinary experience is:

1. A person starts Astrid and receives a durable `UserUid`, a home fleet, and
   one agent principal.
2. The person creates additional specialized agents in that fleet.
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
  -> many PrincipalUid agent tenants per home fleet
```

The user fleet is the security and ownership tenant. Agent principals are
independent actors and views inside that tenant.

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

There is one fleet-owned computer root plus per-principal view roots. The
principal store holds their immutable objects and authoritative generations. A
filesystem provider composes them for a particular user, fleet, acting
principal, session, and generation.

A normal human or application filesystem projection is:

```text
/                   signed, immutable distribution and shared tools
├── home/fleet/     shared user home, configuration, and ordinary files
├── home/agent/     fleet base plus this principal's overlay view
├── workspace/      shared fleet project or explicit task attachment
├── apps/           application-scoped state and projections
├── team/           synthetic collaboration service, not ordinary storage
├── run/aos/        typed portals, handles, and session services
└── tmp/            principal-private ephemeral state
```

The names are an illustrative projection contract, not a requirement that
Astrid itself run Linux or make every typed resource a file. A hosted mount,
native host, Linux Realm capsule, or remote provider may render the same owned
resources through its native path conventions. None reveals physical host paths
or the principal store's private arena, journals, indexes, keys, locks, or
staging layout.

### 3.1 Shared system view

The system projection contains signed release and toolchain artifacts. Its
immutable bytes, page cache, and prewarmed machine state may be shared physically
across every principal. It is read-only inside agent views. A human-facing or
provider-specific projection may label this resource `System`, but that label is
not authority.

This is not the same thing as `StateOwner::System`. The current system-owned
store root contains kernel-owned administrative state such as identity and
ownership records. That state is not an ambient guest filesystem and must not
be exposed merely by mounting the immutable system projection.

### 3.2 Fleet view

The fleet computer root is the deliberate collaboration boundary. It contains
the user's ordinary shared files, installed application state selected for
sharing, browser identity service, and default workspaces. It supports ordinary
file operations, durable staging, generation-checked publication, conflicts,
quota, audit, and recovery.

Fleet ownership does not currently exist in `StateOwnerCodecV1`, whose frozen
grammar contains only `System` and `Principal(PrincipalUid)`. Fleet-owned roots
therefore require a versioned owner grammar and migration, or a distinct
authoritative fleet-root journal. A fleet must never be encoded as a synthetic
principal or hidden beneath `StateOwner::System`.

### 3.3 Principal overlay view

`/home/agent` is a composed view: the fleet home is its common lower/base state
and one `PrincipalUid` owns its writable overlay and session metadata. The
overlay gives an agent stable working context without making a complete copy of
the fleet computer.

The overlay is primarily a collision and lifecycle boundary, not a claim that a
cooperative fleet peer lacks the ambient authority to reach equivalent shared
resources. Agent memory, scratch changes, window state, downloads-in-progress,
and process/session metadata can remain overlay-local. Agents deliberately
publish work into the common fleet root when it should become team-visible.

Secrets that require principal isolation do not live as ambient files in the
shared computer view. They remain capability-mediated resources outside the
fleet filesystem and are leased only to the intended invocation.

### 3.4 Workspace attachment

`/workspace` is selected for a job or desktop session. It may be:

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
generation boundary.

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

The hosted-OS filesystem provider should offer explicit mounts for different
resource owners and views. Illustrative commands are:

```text
astrid storage mount principal <principal> [--read-only]
astrid storage mount fleet <fleet> [--read-only]
astrid storage mount system --read-only
astrid storage sync <mount>
astrid storage status <mount>
astrid storage unmount <mount>
```

Command names are not yet a frozen CLI contract.

A principal mount presents that agent's composed fleet-base-plus-overlay view.
A fleet mount presents the common computer root without selecting an agent's
overlay. A system mount presents a supported administrative projection and is
read-only by default. None exposes raw engine files.

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

Creating another specialized agent creates another principal, assigns it to the
home fleet, allocates its resource slice, and creates an empty overlay root. The
new agent immediately receives the fleet computer's common files, applications,
browser identity, cookies, and ambient authority profile. It does not copy
another agent's overlay, running processes, desktop session, or audit identity.

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

## 11. Product story

The simple truthful story is:

> Every Astrid user gets a fleet computer and a first agent. Add specialists as
> your work grows. Your agents share that computer's files, applications,
> browser sign-ins, cookies, and ambient authority. Linux is one available
> compatibility environment, not the computer's identity. Each agent keeps an
> independent view, overlay, active processes, desktop, working context, and
> identity. Open any agent's terminal or desktop and let the team work together
> without stepping on one another's active state.

The shorter phrase is:

> Your computer. Your fleet of agents. An independent view for each.

The security qualification is:

> Principals preserve attribution and independent views inside the cooperative
> fleet; the hard tenant boundary is between users' home fleets.

## 12. Implementation order

1. Expose read-only ownership inspection and authenticated user/fleet context.
2. Define the versioned fleet-owned root and accounting grammar without changing
   `StateOwnerCodecV1` in place.
3. Implement the provider-neutral path/inode, staging, publication, mount-lease,
   and doctor contracts.
4. Compose system, fleet, principal overlay, application, workspace, browser,
   and synthetic team resources into one provider-neutral principal view.
5. Implement one hosted mount and desktop adapter with crash, `mmap`, browser,
   compiler, provider-death, daemon-upgrade, and repair evidence.
6. Add the remaining macOS, Linux, and Windows mount/desktop adapters against the
   same behavioral contract.
7. Adapt the Linux Realm capsule to consume the same view. Add a fleet-affine
   cooperative mode without removing its principal-isolated mode.
8. Add the fleet team service and handle delegation.
9. Optimize density through shared immutable pages, checkpoints, physical
   objects, workers, and provider-specific fleet residency without weakening
   cross-fleet isolation or principal attribution.

The first release slice should prove two users with distinct home fleets and at
least two principals in one user's fleet:

- every user recovers the same stable home fleet and never another user's fleet;
- same-fleet principals share the ambient computer-authority profile, common
  files, browser sign-ins, and cookies;
- same-fleet principals retain independent overlays, working contexts, process
  sessions, desktops, and audit attribution;
- a shared browser service remains correct under concurrent agent sessions and
  provider crash;
- different home fleets cannot access one another's writable files, cookies,
  processes, tokens, or displays;
- exchange kernel-stamped messages and delegated file handles;
- survive provider and daemon restart with acknowledged writes intact; and
- can each be mounted or remotely viewed by an independently authorized user.

The Linux Realm adapter separately proves that the same roots, acting-principal
attribution, overlays, cookies, and cross-fleet denials survive projection into
its Linux environment. That adapter evidence does not define the Astrid core
contract.

## 13. Stop conditions

Do not ship the fleet-computer claim if any of the following remains true:

- specialized durable agents share one `PrincipalUid`;
- a user can be provisioned without one stable home fleet;
- a fleet or group name is treated as authentication;
- the cooperative profile is described as adversarial isolation between its
  same-fleet principals;
- a principal view can accidentally overwrite another agent's overlay or active
  session state;
- multiple Chrome processes concurrently mutate one unsupported profile
  directory;
- shared cookies or ambient Linux authority cross a home-fleet boundary;
- an application silently chooses fleet-common rather than overlay or isolated
  state;
- a guest path or UID selects an authority-bearing host resource;
- desktop observation is implied by ownership-management authority;
- the immutable guest system view exposes mutable kernel administrative state to
  agents;
- raw principal-store engine files are the human administration interface;
- provider failure can lose acknowledged staged bytes or hang clients without a
  bounded error;
- physical deduplication becomes an authorization or cross-owner equality oracle;
  or
- a shared Linux guest becomes the only isolation boundary between different
  users' home fleets.
