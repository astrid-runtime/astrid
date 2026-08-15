# Astrid fleet computer and principal views

Status: proposed architecture

Last reviewed: 2026-08-15

Related documents:

- [Astrid user and fleet ownership](astrid-user-fleet-ownership.md)
- [Astrid Principal Store](astrid-principal-store.md)
- [Astrid Principal Store Runtime Realization](astrid-principal-store-runtime.md)
- [Astrid Native Component Kernel](astrid-native-kernel.md)
- [AOS Principal Linux Realm](https://github.com/unicity-aos/aos-ce/blob/main/docs/principal-linux-realm.md)

## 1. Product ruling

AOS should present one lightweight computer owned by a fleet, with one private
view for each agent principal and explicit shared views for team resources.

The ordinary experience is:

1. A person starts AOS and receives a durable `UserUid`, a personal fleet, and
   one agent principal.
2. The person creates additional specialized agents in that fleet.
3. Every agent sees the same signed software distribution and any explicitly
   shared fleet workspace.
4. Every agent has its own home, processes, browser profile, desktop session,
   temporary state, credentials, and authority.
5. Agents communicate through a kernel-stamped team service and may cooperate
   through fleet-owned files without acquiring each other's private authority.
6. An authorized person can open a terminal, mount a filesystem view, or attach
   to the desktop belonging to a selected agent.

The phrase "one computer" describes shared custody, software, storage economy,
and team experience. It does not mean one ambient Unix user, one writable root,
or one undifferentiated security domain.

## 2. Identity and ownership boundaries

The existing concepts retain distinct jobs:

| Concept | Role in the fleet computer |
| --- | --- |
| `UserUid` | Durable human authority and authentication subject |
| `FleetUid` | Administrative ownership, team policy, shared resources, and aggregate budget boundary |
| `PrincipalUid` | Durable executable identity of one agent or service |
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

One principal has at most one owning fleet. A user can belong to several fleets,
and a fleet can contain several users and principals. Transferring a principal
between fleets is an explicit ownership transition, not a filesystem move or an
alias change.

Fleet roles authorize management of the ownership graph. They do not by
themselves disclose every principal's files, secrets, browser profile, or active
desktop. Data access, observation, recovery, and impersonation remain separate,
audited grants.

## 3. The filesystem is a composed view

There is no single authoritative directory that all agents share. The principal
store holds immutable objects and authoritative roots. A filesystem provider
assembles a namespace for a particular subject, principal, session, and
generation.

A normal Linux Realm view is:

```text
/                   signed, immutable distribution and shared tools
├── fleet/          explicitly fleet-owned shared files
├── home/agent/     principal-private durable home
├── workspace/      explicit task or project attachment
├── apps/           application-scoped state and projections
├── team/           synthetic collaboration service, not ordinary storage
├── run/aos/        typed portals, handles, and session services
└── tmp/            principal-private ephemeral state
```

The names are a guest contract. They do not reveal physical host paths or the
principal store's private arena, journals, indexes, keys, locks, or staging
layout.

### 3.1 Shared system view

The guest root filesystem contains signed release and toolchain artifacts. Its
immutable bytes, page cache, and prewarmed machine state may be shared physically
across every principal. It is read-only inside agent views. A human-facing host
projection may label this resource `System`, but that label is not guest
authority.

This is not the same thing as `StateOwner::System`. The current system-owned
store root contains kernel-owned administrative state such as identity and
ownership records. That state is not an ambient guest filesystem and must not
be exposed merely by mounting the immutable guest system view.

### 3.2 Fleet view

`/fleet` is the deliberate collaboration boundary. Files placed there are
visible only to principals and users holding the required fleet-resource grant.
It supports ordinary file operations, durable staging, generation-checked
publication, conflicts, quota, audit, and recovery.

Fleet ownership does not currently exist in `StateOwnerCodecV1`, whose frozen
grammar contains only `System` and `Principal(PrincipalUid)`. Fleet-owned roots
therefore require a versioned owner grammar and migration, or a distinct
authoritative fleet-root journal. A fleet must never be encoded as a synthetic
principal or hidden beneath `StateOwner::System`.

### 3.3 Principal-private view

`/home/agent` is owned by exactly one `PrincipalUid`. It contains the agent's
durable working memory, personal configuration, browser profile, caches that
must survive restart, and other private state admitted by policy.

Other principals in the same fleet do not receive this root automatically.
Collaboration occurs through `/fleet`, explicit object grants, or the team
service. This prevents a convenient team feature from becoming universal
credential, cookie, history, or memory sharing.

### 3.4 Workspace attachment

`/workspace` is selected for a job or desktop session. It may be:

- a fleet-owned project root;
- a principal-owned project root;
- a user-selected host directory exposed through a bounded portal; or
- a disposable copy-on-write worktree.

An attachment carries an opaque identity, owner, generation or epoch, access
mode, and lifetime. A guest path never selects a host directory. Stale handles
fail after detach or generation change rather than silently resolving against a
different workspace.

### 3.5 Application state

Application state is isolated below both principal and application identity.
Two applications invoked by the same principal must not silently share a home,
browser profile, service credentials, process namespace, or writable Realm
state. Explicit state volumes may be shared through a named grant.

The complete execution key is at least:

```text
(fleet, acting principal, application, instance, execution generation)
```

The current principal-affine Realm proves the outer principal boundary but does
not yet supply every application and instance component of this key.

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

`UserUid` is normally an authorization subject rather than the owner of agent
state. A personal fleet supplies the ordinary one-person ownership boundary.
User-private settings or credentials may gain a separate user-owned root later;
they must not be smuggled into a principal or fleet root for convenience.

Logical accounting follows the owner whose root retains the object:

- signed system artifacts are operator/system cost;
- fleet files are charged to the fleet budget;
- private home and memory are charged to the principal under its fleet ceiling;
- application state is charged to its declared owner and application slice;
- external workspace portals retain their external accounting policy.

Physical deduplication, reflinks, shared page cache, and principal-free prewarm
checkpoints may reduce host cost. They never reveal whether another owner has
the same bytes and never reduce the caller's logical charge in a way that forms
a cross-owner equality oracle.

## 5. Linux execution boundary

The first implementation should retain one principal-affine Realm per active
principal/profile. Realms may share:

- the signed kernel and immutable system image;
- principal-free prewarm checkpoints;
- content-addressed physical objects;
- read-only page cache;
- compute workers and scheduling infrastructure; and
- network, graphics, storage, and device provider implementations.

They do not share writable guest RAM, process tables, Unix credentials, session
buses, browser profiles, home generations, file handles, or capability tokens.

This gives the product density of one shared computer without moving the
security boundary into a general-purpose Linux kernel. A future provider may
host several views inside one hardware VM or native kernel only after it proves
equivalent principal isolation, revocation, accounting, crash recovery, and
denied-path behavior. The namespace and authority contract must not depend on
that optimization.

Linux remains a compatibility provider. The kernel-stamped principal, Astrid
capabilities, root identities, quotas, and audit trail remain outside Linux.
UID 1000 inside two Realms does not make them the same user and does not confer
cross-principal authority.

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
cannot claim another sender. Receiving a message does not confer the sender's
filesystem, network, secret, or application authority. Any delegated handle
names its exact resource, rights, generation, and lifetime.

Files remain useful for human-readable collaboration and ordinary tools. The
team service remains the authority-preserving coordination plane.

## 7. Desktop and browser views

A desktop is a projection of one principal's Realm, not a remote login to an
ambient shared host account.

Each desktop session binds:

```text
(authenticated UserUid, FleetUid, PrincipalUid,
 application/profile, desktop session, Realm generation)
```

The selected principal receives its own display server/session, browser profile,
terminal processes, clipboard namespace, downloads, and home. Immutable Chrome
and desktop binaries may be shared; their mutable state may not.

Graphics, input, clipboard, screenshots, downloads, notifications, camera, and
microphone cross typed portals. A screenshot capability returns pixels from a
named desktop surface; it does not grant filesystem or general display access.
Clipboard and file-picker grants are scoped resources rather than ambient host
integration.

Remote desktop attaches through an authenticated gateway to one named desktop
session. Its lease is short-lived, revocable, and audited. Fleet ownership
permits management but does not automatically permit silent observation.
Observation, interactive control, recovery control, and principal impersonation
are separate rights.

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

A principal mount presents that principal's composed administrative view. A
fleet mount presents shared fleet-owned state, not every member principal's
private home. A system mount presents a supported administrative projection and
is read-only by default. None exposes raw engine files.

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
∩ fleet membership and delegated role
∩ selected acting principal
∩ target resource grant
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

Exact capability grammar is future contract work. A broad fleet administrator
role may authorize issuing or revoking these grants under fleet policy; it must
not silently collapse them into one superuser permission.

## 10. Provisioning and lifecycle

Fresh setup performs one recoverable ownership transaction:

```text
create or authenticate UserUid
  -> create personal FleetUid
  -> create first PrincipalUid
  -> assign principal to fleet
  -> allocate fleet and principal budgets
  -> create empty authoritative roots
  -> install signed system/application closure
  -> optionally start the first principal view
```

Creating another specialized agent creates another principal, assigns it to the
fleet, allocates its resource slice, and creates empty private roots. It does not
copy the first agent's home or credentials. Shared fleet resources become visible
through the new principal's composed namespace according to policy.

Realm RAM, desktop processes, and temporary state are lazy and evictable. The
principal identity, roots, published state, application identity, service
identity, ownership graph, and audit evidence survive shutdown. Restart
reconstructs execution from those durable objects rather than preserving an
ambient machine as authority.

Removing an agent revokes sessions and handles, stops or evicts its Realm,
publishes or preserves blocked dirty state according to policy, detaches it from
the fleet, and then retires its roots under explicit retention or erasure rules.
Shared fleet objects survive because their owner is the fleet, not the removed
principal.

## 11. Product story

The simple truthful story is:

> Start AOS and meet your first agent. Add specialists as your work grows. They
> share one fleet computer, its software, and the workspaces you give the team,
> while each keeps an independent home, browser, desktop, memory, credentials,
> and authority. Open any agent's terminal or desktop, mount shared or private
> files when authorized, and let the agents coordinate through the team fabric.

The shorter phrase is:

> One computer. A team of agents. A private view for each.

The security qualification is:

> Shared bytes and shared workspaces do not imply shared identity or authority.

## 12. Implementation order

1. Expose read-only ownership inspection and authenticated user/fleet context.
2. Define the versioned fleet-owned root and accounting grammar without changing
   `StateOwnerCodecV1` in place.
3. Implement the provider-neutral path/inode, staging, publication, mount-lease,
   and doctor contracts.
4. Compose system, fleet, principal, application, workspace, and synthetic team
   resources into one principal view.
5. Connect the existing principal-affine Linux Realm to that composed view while
   preserving kernel-stamped principal identity.
6. Implement one hosted mount and desktop adapter with crash, `mmap`, browser,
   compiler, provider-death, daemon-upgrade, and repair evidence.
7. Add the remaining macOS, Linux, and Windows mount/desktop adapters against the
   same behavioral contract.
8. Add the fleet team service and handle delegation.
9. Optimize density through shared immutable pages, checkpoints, physical
   objects, and workers without changing logical isolation.

The first release slice should prove two principals in one fleet:

- see identical immutable system bytes;
- see and concurrently update an explicitly shared fleet workspace;
- retain different homes, browser profiles, process trees, and desktops;
- cannot access one another's private files, tokens, clipboard, or display;
- exchange kernel-stamped messages and delegated file handles;
- survive provider and daemon restart with acknowledged writes intact; and
- can each be mounted or remotely viewed by an independently authorized user.

## 13. Stop conditions

Do not ship the fleet-computer claim if any of the following remains true:

- specialized durable agents share one `PrincipalUid`;
- a fleet or group name is treated as authentication;
- fleet membership automatically exposes every principal's private state;
- two same-principal applications silently share writable Realm state;
- a guest path or UID selects an authority-bearing host resource;
- desktop observation is implied by ownership-management authority;
- the immutable guest system view exposes mutable kernel administrative state to
  agents;
- raw principal-store engine files are the human administration interface;
- provider failure can lose acknowledged staged bytes or hang clients without a
  bounded error;
- physical deduplication becomes an authorization or cross-owner equality oracle;
  or
- a shared Linux guest becomes the only isolation boundary between principals.
