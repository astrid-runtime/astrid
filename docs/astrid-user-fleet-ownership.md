# Astrid user and fleet ownership

Status: implemented foundation. CLI and HTTP management surfaces are not yet
exposed. AOS is not part of this change.

The proposed filesystem, desktop, team, and optional Linux Realm composition built on this
foundation is described in [Astrid fleet computer and principal
views](astrid-fleet-computer.md).

## Model

Astrid now separates identity, ownership, execution, and permission:

| Concept | Meaning | Stable identifier |
|---|---|---|
| User | Human authority that can move between frontends and devices | `UserUid` |
| Fleet | Ownership boundary containing users and executable principals | `FleetUid` |
| Principal | Executable identity used by an agent, service, or legacy process | `PrincipalUid` |
| Group | Reusable capability-permission bundle | Existing `GroupName` |

A principal has at most one fleet owner. It cannot be silently assigned to a
second fleet. Moving it is an explicit transfer authorized in both the source
and destination fleets. Groups remain independent of fleets: changing fleet
membership does not rewrite a principal's capability groups, and assigning a
group does not convey ownership. The existing `agent.delete` path rejects a
principal while it has a fleet assignment, so identity removal cannot leave a
dangling ownership edge.

Fleet membership has three roles:

- owners control owner membership, ordinary membership, and principals;
- administrators control ordinary membership and principals, but cannot make
  themselves an owner or remove or demote an owner; and
- members hold no ownership-management authority.

Every fleet must retain at least one owner.

## Persistence and recovery

The ownership graph lives under the reserved `system:ownership` namespace. A
single compare-and-swap record currently contains users, fleets, memberships,
and principal assignments. Principal edges are additionally checked against
the kernel's admitted durable principal directory during mutation and load.
This deliberately favors atomic invariants over
premature sharding: a new fleet and its first owner commit together, and no
crash or concurrent writer can expose a principal in two fleets. Reads validate
canonical user and fleet genesis records and every graph edge before admitting
the state.

`UserUid` and `FleetUid` are domain-separated BLAKE3 derivations over canonical
genesis bytes. Mutable aliases, display names, current frontend links, and
future key rotation do not change either identifier.

The existing `StateOwnerCodecV1` remains unchanged. Principal-owned KV and
content roots therefore preserve their byte format and behavior. Connecting
fleet accounting or user-owned state to that codec requires an explicit new
format or a separate index; this implementation does not smuggle new tags into
version one.

## Existing installations

Native kernel boot keeps the legacy `default` operator path working. After the
existing CLI root principal identity is loaded, Astrid deterministically and
idempotently creates:

1. a user from the existing root UUID, creation time, and initial public key;
2. a default fleet owned by that user; and
3. an ownership edge from the existing stable `PrincipalUid` to that fleet.

The `default` alias, `cli/local` link, admin group, profile, keys, home, and
current CLI/API behavior do not change. Corrupt ownership state fails kernel
boot instead of being ignored or overwritten.

## Intentionally not included yet

- no interactive onboarding or new CLI commands;
- no HTTP ownership-management endpoints;
- no AOS plugin or downstream migration;
- no automatic fleet assignment for newly created non-root principals;
- no change to capability evaluation, storage quota ownership, or capsule IPC;
- no claim that a fleet is a capability group.

Those surfaces should be added only after the substrate has shipped with a
read-only inspection API and the migration behavior has been exercised against
real existing homes.
