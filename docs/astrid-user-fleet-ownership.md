# Astrid user and fleet ownership

Status: implemented foundation. Native local upgrade assigns leftover
principals to the bound CLI-root operator; CLI exposes authenticated discovery
and named first-assignment for deferred leftovers. HTTP ownership-management
endpoints are not yet exposed. AOS is not part of this change.

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
group does not convey ownership. Deleting a fleet-owned principal requires
both the existing deletion capability and an authenticated device delegated to
a current manager of the target fleet. Removing ownership and reserving the
identity for deletion commit atomically, so removal cannot leave a dangling
ownership edge or an interval in which another fleet can adopt the identity.

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
2. a default fleet owned by that user;
3. an ownership edge from the existing stable `PrincipalUid` to that fleet; and
4. the trusted local-operator device binding on `cli/local`, then local upgrade
   of remaining unowned admitted principals when that binding is current and
   the graph is still unambiguous.

The `default` alias, `cli/local` link, admin group, profile, keys, home, and
current CLI/API behavior do not change. Corrupt ownership state fails kernel
boot instead of being ignored or overwritten.

## Released-home upgrade

Native boot no longer uses `LayoutOrigin::Legacy` as a blanket adoption switch,
and it does not infer ownership of historical principals from a singleton
graph. After the deterministic CLI-root user and fleet exist, the durable
`default` principal is assigned and the trusted `cli/local` device is bound as
the local operator. Unowned admitted leftovers are then adopted only when that
bound local-operator device currently resolves to a manager of `default`'s
fleet **and** the graph still contains exactly that user, exactly that fleet,
and no assignment to any other fleet. Existing assignments, transfers, and deletion reservations are never
moved or adopted. Disabled is a profile flag, not a graph filter: an
unowned admitted principal remains an adoption leftover even when
`profile.enabled` is false.

Released homes have no personal-versus-hosted marker. Extra users, extra
fleets, or a foreign assignment make bulk adoption ambiguous; those leftovers
stay unowned and remain actionable through named confirmation. A missing or
revoked local-operator device binding is the same: no mutation, leftovers stay
claimable. `UserPrincipalList` / `astrid agent list --mine` is read-only and
does not reconcile.

```
astrid agent claim <name>
```

That command remains the remainder path for deferred leftovers. It reuses
ordinary first assignment (`UserPrincipalClaim` /
`assign_created_principal_for_device`). It requires a current user-delegated
device, fleet management authority, and `agent:create`. It is idempotent when
the named principal is already in the caller's fleet, never transfers another
fleet's assignment, and does not copy human-device delegation onto the claimed
principal. Extra users or fleets in the graph do not block a named claim.

`scripts/test-user-principal-discovery.sh` can seed a disposable packed home
with a released CLI and then start the candidate against the same volume. The
upgrade path first uses a leftover principal on the released CLI, then asserts
preserved keys and the same use after candidate start, that packed leftovers
are visible in `--mine` without `astrid agent claim`, that an undelegated child
cannot claim, and that restart keeps the local-operator assignments.

## Intentionally not included yet

- no interactive onboarding or hosted login;
- no HTTP ownership-management endpoints;
- no AOS plugin or downstream migration; local Oracle/CLI daemon start is enough;
- no hosted-versus-personal config marker;
- no change to capability evaluation, storage quota ownership, or capsule IPC;
- no claim that a fleet is a capability group.

Those surfaces should be added only after the substrate has shipped with a
read-only inspection API and the migration behavior has been exercised against
real existing homes.

## In-progress creation integration

The development CLI now exposes `astrid agent list --mine --format json` via
`UserPrincipalList` on `admin.user.principals`, and `astrid agent claim <name>`
via `UserPrincipalClaim` on `admin.user.principal.claim`. Discovery requires
the normal registered-device/capability check and an explicit current user
delegation. It returns only assignments in that user's current fleets, even
when the credential also has administrator capabilities. The existing
`agent list` self/global behavior is unchanged. Rows confer no permission to
switch, approve, answer a form, or use another principal's signing key. Named
claim is the remainder path for leftovers that automatic local upgrade deferred.
Old runtimes do not support the new requests; clients must not fall back to a
global list.

`scripts/test-user-principal-discovery.sh` exercises real candidate CLI/daemon
startup, principal creation, scoped discovery, rejection without human
delegation, and restart persistence in a disposable home. With a released CLI
as the second argument it also seeds a packed volume, upgrades it in place,
checks that signing keys are unchanged, refuses undelegated claim, and expects
packed leftovers to appear in `--mine` after candidate start without a named
claim. It is not an Oracle installation, GUI picker, hosted login, or a claim
that a singleton graph alone owns historical principals.

Agent spawning keeps its existing `agent:create:inherit` capability gate.
The child joins the authenticated spawning principal's fleet, not the template
source's fleet. It retains the creator's historical human assignment provenance
without gaining a human-device delegation or broader capabilities. Creator
ownership is pinned before provisioning and rechecked atomically on assignment;
a transfer during provisioning rejects the stale assignment. An unowned caller
cannot create another unowned principal. Capsule-load failure remains on the
existing rollback path before ownership is assigned.

Deletion reservations retain the target fleet even after the principal's
identity has been removed. Retrying cleanup checks current user delegation and
fleet management authority; revocation or demotion cannot be bypassed through
an alias-only retry. Target device bindings are removed with ownership. Failed
cleanup keeps the alias reserved until generation-scoped reclamation finishes.
Legacy unowned deletion keeps its capability-based path; an unauthenticated
human context cannot delete an owned principal through that path.

Stateful admin tests use `admin::test_support::seed_operator` and explicitly
call `dispatch_as_operator` when creation requires an authenticated operator.
The fixture registers a device, human and fleet binding; it does not bypass
production capability or ownership checks. Tests enter below transport
signature verification and therefore do not prove the socket authentication
journey. Missing/revoked-delegation tests use the raw dispatch path or revoke
the binding, and continue to require rejection without creating an identity.

Deletion tests retain their original success and cleanup assertions. They must
not be made green by silently stripping ownership from the fixture or accepting
the new deletion refusal as success.
