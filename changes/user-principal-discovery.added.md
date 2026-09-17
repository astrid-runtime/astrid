Add a user-scoped ownership query for principal discovery. It filters assignments by current fleet membership without granting permission to act as a principal; callers must authenticate users and recheck authorization independently.

Add atomic first assignment from a creator's current fleet, checking current manager authority and refusing implicit transfers.

Add explicit device-to-user delegation storage scoped to a principal and fleet, revoked on membership removal or cross-fleet transfer. Authentication and client integration remain separate.

Bind newly issued invitations to explicit issuer ownership and commit token consumption together with principal assignment. Revocation, delegation replacement, issuer device removal and changed fleet authority reject enrollment; legacy invitations without ownership must be reissued. Enrolled devices do not inherit the issuer's human identity.

Allow fleet managers with authenticated delegated devices and deletion capability to delete owned principals. Ownership and device bindings retire atomically with the deletion reservation; interrupted cleanup retains the fleet boundary and rechecks current authority on retry.

Assign spawned principals to the authenticated creator's fleet under the existing spawn capability, independently of the template source. Reject stale creator ownership and do not copy human-device delegation or broaden the child's restricted capability profile.
Added `astrid agent list --mine` backed by authenticated server-side fleet
membership filtering. This does not grant acting authority and never falls
back to the administrator's global roster.

Auto-assign historical unowned principals only for the bound local-operator
device on the durable CLI root. Layout origin and a singleton graph are not
proof of human ownership; released homes have no personal-versus-hosted
marker. The bulk repair still refuses extra users, extra fleets, or foreign
assignments, and a missing local-operator binding defers leftovers. Discovery
list remains read-only.

Keep `astrid agent claim <name>` (`UserPrincipalClaim`) as the remainder
path that assigns one named unowned principal to the authenticated human's
current fleet. It reuses first assignment, requires current user delegation
and fleet management plus `agent:create`, is idempotent in the caller's fleet,
and never transfers an existing owner.
