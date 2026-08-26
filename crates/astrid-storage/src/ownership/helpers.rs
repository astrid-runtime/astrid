use astrid_core::{FleetRole, UserUid};

use super::{FleetRecord, OwnershipError, OwnershipStore};

impl OwnershipStore {
    pub(super) fn require_manager(
        fleet: &FleetRecord,
        actor: UserUid,
    ) -> Result<(), OwnershipError> {
        let role = Self::role(fleet, actor);
        if role.is_some_and(FleetRole::can_manage) {
            Ok(())
        } else {
            Err(OwnershipError::NotFleetManager {
                user: actor,
                fleet: fleet.identity.uid,
            })
        }
    }

    pub(super) fn role(fleet: &FleetRecord, user: UserUid) -> Option<FleetRole> {
        fleet
            .memberships
            .get(&user)
            .map(|membership| membership.role)
    }

    pub(super) fn owner_count(fleet: &FleetRecord) -> usize {
        fleet
            .memberships
            .values()
            .filter(|membership| membership.role == FleetRole::Owner)
            .count()
    }
}
