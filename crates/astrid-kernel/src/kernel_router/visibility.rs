//! Caller-scoped capsule inventory visibility.

use std::collections::BTreeSet;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;

use super::AuthorizedRequest;

pub(super) struct CapsuleVisibility {
    pub(super) principal: PrincipalId,
    is_admin: bool,
    capsule_grants: BTreeSet<String>,
}

impl CapsuleVisibility {
    pub(super) fn new(authorization: &AuthorizedRequest) -> Self {
        if authorization.principal.as_str() == "anonymous" {
            return Self::denied(&authorization.principal);
        }
        let profile = authorization.profile.as_ref();
        let check = authorization.capability_check();

        Self {
            principal: authorization.principal.clone(),
            is_admin: check.has("capsule:list"),
            capsule_grants: profile.capsules.iter().cloned().collect(),
        }
    }

    fn denied(caller: &PrincipalId) -> Self {
        Self {
            principal: caller.clone(),
            is_admin: false,
            capsule_grants: BTreeSet::new(),
        }
    }

    pub(super) fn allows(&self, capsule_id: &astrid_capsule::capsule::CapsuleId) -> bool {
        self.is_admin || self.capsule_grants.contains(capsule_id.as_str())
    }

    pub(super) fn capsules(
        &self,
        registry: &astrid_capsule::registry::CapsuleRegistry,
    ) -> Vec<Arc<dyn astrid_capsule::capsule::Capsule>> {
        if self.is_admin {
            registry.cloned_values()
        } else {
            registry.cloned_values_for(&self.principal)
        }
    }
}
