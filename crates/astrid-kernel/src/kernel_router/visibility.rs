//! Caller-scoped capsule inventory visibility.

use std::collections::BTreeSet;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;

use super::AuthorizedRequest;

pub(super) struct CapsuleVisibility {
    pub(super) principal: PrincipalId,
    is_admin: bool,
    all_principals: bool,
    capsule_grants: BTreeSet<String>,
}

impl CapsuleVisibility {
    pub(super) fn new(authorization: &AuthorizedRequest) -> Self {
        if authorization.principal.as_str() == "anonymous" {
            return Self::denied(&authorization.principal);
        }
        let profile = authorization.profile.as_ref();
        let check = authorization.capability_check();

        let is_admin = check.has("capsule:list");
        Self {
            principal: authorization.principal.clone(),
            is_admin,
            all_principals: is_admin,
            capsule_grants: profile.capsules.iter().cloned().collect(),
        }
    }

    pub(super) fn for_target(authorization: &AuthorizedRequest, target: &PrincipalId) -> Self {
        if target == &authorization.principal {
            return Self::new(authorization);
        }
        debug_assert!(authorization.capability_check().has("capsule:list"));
        Self {
            principal: target.clone(),
            is_admin: true,
            all_principals: false,
            capsule_grants: BTreeSet::new(),
        }
    }

    fn denied(caller: &PrincipalId) -> Self {
        Self {
            principal: caller.clone(),
            is_admin: false,
            all_principals: false,
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
        if self.is_admin && self.all_principals {
            registry.cloned_values()
        } else {
            registry.cloned_values_for(&self.principal)
        }
    }
}
