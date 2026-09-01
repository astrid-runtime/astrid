//! Caller-scoped capsule inventory visibility.

use std::collections::BTreeSet;

use super::AuthorizedRequest;

pub(super) struct CapsuleVisibility {
    is_admin: bool,
    capsule_grants: BTreeSet<String>,
}

impl CapsuleVisibility {
    pub(super) fn new(authorization: &AuthorizedRequest) -> Self {
        if authorization.principal.as_str() == "anonymous" {
            return Self::denied();
        }
        let profile = authorization.profile.as_ref();
        let check = authorization.capability_check();

        Self {
            is_admin: check.has("capsule:list"),
            capsule_grants: profile.capsules.iter().cloned().collect(),
        }
    }

    fn denied() -> Self {
        Self {
            is_admin: false,
            capsule_grants: BTreeSet::new(),
        }
    }

    pub(super) fn allows(&self, capsule_id: &astrid_capsule::capsule::CapsuleId) -> bool {
        self.is_admin || self.capsule_grants.contains(capsule_id.as_str())
    }
}
