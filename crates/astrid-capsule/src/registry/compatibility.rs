//! Compatibility entry points whose historical names encode old ownership.

use astrid_core::PrincipalId;

use super::{CapsuleRegistry, RuntimeScope, WasmHash};
use crate::capsule::Capsule;
use crate::error::{CapsuleError, CapsuleResult};

impl CapsuleRegistry {
    /// Compatibility wrapper for explicitly registering a system singleton.
    ///
    /// The historical API creates a default-owned runtime but exposes its
    /// initial view to `view_principal`. Production kernel policy uses
    /// [`Self::register_system_runtime`] only after operator authorization.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested view already has this capsule, a
    /// matching runtime has a non-default owner, or uplink registration fails.
    pub fn register_owned_by_default(
        &mut self,
        capsule: Box<dyn Capsule>,
        hash: WasmHash,
        view_principal: &PrincipalId,
    ) -> CapsuleResult<()> {
        if let Some(runtime_id) = self.system_runtime_for_hash(capsule.id(), &hash) {
            let default = PrincipalId::default();
            let default_owned = self
                .instances
                .get(&runtime_id)
                .and_then(|entry| entry.owner_alias.as_ref())
                == Some(&default);
            if !default_owned {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "capsule '{}' is already registered under a non-default system owner",
                    capsule.id()
                )));
            }
            return self.add_system_view(capsule.id(), &runtime_id, view_principal);
        }
        let runtime_id =
            self.reserve_runtime_id(capsule.id().clone(), hash, RuntimeScope::SystemResident)?;
        self.commit_reserved_runtime(
            capsule,
            runtime_id,
            view_principal,
            Some(PrincipalId::default()),
        )
        .map(|_| ())
    }
}
