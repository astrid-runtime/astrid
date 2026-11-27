use std::sync::Arc;

use astrid_core::{PrincipalId, PrincipalUid, UplinkDescriptor};

use super::{
    Capsule, CapsuleError, CapsuleId, CapsuleRegistry, CapsuleResult, ReplacedRuntime, RuntimeId,
    RuntimePublicationError, RuntimeScope, WasmHash, capsule_source_uuid,
    system_uplink_descriptors,
};

/// Descriptors checked against the registered owners and each other before publication.
struct CheckedSystemUplinks(Vec<UplinkDescriptor>);

impl CheckedSystemUplinks {
    fn new(
        registry: &CapsuleRegistry,
        id: &CapsuleId,
        descriptors: Vec<UplinkDescriptor>,
    ) -> CapsuleResult<Self> {
        let mut pending = std::collections::HashSet::new();
        for descriptor in &descriptors {
            if registry
                .uplinks
                .get(&descriptor.id)
                .is_some_and(|(owner, _)| owner != id)
                || !pending.insert(descriptor.id)
            {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
        }
        Ok(Self(descriptors))
    }
}

impl CapsuleRegistry {
    /// Atomically replace the principal runtime currently visible in one view.
    ///
    /// The replacement capsule must already be loaded but not autonomously
    /// activated. No registry reader can observe a missing view or a partially
    /// installed generation.
    pub fn replace_principal_runtime(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        artifact: WasmHash,
        principal: &PrincipalId,
        uid: PrincipalUid,
    ) -> CapsuleResult<ReplacedRuntime> {
        let id = replacement.id().clone();
        if expected.key().scope() != RuntimeScope::Principal(uid)
            || !self.is_current_runtime(principal, &id, expected)
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "runtime generation changed before replacing '{id}' for '{principal}'"
            )));
        }
        if !replacement.manifest().uplinks.is_empty() {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "uplink capsule '{id}' requires explicit system runtime scope"
            )));
        }

        let runtime_id = self.next_runtime_id(id, artifact, RuntimeScope::Principal(uid))?;
        self.replace_principal_runtime_reserved(expected, replacement, runtime_id, principal, uid)
    }

    /// Atomically publish a preallocated principal generation.
    pub fn replace_principal_runtime_reserved(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        runtime_id: RuntimeId,
        principal: &PrincipalId,
        uid: PrincipalUid,
    ) -> CapsuleResult<ReplacedRuntime> {
        let id = replacement.id();
        super::generation_replacement::admit_principal(
            &self.views,
            principal,
            id,
            uid,
            expected,
            &runtime_id,
            || !replacement.manifest().uplinks.is_empty(),
        )
        .map_err(|reason| match reason {
            super::generation_replacement::PrincipalRefusal::Reservation => {
                CapsuleError::ExecutionFailed(format!(
                    "reserved runtime identity does not match principal replacement '{id}'"
                ))
            },
            super::generation_replacement::PrincipalRefusal::Uplink => {
                CapsuleError::UnsupportedEntryPoint(format!(
                    "uplink capsule '{id}' requires explicit system runtime scope"
                ))
            },
            super::generation_replacement::PrincipalRefusal::Superseded => {
                CapsuleError::ExecutionFailed(format!(
                    "runtime generation changed before replacing '{id}' for '{principal}'"
                ))
            },
        })?;
        self.swap_runtime(expected, runtime_id, replacement, Some(principal.clone()))
            .map_err(|rejected| rejected.error)
    }

    /// Atomically replace an explicit system singleton and all of its views.
    pub fn replace_system_runtime(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        artifact: WasmHash,
    ) -> CapsuleResult<ReplacedRuntime> {
        let descriptors = self.system_replacement_uplinks(expected, replacement.as_ref())?;
        let runtime_id = self.next_runtime_id(
            replacement.id().clone(),
            artifact,
            RuntimeScope::SystemResident,
        )?;
        self.publish_system_replacement(expected, replacement, runtime_id, descriptors)
            .map_err(|rejected| rejected.error)
    }

    /// Atomically publish a preallocated system generation.
    pub fn replace_system_runtime_reserved(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        runtime_id: RuntimeId,
    ) -> CapsuleResult<ReplacedRuntime> {
        self.try_replace_system_runtime_reserved(expected, replacement, runtime_id)
            .map_err(|rejected| rejected.error)
    }

    /// Publish a reserved system replacement or return its candidate for teardown.
    ///
    /// # Errors
    ///
    /// A stale generation, mismatched reservation or conflicting uplink leaves the registry unchanged.
    pub fn try_replace_system_runtime_reserved(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        runtime_id: RuntimeId,
    ) -> Result<ReplacedRuntime, RuntimePublicationError> {
        let descriptors =
            match self.reserved_system_uplinks(expected, replacement.as_ref(), &runtime_id) {
                Ok(descriptors) => descriptors,
                Err(error) => {
                    return Err(RuntimePublicationError {
                        capsule: replacement,
                        error,
                    });
                },
            };
        self.publish_system_replacement(expected, replacement, runtime_id, descriptors)
    }

    fn publish_system_replacement(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        runtime_id: RuntimeId,
        descriptors: CheckedSystemUplinks,
    ) -> Result<ReplacedRuntime, RuntimePublicationError> {
        let owner_alias = self
            .instances
            .get(expected)
            .and_then(|entry| entry.owner_alias.clone());
        let replaced = self.swap_runtime(expected, runtime_id, replacement, owner_alias)?;
        let id = replaced.runtime_id.key().capsule_id();
        self.unregister_capsule_uplinks(id);
        for descriptor in descriptors.0 {
            self.uplinks.insert(descriptor.id, (id.clone(), descriptor));
        }
        Ok(replaced)
    }

    /// Preflight a prepared system replacement without consuming it.
    pub fn validate_system_runtime_replacement(
        &self,
        expected: &RuntimeId,
        replacement: &dyn Capsule,
        runtime_id: &RuntimeId,
    ) -> CapsuleResult<()> {
        self.reserved_system_uplinks(expected, replacement, runtime_id)
            .map(drop)
    }

    fn reserved_system_uplinks(
        &self,
        expected: &RuntimeId,
        replacement: &dyn Capsule,
        runtime_id: &RuntimeId,
    ) -> CapsuleResult<CheckedSystemUplinks> {
        let id = replacement.id();
        if runtime_id.key().scope() != RuntimeScope::SystemResident
            || runtime_id.key().capsule_id() != id
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "reserved runtime identity does not match system replacement '{id}'"
            )));
        }
        self.system_replacement_uplinks(expected, replacement)
    }

    fn system_replacement_uplinks(
        &self,
        expected: &RuntimeId,
        replacement: &dyn Capsule,
    ) -> CapsuleResult<CheckedSystemUplinks> {
        let id = replacement.id();
        if expected.key().scope() != RuntimeScope::SystemResident
            || !self.instances.contains_key(expected)
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "system runtime generation changed before replacing '{id}'"
            )));
        }
        if expected.key().capsule_id() != id {
            return Err(CapsuleError::ExecutionFailed(format!(
                "replacement capsule id '{id}' does not match runtime '{}'",
                expected.key().capsule_id()
            )));
        }
        CheckedSystemUplinks::new(self, id, system_uplink_descriptors(replacement)?)
    }

    pub(super) fn next_runtime_id(
        &mut self,
        id: CapsuleId,
        artifact: WasmHash,
        scope: RuntimeScope,
    ) -> CapsuleResult<RuntimeId> {
        super::generation::issue(&mut self.next_generation, id, artifact, scope).ok_or_else(|| {
            CapsuleError::ExecutionFailed("capsule runtime generation space exhausted".into())
        })
    }

    fn swap_runtime(
        &mut self,
        expected: &RuntimeId,
        runtime_id: RuntimeId,
        replacement: Box<dyn Capsule>,
        owner_alias: Option<PrincipalId>,
    ) -> Result<ReplacedRuntime, RuntimePublicationError> {
        let replacement = super::generation_replacement::Replacement {
            expected,
            reserved: &runtime_id,
            source: capsule_source_uuid(runtime_id.key().capsule_id(), runtime_id.key().artifact()),
            candidate: replacement,
            materialize: Arc::from,
            owner_alias,
        };
        let previous = replacement
            .apply(
                &mut self.instances,
                &mut self.views,
                &mut self.uuid_map,
                &mut self.source_uuid_by_runtime,
                &mut self.uuid_id_map,
                &mut self.legacy_uuid_map,
            )
            .map_err(|capsule| RuntimePublicationError {
                error: CapsuleError::NotFound(format!("runtime {expected:?}")),
                capsule,
            })?;
        Ok(ReplacedRuntime {
            runtime_id,
            previous,
        })
    }
}

#[cfg(test)]
mod tests;
