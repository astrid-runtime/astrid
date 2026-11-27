use std::sync::Arc;

use astrid_core::{PrincipalId, PrincipalUid};

use super::{
    Capsule, CapsuleError, CapsuleId, CapsuleRegistry, CapsuleResult, ReplacedRuntime, RuntimeId,
    RuntimeScope, WasmHash, capsule_source_uuid, system_uplink_descriptors,
};

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
            || self.runtime_id_for(principal, &id).as_ref() != Some(expected)
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
        let id = replacement.id().clone();
        if runtime_id.key().scope() != RuntimeScope::Principal(uid)
            || runtime_id.key().capsule_id() != &id
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "reserved runtime identity does not match principal replacement '{id}'"
            )));
        }
        if !replacement.manifest().uplinks.is_empty() {
            return Err(CapsuleError::UnsupportedEntryPoint(format!(
                "uplink capsule '{id}' requires explicit system runtime scope"
            )));
        }
        if expected.key().scope() != RuntimeScope::Principal(uid)
            || self.runtime_id_for(principal, &id).as_ref() != Some(expected)
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "runtime generation changed before replacing '{id}' for '{principal}'"
            )));
        }
        self.swap_runtime(expected, runtime_id, replacement, Some(principal.clone()))
    }

    /// Atomically replace an explicit system singleton and all of its views.
    pub fn replace_system_runtime(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        artifact: WasmHash,
    ) -> CapsuleResult<ReplacedRuntime> {
        let id = replacement.id().clone();
        if expected.key().scope() != RuntimeScope::SystemResident
            || !self.instances.contains_key(expected)
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "system runtime generation changed before replacing '{id}'"
            )));
        }
        if expected.key().capsule_id() != &id {
            return Err(CapsuleError::ExecutionFailed(format!(
                "replacement capsule id '{id}' does not match runtime '{}'",
                expected.key().capsule_id()
            )));
        }

        let descriptors = system_uplink_descriptors(replacement.as_ref())?;
        for descriptor in &descriptors {
            if let Some((owner, _)) = self.uplinks.get(&descriptor.id)
                && owner != &id
            {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
        }

        let runtime_id = self.next_runtime_id(id, artifact, RuntimeScope::SystemResident)?;
        self.replace_system_runtime_reserved(expected, replacement, runtime_id)
    }

    /// Atomically publish a preallocated system generation.
    pub fn replace_system_runtime_reserved(
        &mut self,
        expected: &RuntimeId,
        replacement: Box<dyn Capsule>,
        runtime_id: RuntimeId,
    ) -> CapsuleResult<ReplacedRuntime> {
        self.validate_system_runtime_replacement(expected, replacement.as_ref(), &runtime_id)?;
        let id = replacement.id().clone();
        let descriptors = system_uplink_descriptors(replacement.as_ref())?;
        let owner_alias = self
            .instances
            .get(expected)
            .and_then(|entry| entry.owner_alias.clone());
        let replaced = self.swap_runtime(expected, runtime_id, replacement, owner_alias)?;
        self.unregister_capsule_uplinks(&id);
        for descriptor in descriptors {
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
        let id = replacement.id().clone();
        if runtime_id.key().scope() != RuntimeScope::SystemResident
            || runtime_id.key().capsule_id() != &id
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "reserved runtime identity does not match system replacement '{id}'"
            )));
        }
        if expected.key().scope() != RuntimeScope::SystemResident
            || !self.instances.contains_key(expected)
        {
            return Err(CapsuleError::ExecutionFailed(format!(
                "system runtime generation changed before replacing '{id}'"
            )));
        }
        if expected.key().capsule_id() != &id {
            return Err(CapsuleError::ExecutionFailed(format!(
                "replacement capsule id '{id}' does not match runtime '{}'",
                expected.key().capsule_id()
            )));
        }
        let descriptors = system_uplink_descriptors(replacement)?;
        let mut pending = std::collections::HashSet::new();
        for descriptor in &descriptors {
            if let Some((owner, _)) = self.uplinks.get(&descriptor.id)
                && owner != &id
            {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
            if !pending.insert(descriptor.id) {
                return Err(CapsuleError::UnsupportedEntryPoint(format!(
                    "Uplink already registered: {}",
                    descriptor.id
                )));
            }
        }
        Ok(())
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
    ) -> CapsuleResult<ReplacedRuntime> {
        let previous_artifact = expected.key().artifact().clone();
        let previous = super::instance_swap::replace(
            &mut self.instances,
            expected,
            runtime_id.clone(),
            Arc::from(replacement),
            owner_alias,
        )
        .ok_or_else(|| CapsuleError::NotFound(format!("runtime {expected:?}")))?;
        for view in self.views.values_mut() {
            for mapped in view.values_mut() {
                super::instance_swap::retarget(mapped, expected, &runtime_id);
            }
        }
        self.uuid_map
            .retain(|_, mapped_runtime| mapped_runtime != expected);
        let previous_source = self.source_uuid_by_runtime.remove(expected);
        if let Some(previous_source) = previous_source
            && !self
                .source_uuid_by_runtime
                .values()
                .any(|candidate| candidate == &previous_source)
        {
            self.uuid_id_map.remove(&previous_source);
        }
        let source_uuid =
            capsule_source_uuid(runtime_id.key().capsule_id(), runtime_id.key().artifact());
        for (principal, view) in &self.views {
            if super::viewers::attached(view, &runtime_id) {
                self.uuid_map
                    .insert((source_uuid, principal.clone()), runtime_id.clone());
            }
        }
        self.source_uuid_by_runtime
            .insert(runtime_id.clone(), source_uuid);
        self.uuid_id_map
            .insert(source_uuid, runtime_id.key().capsule_id().clone());
        self.remove_legacy_uuid_mappings_if_unused(&previous_artifact);
        Ok(ReplacedRuntime {
            runtime_id,
            previous,
        })
    }
}
