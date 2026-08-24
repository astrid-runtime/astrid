//! Execution-provider contract. Not admission and not a grant.

use crate::checkpoint::Checkpoint;
use crate::closure::ApplicationClosure;
use crate::error::ProviderError;
use crate::instance::AdmittedInstance;
use crate::job::Job;
use crate::receipt::ExecutionReceipt;
use astrid_resource_types::{OwnerId, ProviderGeneration, ProviderId};

/// Named provider incarnation. Not a live table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProviderIdentity {
    id: ProviderId,
    generation: ProviderGeneration,
}

impl ProviderIdentity {
    /// Bind a provider id to one incarnation.
    #[must_use]
    pub const fn new(id: ProviderId, generation: ProviderGeneration) -> Self {
        Self { id, generation }
    }

    /// Provider identity.
    #[must_use]
    pub const fn id(self) -> ProviderId {
        self.id
    }

    /// Provider incarnation. Distinct from object generation.
    #[must_use]
    pub const fn generation(self) -> ProviderGeneration {
        self.generation
    }
}

/// Host-neutral execution surface.
///
/// Implementations consume descriptors. They do not admit resources, mint
/// leases, or substitute for live `ResourceAuthority` checks on the host.
pub trait ExecutionProvider {
    /// Provider identity used by binding checks.
    fn identity(&self) -> ProviderIdentity;

    /// Record a start. Must not serialize a live handle.
    ///
    /// # Errors
    ///
    /// Returns binding, generation, or provider-specific failures.
    fn start(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError>;

    /// Record an exit. Must not serialize a live handle.
    ///
    /// # Errors
    ///
    /// Returns binding, generation, or provider-specific failures.
    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError>;

    /// Capture a checkpoint blob identity.
    ///
    /// # Errors
    ///
    /// Returns binding failures or [`ProviderError::NotSupported`].
    fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError>;

    /// Restore yields a new descriptor. Portal refresh is host rebinding.
    ///
    /// # Errors
    ///
    /// Returns binding failures or [`ProviderError::NotSupported`].
    fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError>;
}

/// Reject jobs whose identities do not match the admitted instance.
///
/// # Errors
///
/// Resource or closure disagreement is [`ProviderError::TypeMismatch`].
/// Object-generation disagreement is [`ProviderError::StaleGeneration`].
/// A principal owner that does not match the job is
/// [`ProviderError::PrincipalMismatch`].
pub fn check_binding(instance: &AdmittedInstance, job: &Job) -> Result<(), ProviderError> {
    if job.instance().resource() != instance.id().resource() {
        return Err(ProviderError::TypeMismatch);
    }
    if job.instance().generation() != instance.id().generation() {
        return Err(ProviderError::StaleGeneration {
            found: instance.id().generation().get(),
            requested: job.instance().generation().get(),
        });
    }
    if job.closure() != instance.closure() {
        return Err(ProviderError::TypeMismatch);
    }
    match instance.owner() {
        OwnerId::Principal(bytes) if bytes == *job.principal().as_bytes() => Ok(()),
        OwnerId::Principal(_) => Err(ProviderError::PrincipalMismatch),
        OwnerId::System | OwnerId::Fleet(_) => Err(ProviderError::TypeMismatch),
    }
}

/// Reject closures that do not name this provider incarnation.
///
/// # Errors
///
/// Provider id disagreement is [`ProviderError::TypeMismatch`]. Generation
/// disagreement is [`ProviderError::StaleGeneration`].
pub fn check_provider(
    identity: &ProviderIdentity,
    closure: &ApplicationClosure,
) -> Result<(), ProviderError> {
    if identity.id() != closure.provider() {
        return Err(ProviderError::TypeMismatch);
    }
    if identity.generation() != closure.provider_generation() {
        return Err(ProviderError::StaleGeneration {
            found: identity.generation().get(),
            requested: closure.provider_generation().get(),
        });
    }
    Ok(())
}

/// Shared start/exit preflight used by host-owned providers.
///
/// # Errors
///
/// Propagates [`check_binding`] and [`check_provider`].
pub fn check_start(
    identity: &ProviderIdentity,
    instance: &AdmittedInstance,
    job: &Job,
) -> Result<(), ProviderError> {
    check_binding(instance, job)?;
    check_provider(identity, &instance.closure())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{honest_instance, honest_job};
    use crate::instance::InstanceId;
    use crate::job::Job;
    use astrid_resource_types::ResourceId;

    #[test]
    fn stale_generation_is_not_a_type_mismatch() {
        let instance = honest_instance();
        let stale = Job::claiming(
            honest_job().unwrap().operation(),
            InstanceId::new(
                instance.id().resource(),
                instance.id().generation().checked_next().unwrap(),
            ),
            instance.closure(),
            honest_job().unwrap().argv(),
            honest_job().unwrap().causal(),
            honest_job().unwrap().principal(),
        );
        assert!(matches!(
            check_binding(&instance, &stale),
            Err(ProviderError::StaleGeneration { .. })
        ));
        let confused = Job::claiming(
            stale.operation(),
            InstanceId::new(
                ResourceId::from_bytes([0xfe; 32]),
                instance.id().generation(),
            ),
            instance.closure(),
            stale.argv(),
            stale.causal(),
            stale.principal(),
        );
        assert_eq!(
            check_binding(&instance, &confused),
            Err(ProviderError::TypeMismatch)
        );
    }
}
