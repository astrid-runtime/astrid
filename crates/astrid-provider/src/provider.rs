//! Execution-provider contract. Not admission and not a grant.

use crate::checkpoint::Checkpoint;
use crate::closure::{ApplicationClosure, decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, require_exact_len,
    write_header,
};
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
    /// Exact encoded length, including nested provider id and generation.
    pub const ENCODED_LEN: usize = 49;

    /// Bind a provider id to one incarnation.
    #[must_use]
    pub const fn new(id: ProviderId, generation: ProviderGeneration) -> Self {
        Self { id, generation }
    }

    /// Copy provider identity out of a closure. Not a grant.
    #[must_use]
    pub const fn from_closure(closure: ApplicationClosure) -> Self {
        Self::new(closure.provider(), closure.provider_generation())
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

impl DescriptorEncode for ProviderIdentity {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::ProviderIdentity)?;
        let offset = encode_resource(output, 3, &self.id)?;
        encode_resource(output, offset, &self.generation)?;
        Ok(())
    }
}

impl DescriptorDecode for ProviderIdentity {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::ProviderIdentity)?;
        let (id, offset) = decode_resource::<ProviderId>(input, 3, 35)?;
        let (generation, _) = decode_resource::<ProviderGeneration>(input, offset, 11)?;
        Ok(Self::new(id, generation))
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

/// Reject a provider identity that does not match the expected incarnation.
///
/// # Errors
///
/// Provider id disagreement is [`ProviderError::TypeMismatch`]. Generation
/// disagreement is [`ProviderError::StaleGeneration`].
pub fn check_identity(
    expected: &ProviderIdentity,
    found: &ProviderIdentity,
) -> Result<(), ProviderError> {
    if expected.id() != found.id() {
        return Err(ProviderError::TypeMismatch);
    }
    if expected.generation() != found.generation() {
        return Err(ProviderError::StaleGeneration {
            found: expected.generation().get(),
            requested: found.generation().get(),
        });
    }
    Ok(())
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
    check_identity(identity, &ProviderIdentity::from_closure(*closure))
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

/// Reject a receipt that does not name this request exactly.
///
/// # Errors
///
/// Provider, operation, causal, or instance disagreement is
/// [`ProviderError::TypeMismatch`]. Provider or instance generation
/// disagreement is [`ProviderError::StaleGeneration`].
pub fn check_receipt(
    identity: &ProviderIdentity,
    instance: &AdmittedInstance,
    job: &Job,
    receipt: &ExecutionReceipt,
) -> Result<(), ProviderError> {
    check_identity(identity, &receipt.provider())?;
    if receipt.operation() != job.operation() || receipt.causal() != job.causal() {
        return Err(ProviderError::TypeMismatch);
    }
    if receipt.instance().resource() != instance.id().resource() {
        return Err(ProviderError::TypeMismatch);
    }
    if receipt.instance().generation() != instance.id().generation() {
        return Err(ProviderError::StaleGeneration {
            found: instance.id().generation().get(),
            requested: receipt.instance().generation().get(),
        });
    }
    Ok(())
}

/// Reject a checkpoint that does not name this provider and instance.
///
/// # Errors
///
/// Propagates [`check_identity`] and [`check_restored_instance`].
pub fn check_checkpoint(
    identity: &ProviderIdentity,
    instance: &AdmittedInstance,
    checkpoint: &Checkpoint,
) -> Result<(), ProviderError> {
    check_restore(identity, checkpoint)?;
    check_restored_instance(checkpoint, instance)
}

/// Reject a checkpoint that does not name this provider incarnation.
///
/// # Errors
///
/// Provider id disagreement is [`ProviderError::TypeMismatch`]. Generation
/// disagreement is [`ProviderError::StaleGeneration`]. Internally inconsistent
/// checkpoints are [`ProviderError::NonCanonical`].
pub fn check_restore(
    identity: &ProviderIdentity,
    checkpoint: &Checkpoint,
) -> Result<(), ProviderError> {
    checkpoint.check_consistent()?;
    check_identity(identity, &checkpoint.provider())
}

/// Reject a restored descriptor that does not match the checkpoint binding.
///
/// # Errors
///
/// Resource, application, or provider-id disagreement is
/// [`ProviderError::TypeMismatch`]. Generation disagreement is
/// [`ProviderError::StaleGeneration`]. Principal-owner disagreement is
/// [`ProviderError::PrincipalMismatch`].
pub fn check_restored_instance(
    checkpoint: &Checkpoint,
    restored: &AdmittedInstance,
) -> Result<(), ProviderError> {
    let bound = checkpoint.admitted();
    if restored.id().resource() != bound.id().resource() {
        return Err(ProviderError::TypeMismatch);
    }
    if restored.id().generation() != bound.id().generation() {
        return Err(ProviderError::StaleGeneration {
            found: bound.id().generation().get(),
            requested: restored.id().generation().get(),
        });
    }
    if restored.closure().application() != bound.closure().application()
        || restored.closure().provider() != bound.closure().provider()
    {
        return Err(ProviderError::TypeMismatch);
    }
    if restored.closure().provider_generation() != bound.closure().provider_generation() {
        return Err(ProviderError::StaleGeneration {
            found: bound.closure().provider_generation().get(),
            requested: restored.closure().provider_generation().get(),
        });
    }
    match (bound.owner(), restored.owner()) {
        (left, right) if left == right => {},
        (OwnerId::Principal(_), OwnerId::Principal(_)) => {
            return Err(ProviderError::PrincipalMismatch);
        },
        _ => return Err(ProviderError::TypeMismatch),
    }
    check_provider(&checkpoint.provider(), &restored.closure())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{DescriptorDecode, DescriptorEncode};
    use crate::fixtures::{honest_instance, honest_job};
    use crate::instance::InstanceId;
    use crate::job::Job;
    use crate::null::NullProvider;
    use crate::receipt::ExecutionOutcome;
    use astrid_resource_types::{CanonicalEncode, ResourceId};

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

    #[test]
    fn provider_identity_encoding_is_not_a_bare_provider_id() {
        let identity = NullProvider.identity();
        let mut encoded = [0_u8; ProviderIdentity::ENCODED_LEN];
        identity.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(ProviderIdentity::decode_descriptor(&encoded), Ok(identity));
        let mut provider = [0_u8; 35];
        identity.id().encode_canonical(&mut provider).unwrap();
        assert_eq!(
            ProviderIdentity::decode_descriptor(&provider),
            Err(ProviderError::InvalidLength)
        );
    }

    #[test]
    fn forged_receipt_fields_fail_closed() {
        let instance = honest_instance();
        let job = honest_job().unwrap();
        let identity = NullProvider.identity();
        let honest = ExecutionReceipt::for_request(
            identity,
            &job,
            &instance,
            ExecutionOutcome::OutcomeUnknown,
        );
        check_receipt(&identity, &instance, &job, &honest).unwrap();
        let forged_operation = ExecutionReceipt::new(
            identity,
            astrid_resource_types::OperationId::from_bytes([0x99; 16]),
            job.causal(),
            instance.id(),
            ExecutionOutcome::OutcomeUnknown,
        );
        assert_eq!(
            check_receipt(&identity, &instance, &job, &forged_operation),
            Err(ProviderError::TypeMismatch)
        );
        let forged_instance = ExecutionReceipt::new(
            identity,
            job.operation(),
            job.causal(),
            InstanceId::new(
                ResourceId::from_bytes([0xfe; 32]),
                instance.id().generation(),
            ),
            ExecutionOutcome::OutcomeUnknown,
        );
        assert_eq!(
            check_receipt(&identity, &instance, &job, &forged_instance),
            Err(ProviderError::TypeMismatch)
        );
        let other = ProviderIdentity::new(
            astrid_resource_types::ProviderId::from_bytes([0xb5; 32]),
            identity.generation(),
        );
        let cross = ExecutionReceipt::new(
            other,
            job.operation(),
            job.causal(),
            instance.id(),
            ExecutionOutcome::OutcomeUnknown,
        );
        assert_ne!(honest, cross);
        assert_ne!(honest.binding(), cross.binding());
        assert_eq!(
            check_receipt(&identity, &instance, &job, &cross),
            Err(ProviderError::TypeMismatch)
        );
        let stale = ExecutionReceipt::new(
            ProviderIdentity::new(identity.id(), identity.generation().checked_next().unwrap()),
            job.operation(),
            job.causal(),
            instance.id(),
            ExecutionOutcome::OutcomeUnknown,
        );
        assert!(matches!(
            check_receipt(&identity, &instance, &job, &stale),
            Err(ProviderError::StaleGeneration { .. })
        ));
    }

    #[test]
    fn restored_wrong_closure_fails_closed() {
        use crate::checkpoint::CheckpointBlobId;
        use crate::closure::ApplicationClosure;
        use astrid_resource_types::ApplicationGenerationRef;

        let checkpoint =
            Checkpoint::from_instance(honest_instance(), CheckpointBlobId::from_bytes([0x61; 32]));
        let wrong_closure = AdmittedInstance::new(
            honest_instance().id(),
            ApplicationClosure::new(
                ApplicationGenerationRef::from_bytes([0x99; 32]),
                honest_instance().closure().provider(),
                honest_instance().closure().provider_generation(),
            ),
            honest_instance().owner(),
        );
        assert_eq!(
            check_restored_instance(&checkpoint, &wrong_closure),
            Err(ProviderError::TypeMismatch)
        );
    }
}
