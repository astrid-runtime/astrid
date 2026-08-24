//! Reference interpreter over structured argv. Not a guest OS.

use astrid_provider::{
    AdmittedInstance, Checkpoint, ExecutionOutcome, ExecutionProvider, ExecutionReceipt, Job,
    ProviderError, ProviderIdentity, check_provider, check_start,
};
use astrid_resource_types::{ProviderGeneration, ProviderId};

use crate::ramfs::EphemeralRamfs;

/// Well-known compatibility provider identity. Not a named guest runtime.
pub const COMPAT_PROVIDER_ID: ProviderId = ProviderId::from_bytes([0xC1; 32]);
/// Compatibility provider incarnation.
pub const COMPAT_PROVIDER_GENERATION: ProviderGeneration = ProviderGeneration::INITIAL;

/// Workload-neutral reference interpreter with an ephemeral ramfs.
///
/// `true` and `echo` are non-normative falsifier tokens, not ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceInterpreter {
    ramfs: EphemeralRamfs,
}

impl ReferenceInterpreter {
    /// Construct an interpreter with an empty ephemeral ramfs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ramfs: EphemeralRamfs::new(),
        }
    }

    /// Well-known identity for this provider.
    #[must_use]
    pub const fn identity_value() -> ProviderIdentity {
        ProviderIdentity::new(COMPAT_PROVIDER_ID, COMPAT_PROVIDER_GENERATION)
    }

    /// Borrow the ephemeral namespace. Never a host directory.
    #[must_use]
    pub const fn ramfs(&self) -> &EphemeralRamfs {
        &self.ramfs
    }

    fn receipt(
        self,
        job: &Job,
        instance: &AdmittedInstance,
        outcome: ExecutionOutcome,
    ) -> ExecutionReceipt {
        ExecutionReceipt::for_request(self.identity(), job, instance, outcome)
    }
}

/// Interpret structured argv against the ephemeral namespace.
///
/// Unknown programs and non-empty attachments or streams fail closed.
///
/// # Errors
///
/// Returns [`ProviderError::NotSupported`] for unknown programs or for jobs
/// that carry attachments or streams. Empty argv is [`ProviderError::EmptyArgv`].
pub fn interpret_status(job: &Job) -> Result<u8, ProviderError> {
    if !job.attachments().is_empty() || !job.streams().is_empty() {
        return Err(ProviderError::NotSupported);
    }
    let Some(program) = job.argv().iter().next() else {
        return Err(ProviderError::EmptyArgv);
    };
    match program.as_bytes() {
        b"true" | b"echo" => Ok(0),
        _ => Err(ProviderError::NotSupported),
    }
}

impl ExecutionProvider for ReferenceInterpreter {
    fn identity(&self) -> ProviderIdentity {
        Self::identity_value()
    }

    fn start(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        let _status = interpret_status(job)?;
        Ok(self.receipt(job, instance, ExecutionOutcome::Started))
    }

    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        let status = interpret_status(job)?;
        Ok(self.receipt(job, instance, ExecutionOutcome::Exited { status }))
    }

    fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
        check_provider(&self.identity(), &instance.closure())?;
        Err(ProviderError::NotSupported)
    }

    fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
        let _ = checkpoint;
        Err(ProviderError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::{ReferenceInterpreter, interpret_status};
    use crate::fixtures::{alice_principal, bob_principal, instance_for, job_for};
    use astrid_projection::SemanticObjectId;
    use astrid_provider::{
        AttachmentDescriptor, AttachmentSet, CapsuleAdapter, ExecutionOutcome, ExecutionProvider,
        Job, JobArgv, ProviderError, StreamDescriptor, StreamSet, check_receipt, honest_closure,
    };
    use astrid_resource_types::{CausalRequestId, ObjectGeneration, OperationId, ResourceId};

    fn true_job() -> Job {
        job_for(alice_principal(), &[b"true"]).expect("true argv is in range")
    }

    fn job_with_attachments() -> Job {
        Job::for_instance(
            OperationId::from_bytes([0x41; 16]),
            &instance_for(alice_principal()),
            &JobArgv::try_from_args(&[b"true"]).expect("true argv is in range"),
            &AttachmentSet::try_from_descriptors(&[AttachmentDescriptor::new(
                SemanticObjectId::for_resource(ResourceId::from_bytes([0x77; 32])),
                ObjectGeneration::INITIAL,
            )])
            .expect("one attachment is in range"),
            &StreamSet::EMPTY,
            CausalRequestId::from_bytes([0x51; 16]),
            alice_principal(),
        )
    }

    fn job_with_streams() -> Job {
        Job::for_instance(
            OperationId::from_bytes([0x41; 16]),
            &instance_for(alice_principal()),
            &JobArgv::try_from_args(&[b"true"]).expect("true argv is in range"),
            &AttachmentSet::EMPTY,
            &StreamSet::try_from_descriptors(&[StreamDescriptor::new(
                SemanticObjectId::for_resource(ResourceId::from_bytes([0x88; 32])),
                ObjectGeneration::INITIAL,
            )])
            .expect("one stream is in range"),
            CausalRequestId::from_bytes([0x51; 16]),
            alice_principal(),
        )
    }

    #[test]
    fn true_start_and_exit_are_not_live_handles() {
        let provider = ReferenceInterpreter::new();
        let instance = instance_for(alice_principal());
        let job = true_job();
        let started = provider.start(&instance, &job).unwrap();
        assert_eq!(started.outcome(), ExecutionOutcome::Started);
        assert_eq!(started.as_live_handle(), Err(ProviderError::NotALiveHandle));
        check_receipt(&provider.identity(), &instance, &job, &started).unwrap();
        let exited = provider.exit(&instance, &job).unwrap();
        assert_eq!(exited.outcome(), ExecutionOutcome::Exited { status: 0 });
        assert_eq!(exited.as_live_handle(), Err(ProviderError::NotALiveHandle));
        assert!(provider.ramfs().as_host_path().is_none());
    }

    #[test]
    fn echo_is_a_non_normative_argv_falsifier() {
        let provider = CapsuleAdapter::new(ReferenceInterpreter::new());
        let instance = instance_for(alice_principal());
        let job = job_for(alice_principal(), &[b"echo", b"hello"]).unwrap();
        let started = provider.start(&instance, &job).unwrap();
        assert_eq!(started.outcome(), ExecutionOutcome::Started);
        let exited = provider.exit(&instance, &job).unwrap();
        assert_eq!(exited.outcome(), ExecutionOutcome::Exited { status: 0 });
        assert_eq!(exited.as_live_handle(), Err(ProviderError::NotALiveHandle));
    }

    #[test]
    fn unknown_program_and_host_looking_attachments_fail_closed() {
        let provider = ReferenceInterpreter::new();
        let instance = instance_for(alice_principal());
        let unknown = job_for(alice_principal(), &[b"sh"]).unwrap();
        assert_eq!(
            provider.start(&instance, &unknown),
            Err(ProviderError::NotSupported)
        );
        assert_eq!(
            interpret_status(&job_with_attachments()),
            Err(ProviderError::NotSupported)
        );
        assert_eq!(
            interpret_status(&job_with_streams()),
            Err(ProviderError::NotSupported)
        );
    }

    #[test]
    fn two_principals_are_isolated_by_the_stamp_seam() {
        let provider = ReferenceInterpreter::new();
        let alice_instance = instance_for(alice_principal());
        let bob_job = job_for(bob_principal(), &[b"true"]).unwrap();
        assert_eq!(
            provider.start(&alice_instance, &bob_job),
            Err(ProviderError::PrincipalMismatch)
        );
        assert!(provider.start(&alice_instance, &true_job()).is_ok());
        assert!(
            provider
                .start(&instance_for(bob_principal()), &bob_job)
                .is_ok()
        );
    }

    #[test]
    fn binding_mismatch_and_checkpoint_fail_closed() {
        let provider = ReferenceInterpreter::new();
        let instance = instance_for(alice_principal());
        let foreign = astrid_provider::AdmittedInstance::new(
            instance.id(),
            honest_closure(),
            instance.owner(),
        );
        assert_eq!(
            provider.start(&foreign, &true_job()),
            Err(ProviderError::TypeMismatch)
        );
        assert_eq!(
            provider.checkpoint(&instance),
            Err(ProviderError::NotSupported)
        );
    }
}
