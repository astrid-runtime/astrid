//! Reference interpreter over structured argv. Not a guest OS.

use astrid_provider::{
    AdmittedInstance, Checkpoint, ExecutionOutcome, ExecutionProvider, ExecutionReceipt,
    HostPrincipal, Job, ProviderError, ProviderIdentity, check_provider, check_start,
};
use astrid_resource_types::{ProviderGeneration, ProviderId};

use crate::fixtures::ARGV_FALSIFIER_APPLICATION;
use crate::image::known_image;
use crate::machine::{DEFAULT_INSTRUCTION_FUEL, PortableMachine};
use crate::ramfs::EphemeralRamfs;

/// Well-known compatibility provider identity. Not a named guest runtime.
pub const COMPAT_PROVIDER_ID: ProviderId = ProviderId::from_bytes([0xC1; 32]);
/// Compatibility provider incarnation.
pub const COMPAT_PROVIDER_GENERATION: ProviderGeneration = ProviderGeneration::INITIAL;

/// Workload-neutral reference interpreter.
///
/// Each execution receives a fresh owner-bound ramfs. There is no shared
/// unowned namespace and no global table. `true` and `echo` are non-normative
/// falsifier tokens, not ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceInterpreter;

impl ReferenceInterpreter {
    /// Construct an interpreter with no retained execution state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Well-known identity for this provider.
    #[must_use]
    pub const fn identity_value() -> ProviderIdentity {
        ProviderIdentity::new(COMPAT_PROVIDER_ID, COMPAT_PROVIDER_GENERATION)
    }

    /// Fresh owner-bound namespace. Guest argv, paths, and payloads cannot select it.
    #[must_use]
    pub const fn namespace_for(self, owner: HostPrincipal) -> EphemeralRamfs {
        let _ = self;
        EphemeralRamfs::for_owner(owner)
    }

    /// Bind a namespace to the instance owner and require `caller`.
    ///
    /// This is independent of [`check_start`]: a mismatched caller cannot
    /// observe or mutate the owner's namespace.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::TypeMismatch`] when the instance owner is not
    /// a principal, or [`ProviderError::PrincipalMismatch`] when `caller` is
    /// not that owner.
    pub fn activate_namespace(
        self,
        instance: &AdmittedInstance,
        caller: HostPrincipal,
    ) -> Result<EphemeralRamfs, ProviderError> {
        let owner = HostPrincipal::try_from_owner(instance.owner())?;
        self.namespace_for(owner).require_owner(caller)
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
/// This path is the non-normative `true`/`echo` falsifier. It does not
/// execute guest instructions.
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

fn execute_status(job: &Job) -> Result<u8, ProviderError> {
    if !job.attachments().is_empty() || !job.streams().is_empty() {
        return Err(ProviderError::NotSupported);
    }
    if job.argv().iter().next().is_none() {
        return Err(ProviderError::EmptyArgv);
    }
    let application = job.closure().application();
    if application.as_bytes() == &ARGV_FALSIFIER_APPLICATION {
        return interpret_status(job);
    }
    let image = known_image(application)?;
    if image.id().application_generation() != application {
        return Err(ProviderError::TypeMismatch);
    }
    let mut machine = PortableMachine::for_owner(job.principal(), &image, DEFAULT_INSTRUCTION_FUEL)
        .map_err(crate::machine::MachineError::as_provider_error)?;
    machine
        .run(job.principal())
        .map_err(crate::machine::MachineError::as_provider_error)
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
        let namespace = self.activate_namespace(instance, job.principal())?;
        namespace.touch(job.principal())?;
        let _status = execute_status(job)?;
        Ok(self.receipt(job, instance, ExecutionOutcome::Started))
    }

    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        let namespace = self.activate_namespace(instance, job.principal())?;
        namespace.touch(job.principal())?;
        let status = execute_status(job)?;
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
    use crate::ramfs::EphemeralRamfs;
    use astrid_projection::SemanticObjectId;
    use astrid_provider::{
        AdmittedInstance, AttachmentDescriptor, AttachmentSet, CapsuleAdapter, ExecutionOutcome,
        ExecutionProvider, ExecutionReceipt, Job, JobArgv, ProviderError, StreamDescriptor,
        StreamSet, check_receipt, honest_closure,
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
        assert!(
            provider
                .namespace_for(alice_principal())
                .as_host_path()
                .is_none()
        );
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

    #[test]
    fn compatible_descriptors_cannot_select_foreign_namespace() {
        let provider = ReferenceInterpreter::new();
        let alice_instance = instance_for(alice_principal());
        let bob_instance = instance_for(bob_principal());
        assert_eq!(alice_instance.id(), bob_instance.id());
        assert_eq!(alice_instance.closure(), bob_instance.closure());
        assert_eq!(
            provider.activate_namespace(&alice_instance, bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            provider.activate_namespace(&bob_instance, alice_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        let alice_ns = provider
            .activate_namespace(&alice_instance, alice_principal())
            .unwrap();
        let bob_ns = provider
            .activate_namespace(&bob_instance, bob_principal())
            .unwrap();
        assert_ne!(alice_ns, bob_ns);
        assert_eq!(
            alice_ns.observe(bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            bob_ns.touch(alice_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
        assert_eq!(
            EphemeralRamfs::for_owner(alice_principal()).touch(bob_principal()),
            Err(ProviderError::PrincipalMismatch)
        );
    }

    fn image_job(image_bytes: &[u8]) -> (AdmittedInstance, Job) {
        use crate::fixtures::{instance_for_image, job_against};
        use crate::image::GuestImage;

        let image = GuestImage::admit(image_bytes).expect("synthetic image admits");
        let instance = instance_for_image(alice_principal(), &image);
        let job = job_against(&instance, alice_principal(), &[b"guest"]).expect("argv in range");
        (instance, job)
    }

    #[test]
    fn synthetic_guest_executes_instructions_and_binds_receipts() {
        use crate::image::{SYNTHETIC_EXIT_SEVEN, SYNTHETIC_EXIT_ZERO};

        let provider = ReferenceInterpreter::new();
        let (instance, job) = image_job(&SYNTHETIC_EXIT_ZERO);
        let started = provider.start(&instance, &job).unwrap();
        assert_eq!(started.outcome(), ExecutionOutcome::Started);
        check_receipt(&provider.identity(), &instance, &job, &started).unwrap();
        let exited = provider.exit(&instance, &job).unwrap();
        assert_eq!(exited.outcome(), ExecutionOutcome::Exited { status: 0 });
        check_receipt(&provider.identity(), &instance, &job, &exited).unwrap();

        let (seven_instance, seven_job) = image_job(&SYNTHETIC_EXIT_SEVEN);
        let exited = provider.exit(&seven_instance, &seven_job).unwrap();
        assert_eq!(exited.outcome(), ExecutionOutcome::Exited { status: 7 });
        let mismatched = ExecutionReceipt::for_request(
            provider.identity(),
            &seven_job,
            &seven_instance,
            ExecutionOutcome::Exited { status: 0 },
        );
        assert_ne!(exited.outcome(), mismatched.outcome());
        let foreign_receipt = ExecutionReceipt::new(
            provider.identity(),
            OperationId::from_bytes([0x99; 16]),
            seven_job.causal(),
            seven_instance.id(),
            exited.outcome(),
        );
        assert_eq!(
            check_receipt(
                &provider.identity(),
                &seven_instance,
                &seven_job,
                &foreign_receipt,
            ),
            Err(ProviderError::TypeMismatch)
        );
    }

    #[test]
    fn unknown_image_identity_stale_generation_and_cross_principal_fail_closed() {
        use crate::fixtures::{instance_for_image, instance_with_application, job_against};
        use crate::image::{GuestImage, SYNTHETIC_EXIT_ZERO};
        use astrid_resource_types::{ApplicationGenerationRef, ObjectGeneration};

        let provider = ReferenceInterpreter::new();
        let unknown = instance_with_application(
            alice_principal(),
            ApplicationGenerationRef::from_bytes([0xEE; 32]),
            ObjectGeneration::INITIAL,
        );
        let unknown_job =
            job_against(&unknown, alice_principal(), &[b"guest"]).expect("argv in range");
        assert_eq!(
            provider.start(&unknown, &unknown_job),
            Err(ProviderError::TypeMismatch)
        );

        let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).unwrap();
        let current = instance_for_image(alice_principal(), &image);
        let stale = instance_with_application(
            alice_principal(),
            image.id().application_generation(),
            ObjectGeneration::from_raw(2).expect("generation 2"),
        );
        let current_job =
            job_against(&current, alice_principal(), &[b"guest"]).expect("argv in range");
        assert!(matches!(
            provider.start(&stale, &current_job),
            Err(ProviderError::StaleGeneration {
                found: 2,
                requested: 1
            })
        ));

        let bob_instance = instance_for_image(bob_principal(), &image);
        assert_eq!(
            provider.start(&bob_instance, &current_job),
            Err(ProviderError::PrincipalMismatch)
        );
    }
}
