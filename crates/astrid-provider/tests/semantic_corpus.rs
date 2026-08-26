//! Workload-neutral semantic corpus for [`astrid_provider::NullProvider`].
//!
//! The corpus exercises the public provider surface without introducing a
//! workload name, a live execution handle, or a host fallback.  Cancellation
//! and restart remain unavailable capabilities because the provider trait has
//! no lifecycle methods for them; the existing checkpoint/restore surface is
//! therefore tested as the fail-closed boundary.

use astrid_provider::{
    AdmittedInstance, ApplicationClosure, AttachmentSet, Checkpoint, CheckpointBlobId,
    DescriptorDecode, DescriptorEncode, ExecutionOutcome, ExecutionProvider, HostPrincipal,
    InstanceId, Job, JobArgv, NullProvider, ProviderError, ProviderIdentity, StreamSet,
    check_binding, check_identity, check_provider, check_receipt, honest_closure, honest_instance,
    honest_job, honest_principal,
};
use astrid_resource_types::{
    ApplicationGenerationRef, CausalRequestId, OperationId, OwnerId, ProviderGeneration, ProviderId,
};

fn instance_for(owner: OwnerId) -> AdmittedInstance {
    AdmittedInstance::new(honest_instance().id(), honest_closure(), owner)
}

fn job_for(instance: &AdmittedInstance, principal: HostPrincipal) -> Job {
    let argv = JobArgv::try_from_args(&[b"prog"]).expect("corpus argv is bounded");
    Job::for_instance(
        OperationId::from_bytes([0x41; 16]),
        instance,
        &argv,
        &AttachmentSet::EMPTY,
        &StreamSet::EMPTY,
        CausalRequestId::from_bytes([0x51; 16]),
        principal,
    )
}

#[test]
fn identity_and_generation_bind_every_request() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");
    let identity = provider.identity();

    assert_eq!(identity, NullProvider::identity_value());
    assert_eq!(identity.id(), NullProvider::identity_value().id());
    assert_eq!(
        identity.generation(),
        NullProvider::identity_value().generation()
    );
    check_identity(&identity, &identity).expect("identity binds to itself");
    check_provider(&identity, &instance.closure()).expect("closure names this provider");
    check_binding(&instance, &job).expect("fixture job binds to its instance");

    let receipt = provider
        .start(&instance, &job)
        .expect("valid start is admitted");
    check_receipt(&identity, &instance, &job, &receipt)
        .expect("receipt keeps provider, request, and instance identities");
    assert_eq!(receipt.provider(), identity);
    assert_eq!(receipt.instance(), instance.id());
    assert_eq!(receipt.causal(), job.causal());
}

#[test]
fn outcome_unknown_is_distinct_and_never_a_live_handle() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");
    let started = provider
        .start(&instance, &job)
        .expect("valid start is admitted");
    let exited = provider
        .exit(&instance, &job)
        .expect("valid exit is admitted");

    assert_eq!(started.outcome(), ExecutionOutcome::OutcomeUnknown);
    assert_eq!(exited.outcome(), ExecutionOutcome::OutcomeUnknown);
    assert_ne!(started.outcome(), ExecutionOutcome::Started);
    assert_ne!(started.outcome(), ExecutionOutcome::Exited { status: 0 });
    assert_eq!(started.binding(), exited.binding());
    assert_eq!(started.as_live_handle(), Err(ProviderError::NotALiveHandle));
    assert_eq!(exited.as_live_handle(), Err(ProviderError::NotALiveHandle));

    let mut encoded = [0_u8; ExecutionOutcome::ENCODED_LEN];
    ExecutionOutcome::OutcomeUnknown
        .encode_descriptor(&mut encoded)
        .expect("unknown outcome has one canonical encoding");
    assert_eq!(
        ExecutionOutcome::decode_descriptor(&encoded),
        Ok(ExecutionOutcome::OutcomeUnknown)
    );
}

#[test]
fn cancel_and_restart_boundaries_fail_closed_as_unavailable() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");
    let checkpoint = Checkpoint::from_instance(instance, CheckpointBlobId::from_bytes([0x91; 32]));

    // There are intentionally no cancel/restart methods on the trait.  The
    // only state-transition-shaped surface is checkpoint/restore, and Null
    // Provider reports both capabilities as unavailable.
    assert_eq!(
        provider.checkpoint(&instance),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        provider.restore(&checkpoint),
        Err(ProviderError::NotSupported)
    );

    let before = provider
        .start(&instance, &job)
        .expect("valid start is admitted");
    let after = provider
        .exit(&instance, &job)
        .expect("valid exit is admitted");
    assert_eq!(before.binding(), after.binding());
    assert_eq!(before.outcome(), ExecutionOutcome::OutcomeUnknown);
    assert_eq!(after.outcome(), ExecutionOutcome::OutcomeUnknown);
}

#[test]
fn stale_generations_fail_closed_before_unknown_receipts() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");
    let next_instance_generation = instance
        .id()
        .generation()
        .checked_next()
        .expect("initial object generation has a successor");
    let stale_instance = AdmittedInstance::new(
        InstanceId::new(instance.id().resource(), next_instance_generation),
        instance.closure(),
        instance.owner(),
    );
    let stale_job = job_for(&stale_instance, honest_principal());

    assert!(matches!(
        provider.start(&instance, &stale_job),
        Err(ProviderError::StaleGeneration { .. })
    ));
    assert!(matches!(
        provider.start(&stale_instance, &job),
        Err(ProviderError::StaleGeneration { .. })
    ));

    let stale_provider_generation = instance
        .closure()
        .provider_generation()
        .checked_next()
        .expect("initial provider generation has a successor");
    let stale_closure = ApplicationClosure::new(
        instance.closure().application(),
        instance.closure().provider(),
        stale_provider_generation,
    );
    assert!(matches!(
        check_provider(&provider.identity(), &stale_closure),
        Err(ProviderError::StaleGeneration { .. })
    ));
}

#[test]
fn malformed_descriptors_never_reach_provider_execution() {
    let short_job = [0_u8; 1];
    assert_eq!(
        Job::decode_descriptor(&short_job),
        Err(ProviderError::InvalidLength)
    );

    let argv = JobArgv::try_from_args(&[b"prog"]).expect("corpus argv is bounded");
    let mut malformed_argv = [0_u8; JobArgv::ENCODED_LEN];
    argv.encode_descriptor(&mut malformed_argv)
        .expect("fixture argv encodes");
    malformed_argv[3] = 0;
    assert_eq!(
        JobArgv::decode_descriptor(&malformed_argv),
        Err(ProviderError::EmptyArgv)
    );

    let mut malformed_outcome = [0_u8; ExecutionOutcome::ENCODED_LEN];
    ExecutionOutcome::OutcomeUnknown
        .encode_descriptor(&mut malformed_outcome)
        .expect("unknown outcome encodes");
    malformed_outcome[3] = 0xff;
    assert_eq!(
        ExecutionOutcome::decode_descriptor(&malformed_outcome),
        Err(ProviderError::UnknownDiscriminant(255))
    );
}

#[test]
fn owner_namespaces_are_isolated_even_for_equal_instance_ids() {
    let provider = NullProvider;
    let principal_a = honest_principal();
    let principal_b = HostPrincipal::from_principal_uid_bytes([0x77; 32]);
    let instance_a = instance_for(principal_a.as_owner());
    let instance_b = instance_for(principal_b.as_owner());
    let job_a = job_for(&instance_a, principal_a);
    let job_b = job_for(&instance_b, principal_b);

    assert_eq!(instance_a.id(), instance_b.id());
    assert_ne!(instance_a.owner(), instance_b.owner());
    provider
        .start(&instance_a, &job_a)
        .expect("owner A can use its namespace");
    provider
        .start(&instance_b, &job_b)
        .expect("owner B can use its namespace");
    assert_eq!(
        provider.start(&instance_a, &job_b),
        Err(ProviderError::PrincipalMismatch)
    );
    assert_eq!(
        provider.start(&instance_b, &job_a),
        Err(ProviderError::PrincipalMismatch)
    );

    let system_owned = instance_for(OwnerId::System);
    assert_eq!(
        provider.start(&system_owned, &job_a),
        Err(ProviderError::TypeMismatch)
    );
}

#[test]
fn unavailable_capabilities_and_no_host_fallback_are_observable() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");

    assert_eq!(core::mem::size_of::<NullProvider>(), 0);
    assert_eq!(core::mem::align_of::<NullProvider>(), 1);
    let first = provider
        .start(&instance, &job)
        .expect("valid start is admitted");
    let second = provider
        .start(&instance, &job)
        .expect("valid start is admitted");
    assert_eq!(first, second);
    assert_eq!(first.as_live_handle(), Err(ProviderError::NotALiveHandle));
    assert_eq!(
        provider.checkpoint(&instance),
        Err(ProviderError::NotSupported)
    );
}

#[test]
fn foreign_provider_identity_is_rejected_without_rebinding() {
    let provider = NullProvider;
    let identity = provider.identity();
    let foreign = ProviderIdentity::new(ProviderId::from_bytes([0xb5; 32]), identity.generation());
    assert_eq!(
        check_identity(&identity, &foreign),
        Err(ProviderError::TypeMismatch)
    );
    let foreign_generation = ProviderIdentity::new(
        identity.id(),
        identity
            .generation()
            .checked_next()
            .expect("initial provider generation has a successor"),
    );
    assert!(matches!(
        check_identity(&identity, &foreign_generation),
        Err(ProviderError::StaleGeneration { .. })
    ));
}

#[test]
fn hostile_owner_and_closure_inputs_remain_non_authoritative() {
    let provider = NullProvider;
    let instance = honest_instance();
    let job = honest_job().expect("honest fixture is valid");
    let wrong_owner = AdmittedInstance::new(
        instance.id(),
        instance.closure(),
        OwnerId::fleet([0x99; 32]),
    );
    assert_eq!(
        check_binding(&wrong_owner, &job),
        Err(ProviderError::TypeMismatch)
    );

    let wrong_application = ApplicationClosure::new(
        ApplicationGenerationRef::from_bytes([0x99; 32]),
        instance.closure().provider(),
        ProviderGeneration::INITIAL,
    );
    let wrong_instance = AdmittedInstance::new(instance.id(), wrong_application, instance.owner());
    assert_eq!(
        provider.start(&wrong_instance, &job),
        Err(ProviderError::TypeMismatch)
    );
}
