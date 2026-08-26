//! Issue-level isolation and fallback corpus for the reference interpreter.
//!
//! These tests exercise the provider boundary and the owner-bound machine and
//! ramfs directly. They deliberately do not introduce a cancellation method,
//! host process, guest filesystem, or ambient resource lookup.

use core::mem::size_of;

use astrid_projection::SemanticObjectId;
use astrid_provider::{
    AdmittedInstance, ApplicationClosure, AttachmentDescriptor, AttachmentSet, Checkpoint,
    CheckpointBlobId, ExecutionOutcome, ExecutionProvider, ExecutionReceipt, Job, JobArgv,
    ProviderError, StreamDescriptor, StreamSet, check_receipt,
};
use astrid_resource_types::{
    ApplicationGenerationRef, CausalRequestId, ObjectGeneration, OperationId, ProviderGeneration,
    ResourceId,
};

use crate::fixtures::{
    ARGV_FALSIFIER_APPLICATION, alice_principal, bob_principal, instance_for, instance_for_image,
    instance_with_application, job_against, job_for,
};
use crate::image::{GuestImage, SYNTHETIC_EXIT_ZERO};
use crate::interpreter::{
    COMPAT_PROVIDER_GENERATION, COMPAT_PROVIDER_ID, ReferenceInterpreter, interpret_status,
};
use crate::machine::{DEFAULT_INSTRUCTION_FUEL, DRAM_BASE, PortableMachine};
use crate::ramfs::EphemeralRamfs;

fn opaque_attachment_job() -> Job {
    Job::for_instance(
        OperationId::from_bytes([0x61; 16]),
        &instance_for(alice_principal()),
        &JobArgv::try_from_args(&[b"true"]).expect("valid argv"),
        &AttachmentSet::try_from_descriptors(&[AttachmentDescriptor::new(
            SemanticObjectId::for_resource(ResourceId::from_bytes([0x71; 32])),
            ObjectGeneration::INITIAL,
        )])
        .expect("one attachment"),
        &StreamSet::EMPTY,
        CausalRequestId::from_bytes([0x81; 16]),
        alice_principal(),
    )
}

fn opaque_stream_job() -> Job {
    Job::for_instance(
        OperationId::from_bytes([0x62; 16]),
        &instance_for(alice_principal()),
        &JobArgv::try_from_args(&[b"true"]).expect("valid argv"),
        &AttachmentSet::EMPTY,
        &StreamSet::try_from_descriptors(&[StreamDescriptor::new(
            SemanticObjectId::for_resource(ResourceId::from_bytes([0x72; 32])),
            ObjectGeneration::INITIAL,
        )])
        .expect("one stream"),
        CausalRequestId::from_bytes([0x82; 16]),
        alice_principal(),
    )
}

fn cancel_probe(receipt: &ExecutionReceipt) -> Result<(), ProviderError> {
    match receipt.as_live_handle() {
        Err(error) => Err(error),
        Ok(handle) => match handle {},
    }
}

#[test]
fn provider_restart_is_fresh_and_does_not_retain_owner_state() {
    let provider = ReferenceInterpreter::new();
    let instance = instance_for(alice_principal());
    let job = job_for(alice_principal(), &[b"true"]).expect("valid argv");

    let first_start = provider.start(&instance, &job).expect("first start");
    let first_exit = provider.exit(&instance, &job).expect("first exit");
    let second_start = provider.start(&instance, &job).expect("restart start");
    let second_exit = provider.exit(&instance, &job).expect("restart exit");
    assert_eq!(first_start.outcome(), ExecutionOutcome::Started);
    assert_eq!(first_exit.outcome(), ExecutionOutcome::Exited { status: 0 });
    assert_eq!(second_start.outcome(), ExecutionOutcome::Started);
    assert_eq!(
        second_exit.outcome(),
        ExecutionOutcome::Exited { status: 0 }
    );
    check_receipt(&provider.identity(), &instance, &job, &second_exit).expect("bound receipt");

    // The interpreter and ramfs carry no mutable or global execution table.
    assert_eq!(size_of::<ReferenceInterpreter>(), 0);
    assert_eq!(
        size_of::<EphemeralRamfs>(),
        size_of::<astrid_provider::HostPrincipal>()
    );

    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).expect("synthetic image");
    let mut first_machine =
        PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
            .expect("first machine");
    first_machine
        .store_u8(DRAM_BASE + 64, 0xA5, alice_principal())
        .expect("owner can write its RAM");
    assert_eq!(
        first_machine.load_u8(DRAM_BASE + 64, alice_principal()),
        Ok(0xA5)
    );
    assert_eq!(first_machine.run(alice_principal()), Ok(0));

    let second_machine =
        PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
            .expect("restart machine");
    assert_eq!(
        second_machine.load_u8(DRAM_BASE + 64, alice_principal()),
        Ok(0)
    );
    assert_eq!(
        second_machine.load_u8(DRAM_BASE, alice_principal()),
        Ok(SYNTHETIC_EXIT_ZERO[0])
    );
    assert_eq!(second_machine.instructions_retired(), 0);
}

#[test]
fn direct_owner_state_cannot_cross_principals_during_restart() {
    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).expect("synthetic image");
    let mut alice = PortableMachine::for_owner(alice_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
        .expect("Alice machine");
    let mut bob = PortableMachine::for_owner(bob_principal(), &image, DEFAULT_INSTRUCTION_FUEL)
        .expect("Bob machine");

    alice
        .store_u8(DRAM_BASE + 64, 0xA1, alice_principal())
        .expect("Alice owns Alice RAM");
    bob.store_u8(DRAM_BASE + 64, 0xB2, bob_principal())
        .expect("Bob owns Bob RAM");
    assert_eq!(alice.load_u8(DRAM_BASE + 64, alice_principal()), Ok(0xA1));
    assert_eq!(bob.load_u8(DRAM_BASE + 64, bob_principal()), Ok(0xB2));
    assert_eq!(
        alice.load_u8(DRAM_BASE + 64, bob_principal()),
        Err(crate::machine::MachineError::PrincipalMismatch)
    );
    assert_eq!(
        bob.load_u8(DRAM_BASE + 64, alice_principal()),
        Err(crate::machine::MachineError::PrincipalMismatch)
    );
    assert_eq!(
        alice.store_u8(DRAM_BASE + 64, 0xFF, bob_principal()),
        Err(crate::machine::MachineError::PrincipalMismatch)
    );
    assert_eq!(
        bob.store_u8(DRAM_BASE + 64, 0xFF, alice_principal()),
        Err(crate::machine::MachineError::PrincipalMismatch)
    );
    assert_eq!(alice.load_u8(DRAM_BASE + 64, alice_principal()), Ok(0xA1));
    assert_eq!(bob.load_u8(DRAM_BASE + 64, bob_principal()), Ok(0xB2));
}

#[test]
fn restore_and_cancel_attempts_fail_closed_without_live_handles() {
    let provider = ReferenceInterpreter::new();
    let instance = instance_for(alice_principal());
    let job = job_for(alice_principal(), &[b"true"]).expect("valid argv");
    let started = provider.start(&instance, &job).expect("started");
    let exited = provider.exit(&instance, &job).expect("exited");
    assert_eq!(cancel_probe(&started), Err(ProviderError::NotALiveHandle));
    assert_eq!(cancel_probe(&exited), Err(ProviderError::NotALiveHandle));

    let unknown = ExecutionReceipt::for_request(
        provider.identity(),
        &job,
        &instance,
        ExecutionOutcome::OutcomeUnknown,
    );
    assert_eq!(cancel_probe(&unknown), Err(ProviderError::NotALiveHandle));

    let checkpoint = Checkpoint::from_instance(instance, CheckpointBlobId::from_bytes([0xCC; 32]));
    assert_eq!(
        provider.restore(&checkpoint),
        Err(ProviderError::NotSupported)
    );
}

#[test]
fn provider_generation_mismatch_is_stale_on_start_and_exit() {
    let provider = ReferenceInterpreter::new();
    let application = ApplicationGenerationRef::from_bytes(ARGV_FALSIFIER_APPLICATION);
    let stale_closure = ApplicationClosure::new(
        application,
        COMPAT_PROVIDER_ID,
        ProviderGeneration::from_raw(2).expect("generation 2"),
    );
    let instance = AdmittedInstance::new(
        instance_for(alice_principal()).id(),
        stale_closure,
        instance_for(alice_principal()).owner(),
    );
    let job = job_against(&instance, alice_principal(), &[b"true"]).expect("valid argv");
    let expected = Err(ProviderError::StaleGeneration {
        found: COMPAT_PROVIDER_GENERATION.get(),
        requested: 2,
    });
    assert_eq!(provider.start(&instance, &job), expected);
    assert_eq!(provider.exit(&instance, &job), expected);
}

#[test]
fn provider_level_unavailable_backing_inputs_fail_closed() {
    let provider = ReferenceInterpreter::new();
    let instance = instance_for(alice_principal());
    assert_eq!(
        provider.start(&instance, &opaque_attachment_job()),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        provider.exit(&instance, &opaque_attachment_job()),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        provider.start(&instance, &opaque_stream_job()),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        provider.exit(&instance, &opaque_stream_job()),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(JobArgv::try_from_args(&[]), Err(ProviderError::EmptyArgv));
    assert_eq!(
        interpret_status(&opaque_attachment_job()),
        Err(ProviderError::NotSupported)
    );
    assert_eq!(
        interpret_status(&opaque_stream_job()),
        Err(ProviderError::NotSupported)
    );
}

#[test]
fn hostile_argv_tokens_never_select_ambient_host_fallbacks() {
    let provider = ReferenceInterpreter::new();
    let instance = instance_for(alice_principal());
    let namespace = provider
        .activate_namespace(&instance, alice_principal())
        .expect("owner namespace");
    assert!(namespace.as_host_path().is_none());
    assert_eq!(namespace.owner(), alice_principal());
    assert_eq!(namespace.namespace_id(), alice_principal());
    assert_eq!(
        size_of::<EphemeralRamfs>(),
        size_of::<astrid_provider::HostPrincipal>()
    );

    for token in [
        b"/bin/true".as_slice(),
        b"home://".as_slice(),
        b"cwd://".as_slice(),
        b"process".as_slice(),
        b"network".as_slice(),
        b"credential".as_slice(),
    ] {
        let job = job_for(alice_principal(), &[token]).expect("bounded hostile token");
        assert_eq!(
            provider.start(&instance, &job),
            Err(ProviderError::NotSupported)
        );
        assert_eq!(
            provider.exit(&instance, &job),
            Err(ProviderError::NotSupported)
        );
    }

    // Only explicit stamped principals are accepted; there is no env/home or
    // cwd lookup from which a second principal could be inferred.
    assert_ne!(alice_principal(), bob_principal());
    assert_eq!(namespace.observe(alice_principal()), Ok(()));
    assert_eq!(
        namespace.observe(bob_principal()),
        Err(ProviderError::PrincipalMismatch)
    );
}

#[test]
fn same_reference_workload_isolated_at_provider_and_machine_boundaries() {
    let provider = ReferenceInterpreter::new();
    let alice_instance = instance_for(alice_principal());
    let bob_instance = instance_for(bob_principal());
    let alice_job = job_for(alice_principal(), &[b"true"]).expect("Alice argv");
    let bob_job = job_for(bob_principal(), &[b"true"]).expect("Bob argv");

    let alice_started = provider
        .start(&alice_instance, &alice_job)
        .expect("Alice start");
    let bob_started = provider.start(&bob_instance, &bob_job).expect("Bob start");
    assert_eq!(alice_started.outcome(), ExecutionOutcome::Started);
    assert_eq!(bob_started.outcome(), ExecutionOutcome::Started);
    assert_eq!(
        provider.start(&alice_instance, &bob_job),
        Err(ProviderError::PrincipalMismatch)
    );
    assert_eq!(
        provider.exit(&bob_instance, &alice_job),
        Err(ProviderError::PrincipalMismatch)
    );

    let alice_namespace = provider
        .activate_namespace(&alice_instance, alice_principal())
        .expect("Alice namespace");
    let bob_namespace = provider
        .activate_namespace(&bob_instance, bob_principal())
        .expect("Bob namespace");
    assert_ne!(alice_namespace.namespace_id(), bob_namespace.namespace_id());
    assert_eq!(alice_namespace.touch(alice_principal()), Ok(()));
    assert_eq!(bob_namespace.touch(bob_principal()), Ok(()));
    assert_eq!(
        alice_namespace.touch(bob_principal()),
        Err(ProviderError::PrincipalMismatch)
    );
    assert_eq!(
        bob_namespace.touch(alice_principal()),
        Err(ProviderError::PrincipalMismatch)
    );
}

#[test]
fn unknown_image_and_stale_object_never_allocate_owner_state() {
    let provider = ReferenceInterpreter::new();
    let unknown = instance_with_application(
        alice_principal(),
        ApplicationGenerationRef::from_bytes([0xEE; 32]),
        ObjectGeneration::INITIAL,
    );
    let unknown_job = job_against(&unknown, alice_principal(), &[b"guest"]).expect("argv");
    assert_eq!(
        provider.start(&unknown, &unknown_job),
        Err(ProviderError::TypeMismatch)
    );
    assert_eq!(
        provider.exit(&unknown, &unknown_job),
        Err(ProviderError::TypeMismatch)
    );

    let image = GuestImage::admit(&SYNTHETIC_EXIT_ZERO).expect("image");
    let current = instance_for_image(alice_principal(), &image);
    let stale = instance_with_application(
        alice_principal(),
        image.id().application_generation(),
        ObjectGeneration::from_raw(2).expect("generation 2"),
    );
    let current_job = job_against(&current, alice_principal(), &[b"guest"]).expect("argv");
    assert!(matches!(
        provider.start(&stale, &current_job),
        Err(ProviderError::StaleGeneration {
            found: 2,
            requested: 1
        })
    ));
    assert!(matches!(
        provider.exit(&stale, &current_job),
        Err(ProviderError::StaleGeneration {
            found: 2,
            requested: 1
        })
    ));
}
