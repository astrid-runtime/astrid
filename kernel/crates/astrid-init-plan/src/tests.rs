use ed25519_dalek::{Signer, SigningKey};
use std::{vec, vec::Vec};

use astrid_system_generation::{
    ComponentSet, ContentId, Expiration, Generation, MANIFEST_LEN, ManifestInput, ManifestSizes,
    TrustedInput, TrustedInputData, verify_manifest,
};

use crate::types::{ComponentId, ComponentIds};
use crate::{
    InitPlan, LifecycleError, LifecycleState, MAX_READINESS_POLLS, MAX_SERVICES,
    MAX_START_ATTEMPTS, MAX_STEPS, PlanError, PlanLimits, Readiness, ServiceDriver,
};

const DOMAIN: &[u8] = b"astrid.system-generation.manifest.v1";
const UNSIGNED_LEN: usize = 452;
const SIGNER_OFFSET: usize = UNSIGNED_LEN;
const SIGNATURE_OFFSET: usize = SIGNER_OFFSET + 32;

fn id(byte: u8) -> ContentId {
    ContentId::try_from_bytes([byte; 32]).expect("nonzero fixture id")
}

fn verified(count: usize, generation: u64) -> astrid_system_generation::VerifiedGeneration {
    let mut values = [id(1); MAX_SERVICES];
    let mut index = 0;
    while index < MAX_SERVICES {
        values[index] = id((index + 1) as u8);
        index += 1;
    }
    let components = ComponentSet::try_from_slice(&values[..count]).expect("component set");
    let sizes = ManifestSizes::new(1, 2, 3, 4);
    let manifest = astrid_system_generation::SystemGenerationManifest::try_new(ManifestInput {
        kernel_identity: id(40),
        plan_digest: id(41),
        components,
        object_root: id(42),
        closure_root: id(43),
        generation: Generation::new(generation),
        rollback_floor: astrid_system_generation::RollbackFloor::new(generation),
        expires_at: Expiration::never(),
        revocation: astrid_system_generation::Revocation::Active,
        sizes,
    })
    .expect("manifest");

    let mut unsigned = [0u8; UNSIGNED_LEN];
    unsigned[..8].copy_from_slice(b"ASTRIDSG");
    unsigned[8] = 1;
    unsigned[9] = 0;
    unsigned[10] = count as u8;
    unsigned[11] = 0;
    unsigned[12..44].copy_from_slice(&manifest.kernel_identity().as_bytes());
    unsigned[44..76].copy_from_slice(&manifest.plan_digest().as_bytes());
    let mut component_index = 0;
    while component_index < MAX_SERVICES {
        let start = 76 + component_index * 32;
        if let Some(component) = manifest.components().digest(component_index) {
            unsigned[start..start + 32].copy_from_slice(&component.as_bytes());
        }
        component_index += 1;
    }
    unsigned[332..364].copy_from_slice(&manifest.object_root().as_bytes());
    unsigned[364..396].copy_from_slice(&manifest.closure_root().as_bytes());
    put_u64(manifest.generation().get(), &mut unsigned[396..404]);
    put_u64(manifest.rollback_floor().get(), &mut unsigned[404..412]);
    put_u64(manifest.expires_at().get(), &mut unsigned[412..420]);
    put_u64(manifest.sizes().kernel_bytes(), &mut unsigned[420..428]);
    put_u64(manifest.sizes().plan_bytes(), &mut unsigned[428..436]);
    put_u64(manifest.sizes().object_bytes(), &mut unsigned[436..444]);
    put_u64(manifest.sizes().closure_bytes(), &mut unsigned[444..452]);

    let key = SigningKey::from_bytes(&[7; 32]);
    let mut message = Vec::with_capacity(DOMAIN.len() + UNSIGNED_LEN);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&unsigned);
    let signature = key.sign(&message).to_bytes();
    let mut bytes = [0u8; MANIFEST_LEN];
    bytes[..UNSIGNED_LEN].copy_from_slice(&unsigned);
    bytes[SIGNER_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&key.verifying_key().to_bytes());
    bytes[SIGNATURE_OFFSET..].copy_from_slice(&signature);
    let trusted = TrustedInput::try_new(TrustedInputData {
        signer: key.verifying_key().to_bytes(),
        kernel_identity: manifest.kernel_identity(),
        plan_digest: manifest.plan_digest(),
        components,
        object_root: manifest.object_root(),
        closure_root: manifest.closure_root(),
        generation_floor: Generation::new(generation),
        now_unix_seconds: 0,
        sizes,
    })
    .expect("trusted input");
    verify_manifest(&bytes, &trusted).expect("verified fixture")
}

fn put_u64(value: u64, bytes: &mut [u8]) {
    bytes.copy_from_slice(&value.to_le_bytes());
}

#[derive(Default)]
struct Driver {
    starts: Vec<u8>,
    readiness: Vec<u8>,
    stops: Vec<u8>,
    publish_calls: usize,
    retire_calls: usize,
    start_failures: Vec<u8>,
    readiness_failures: Vec<u8>,
    pending_polls: Vec<u8>,
    stop_failures: Vec<u8>,
    fail_publish: bool,
    fail_retire: bool,
}

impl Driver {
    fn component(component: ComponentId) -> u8 {
        component.as_bytes()[0]
    }

    fn fail_start_at(mut self, component: u8) -> Self {
        self.start_failures.push(component);
        self
    }

    fn fail_readiness_at(mut self, component: u8) -> Self {
        self.readiness_failures.push(component);
        self
    }

    fn pending_at(mut self, component: u8) -> Self {
        self.pending_polls.push(component);
        self
    }

    fn fail_stop_at(mut self, component: u8) -> Self {
        self.stop_failures.push(component);
        self
    }
}

impl ServiceDriver for Driver {
    type Error = u8;

    fn start(&mut self, component: ComponentId) -> Result<(), Self::Error> {
        let id = Self::component(component);
        self.starts.push(id);
        if self.start_failures.contains(&id) {
            Err(id)
        } else {
            Ok(())
        }
    }

    fn poll_readiness(&mut self, component: ComponentId) -> Result<Readiness, Self::Error> {
        let id = Self::component(component);
        self.readiness.push(id);
        if self.readiness_failures.contains(&id) {
            return Err(id);
        }
        if self.pending_polls.contains(&id) {
            return Ok(Readiness::Pending);
        }
        Ok(Readiness::Ready)
    }

    fn publish_generation(
        &mut self,
        _generation: astrid_system_generation::ManifestIdentity,
    ) -> Result<(), Self::Error> {
        self.publish_calls += 1;
        if self.fail_publish { Err(99) } else { Ok(()) }
    }

    fn retire(
        &mut self,
        _generation: astrid_system_generation::ManifestIdentity,
    ) -> Result<(), Self::Error> {
        self.retire_calls += 1;
        if self.fail_retire { Err(98) } else { Ok(()) }
    }

    fn stop(&mut self, component: ComponentId) -> Result<(), Self::Error> {
        let id = Self::component(component);
        self.stops.push(id);
        if self.stop_failures.contains(&id) {
            Err(id)
        } else {
            Ok(())
        }
    }
}

#[test]
fn plan_copies_only_verified_identity_and_sorted_components() {
    let verified = verified(3, 10);
    let plan = InitPlan::try_from_verified(verified).expect("plan");
    assert_eq!(plan.state(), LifecycleState::Verified);
    assert_eq!(plan.component_count(), 3);
    assert_eq!(plan.component(0).expect("first").as_bytes()[0], 1);
    assert_eq!(plan.component(2).expect("third").as_bytes()[0], 3);
    assert_eq!(plan.generation_identity(), verified.manifest_identity());
    assert!(!plan.admission_open());
}

#[test]
fn zero_services_and_limit_overflow_fail_closed() {
    assert_eq!(
        InitPlan::try_from_verified(verified(0, 1)),
        Err(PlanError::ZeroServices)
    );
    assert_eq!(
        PlanLimits::try_new(0, MAX_READINESS_POLLS, MAX_STEPS),
        Err(PlanError::ZeroStartAttempts)
    );
    assert_eq!(
        PlanLimits::try_new(MAX_START_ATTEMPTS + 1, 1, 1),
        Err(PlanError::TooManyStartAttempts)
    );
    assert_eq!(
        PlanLimits::try_new(1, MAX_READINESS_POLLS + 1, 1),
        Err(PlanError::TooManyReadinessPolls)
    );
    assert_eq!(
        PlanLimits::try_new(1, 1, MAX_STEPS + 1),
        Err(PlanError::TooManySteps)
    );
}

#[test]
fn duplicate_and_unsorted_component_lists_are_rejected_at_the_private_boundary() {
    let first = ComponentId::from_content_id(id(1));
    let second = ComponentId::from_content_id(id(2));
    let mut values = [None; MAX_SERVICES];
    values[0] = Some(first);
    values[1] = Some(first);
    assert_eq!(
        ComponentIds::from_array(values, 2),
        Err(PlanError::DuplicateServices)
    );
    values[1] = Some(second);
    values[0] = Some(second);
    values[1] = Some(first);
    assert_eq!(
        ComponentIds::from_array(values, 2),
        Err(PlanError::UnsortedServices)
    );
}

#[test]
fn successful_run_publishes_once_only_after_all_ready() {
    let mut plan = InitPlan::try_from_verified(verified(3, 1)).expect("plan");
    let mut driver = Driver::default();
    plan.run(&mut driver).expect("run");
    assert_eq!(plan.state(), LifecycleState::Published);
    assert!(plan.admission_open());
    assert_eq!(driver.publish_calls, 1);
    assert_eq!(driver.starts, vec![1, 2, 3]);
    assert_eq!(driver.readiness, vec![1, 2, 3]);
}

#[test]
fn start_failure_at_each_position_cleans_up_reverse_order_and_exhausts_attempts() {
    for failed in 1..=3 {
        let mut plan = InitPlan::try_from_verified(verified(3, u64::from(failed))).expect("plan");
        let mut driver = Driver::default().fail_start_at(failed);
        let result = plan.run(&mut driver);
        assert!(matches!(
            result,
            Err(LifecycleError::StartAttemptsExhausted { .. })
        ));
        assert_eq!(plan.state(), LifecycleState::Failed);
        assert_eq!(driver.publish_calls, 0);
        assert_eq!(
            driver.starts.iter().filter(|id| **id == failed).count(),
            MAX_START_ATTEMPTS
        );
        let expected = match failed {
            1 => vec![],
            2 => vec![1],
            3 => vec![2, 1],
            _ => unreachable!(),
        };
        assert_eq!(driver.stops, expected);
    }
}

#[test]
fn readiness_failure_and_timeout_never_publish() {
    let mut plan = InitPlan::try_from_verified(verified(3, 20)).expect("plan");
    let mut driver = Driver::default().fail_readiness_at(2);
    assert!(matches!(
        plan.run(&mut driver),
        Err(LifecycleError::Readiness { component, .. }) if component.as_bytes()[0] == 2
    ));
    assert_eq!(plan.state(), LifecycleState::Failed);
    assert_eq!(driver.publish_calls, 0);
    assert_eq!(driver.stops, vec![3, 2, 1]);

    let limits = PlanLimits::try_new(1, 2, MAX_STEPS).expect("limits");
    let mut timeout =
        InitPlan::try_from_verified_with_limits(verified(1, 21), limits).expect("plan");
    let mut pending = Driver::default().pending_at(1);
    assert!(matches!(
        timeout.run(&mut pending),
        Err(LifecycleError::ReadinessTimeout { .. })
    ));
    assert_eq!(pending.publish_calls, 0);
}

#[test]
fn publication_failure_is_a_barrier_and_retry_is_possible() {
    let mut plan = InitPlan::try_from_verified(verified(2, 30)).expect("plan");
    let mut driver = Driver {
        fail_publish: true,
        ..Driver::default()
    };
    assert!(matches!(
        plan.run(&mut driver),
        Err(LifecycleError::Publish { .. })
    ));
    assert_eq!(plan.state(), LifecycleState::Failed);
    assert_eq!(driver.publish_calls, 1);
    assert_eq!(driver.stops, vec![2, 1]);

    driver.fail_publish = false;
    plan.run(&mut driver).expect("retry");
    assert_eq!(plan.state(), LifecycleState::Published);
    assert_eq!(driver.publish_calls, 2);
}

#[test]
fn cleanup_attempts_every_started_service_after_a_stop_error() {
    let mut plan = InitPlan::try_from_verified(verified(3, 35)).expect("plan");
    let mut driver = Driver::default().fail_readiness_at(3).fail_stop_at(2);
    assert!(plan.run(&mut driver).is_err());
    assert_eq!(plan.state(), LifecycleState::Failed);
    assert_eq!(driver.stops, vec![3, 2, 1]);
    assert_eq!(driver.publish_calls, 0);
}

#[test]
fn stop_retires_once_and_is_idempotent() {
    let mut plan = InitPlan::try_from_verified(verified(3, 40)).expect("plan");
    let mut driver = Driver::default();
    plan.run(&mut driver).expect("run");
    plan.stop(&mut driver).expect("stop");
    assert_eq!(plan.state(), LifecycleState::Stopped);
    assert_eq!(driver.retire_calls, 1);
    assert_eq!(driver.stops, vec![3, 2, 1]);
    plan.stop(&mut driver).expect("idempotent stop");
    assert_eq!(driver.retire_calls, 1);
    assert_eq!(driver.stops, vec![3, 2, 1]);
}

#[test]
fn recovery_rejects_stale_identity_and_accepts_fresh_verified_generation() {
    let original = verified(2, 50);
    let mut plan = InitPlan::try_from_verified(original).expect("plan");
    let mut driver = Driver::default();
    assert_eq!(
        plan.recover(original, &mut driver),
        Err(LifecycleError::Plan(PlanError::StaleGeneration))
    );
    let fresh = verified(1, 51);
    plan.recover(fresh, &mut driver).expect("fresh recovery");
    assert_eq!(plan.state(), LifecycleState::Verified);
    assert_eq!(plan.component_count(), 1);
    assert_eq!(plan.generation_identity(), fresh.manifest_identity());
}

#[test]
fn recovery_retires_and_stops_an_active_generation_before_swap() {
    let original = verified(2, 60);
    let fresh = verified(1, 61);
    let mut plan = InitPlan::try_from_verified(original).expect("plan");
    let mut driver = Driver::default();
    plan.run(&mut driver).expect("run");
    plan.recover(fresh, &mut driver).expect("recovery");
    assert_eq!(plan.state(), LifecycleState::Verified);
    assert_eq!(plan.component_count(), 1);
    assert_eq!(driver.retire_calls, 1);
    assert_eq!(driver.stops, vec![2, 1]);
}

#[test]
fn recovery_does_not_swap_when_retirement_fails_and_retries_teardown() {
    let original = verified(2, 70);
    let fresh = verified(1, 71);
    let mut plan = InitPlan::try_from_verified(original).expect("plan");
    let mut driver = Driver {
        fail_retire: true,
        ..Driver::default()
    };
    plan.run(&mut driver).expect("run");
    assert!(matches!(
        plan.recover(fresh, &mut driver),
        Err(LifecycleError::Retire { .. })
    ));
    assert_eq!(plan.state(), LifecycleState::Failed);
    assert_eq!(plan.component_count(), 2);
    driver.fail_retire = false;
    plan.recover(fresh, &mut driver).expect("retry teardown");
    assert_eq!(plan.state(), LifecycleState::Verified);
    assert_eq!(plan.component_count(), 1);
    assert_eq!(driver.retire_calls, 2);
}
