//! Honest and hostile in-crate provider fixtures.

use astrid_resource_types::{
    ApplicationGenerationRef, CausalRequestId, ObjectGeneration, OperationId, OwnerId, ResourceId,
};

use crate::argv::JobArgv;
use crate::attachment::{AttachmentSet, StreamSet};
use crate::closure::ApplicationClosure;
use crate::instance::{AdmittedInstance, InstanceId};
use crate::job::Job;
use crate::null::{NULL_PROVIDER_GENERATION, NULL_PROVIDER_ID};
use crate::principal::HostPrincipal;

/// Honest host principal used by consumer tests.
#[must_use]
pub fn honest_principal() -> HostPrincipal {
    HostPrincipal::from_principal_uid_bytes([0x11; 32])
}

/// Honest application closure bound to the null provider.
#[must_use]
pub fn honest_closure() -> ApplicationClosure {
    ApplicationClosure::new(
        ApplicationGenerationRef::from_bytes([0x21; 32]),
        NULL_PROVIDER_ID,
        NULL_PROVIDER_GENERATION,
    )
}

/// Honest admitted-instance descriptor. Not a grant.
#[must_use]
pub fn honest_instance() -> AdmittedInstance {
    AdmittedInstance::new(
        InstanceId::new(
            ResourceId::from_bytes([0x31; 32]),
            ObjectGeneration::INITIAL,
        ),
        honest_closure(),
        OwnerId::principal(*honest_principal().as_bytes()),
    )
}

/// Honest structured job copied from [`honest_instance`].
///
/// # Errors
///
/// Returns argv construction failures. The fixture token is in range.
pub fn honest_job() -> Result<Job, crate::error::ProviderError> {
    Ok(Job::for_instance(
        OperationId::from_bytes([0x41; 16]),
        &honest_instance(),
        &JobArgv::try_from_args(&[b"prog"])?,
        &AttachmentSet::EMPTY,
        &StreamSet::EMPTY,
        CausalRequestId::from_bytes([0x51; 16]),
        honest_principal(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{DescriptorDecode, DescriptorEncode};
    use crate::error::ProviderError;
    use crate::null::NullProvider;
    use crate::provider::{ExecutionProvider, check_binding, check_provider};
    use crate::receipt::{ExecutionOutcome, ExecutionReceipt};
    use astrid_resource_types::{
        CanonicalEncode, ProviderGeneration, ResourceKind, SystemGenerationRef,
    };

    #[test]
    fn honest_null_start_is_unknown_and_binding_holds() {
        let instance = honest_instance();
        let job = honest_job().unwrap();
        check_binding(&instance, &job).unwrap();
        check_provider(&NullProvider.identity(), &instance.closure()).unwrap();
        let receipt = NullProvider.start(&instance, &job).unwrap();
        assert_eq!(receipt.outcome(), ExecutionOutcome::OutcomeUnknown);
        assert_eq!(receipt.causal(), job.causal());
        assert_eq!(receipt.as_live_handle(), Err(ProviderError::NotALiveHandle));
    }

    #[test]
    fn hostile_type_confusion_cannot_decode_as_job_or_closure() {
        let mut kind = [0_u8; 5];
        ResourceKind::Process.encode_canonical(&mut kind).unwrap();
        assert_eq!(
            Job::decode_descriptor(&kind),
            Err(ProviderError::InvalidLength)
        );

        let mut system = [0_u8; 35];
        SystemGenerationRef::from_bytes([0x21; 32])
            .encode_canonical(&mut system)
            .unwrap();
        assert_eq!(
            ApplicationClosure::decode_descriptor(&system),
            Err(ProviderError::InvalidLength)
        );
    }

    #[test]
    fn hostile_stale_provider_generation_fails_closed() {
        let instance = honest_instance();
        let stale_closure = ApplicationClosure::new(
            instance.closure().application(),
            instance.closure().provider(),
            ProviderGeneration::INITIAL
                .checked_next()
                .expect("initial provider generation has a successor"),
        );
        assert!(matches!(
            check_provider(&NullProvider.identity(), &stale_closure),
            Err(ProviderError::StaleGeneration { .. })
        ));
        let confused = AdmittedInstance::new(instance.id(), stale_closure, instance.owner());
        assert_eq!(
            NullProvider.start(&confused, &honest_job().unwrap()),
            Err(ProviderError::TypeMismatch)
        );
    }

    #[test]
    fn serialized_receipt_cannot_become_a_live_handle() {
        let receipt = ExecutionReceipt::for_request(
            NullProvider.identity(),
            &honest_job().unwrap(),
            &honest_instance(),
            ExecutionOutcome::Started,
        );
        let mut encoded = [0_u8; ExecutionReceipt::ENCODED_LEN];
        receipt.encode_descriptor(&mut encoded).unwrap();
        let decoded = ExecutionReceipt::decode_descriptor(&encoded).unwrap();
        assert_eq!(decoded.as_live_handle(), Err(ProviderError::NotALiveHandle));
        let mut leftover = [0_u8; ExecutionReceipt::ENCODED_LEN + 1];
        leftover[..ExecutionReceipt::ENCODED_LEN].copy_from_slice(&encoded);
        leftover[ExecutionReceipt::ENCODED_LEN] = 1;
        assert_eq!(
            ExecutionReceipt::decode_descriptor(&leftover),
            Err(ProviderError::InvalidLength)
        );
    }

    #[test]
    fn mismatched_owner_is_not_a_stamp_or_grant() {
        let instance = AdmittedInstance::new(
            honest_instance().id(),
            honest_closure(),
            OwnerId::fleet([0x99; 32]),
        );
        assert_eq!(
            check_binding(&instance, &honest_job().unwrap()),
            Err(ProviderError::TypeMismatch)
        );
        let other = AdmittedInstance::new(
            honest_instance().id(),
            honest_closure(),
            OwnerId::principal([0x77; 32]),
        );
        assert_eq!(
            check_binding(&other, &honest_job().unwrap()),
            Err(ProviderError::PrincipalMismatch)
        );
    }
}
