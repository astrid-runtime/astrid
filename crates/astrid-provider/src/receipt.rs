//! Execution receipts. They cannot become live handles.

use astrid_resource_types::{CausalRequestId, OperationId};

use crate::closure::{decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, take, write_header, write_nested,
};
use crate::error::ProviderError;
use crate::instance::{AdmittedInstance, InstanceId};
use crate::job::Job;
use crate::provider::ProviderIdentity;

/// Uninhabited type: receipts cannot produce a live handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveHandle {}

/// Closed execution outcome. [`Self::OutcomeUnknown`] is a first-class value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The job was accepted for execution.
    Started,
    /// The job exited with a provider-local status byte.
    Exited {
        /// Opaque status. Not a grant or handle.
        status: u8,
    },
    /// The provider cannot classify the outcome.
    OutcomeUnknown,
}

impl ExecutionOutcome {
    /// Exact encoded length, including a canonical unused status byte.
    pub const ENCODED_LEN: usize = 5;

    const STARTED: u8 = 1;
    const EXITED: u8 = 2;
    const UNKNOWN: u8 = 3;
}

impl DescriptorEncode for ExecutionOutcome {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::ExecutionOutcome)?;
        let (code, status) = match *self {
            Self::Started => (Self::STARTED, 0),
            Self::Exited { status } => (Self::EXITED, status),
            Self::OutcomeUnknown => (Self::UNKNOWN, 0),
        };
        let slot = output.get_mut(3..5).ok_or(ProviderError::InvalidLength)?;
        slot[0] = code;
        slot[1] = status;
        Ok(())
    }
}

impl DescriptorDecode for ExecutionOutcome {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::ExecutionOutcome)?;
        let (payload, _) = take(input, 3, 2)?;
        let [code, status] = payload
            .try_into()
            .map_err(|_| ProviderError::InvalidLength)?;
        match (code, status) {
            (Self::STARTED, 0) => Ok(Self::Started),
            (Self::EXITED, status) => Ok(Self::Exited { status }),
            (Self::UNKNOWN, 0) => Ok(Self::OutcomeUnknown),
            (Self::STARTED | Self::UNKNOWN, _) => Err(ProviderError::NonCanonical),
            (code, _) => Err(ProviderError::UnknownDiscriminant(u16::from(code))),
        }
    }
}

/// Canonical receipt identity. Not a replay ledger and not exactly-once
/// execution. Duplicate [`CausalRequestId`] values share this binding when
/// provider, operation, and instance also match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptBinding {
    provider: ProviderIdentity,
    operation: OperationId,
    causal: CausalRequestId,
    instance: InstanceId,
}

impl ReceiptBinding {
    /// Provider incarnation named by this binding.
    #[must_use]
    pub const fn provider(self) -> ProviderIdentity {
        self.provider
    }

    /// Operation named by this binding.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Causal request identity.
    #[must_use]
    pub const fn causal(self) -> CausalRequestId {
        self.causal
    }

    /// Instance named by this binding.
    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }
}

/// Durable-looking receipt of start or exit. Not a live handle or lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    provider: ProviderIdentity,
    operation: OperationId,
    causal: CausalRequestId,
    instance: InstanceId,
    outcome: ExecutionOutcome,
}

impl ExecutionReceipt {
    /// Exact encoded length, including nested identities.
    pub const ENCODED_LEN: usize = 144;

    /// Construct a receipt for one provider request.
    #[must_use]
    pub const fn new(
        provider: ProviderIdentity,
        operation: OperationId,
        causal: CausalRequestId,
        instance: InstanceId,
        outcome: ExecutionOutcome,
    ) -> Self {
        Self {
            provider,
            operation,
            causal,
            instance,
            outcome,
        }
    }

    /// Copy identities from a validated request. Outcome remains caller-chosen.
    #[must_use]
    pub const fn for_request(
        provider: ProviderIdentity,
        job: &Job,
        instance: &AdmittedInstance,
        outcome: ExecutionOutcome,
    ) -> Self {
        Self::new(
            provider,
            job.operation(),
            job.causal(),
            instance.id(),
            outcome,
        )
    }

    /// Provider incarnation named by this receipt.
    #[must_use]
    pub const fn provider(&self) -> ProviderIdentity {
        self.provider
    }

    /// Operation this receipt names.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Causal request identity copied from the job.
    #[must_use]
    pub const fn causal(&self) -> CausalRequestId {
        self.causal
    }

    /// Instance this receipt names.
    #[must_use]
    pub const fn instance(&self) -> InstanceId {
        self.instance
    }

    /// Recorded outcome, including [`ExecutionOutcome::OutcomeUnknown`].
    #[must_use]
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    /// Canonical identity/binding, independent of outcome.
    #[must_use]
    pub const fn binding(&self) -> ReceiptBinding {
        ReceiptBinding {
            provider: self.provider,
            operation: self.operation,
            causal: self.causal,
            instance: self.instance,
        }
    }

    /// Receipts never become live handles.
    ///
    /// # Errors
    ///
    /// Always [`ProviderError::NotALiveHandle`].
    pub const fn as_live_handle(&self) -> Result<LiveHandle, ProviderError> {
        let _ = self;
        Err(ProviderError::NotALiveHandle)
    }
}

impl DescriptorEncode for ExecutionReceipt {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::ExecutionReceipt)?;
        let offset = write_nested(output, 3, &self.provider)?;
        let offset = encode_resource(output, offset, &self.operation)?;
        let offset = encode_resource(output, offset, &self.causal)?;
        let offset = write_nested(output, offset, &self.instance)?;
        write_nested(output, offset, &self.outcome)?;
        Ok(())
    }
}

impl DescriptorDecode for ExecutionReceipt {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::ExecutionReceipt)?;
        let (provider, offset) =
            read_nested::<ProviderIdentity>(input, 3, ProviderIdentity::ENCODED_LEN)?;
        let (operation, offset) = decode_resource::<OperationId>(input, offset, 19)?;
        let (causal, offset) = decode_resource::<CausalRequestId>(input, offset, 19)?;
        let (instance, offset) = read_nested::<InstanceId>(input, offset, InstanceId::ENCODED_LEN)?;
        let (outcome, _) =
            read_nested::<ExecutionOutcome>(input, offset, ExecutionOutcome::ENCODED_LEN)?;
        Ok(Self::new(provider, operation, causal, instance, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{honest_instance, honest_job};
    use crate::null::NullProvider;
    use astrid_resource_types::{ObjectGeneration, ProviderId, ResourceId};

    fn receipt(outcome: ExecutionOutcome) -> ExecutionReceipt {
        ExecutionReceipt::new(
            NullProvider::identity_value(),
            OperationId::from_bytes([0x41; 16]),
            CausalRequestId::from_bytes([0x42; 16]),
            InstanceId::new(
                ResourceId::from_bytes([0x31; 32]),
                ObjectGeneration::INITIAL,
            ),
            outcome,
        )
    }

    #[test]
    fn every_outcome_roundtrips_and_is_not_a_live_handle() {
        for outcome in [
            ExecutionOutcome::Started,
            ExecutionOutcome::Exited { status: 7 },
            ExecutionOutcome::OutcomeUnknown,
        ] {
            let value = receipt(outcome);
            let mut encoded = [0_u8; ExecutionReceipt::ENCODED_LEN];
            value.encode_descriptor(&mut encoded).unwrap();
            assert_eq!(ExecutionReceipt::decode_descriptor(&encoded), Ok(value));
            assert_eq!(value.as_live_handle(), Err(ProviderError::NotALiveHandle));
        }
        let mut started = [0_u8; ExecutionOutcome::ENCODED_LEN];
        ExecutionOutcome::Started
            .encode_descriptor(&mut started)
            .unwrap();
        started[4] = 1;
        assert_eq!(
            ExecutionOutcome::decode_descriptor(&started),
            Err(ProviderError::NonCanonical)
        );
    }

    #[test]
    fn outcome_unknown_is_distinct_and_causal_binding_is_canonical() {
        let unknown = receipt(ExecutionOutcome::OutcomeUnknown);
        let started = receipt(ExecutionOutcome::Started);
        assert_ne!(unknown, started);
        assert_ne!(unknown.outcome(), started.outcome());
        assert_eq!(unknown.binding(), started.binding());
        let other_provider = ExecutionReceipt::new(
            ProviderIdentity::new(
                ProviderId::from_bytes([0xb5; 32]),
                unknown.provider().generation(),
            ),
            unknown.operation(),
            unknown.causal(),
            unknown.instance(),
            ExecutionOutcome::OutcomeUnknown,
        );
        assert_ne!(unknown, other_provider);
        assert_ne!(unknown.binding(), other_provider.binding());
        let job = honest_job().unwrap();
        let instance = honest_instance();
        let first = ExecutionReceipt::for_request(
            NullProvider::identity_value(),
            &job,
            &instance,
            ExecutionOutcome::OutcomeUnknown,
        );
        let second = ExecutionReceipt::for_request(
            NullProvider::identity_value(),
            &job,
            &instance,
            ExecutionOutcome::Exited { status: 0 },
        );
        assert_eq!(first.binding(), second.binding());
        assert_eq!(first.causal(), second.causal());
        assert_ne!(first.outcome(), second.outcome());
        let mut leftover = [0_u8; ExecutionReceipt::ENCODED_LEN + 1];
        first
            .encode_descriptor(&mut leftover[..ExecutionReceipt::ENCODED_LEN])
            .unwrap();
        leftover[ExecutionReceipt::ENCODED_LEN] = 1;
        assert_eq!(
            ExecutionReceipt::decode_descriptor(&leftover),
            Err(ProviderError::InvalidLength)
        );
    }
}
