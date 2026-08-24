//! Execution receipts. They cannot become live handles.

use astrid_resource_types::{CausalRequestId, OperationId};

use crate::closure::{decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, take, write_header, write_nested,
};
use crate::error::ProviderError;
use crate::instance::InstanceId;

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

/// Durable-looking receipt of start or exit. Not a live handle or lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    operation: OperationId,
    causal: CausalRequestId,
    instance: InstanceId,
    outcome: ExecutionOutcome,
}

impl ExecutionReceipt {
    /// Exact encoded length, including nested identities.
    pub const ENCODED_LEN: usize = 95;

    /// Construct a receipt for one operation.
    #[must_use]
    pub const fn new(
        operation: OperationId,
        causal: CausalRequestId,
        instance: InstanceId,
        outcome: ExecutionOutcome,
    ) -> Self {
        Self {
            operation,
            causal,
            instance,
            outcome,
        }
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
        let offset = encode_resource(output, 3, &self.operation)?;
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
        let (operation, offset) = decode_resource::<OperationId>(input, 3, 19)?;
        let (causal, offset) = decode_resource::<CausalRequestId>(input, offset, 19)?;
        let (instance, offset) = read_nested::<InstanceId>(input, offset, InstanceId::ENCODED_LEN)?;
        let (outcome, _) =
            read_nested::<ExecutionOutcome>(input, offset, ExecutionOutcome::ENCODED_LEN)?;
        Ok(Self::new(operation, causal, instance, outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::{ObjectGeneration, ResourceId};

    fn receipt(outcome: ExecutionOutcome) -> ExecutionReceipt {
        ExecutionReceipt::new(
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
}
