//! Workload-neutral null provider. Receipts are unknown; never a harness.

use crate::checkpoint::Checkpoint;
use crate::error::ProviderError;
use crate::instance::AdmittedInstance;
use crate::job::Job;
use crate::provider::{ExecutionProvider, ProviderIdentity, check_provider, check_start};
use crate::receipt::{ExecutionOutcome, ExecutionReceipt};
use astrid_resource_types::{ProviderGeneration, ProviderId};

/// Well-known null provider identity. Not a named guest runtime.
pub const NULL_PROVIDER_ID: ProviderId = ProviderId::from_bytes([0xA5; 32]);
/// Null provider incarnation.
pub const NULL_PROVIDER_GENERATION: ProviderGeneration = ProviderGeneration::INITIAL;

/// Provider that validates bindings and then reports unknown outcomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NullProvider;

impl NullProvider {
    /// Well-known identity for this provider.
    #[must_use]
    pub const fn identity_value() -> ProviderIdentity {
        ProviderIdentity::new(NULL_PROVIDER_ID, NULL_PROVIDER_GENERATION)
    }

    fn unknown_receipt(job: &Job, instance: &AdmittedInstance) -> ExecutionReceipt {
        ExecutionReceipt::new(
            job.operation(),
            job.causal(),
            instance.id(),
            ExecutionOutcome::OutcomeUnknown,
        )
    }
}

impl ExecutionProvider for NullProvider {
    fn identity(&self) -> ProviderIdentity {
        Self::identity_value()
    }

    fn start(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        Ok(Self::unknown_receipt(job, instance))
    }

    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        Ok(Self::unknown_receipt(job, instance))
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
    use super::*;
    use crate::checkpoint::{Checkpoint, CheckpointBlobId};
    use crate::fixtures::{honest_instance, honest_job};

    #[test]
    fn null_provider_start_and_exit_are_unknown_and_not_handles() {
        let provider = NullProvider;
        let instance = honest_instance();
        let job = honest_job().unwrap();
        let started = provider.start(&instance, &job).unwrap();
        assert_eq!(started.outcome(), ExecutionOutcome::OutcomeUnknown);
        assert_eq!(started.as_live_handle(), Err(ProviderError::NotALiveHandle));
        let exited = provider.exit(&instance, &job).unwrap();
        assert_eq!(exited.outcome(), ExecutionOutcome::OutcomeUnknown);
        assert_eq!(
            provider.checkpoint(&instance),
            Err(ProviderError::NotSupported)
        );
        assert_eq!(
            provider.restore(&Checkpoint::new(
                instance.id(),
                CheckpointBlobId::from_bytes([9; 32]),
            )),
            Err(ProviderError::NotSupported)
        );
    }
}
