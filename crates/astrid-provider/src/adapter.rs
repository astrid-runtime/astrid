//! Host-owned adapter that validates bindings then delegates.

use core::fmt;

use crate::checkpoint::Checkpoint;
use crate::error::ProviderError;
use crate::instance::AdmittedInstance;
use crate::job::Job;
use crate::provider::{
    ExecutionProvider, ProviderIdentity, check_checkpoint, check_provider, check_receipt,
    check_restore, check_restored_instance, check_start,
};
use crate::receipt::ExecutionReceipt;

/// Host-owned adapter around an inner [`ExecutionProvider`].
///
/// This is not a named guest runtime. It validates identity bindings, then
/// delegates, then validates returned descriptors. There is no public borrow of
/// the inner provider. Debug prints only the adapter name.
pub struct CapsuleAdapter<P> {
    inner: P,
}

impl<P> CapsuleAdapter<P> {
    /// Wrap an inner provider.
    #[must_use]
    pub const fn new(inner: P) -> Self {
        Self { inner }
    }
}

impl<P: ExecutionProvider> ExecutionProvider for CapsuleAdapter<P> {
    fn identity(&self) -> ProviderIdentity {
        self.inner.identity()
    }

    fn start(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        let receipt = self.inner.start(instance, job)?;
        check_receipt(&self.identity(), instance, job, &receipt)?;
        Ok(receipt)
    }

    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        let receipt = self.inner.exit(instance, job)?;
        check_receipt(&self.identity(), instance, job, &receipt)?;
        Ok(receipt)
    }

    fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
        check_provider(&self.identity(), &instance.closure())?;
        let checkpoint = self.inner.checkpoint(instance)?;
        check_checkpoint(&self.identity(), instance, &checkpoint)?;
        Ok(checkpoint)
    }

    fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
        check_restore(&self.identity(), checkpoint)?;
        let restored = self.inner.restore(checkpoint)?;
        check_restored_instance(checkpoint, &restored)?;
        Ok(restored)
    }
}

impl<P> fmt::Debug for CapsuleAdapter<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("CapsuleAdapter")
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::checkpoint::CheckpointBlobId;
    use crate::closure::ApplicationClosure;
    use crate::fixtures::{honest_instance, honest_job};
    use crate::instance::InstanceId;
    use crate::null::{NULL_PROVIDER_GENERATION, NullProvider};
    use crate::provider::ExecutionProvider;
    use crate::receipt::ExecutionOutcome;
    use alloc::format;
    use astrid_resource_types::{ObjectGeneration, OwnerId, ProviderId, ResourceId};

    struct PermissiveProvider;

    impl ExecutionProvider for PermissiveProvider {
        fn identity(&self) -> ProviderIdentity {
            NullProvider.identity()
        }

        fn start(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            Ok(ExecutionReceipt::for_request(
                self.identity(),
                job,
                instance,
                ExecutionOutcome::Started,
            ))
        }

        fn exit(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            Ok(ExecutionReceipt::for_request(
                self.identity(),
                job,
                instance,
                ExecutionOutcome::Exited { status: 0 },
            ))
        }

        fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
            Ok(Checkpoint::from_instance(
                *instance,
                CheckpointBlobId::from_bytes([0x61; 32]),
            ))
        }

        fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
            Ok(checkpoint.admitted())
        }
    }

    fn resource_b_instance() -> AdmittedInstance {
        AdmittedInstance::new(
            InstanceId::new(
                ResourceId::from_bytes([0x32; 32]),
                ObjectGeneration::INITIAL,
            ),
            honest_instance().closure(),
            honest_instance().owner(),
        )
    }

    fn other_provider_instance() -> AdmittedInstance {
        AdmittedInstance::new(
            honest_instance().id(),
            ApplicationClosure::new(
                honest_instance().closure().application(),
                ProviderId::from_bytes([0xb5; 32]),
                NULL_PROVIDER_GENERATION,
            ),
            honest_instance().owner(),
        )
    }

    fn stale_provider_instance() -> AdmittedInstance {
        AdmittedInstance::new(
            honest_instance().id(),
            ApplicationClosure::new(
                honest_instance().closure().application(),
                honest_instance().closure().provider(),
                NULL_PROVIDER_GENERATION
                    .checked_next()
                    .expect("initial provider generation has a successor"),
            ),
            honest_instance().owner(),
        )
    }

    fn owner_swapped_instance() -> AdmittedInstance {
        AdmittedInstance::new(
            honest_instance().id(),
            honest_instance().closure(),
            OwnerId::principal([0x77; 32]),
        )
    }

    #[test]
    fn adapter_rejects_cross_instance_job_without_exposing_inner() {
        let inner = PermissiveProvider;
        let instance = honest_instance();
        let job = honest_job().unwrap();
        let mismatched = crate::Job::claiming(
            job.operation(),
            InstanceId::new(
                ResourceId::from_bytes([0xfe; 32]),
                instance.id().generation(),
            ),
            instance.closure(),
            job.argv(),
            job.causal(),
            job.principal(),
        );
        assert!(inner.start(&instance, &mismatched).is_ok());
        let adapter = CapsuleAdapter::new(inner);
        assert_eq!(
            adapter.start(&instance, &mismatched),
            Err(ProviderError::TypeMismatch)
        );
        assert_eq!(
            adapter.start(&instance, &job).unwrap().outcome(),
            ExecutionOutcome::Started
        );
        let rendered = format!("{adapter:?}");
        assert_eq!(rendered, "CapsuleAdapter");
        assert!(!rendered.contains("PermissiveProvider"));
        assert!(!rendered.contains("inner"));
    }

    struct SwapRestoreProvider;

    impl ExecutionProvider for SwapRestoreProvider {
        fn identity(&self) -> ProviderIdentity {
            NullProvider.identity()
        }

        fn start(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Err(ProviderError::NotSupported)
        }

        fn exit(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Err(ProviderError::NotSupported)
        }

        fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
            Ok(Checkpoint::from_instance(
                *instance,
                CheckpointBlobId::from_bytes([0x61; 32]),
            ))
        }

        fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
            let _ = checkpoint;
            Ok(resource_b_instance())
        }
    }

    struct OwnerSwapProvider;

    impl ExecutionProvider for OwnerSwapProvider {
        fn identity(&self) -> ProviderIdentity {
            NullProvider.identity()
        }

        fn start(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Err(ProviderError::NotSupported)
        }

        fn exit(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Err(ProviderError::NotSupported)
        }

        fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
            let _ = instance;
            Err(ProviderError::NotSupported)
        }

        fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
            let _ = checkpoint;
            Ok(owner_swapped_instance())
        }
    }

    #[test]
    fn adapter_rejects_swapped_restore_and_cross_provider_checkpoint() {
        let adapter = CapsuleAdapter::new(SwapRestoreProvider);
        let instance = honest_instance();
        let blob = CheckpointBlobId::from_bytes([0x61; 32]);
        let checkpoint_a = Checkpoint::from_instance(instance, blob);
        assert_eq!(adapter.checkpoint(&instance).unwrap().admitted(), instance);
        assert_eq!(
            adapter.restore(&checkpoint_a),
            Err(ProviderError::TypeMismatch)
        );
        assert_eq!(
            adapter.restore(&Checkpoint::from_instance(other_provider_instance(), blob)),
            Err(ProviderError::TypeMismatch)
        );
        assert!(matches!(
            adapter.restore(&Checkpoint::from_instance(stale_provider_instance(), blob)),
            Err(ProviderError::StaleGeneration { .. })
        ));
        assert_eq!(
            CapsuleAdapter::new(OwnerSwapProvider).restore(&checkpoint_a),
            Err(ProviderError::PrincipalMismatch)
        );
        let wrong_closure = AdmittedInstance::new(
            instance.id(),
            other_provider_instance().closure(),
            instance.owner(),
        );
        assert_eq!(
            adapter.restore(&Checkpoint::from_instance(wrong_closure, blob)),
            Err(ProviderError::TypeMismatch)
        );
    }

    struct ForgedReceiptProvider {
        receipt: ExecutionReceipt,
    }

    impl ExecutionProvider for ForgedReceiptProvider {
        fn identity(&self) -> ProviderIdentity {
            NullProvider.identity()
        }

        fn start(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Ok(self.receipt)
        }

        fn exit(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            let _ = (instance, job);
            Ok(self.receipt)
        }

        fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
            let _ = instance;
            Err(ProviderError::NotSupported)
        }

        fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
            let _ = checkpoint;
            Err(ProviderError::NotSupported)
        }
    }

    #[test]
    fn adapter_rejects_forged_receipt_identity() {
        let instance = honest_instance();
        let job = honest_job().unwrap();
        let identity = NullProvider.identity();
        let honest =
            ExecutionReceipt::for_request(identity, &job, &instance, ExecutionOutcome::Started);
        let forged_operation = ExecutionReceipt::new(
            identity,
            astrid_resource_types::OperationId::from_bytes([0x99; 16]),
            job.causal(),
            instance.id(),
            ExecutionOutcome::Started,
        );
        assert_eq!(
            CapsuleAdapter::new(ForgedReceiptProvider {
                receipt: forged_operation
            })
            .start(&instance, &job),
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
            ExecutionOutcome::Started,
        );
        assert_eq!(
            CapsuleAdapter::new(ForgedReceiptProvider {
                receipt: forged_instance
            })
            .start(&instance, &job),
            Err(ProviderError::TypeMismatch)
        );
        let cross = ExecutionReceipt::new(
            ProviderIdentity::new(ProviderId::from_bytes([0xb5; 32]), identity.generation()),
            job.operation(),
            job.causal(),
            instance.id(),
            ExecutionOutcome::Started,
        );
        assert_ne!(cross, honest);
        assert_ne!(cross.binding(), honest.binding());
        assert_eq!(
            CapsuleAdapter::new(ForgedReceiptProvider { receipt: cross }).start(&instance, &job),
            Err(ProviderError::TypeMismatch)
        );
        let stale = ExecutionReceipt::new(
            ProviderIdentity::new(identity.id(), identity.generation().checked_next().unwrap()),
            job.operation(),
            job.causal(),
            instance.id(),
            ExecutionOutcome::Started,
        );
        assert!(matches!(
            CapsuleAdapter::new(ForgedReceiptProvider { receipt: stale }).start(&instance, &job),
            Err(ProviderError::StaleGeneration { .. })
        ));
    }
}
