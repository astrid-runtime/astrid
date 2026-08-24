//! Host-owned adapter that validates bindings then delegates.

use core::fmt;

use crate::checkpoint::Checkpoint;
use crate::error::ProviderError;
use crate::instance::AdmittedInstance;
use crate::job::Job;
use crate::provider::{ExecutionProvider, ProviderIdentity, check_provider, check_start};
use crate::receipt::ExecutionReceipt;

/// Host-owned adapter around an inner [`ExecutionProvider`].
///
/// This is not a named guest runtime. It validates identity bindings, then
/// delegates. Debug prints only the adapter name.
pub struct CapsuleAdapter<P> {
    inner: P,
}

impl<P> CapsuleAdapter<P> {
    /// Wrap an inner provider.
    #[must_use]
    pub const fn new(inner: P) -> Self {
        Self { inner }
    }

    /// Borrow the inner provider.
    #[must_use]
    pub const fn inner(&self) -> &P {
        &self.inner
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
        self.inner.start(instance, job)
    }

    fn exit(
        &self,
        instance: &AdmittedInstance,
        job: &Job,
    ) -> Result<ExecutionReceipt, ProviderError> {
        check_start(&self.identity(), instance, job)?;
        self.inner.exit(instance, job)
    }

    fn checkpoint(&self, instance: &AdmittedInstance) -> Result<Checkpoint, ProviderError> {
        check_provider(&self.identity(), &instance.closure())?;
        self.inner.checkpoint(instance)
    }

    fn restore(&self, checkpoint: &Checkpoint) -> Result<AdmittedInstance, ProviderError> {
        self.inner.restore(checkpoint)
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
    use crate::fixtures::{honest_instance, honest_job};
    use crate::null::NullProvider;
    use crate::provider::ExecutionProvider;
    use crate::receipt::ExecutionOutcome;
    use alloc::format;

    struct StartedProvider;

    impl ExecutionProvider for StartedProvider {
        fn identity(&self) -> ProviderIdentity {
            NullProvider.identity()
        }

        fn start(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            Ok(ExecutionReceipt::new(
                job.operation(),
                job.causal(),
                instance.id(),
                ExecutionOutcome::Started,
            ))
        }

        fn exit(
            &self,
            instance: &AdmittedInstance,
            job: &Job,
        ) -> Result<ExecutionReceipt, ProviderError> {
            Ok(ExecutionReceipt::new(
                job.operation(),
                job.causal(),
                instance.id(),
                ExecutionOutcome::Exited { status: 0 },
            ))
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
    fn adapter_validates_before_delegate_and_debug_is_opaque() {
        let adapter = CapsuleAdapter::new(StartedProvider);
        let instance = honest_instance();
        let job = honest_job().unwrap();
        assert_eq!(
            adapter.start(&instance, &job).unwrap().outcome(),
            ExecutionOutcome::Started
        );
        let mismatched = crate::Job::claiming(
            job.operation(),
            crate::InstanceId::new(
                astrid_resource_types::ResourceId::from_bytes([0xfe; 32]),
                instance.id().generation(),
            ),
            instance.closure(),
            job.argv(),
            job.causal(),
            job.principal(),
        );
        assert_eq!(
            adapter.start(&instance, &mismatched),
            Err(ProviderError::TypeMismatch)
        );
        let rendered = format!("{adapter:?}");
        assert_eq!(rendered, "CapsuleAdapter");
        assert!(!rendered.contains("StartedProvider"));
        assert!(!rendered.contains("inner"));
    }
}
