//! Principal-scoped readiness for the native socket ingress boundary.

use super::Kernel;
use astrid_capsule::capsule::ReadyStatus;
use astrid_core::kernel_api::CapsuleTopicProbe;
use std::sync::Arc;
use std::time::Duration;

impl Kernel {
    /// Probe and demand-load only the authenticated caller's capsule view.
    /// A registered manifest alone does not prove its run loop subscribed.
    #[must_use]
    pub fn capsule_ingress_readiness(self: &Arc<Self>) -> CapsuleTopicProbe {
        let passive = Arc::clone(self);
        let active = Arc::clone(self);
        CapsuleTopicProbe::new_with_ensure(
            move |key| {
                let kernel = Arc::clone(&passive);
                Box::pin(async move { kernel.ingress_topic_ready(&key).await })
            },
            move |key| {
                let kernel = Arc::clone(&active);
                Box::pin(async move {
                    // The socket owns only this wait. A disconnect or turn
                    // cancellation must not drop a partially loaded capsule.
                    kernel
                        .run_owned_readiness(move |kernel| async move {
                            if *kernel.shutdown_tx.borrow() {
                                return false;
                            }
                            let Some((principal, _, _)) = Self::split_scoped_topic_probe_key(&key)
                            else {
                                return false;
                            };
                            kernel.ensure_principal_loaded(&principal).await;
                            kernel.ingress_topic_ready(&key).await
                        })
                        .await
                })
            },
        )
    }

    /// Own lifecycle admission independently of any socket/HTTP waiter.
    /// Dropping the join handle leaves the transaction owned by its task.
    pub(super) async fn run_owned_readiness<F, Fut>(self: Arc<Self>, work: F) -> bool
    where
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        tokio::spawn(async move {
            let Some(_permit) = self.runtime_work.admit() else {
                return false;
            };
            work(Arc::clone(&self)).await
        })
        .await
        .unwrap_or(false)
    }

    async fn ingress_topic_ready(&self, key: &str) -> bool {
        if *self.shutdown_tx.borrow() {
            return false;
        }
        let Some((principal, selected, topic)) = Self::split_scoped_topic_probe_key(key) else {
            return false;
        };
        let capsules = {
            let registry = self.capsules.read().await;
            registry
                .cloned_values_for(&principal)
                .into_iter()
                .filter(|capsule| {
                    selected.as_ref().is_none_or(|id| capsule.id() == id)
                        && astrid_capsule::readiness::manifest_subscribes_topic(
                            capsule.manifest(),
                            &topic,
                        )
                })
                .collect::<Vec<_>>()
        };
        if capsules.is_empty() {
            return false;
        }
        // Use the existing capsule-readiness budget, shared across providers.
        let Some(deadline) =
            astrid_runtime::time::Instant::now().checked_add(Duration::from_millis(500))
        else {
            return false;
        };
        for capsule in capsules {
            let remaining =
                deadline.saturating_duration_since(astrid_runtime::time::Instant::now());
            if !matches!(capsule.wait_ready(remaining).await, ReadyStatus::Ready) {
                return false;
            }
        }
        !*self.shutdown_tx.borrow()
    }
}

#[cfg(test)]
pub(super) mod tests;
