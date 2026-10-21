//! Kernel-local scheduling controls; unrelated projection tests never share a gate.

use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Default)]
struct Gate {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

type Slot = Arc<Mutex<Option<Arc<Gate>>>>;

#[derive(Default)]
pub(crate) struct RetainTestGates {
    validation: Slot,
    reference: Slot,
}

pub(crate) struct RetainValidationGateGuard {
    slot: Slot,
    gate: Arc<Gate>,
}

impl RetainValidationGateGuard {
    pub(crate) fn entered(&self) -> Arc<Notify> {
        Arc::clone(&self.gate.entered)
    }

    pub(crate) fn release(&self) -> Arc<Notify> {
        Arc::clone(&self.gate.release)
    }
}

impl Drop for RetainValidationGateGuard {
    fn drop(&mut self) {
        let mut installed = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if installed
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
        {
            *installed = None;
        }
    }
}

fn arm(slot: &Slot) -> RetainValidationGateGuard {
    let gate = Arc::new(Gate::default());
    let mut installed = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        installed.is_none(),
        "a scheduling gate is already armed for this kernel"
    );
    *installed = Some(Arc::clone(&gate));
    RetainValidationGateGuard {
        slot: Arc::clone(slot),
        gate,
    }
}

pub(crate) fn arm_retain_validation_gate(kernel: &crate::Kernel) -> RetainValidationGateGuard {
    arm(&kernel.projection_retain_test_gates.validation)
}

pub(crate) fn arm_retain_reference_gate(kernel: &crate::Kernel) -> RetainValidationGateGuard {
    arm(&kernel.projection_retain_test_gates.reference)
}

async fn pause(slot: &Slot) {
    let gate = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
}

pub(super) async fn pause_validation(kernel: &crate::Kernel) {
    pause(&kernel.projection_retain_test_gates.validation).await;
}

pub(super) async fn pause_reference(kernel: &crate::Kernel) {
    pause(&kernel.projection_retain_test_gates.reference).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_retain_gate_pauses_only_one_admission() {
        let slot = Slot::default();
        let gate = arm(&slot);
        let task = tokio::spawn({
            let slot = Arc::clone(&slot);
            async move { pause(&slot).await }
        });
        gate.entered().notified().await;
        gate.release().notify_one();
        task.await.expect("first admission released");
        tokio::time::timeout(std::time::Duration::from_secs(1), pause(&slot))
            .await
            .expect("a replacement admission must not hit the consumed gate");
    }
}
