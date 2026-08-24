//! Test barrier for storage-mount issue admission.

use std::sync::{Arc, LazyLock};

use astrid_core::PrincipalUid;
use dashmap::DashMap;

use crate::Kernel;

/// Pause after owner resolution and before the mutation-lock publication.
pub(crate) struct IssueAdmissionTestGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl IssueAdmissionTestGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        })
    }

    pub(crate) async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("admission entered")
            .forget();
    }

    pub(crate) fn release(&self) {
        self.release.add_permits(1);
    }
}

/// Uninstalls the per-kernel admission gate when the test drops it.
pub(crate) struct IssueAdmissionGateGuard {
    kernel: Arc<Kernel>,
    gate: Arc<IssueAdmissionTestGate>,
}

impl IssueAdmissionGateGuard {
    pub(crate) fn gate(&self) -> &IssueAdmissionTestGate {
        &self.gate
    }
}

impl Drop for IssueAdmissionGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        ISSUE_GATES.remove(&arc_key(&self.kernel));
    }
}

static ISSUE_GATES: LazyLock<DashMap<usize, Arc<IssueAdmissionTestGate>>> =
    LazyLock::new(DashMap::new);
static AUTHORIZED_CALLERS: LazyLock<DashMap<usize, PrincipalUid>> = LazyLock::new(DashMap::new);

/// Install a deterministic pause before lease publication for `kernel`.
#[must_use]
pub(crate) fn arm_issue_admission_gate(kernel: &Arc<Kernel>) -> IssueAdmissionGateGuard {
    let gate = IssueAdmissionTestGate::new();
    ISSUE_GATES.insert(arc_key(kernel), Arc::clone(&gate));
    IssueAdmissionGateGuard {
        kernel: Arc::clone(kernel),
        gate,
    }
}

pub(super) async fn pause_issue_admission_for_test(kernel: &Arc<Kernel>) {
    let gate = ISSUE_GATES
        .get(&arc_key(kernel))
        .map(|entry| Arc::clone(entry.value()));
    if let Some(gate) = gate {
        gate.entered.add_permits(1);
        if let Ok(permit) = gate.release.acquire().await {
            permit.forget();
        }
    }
}

pub(super) fn record_authorized_caller(kernel: &Kernel, uid: PrincipalUid) {
    AUTHORIZED_CALLERS.insert(kernel_key(kernel), uid);
}

pub(crate) fn last_authorized_caller_uid(kernel: &Kernel) -> Option<PrincipalUid> {
    AUTHORIZED_CALLERS
        .get(&kernel_key(kernel))
        .map(|entry| *entry.value())
}

fn kernel_key(kernel: &Kernel) -> usize {
    std::ptr::from_ref(kernel) as usize
}

fn arc_key(kernel: &Arc<Kernel>) -> usize {
    kernel_key(kernel)
}
