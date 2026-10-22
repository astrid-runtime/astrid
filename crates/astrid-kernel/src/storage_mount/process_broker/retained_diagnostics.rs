//! Bounded, test-only evidence for retained projection cleanup refusals.

use super::StorageMountId;
use crate::storage_mount::cleanup::MountCleanupStage;
use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    Binding,
    ProviderStop,
    NativeUnmount,
    KernelUnavailable,
    ExactIdentity,
    InitialDrain,
    LeaseDrain,
    Resource(MountCleanupStage),
    Ledger(MountCleanupStage),
    RootRemoval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Component {
    Branch,
    Owner,
    FleetShared,
    ProjectionSet,
    Lease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Diagnostic {
    pub(super) stage: Stage,
    pub(super) component: Component,
    pub(super) mount_id: StorageMountId,
    pub(super) error_kind: Option<io::ErrorKind>,
    pub(super) os_error: Option<i32>,
}

tokio::task_local! {
    static LAST: Arc<Mutex<Option<Diagnostic>>>;
}

pub(super) fn report(
    stage: Stage,
    component: Component,
    mount_id: StorageMountId,
    error: Option<&io::Error>,
) {
    let diagnostic = Diagnostic {
        stage,
        component,
        mount_id,
        error_kind: error.map(io::Error::kind),
        os_error: error.and_then(io::Error::raw_os_error),
    };
    // Spawned drain tasks do not inherit task locals. Their fixed diagnostics
    // still reach the native test log without requiring a tracing subscriber.
    eprintln!("retained projection cleanup: {diagnostic:?}");
    let _ = LAST.try_with(|last| {
        *last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(diagnostic);
    });
}

pub(super) async fn capture<F: Future>(future: F) -> (F::Output, Option<Diagnostic>) {
    let last = Arc::new(Mutex::new(None));
    let result = LAST.scope(Arc::clone(&last), future).await;
    let diagnostic = *last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (result, diagnostic)
}

pub(super) fn provider_failures(
    state: &super::ProjectionCleanupState,
    binding_valid: bool,
    stopped: [bool; 3],
) {
    let [branch, owner, shared] = stopped;
    if !binding_valid {
        report(
            Stage::Binding,
            Component::ProjectionSet,
            state.branch.lease.mount_id,
            None,
        );
        return;
    }
    for (stopped, component, mount_id) in [
        (branch, Component::Branch, state.branch.lease.mount_id),
        (owner, Component::Owner, state.owner.lease.mount_id),
    ] {
        if !stopped {
            report(Stage::ProviderStop, component, mount_id, None);
        }
    }
    if let Some(provider) = state.shared.as_ref().filter(|_| !shared) {
        report(
            Stage::ProviderStop,
            Component::FleetShared,
            provider.lease.mount_id,
            None,
        );
    }
}

pub(super) fn projection(stage: Stage, mount_id: StorageMountId) {
    report(stage, Component::ProjectionSet, mount_id, None);
}

pub(super) fn root_failure(mount_id: StorageMountId, error: &io::Error) {
    report(Stage::RootRemoval, Component::Branch, mount_id, Some(error));
}
