//! Order lease publication against disable and deletion without holding a lock
//! while a provider callback path is being prepared.
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use astrid_core::storage_provider::StorageMountId;
use astrid_core::{PrincipalId, PrincipalUid};

use super::lease_authority::reservation::{RequesterKey, Reservation};
use super::{Kernel, StorageMountLeaseState, cleanup_resource};

#[derive(Clone)]
pub(super) enum Requester {
    Registered(PrincipalUid),
    // Global management authority can have a profile without a storage UID.
    Management(PrincipalId),
}

impl Requester {
    pub(super) fn new(alias: &PrincipalId, uid: Option<PrincipalUid>) -> Self {
        uid.map_or_else(|| Self::Management(alias.clone()), Self::Registered)
    }

    pub(super) fn uid(&self) -> Option<PrincipalUid> {
        match self {
            Self::Registered(uid) => Some(*uid),
            Self::Management(_) => None,
        }
    }

    fn retiring(&self, alias: &PrincipalId, uid: Option<PrincipalUid>) -> bool {
        let key = match self {
            Self::Registered(id) => RequesterKey::Registered(*id.as_bytes()),
            Self::Management(name) => RequesterKey::Management(name.as_str()),
        };
        key.retires(alias.as_str(), uid.map(|id| *id.as_bytes()))
    }
}

impl StorageMountLeaseState {
    pub(super) fn is_owned_by(&self, caller: Option<astrid_core::PrincipalUid>) -> bool {
        super::lease_authority::same_requester(
            self.requester.uid().map(|uid| *uid.as_bytes()),
            caller.map(|uid| *uid.as_bytes()),
        )
    }
}

type Reservations = HashMap<StorageMountId, Reservation<Requester>>;

#[derive(Default)]
pub(crate) struct PendingMountIssues(Mutex<Reservations>);

impl PendingMountIssues {
    fn lock(&self) -> std::sync::MutexGuard<'_, Reservations> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(super) struct Issue<'a> {
    issues: &'a PendingMountIssues,
    id: StorageMountId,
}

impl<'a> Issue<'a> {
    pub(super) async fn admit(
        kernel: &'a Kernel,
        mount_id: StorageMountId,
        caller: &PrincipalId,
        requester: &Requester,
    ) -> Result<Self, String> {
        let issue = Self::begin(kernel, mount_id, requester.clone())?;
        if kernel.principal_directory.uid_for(caller).ok() != requester.uid()
            || kernel.capabilities.is_principal_retiring(caller).await
            || !kernel
                .profile_cache
                .resolve(caller)
                .map_err(|error| format!("resolve storage requester profile: {error}"))?
                .enabled
        {
            return Err("storage mount requester is no longer active".to_owned());
        }
        Ok(issue)
    }

    fn begin(kernel: &'a Kernel, id: StorageMountId, requester: Requester) -> Result<Self, String> {
        let issues = &kernel.pending_mount_issues;
        let mut pending = issues.lock();
        if pending.contains_key(&id) || kernel.storage_mounts.contains_key(&id) {
            return Err("storage mount identity already allocated".to_owned());
        }
        pending.insert(id, Reservation::Preparing(requester));
        Ok(Self { issues, id })
    }

    pub(super) fn publish(self, install: impl FnOnce()) -> bool {
        let mut pending = self.issues.lock();
        if !pending
            .get_mut(&self.id)
            .is_some_and(Reservation::claim_publication)
        {
            return false;
        }
        install();
        drop(pending);
        true
    }
}

impl Drop for Issue<'_> {
    fn drop(&mut self) {
        self.issues.lock().remove(&self.id);
    }
}

pub(crate) async fn retire_requester(
    kernel: &Kernel,
    alias: &PrincipalId,
    uid: Option<PrincipalUid>,
) {
    let retired = {
        let mut pending = kernel.pending_mount_issues.lock();
        for reservation in pending.values_mut() {
            let affected = reservation
                .requester()
                .is_some_and(|requester| requester.retiring(alias, uid));
            reservation.retire(affected);
        }
        let mut retired = Vec::new();
        for lease in kernel.storage_mounts.iter() {
            if lease.requester.retiring(alias, uid) {
                lease.revoked.store(true, Ordering::Release);
                let _ = lease.shutdown_tx.send(true);
                retired.push(Arc::clone(lease.value()));
            }
        }
        retired
    };
    if retired.is_empty() {
        return;
    }
    let _drain = kernel.storage_mount_mutations.lock().await;
    for state in retired {
        kernel.storage_mounts.remove(&state.mount_id);
        cleanup_resource(&state.resource_path, &state.callback_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retirement_closes_prepared_publication_and_preserves_other_requesters() {
        let dir = tempfile::tempdir().unwrap();
        let kernel =
            crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(dir.path()))
                .await;
        let original = PrincipalId::default();
        let uid = kernel.principal_directory.uid_for(&original).unwrap();
        let renamed = PrincipalId::new("renamed").unwrap();
        let id = StorageMountId::new();
        let prepared = Issue::begin(&kernel, id, Requester::Registered(uid)).unwrap();
        let other = Issue::begin(
            &kernel,
            StorageMountId::new(),
            Requester::Management(original.clone()),
        )
        .unwrap();
        retire_requester(&kernel, &renamed, Some(uid)).await;
        assert!(Issue::begin(&kernel, id, Requester::Registered(uid)).is_err());
        assert!(!prepared.publish(|| panic!("retired issue published")));
        assert!(other.publish(|| {}));
        assert!(kernel.pending_mount_issues.lock().is_empty());
        let abandoned = Issue::begin(&kernel, id, Requester::Registered(uid)).unwrap();
        drop(abandoned);
        assert!(kernel.pending_mount_issues.lock().is_empty());
    }
}
