//! Real lease issuance paused after endpoint and manifest preparation.
use crate::Kernel;
use astrid_core::PrincipalId;
use astrid_core::storage_filesystem::{StorageFilesystemTargetV1, StorageMountLeaseV1};
use astrid_core::storage_provider::{StorageProviderAccessV1, StorageProviderViewV1};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

pub(crate) async fn issue(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    mountpoint: &std::path::Path,
) -> Result<StorageMountLeaseV1, String> {
    crate::storage_mount::issue_lease(
        kernel,
        principal.clone(),
        false,
        StorageProviderViewV1::Principal(principal.clone()),
        StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadWrite,
        "test-provider".to_owned(),
        mountpoint.to_owned(),
    )
    .await
}

pub(crate) struct PreparedIssue {
    resume: mpsc::Sender<()>,
    worker: tokio::task::JoinHandle<Result<StorageMountLeaseV1, String>>,
    resource: PathBuf,
    socket: PathBuf,
}

impl PreparedIssue {
    pub(crate) async fn begin(
        kernel: &Arc<Kernel>,
        caller: &PrincipalId,
        mountpoint: &Path,
    ) -> Self {
        let (prepared, resume) = kernel.pending_mount_issues.hold_next_publication();
        let kernel = Arc::clone(kernel);
        let caller = caller.clone();
        let mountpoint = mountpoint.to_owned();
        let worker = tokio::spawn(async move { issue(&kernel, &caller, &mountpoint).await });
        let (resource, socket) = prepared.await.unwrap();
        assert!(resource.join("lease.json").is_file());
        Self {
            resume,
            worker,
            resource,
            socket,
        }
    }

    pub(crate) async fn assert_retired(self) {
        self.resume.send(()).unwrap();
        assert!(
            self.worker
                .await
                .unwrap()
                .unwrap_err()
                .contains("retired during issuance")
        );
        assert!(!self.resource.exists());
        assert!(!self.socket.exists());
    }
}
