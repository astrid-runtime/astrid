//! Shared authority assertions for partial issue rollback.

use super::super::ProcessLaunchStage;
use crate::Kernel;

pub(super) fn expected_lease_count(stage: ProcessLaunchStage) -> usize {
    match stage {
        ProcessLaunchStage::OwnerHome => 1,
        ProcessLaunchStage::FleetShared => 2,
        ProcessLaunchStage::Branch => {
            unreachable!("the first issue cannot roll back a prior lease")
        },
    }
}

pub(super) fn assert_retained_issue_authority(kernel: &Kernel, stage: ProcessLaunchStage) {
    assert_eq!(
        kernel.storage_mounts.len(),
        expected_lease_count(stage),
        "{stage:?} failed cleanup must retain every issued lease"
    );
    for entry in kernel.storage_mounts.iter() {
        let retained_lease = entry.value();
        assert!(
            retained_lease.is_revoked_for_test(),
            "cleanup-faulted lease must remain revoked"
        );

        // Unix socket pathnames may outlive their listener; Windows named
        // pipes vanish with the final server handle. Durable authority does
        // not depend on this transport-specific pathname.
        #[cfg(unix)]
        {
            let callback_path = retained_lease.callback_identity_for_test().0;
            assert!(
                astrid_core::local_transport::endpoint_is_present(&callback_path).unwrap(),
                "cleanup-faulted callback endpoint must remain retained"
            );
        }
    }
    assert_eq!(
        kernel
            .astrid_home
            .run_dir()
            .join("process-storage")
            .read_dir()
            .expect("process storage root")
            .count(),
        1,
        "{stage:?} failed cleanup must retain its exact provider root"
    );
}
