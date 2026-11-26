use super::{AdminRequestKind, AdminResponseBody, AstridHome, full_device, handlers, pid, seed};

const CHILD_HOME: &str = "ASTRID_DEVICE_REVOCATION_TEST_HOME";
const ACKNOWLEDGED_EXIT: i32 = 75;

#[tokio::test]
#[ignore = "subprocess for the paired-device restart test"]
async fn exit_after_revocation_acknowledgement() {
    let home = AstridHome::from_path(std::env::var_os(CHILD_HOME).expect("isolated test home"));
    let kernel = crate::test_kernel_with_home(home).await;
    let owner = pid("device_owner");
    let device = full_device('a');
    let removed = device.key_id.clone();
    seed(&kernel, &owner, &["self:*"], vec![device, full_device('b')]);
    assert!(kernel.native_input_device_is_live(&owner, &removed));
    let response = handlers::dispatch(
        &kernel,
        &owner,
        AdminRequestKind::PairDeviceRevoke {
            principal: owner.clone(),
            key_id: removed.clone(),
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::PairDeviceRevoked { key_id } if key_id == removed)
    );
    // Skip daemon shutdown and all Rust destructors after the acknowledgement.
    std::process::exit(ACKNOWLEDGED_EXIT);
}

#[tokio::test]
async fn acknowledged_device_removal_survives_process_exit_and_kernel_reopen() {
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "kernel_router::admin::pair_device_tests::restart::exit_after_revocation_acknowledgement", "--ignored", "--nocapture"])
        .env(CHILD_HOME, home.path()).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(ACKNOWLEDGED_EXIT),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(home.path())).await;
    let owner = pid("device_owner");
    assert!(!kernel.native_input_device_is_live(&owner, &full_device('a').key_id));
    assert!(kernel.native_input_device_is_live(&owner, &full_device('b').key_id));
}
