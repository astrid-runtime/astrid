use crate::Kernel;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_kernel_new_keeps_fresh_ownership_unenrolled() {
    // Run the native composition root in a child process so the test can
    // provide ASTRID_HOME without mutating the parent test process. This
    // exercises the exact Kernel::new boot block, not only the gate helper.
    if std::env::var_os("ASTRID_FIRST_OWNER_BOOT_CHILD").is_some() {
        let kernel = Kernel::new(
            astrid_core::SessionId::SYSTEM,
            std::env::current_dir().expect("test workspace root"),
            astrid_capsule_types::CapsuleRuntimeLimits::default(),
            std::collections::HashMap::new(),
            astrid_capsule_types::HttpLimits::default(),
        )
        .await
        .expect("fresh native kernel boot");
        let graph = kernel
            .ownership_store
            .load()
            .await
            .expect("fresh ownership graph");
        assert_eq!(
            kernel
                .ownership_store
                .first_owner_state()
                .await
                .expect("fresh first-owner state"),
            astrid_storage::FirstOwnerEnrollment::Unenrolled
        );
        assert!(
            graph.fleets().next().is_none(),
            "fresh Kernel::new must not promote the CLI root before enrollment"
        );
        return;
    }

    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("first_owner_boot_tests::native_kernel_new_keeps_fresh_ownership_unenrolled")
        .arg("--nocapture")
        .env("ASTRID_HOME", home.path())
        .env("ASTRID_FIRST_OWNER_BOOT_CHILD", "1")
        .output()
        .expect("spawn native boot child");
    assert!(
        output.status.success(),
        "native boot child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
