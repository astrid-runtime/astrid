use std::{collections::HashMap, sync::Arc};

use crate::Kernel;
use astrid_audit::AuditLog;
use astrid_core::dirs::AstridHome;

fn scratch_home() -> (tempfile::TempDir, AstridHome) {
    let dir = tempfile::tempdir().expect("test home root");
    let home = AstridHome::from_path(dir.path());
    (dir, home)
}

fn injected_kernel_resources(home: &AstridHome) -> crate::KernelResources {
    home.ensure().expect("ensure test home");
    let kv: Arc<dyn astrid_storage::KvStore> = Arc::new(astrid_storage::MemoryKvStore::new());
    let runtime_key = Arc::new(astrid_crypto::KeyPair::generate());
    let audit_log = Arc::new(
        AuditLog::open_with_kv_store(Arc::clone(&kv), Arc::clone(&runtime_key))
            .expect("open test audit log"),
    );
    crate::KernelResources::new(
        home.clone(),
        kv,
        audit_log,
        runtime_key,
        Arc::new(astrid_core::session_token::SessionToken::generate()),
        home.token_path(),
        None,
        None,
    )
}

async fn boot_with_injected_resources(
    home: &AstridHome,
    resources: crate::KernelResources,
) -> std::io::Result<Arc<Kernel>> {
    Kernel::with_resources(
        astrid_core::SessionId::SYSTEM,
        home.root().to_path_buf(),
        astrid_capsule_types::CapsuleRuntimeLimits::default(),
        HashMap::new(),
        astrid_capsule_types::HttpLimits::default(),
        resources,
    )
    .await
}

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

#[tokio::test(flavor = "multi_thread")]
async fn production_startup_reclaims_stale_process_storage() {
    let (_dir, home) = scratch_home();
    home.ensure().expect("initialize test home");
    let stale_root = home
        .run_dir()
        .join("process-storage")
        .join("018f0000000000000000000000000000");
    std::fs::create_dir_all(stale_root.join("workspace")).expect("seed stale UUID root");
    std::fs::write(stale_root.join("workspace").join("leftover"), b"stale")
        .expect("seed stale process-storage file");

    let kernel = boot_with_injected_resources(&home, injected_kernel_resources(&home))
        .await
        .expect("production startup after safe reclamation");

    let process_storage = home.run_dir().join("process-storage");
    assert!(process_storage.is_dir());
    assert!(
        process_storage
            .read_dir()
            .expect("process storage root")
            .next()
            .is_none()
    );
    drop(kernel);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_startup_fails_closed_when_process_storage_is_redirected() {
    use std::os::unix::fs::symlink;

    let (dir, home) = scratch_home();
    home.ensure().expect("initialize test home");
    let outside = dir.path().join("outside-process-storage");
    std::fs::create_dir_all(&outside).expect("create redirect target");
    std::fs::write(outside.join("survive"), b"outside").expect("seed redirect-target file");
    let process_storage = home.run_dir().join("process-storage");
    std::fs::create_dir_all(&process_storage).expect("create process-storage root");
    let stale_root = process_storage.join("018f0000000000000000000000000000");
    symlink(&outside, &stale_root).expect("redirect stale UUID root");

    let Err(error) = boot_with_injected_resources(&home, injected_kernel_resources(&home)).await
    else {
        panic!("redirected process storage must fail startup closed");
    };

    assert!(
        error.to_string().contains("reclaim stale process storage"),
        "unexpected startup error: {error}"
    );
    assert!(
        std::fs::symlink_metadata(stale_root)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(outside.join("survive")).unwrap(), b"outside");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_startup_fails_closed_when_process_storage_has_special_entry() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let (_dir, home) = scratch_home();
    home.ensure().expect("initialize test home");
    let stale_root = home
        .run_dir()
        .join("process-storage")
        .join("018f0000000000000000000000000000");
    std::fs::create_dir_all(&stale_root).expect("seed stale UUID root");
    let retained = stale_root.join("retained");
    std::fs::write(&retained, b"must survive").expect("seed retained file");
    let fifo = stale_root.join("unsafe.fifo");
    mkfifo(&fifo, Mode::from_bits_truncate(0o600)).expect("seed special entry");

    let Err(error) = boot_with_injected_resources(&home, injected_kernel_resources(&home)).await
    else {
        panic!("special process-storage entry must fail startup closed");
    };

    assert!(
        error.to_string().contains("reclaim stale process storage"),
        "unexpected startup error: {error}"
    );
    assert_eq!(std::fs::read(retained).unwrap(), b"must survive");
    assert!(fifo.exists());
}
