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

fn singleton_owned_kernel_resources(home: &AstridHome) -> crate::KernelResources {
    let mut resources = injected_kernel_resources(home);
    resources.singleton_lock = Some(
        crate::socket::acquire_boot_singleton_lock(home)
            .expect("acquire test singleton boot ownership"),
    );
    resources.with_native_process_storage_ownership()
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

    let kernel = boot_with_injected_resources(&home, singleton_owned_kernel_resources(&home))
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

    let Err(error) =
        boot_with_injected_resources(&home, singleton_owned_kernel_resources(&home)).await
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

    let Err(error) =
        boot_with_injected_resources(&home, singleton_owned_kernel_resources(&home)).await
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

#[tokio::test(flavor = "multi_thread")]
async fn lockless_injected_kernel_preserves_live_process_storage() {
    let (_dir, home) = scratch_home();
    let first = boot_with_injected_resources(&home, injected_kernel_resources(&home))
        .await
        .expect("boot first lockless injected kernel");

    let process_storage = home.run_dir().join("process-storage");
    let live_root = process_storage.join("first-live-uuid-root");
    std::fs::create_dir_all(live_root.join("workspace")).expect("create live process root");
    std::fs::write(live_root.join("workspace").join("live"), b"live authority")
        .expect("seed live process root");

    let second = boot_with_injected_resources(&home, injected_kernel_resources(&home))
        .await
        .expect("boot second lockless injected kernel");
    assert!(
        process_storage.is_dir(),
        "lockless boot must not remove the shared run/process-storage root"
    );
    assert_eq!(
        std::fs::read(live_root.join("workspace").join("live")).unwrap(),
        b"live authority",
        "a lockless boot must not delete the first live kernel's UUID root"
    );

    drop(second);
    assert!(
        live_root.exists(),
        "second boot completion must remain non-destructive"
    );
    drop(first);
}

#[tokio::test(flavor = "multi_thread")]
async fn arbitrary_injected_file_preserves_live_process_storage() {
    let (dir, home) = scratch_home();
    let mut resources = injected_kernel_resources(&home);
    let unrelated = dir.path().join("unrelated.lock");
    resources.singleton_lock = Some(std::fs::File::create(&unrelated).expect("unrelated file"));

    let process_storage = home.run_dir().join("process-storage");
    let live_root = process_storage.join("fake-file-live-root");
    std::fs::create_dir_all(live_root.join("workspace")).expect("create live root");
    std::fs::write(live_root.join("workspace").join("live"), b"live")
        .expect("seed live process root");

    let kernel = boot_with_injected_resources(&home, resources)
        .await
        .expect("boot injected kernel with unrelated singleton resource");
    assert_eq!(
        std::fs::read(live_root.join("workspace").join("live")).unwrap(),
        b"live",
        "an arbitrary Some(File) must not authorize process-storage cleanup"
    );
    drop(kernel);
}
