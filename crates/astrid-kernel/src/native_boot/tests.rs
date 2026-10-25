//! Native composition and actual volume-only restart, without ambient-home mutation.

use super::*;
use astrid_storage::principal_state::RuntimeLifecycleGuard;

const LEGACY: &str =
    "[runtime]\nsystem_prompt = 'legacy packed prompt'\n[audit.retention]\nrequire_anchor = true\n";
const CANONICAL: &str = "[capsule]\nhost_blocking_concurrency = 3\nhost_io_concurrency = 73\ninstance_pool_size = 7\n[http]\ndefault_timeout_secs = 47\n[logging]\nlevel = 'debug'\n[rate_limits]\ncapsule_reload_per_min = 71\n[[identity.links]]\nastrid_user = 'packed-policy-user'\nplatform = 'boot-test'\nplatform_user_id = 'packed-user'\n";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn write(home: &AstridHome, relative: &str, bytes: &str) {
    let path = home.root().join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn packed_home(home: &AstridHome, workspace: &std::path::Path, files: &[(&str, &str)]) {
    let lifecycle = RuntimeLifecycleGuard::acquire(home).unwrap();
    let retirement = {
        let runtime = runtime();
        runtime.block_on(async {
            let admitted = AdmittedNativeBoot::admit(
                home.clone(),
                workspace.to_path_buf(),
                WorkspaceLayout::default(),
            )
            .await
            .unwrap();
            let kernel = admitted
                .start(
                    SessionId::SYSTEM,
                    CapsuleRuntimeLimits::default(),
                    HashMap::new(),
                    HttpLimits::default(),
                )
                .await
                .unwrap();
            socket::write_readiness_file_for_home(home, workspace, &WorkspaceLayout::default())
                .unwrap();
            assert!(home.ready_path().exists());
            for (path, bytes) in files {
                write(home, path, bytes);
            }
            kernel
                .shutdown_for_finalization(Some("packed policy fixture".into()))
                .await
                .unwrap()
                .unwrap()
        })
    };
    lifecycle.finish_with_owner(retirement).unwrap();
    let entries: Vec<_> = std::fs::read_dir(home.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [std::ffi::OsString::from("astrid.volume")]);
}

#[test]
fn volume_only_restart_uses_one_restored_snapshot_for_all_boot_consumers() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    packed_home(
        &home,
        &workspace,
        &[("config.toml", LEGACY), ("etc/config.toml", CANONICAL)],
    );
    // This is the old daemon ordering: a pre-restore load has no user files.
    let before = boot_policy::load(&home, &workspace, &WorkspaceLayout::default()).unwrap();
    assert!(before.config.capsule.host_blocking_concurrency.is_none());
    assert!(!before.config.audit.retention.require_anchor);
    let lifecycle = RuntimeLifecycleGuard::acquire(&home).unwrap();
    let retirement = {
        let runtime = runtime();
        runtime.block_on(async {
            let admitted = AdmittedNativeBoot::admit(
                home.clone(),
                workspace.clone(),
                WorkspaceLayout::default(),
            )
            .await
            .unwrap();
            let config = admitted.config();
            assert_eq!(config.config.runtime.system_prompt, "legacy packed prompt");
            assert_eq!(config.config.logging.level, "debug");
            assert_eq!(config.config.capsule.host_blocking_concurrency, Some(3));
            assert_eq!(config.config.http.default_timeout_secs, 47);
            assert!(config.config.audit.retention.require_anchor);
            assert!(Arc::ptr_eq(&config, &admitted.config()));
            let capsule = &config.config.capsule;
            let limits = CapsuleRuntimeLimits::resolve(
                capsule.host_blocking_concurrency,
                capsule.host_io_concurrency,
                capsule.instance_pool_size,
            );
            let http = &config.config.http;
            let http_limits = HttpLimits::from_config_values(
                http.default_timeout_secs,
                http.stream_connect_timeout_secs,
                http.stream_read_timeout_secs,
                http.header_deadline_secs,
                http.max_redirects,
                http.max_concurrent_streams,
                http.max_response_bytes,
            );
            // An operator edit after capture belongs to the next boot. All
            // consumers below must use the one captured generation together.
            write(
                &home,
                "config.toml",
                "[audit.retention]\nrequire_anchor = false\n",
            );
            write(&home, "etc/config.toml", "# changed after snapshot\n");
            let kernel = admitted
                .start(SessionId::SYSTEM, limits, HashMap::new(), http_limits)
                .await
                .unwrap();
            assert_eq!(kernel.runtime_limits.blocking_concurrency, 3);
            assert_eq!(kernel.runtime_limits.io_concurrency, 73);
            assert_eq!(kernel.runtime_limits.instance_pool_size, 7);
            assert_eq!(
                kernel.http_limits.default_total_timeout,
                std::time::Duration::from_secs(47)
            );
            assert!(kernel.audit_log.require_anchor_before_prune());
            assert_eq!(
                kernel.management_rate_limits.capsule_reload_per_min,
                config.config.rate_limits.capsule_reload_per_min
            );
            assert!(
                kernel
                    .identity_store
                    .get_user_by_name("packed-policy-user")
                    .await
                    .unwrap()
                    .is_some()
            );
            kernel
                .shutdown_for_finalization(Some("snapshot regression".into()))
                .await
                .unwrap()
                .unwrap()
        })
    };
    lifecycle.finish_with_owner(retirement).unwrap();
}

#[test]
fn malformed_packed_policy_fails_before_native_listener_or_readiness() {
    for path in ["config.toml", "etc/config.toml"] {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path().join("home"));
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        packed_home(&home, &workspace, &[(path, "[invalid TOML")]);
        let runtime = runtime();
        let Err(error) = runtime.block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace,
            WorkspaceLayout::default(),
        )) else {
            panic!("malformed packed policy must not produce an admitted stage");
        };
        assert!(error.to_string().contains("load admitted-home boot policy"));
        assert!(error.to_string().contains(path));
        assert!(!home.ready_path().exists());
        assert!(!home.socket_path().exists());
        assert!(!home.pid_path().exists());
        // Invalid configuration must release the singleton on failure.
        let _singleton = socket::acquire_boot_singleton_lock(&home).unwrap();
    }
}

#[test]
fn dropping_admitted_stage_releases_singleton_without_starting_dispatcher() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let runtime = runtime();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace,
            WorkspaceLayout::default(),
        ))
        .unwrap();
    assert!(socket::acquire_boot_singleton_lock(&home).is_err());
    assert!(!home.ready_path().exists());
    drop(admitted);
    let _singleton = socket::acquire_boot_singleton_lock(&home).unwrap();
}

#[test]
fn abandoned_fresh_admission_can_restart_and_complete_initialization() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    for _ in 0..2 {
        let runtime = runtime();
        let admitted = runtime
            .block_on(AdmittedNativeBoot::admit(
                home.clone(),
                workspace.clone(),
                WorkspaceLayout::default(),
            ))
            .unwrap();
        let key = std::fs::read(home.runtime_key_path()).unwrap();
        drop(admitted);
        assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    }
    let key = std::fs::read(home.runtime_key_path()).unwrap();
    packed_home(&home, &workspace, &[]);
    let runtime = runtime();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace,
            WorkspaceLayout::default(),
        ))
        .unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    drop(admitted);
}

#[test]
fn abandoned_admission_before_host_sentinel_can_restart_with_same_identity() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let runtime = runtime();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace.clone(),
            WorkspaceLayout::default(),
        ))
        .unwrap();
    let key = std::fs::read(home.runtime_key_path()).unwrap();
    drop(admitted);
    // The durable bootstrap projection can exist before its first host sentinel
    // has been materialized. The empty directory survives that interruption.
    std::fs::remove_file(home.layout_version_path()).unwrap();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace.clone(),
            WorkspaceLayout::default(),
        ))
        .unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    drop(admitted);
    packed_home(&home, &workspace, &[]);
}

#[test]
fn captured_home_boot_and_cleanup_leave_ambient_home_untouched() {
    let root = tempfile::tempdir().unwrap();
    let ambient = AstridHome::from_path(root.path().join("ambient"));
    for name in ["system.pid", "system.token", "system.ready"] {
        write(&ambient, &format!("run/{name}"), "foreign daemon fixture");
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_boot::tests::captured_home_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ASTRID_HOME", ambient.root())
        .env_remove("ASTRID_RUN_DIR")
        .env("ASTRID_TEST_CAPTURED_BOOT_ROOT", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "captured-home child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("captured-home child completed"));
    for name in ["system.pid", "system.token", "system.ready"] {
        assert_eq!(
            std::fs::read_to_string(ambient.run_dir().join(name)).unwrap(),
            "foreign daemon fixture",
            "captured-home lifecycle changed ambient {name}"
        );
    }
}

#[test]
fn captured_home_child() {
    let Some(root) = std::env::var_os("ASTRID_TEST_CAPTURED_BOOT_ROOT") else {
        return;
    };
    // The parent owns both homes. Process-local environment selection prevents
    // parallel tests from redirecting a real daemon's endpoints or cleanup.
    let root = PathBuf::from(root);
    let home = AstridHome::from_path(root.join("captured"));
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    packed_home(&home, &workspace, &[]);
    println!("captured-home child completed");
}

#[test]
fn completed_fresh_home_missing_host_ledger_cannot_restart_as_bootstrap() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    packed_home(&home, &workspace, &[]);
    {
        let runtime = runtime();
        let admitted = runtime
            .block_on(AdmittedNativeBoot::admit(
                home.clone(),
                workspace.clone(),
                WorkspaceLayout::default(),
            ))
            .unwrap();
        drop(admitted);
    }
    std::fs::remove_file(legacy_migration_barrier::ledger_path(&home)).unwrap();
    let key = std::fs::read(home.runtime_key_path()).unwrap();
    let runtime = runtime();
    let result = runtime.block_on(AdmittedNativeBoot::admit(
        home.clone(),
        workspace,
        WorkspaceLayout::default(),
    ));
    assert!(
        result.is_err(),
        "completed volume cannot use bootstrap retry"
    );
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    assert!(!legacy_migration_barrier::ledger_path(&home).exists());
}

#[test]
fn malformed_fresh_retry_ledger_remains_a_hard_error() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let runtime = runtime();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace.clone(),
            WorkspaceLayout::default(),
        ))
        .unwrap();
    drop(admitted);
    let ledger = legacy_migration_barrier::ledger_path(&home);
    std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    std::fs::write(&ledger, b"invalid ledger").unwrap();
    assert!(
        runtime
            .block_on(AdmittedNativeBoot::admit(
                home,
                workspace,
                WorkspaceLayout::default(),
            ))
            .is_err()
    );
    assert_eq!(std::fs::read(ledger).unwrap(), b"invalid ledger");
}

#[test]
fn abandoned_admission_with_boot_log_retries_without_importing_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let runtime = runtime();
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace.clone(),
            WorkspaceLayout::default(),
        ))
        .unwrap();
    let key = std::fs::read(home.runtime_key_path()).unwrap();
    // The daemon starts file logging after admission, before start() publishes
    // its component ledger. Reproduce an interruption in that exact window.
    write(&home, "log/boot.log", "startup diagnostics");
    drop(admitted);
    let admitted = runtime
        .block_on(AdmittedNativeBoot::admit(
            home.clone(),
            workspace,
            WorkspaceLayout::default(),
        ))
        .unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), key);
    assert_eq!(
        std::fs::read(home.root().join("log/boot.log")).unwrap(),
        b"startup diagnostics"
    );
    assert!(!crate::legacy_migration_barrier::ledger_path(&home).exists());
    let name = astrid_storage::ContentName::new("log/boot.log").unwrap();
    assert!(
        admitted
            .native
            .principal_store
            .content()
            .describe(&astrid_storage::StateOwner::System, &name)
            .unwrap()
            .is_none()
    );
    drop(admitted);
}
