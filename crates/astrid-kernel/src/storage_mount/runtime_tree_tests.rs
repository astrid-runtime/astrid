use super::*;

async fn read_directory_entries(
    lease: &StorageMountLeaseV1,
    path: &str,
) -> Vec<StorageFilesystemEntryV1> {
    let outcome = callback(
        lease,
        &lease.lease_token,
        StorageFilesystemOperationV1::ReadDirectory {
            path: path.to_owned(),
        },
    )
    .await;
    let StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Entries(entries)) = outcome
    else {
        panic!("expected directory listing for {path}");
    };
    entries
}

fn assert_entry_kind(
    entries: &[StorageFilesystemEntryV1],
    name: &str,
    kind: StorageFilesystemEntryKindV1,
) {
    assert!(
        entries
            .iter()
            .any(|entry| entry.name == name && entry.kind == kind)
    );
}

fn seed_packed_runtime_tree(home: &astrid_core::dirs::AstridHome) -> String {
    let wasm = b"\0asm\x01\0\0\0runtime-mount-test";
    let wasm_hash = blake3::hash(wasm).to_hex().to_string();
    std::fs::write(home.bin_dir().join(format!("{wasm_hash}.wasm")), wasm).unwrap();
    std::fs::create_dir_all(home.run_dir().join("capsules/example")).unwrap();
    std::fs::write(
        home.run_dir().join("capsules/example/component.wasm"),
        b"run-capsule",
    )
    .unwrap();
    std::fs::write(
        home.wit_dir().join("runtime.wit"),
        b"package astrid:runtime;",
    )
    .unwrap();
    std::fs::write(
        home.etc_dir().join("config.toml"),
        b"[runtime]\nmode = \"test\"\n",
    )
    .unwrap();
    std::fs::write(home.layout_version_path(), b"2").unwrap();
    std::fs::create_dir_all(home.home_dir().join("default")).unwrap();
    std::fs::write(
        home.home_dir().join("default/profile.json"),
        b"{\"durable\":true}",
    )
    .unwrap();
    std::fs::write(home.log_dir().join("runtime.log"), b"runtime log").unwrap();
    std::fs::write(home.keys_dir().join("operator.pub"), b"operator public key").unwrap();
    std::fs::write(home.runtime_key_path(), b"host-only").unwrap();
    std::fs::write(home.var_dir().join("config.json"), b"{\"durable\":true}").unwrap();
    std::fs::write(home.bin_dir().join("astrid"), b"bootstrap").unwrap();
    std::fs::write(home.bin_dir().join("astrid-daemon"), b"bootstrap-daemon").unwrap();
    std::fs::write(home.root().join("astrid"), b"host-only").unwrap();
    std::fs::write(home.root().join("astrid-daemon"), b"host-only").unwrap();

    for (relative, contents) in [
        ("var/migrations/marker", b"migration".as_slice()),
        ("var/content-staging/payload", b"staged".as_slice()),
        ("var/principal-store/legacy", b"legacy".as_slice()),
    ] {
        let path = home.root().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    for sentinel in [
        home.socket_path(),
        home.run_dir().join("system.lock"),
        home.run_dir().join("system.pid"),
        home.run_dir().join("system.ready"),
        home.token_path(),
    ] {
        std::fs::write(sentinel, b"host-only").unwrap();
    }

    wasm_hash
}

async fn assert_root_entries(lease: &StorageMountLeaseV1) {
    let root_entries = read_directory_entries(lease, "").await;
    for name in ["bin", "etc", "home", "keys", "log", "run", "var", "wit"] {
        assert_entry_kind(&root_entries, name, StorageFilesystemEntryKindV1::Directory);
    }
    for name in ["astrid", "astrid-daemon"] {
        assert_entry_kind(&root_entries, name, StorageFilesystemEntryKindV1::File);
    }
    assert!(!root_entries.iter().any(|entry| entry.name == "volume"));
}

async fn assert_packed_files(lease: &StorageMountLeaseV1, wasm_hash: &str) {
    let bin_entries = read_directory_entries(lease, "bin").await;
    assert_entry_kind(
        &bin_entries,
        &format!("{wasm_hash}.wasm"),
        StorageFilesystemEntryKindV1::File,
    );
    for name in ["astrid", "astrid-daemon"] {
        assert_entry_kind(&bin_entries, name, StorageFilesystemEntryKindV1::File);
    }

    let run_entries = read_directory_entries(lease, "run").await;
    assert_entry_kind(
        &run_entries,
        "capsules",
        StorageFilesystemEntryKindV1::Directory,
    );
    let example_capsule_files = read_directory_entries(lease, "run/capsules/example").await;
    assert_entry_kind(
        &example_capsule_files,
        "component.wasm",
        StorageFilesystemEntryKindV1::File,
    );
    let capsules_dir_entries = read_directory_entries(lease, "run/capsules").await;
    assert_entry_kind(
        &capsules_dir_entries,
        "example",
        StorageFilesystemEntryKindV1::Directory,
    );

    let wit_entries = read_directory_entries(lease, "wit").await;
    assert_entry_kind(
        &wit_entries,
        "runtime.wit",
        StorageFilesystemEntryKindV1::File,
    );

    let etc_entries = read_directory_entries(lease, "etc").await;
    assert_entry_kind(
        &etc_entries,
        "config.toml",
        StorageFilesystemEntryKindV1::File,
    );

    let home_root_entries = read_directory_entries(lease, "home").await;
    assert_entry_kind(
        &home_root_entries,
        "default",
        StorageFilesystemEntryKindV1::Directory,
    );
    let home_entries = read_directory_entries(lease, "home/default").await;
    assert_entry_kind(
        &home_entries,
        "profile.json",
        StorageFilesystemEntryKindV1::File,
    );

    let log_entries = read_directory_entries(lease, "log").await;
    assert_entry_kind(
        &log_entries,
        "runtime.log",
        StorageFilesystemEntryKindV1::File,
    );

    let keys_entries = read_directory_entries(lease, "keys").await;
    assert_entry_kind(
        &keys_entries,
        "operator.pub",
        StorageFilesystemEntryKindV1::File,
    );

    let var_entries = read_directory_entries(lease, "var").await;
    assert_entry_kind(
        &var_entries,
        "config.json",
        StorageFilesystemEntryKindV1::File,
    );
}

async fn assert_volume_and_socket_absent(lease: &StorageMountLeaseV1) {
    let run_entries = read_directory_entries(lease, "run").await;
    assert!(!run_entries.iter().any(|entry| entry.name == "system.sock"));
    for sentinel in ["system.lock", "system.pid", "system.ready", "system.token"] {
        assert_entry_kind(&run_entries, sentinel, StorageFilesystemEntryKindV1::File);
    }

    let etc_entries = read_directory_entries(lease, "etc").await;
    assert_entry_kind(
        &etc_entries,
        "layout-version",
        StorageFilesystemEntryKindV1::File,
    );

    let keys_entries = read_directory_entries(lease, "keys").await;
    assert_entry_kind(
        &keys_entries,
        "runtime.key",
        StorageFilesystemEntryKindV1::File,
    );

    let var_entries = read_directory_entries(lease, "var").await;
    for name in [
        "config.json",
        "content-staging",
        "migrations",
        "principal-store",
    ] {
        let kind = if name == "config.json" {
            StorageFilesystemEntryKindV1::File
        } else {
            StorageFilesystemEntryKindV1::Directory
        };
        assert_entry_kind(&var_entries, name, kind);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_mount_projects_packed_runtime_tree_with_only_volume_and_socket_leftovers() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let store = kernel.principal_store.clone().unwrap();

    let wasm_hash = seed_packed_runtime_tree(&home);

    store.admit_runtime_tree(home.root()).unwrap();

    let lease = issue_lease(
        &kernel,
        PrincipalId::default(),
        true,
        StorageProviderViewV1::Admin,
        astrid_core::storage_filesystem::StorageFilesystemTargetV1::OwnerRoot,
        StorageProviderAccessV1::ReadOnly,
        "runtime-tree-mount-test".to_owned(),
        temporary.path().join("mount"),
    )
    .await
    .unwrap();

    assert_root_entries(&lease).await;
    assert_packed_files(&lease, &wasm_hash).await;
    assert_volume_and_socket_absent(&lease).await;

    revoke_lease(&kernel, &PrincipalId::default(), true, lease.mount_id)
        .await
        .unwrap();
}
