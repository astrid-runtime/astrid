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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_mount_projects_packed_runtime_tree_without_host_endpoints() {
    let temporary = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(temporary.path().join(".astrid"));
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let store = kernel.principal_store.clone().unwrap();

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

    for sentinel in [
        home.socket_path(),
        home.run_dir().join("system.lock"),
        home.run_dir().join("system.pid"),
        home.run_dir().join("system.ready"),
        home.token_path(),
    ] {
        std::fs::write(sentinel, b"host-only").unwrap();
    }

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

    let root_entries = read_directory_entries(&lease, "").await;
    for name in ["bin", "run", "wit"] {
        assert_entry_kind(&root_entries, name, StorageFilesystemEntryKindV1::Directory);
    }

    let bin_entries = read_directory_entries(&lease, "bin").await;
    assert_entry_kind(
        &bin_entries,
        &format!("{wasm_hash}.wasm"),
        StorageFilesystemEntryKindV1::File,
    );

    let run_entries = read_directory_entries(&lease, "run").await;
    assert_entry_kind(
        &run_entries,
        "capsules",
        StorageFilesystemEntryKindV1::Directory,
    );
    assert!(!run_entries.iter().any(|entry| entry.name == "system.sock"));
    for sentinel in ["system.lock", "system.pid", "system.ready", "system.token"] {
        assert!(!run_entries.iter().any(|entry| entry.name == sentinel));
    }

    let capsule_entries = read_directory_entries(&lease, "run/capsules/example").await;
    assert_entry_kind(
        &capsule_entries,
        "component.wasm",
        StorageFilesystemEntryKindV1::File,
    );

    let wit_entries = read_directory_entries(&lease, "wit").await;
    assert_entry_kind(
        &wit_entries,
        "runtime.wit",
        StorageFilesystemEntryKindV1::File,
    );

    revoke_lease(&kernel, &PrincipalId::default(), true, lease.mount_id)
        .await
        .unwrap();
}
