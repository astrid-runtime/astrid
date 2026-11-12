use super::*;

#[cfg(unix)]
#[tokio::test]
async fn surviving_redirect_fails_closed_before_restore() {
    use std::os::unix::fs::symlink;

    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack volume-only stop state");
    drop(packer);

    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), home.root().join("redirect")).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("redirected surviving tree must fail before projection restore");
    };
    assert!(error.to_string().contains("symbolic link"), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn unadmitted_special_entry_fails_closed_before_restore() {
    use std::os::unix::net::UnixListener;

    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack volume-only stop state");
    drop(packer);

    let _socket = UnixListener::bind(home.root().join("ordinary.sock")).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("unadmitted special entry must fail before projection restore");
    };
    assert!(
        error.to_string().contains("unadmitted special entry"),
        "{error}"
    );
}

#[tokio::test]
async fn active_receipt_missing_object_identity_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let config_path = home.root().join("etc/identity.conf");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, b"identity").unwrap();
    let config_name = ContentName::new("etc/identity.conf").unwrap();
    running
        .content()
        .put(&StateOwner::System, &config_name, b"identity")
        .unwrap();
    write_active_identity_receipt(&home, &running, &config_name, None);
    drop(running);

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("ACTIVE receipt without an object identity must fail closed");
    };
    assert!(
        error.to_string().contains("missing field `file`"),
        "{error}"
    );
}

#[tokio::test]
async fn active_receipt_wrong_object_identity_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let config_path = home.root().join("etc/identity.conf");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, b"identity").unwrap();
    let config_name = ContentName::new("etc/identity.conf").unwrap();
    running
        .content()
        .put(&StateOwner::System, &config_name, b"identity")
        .unwrap();
    write_active_identity_receipt(&home, &running, &config_name, Some(&"00".repeat(32)));
    drop(running);

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("ACTIVE receipt with a wrong object identity must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("active receipt does not match durable projection"),
        "{error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn special_inside_run_capsules_fails_closed_before_restore() {
    use std::os::unix::net::UnixListener;

    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack volume-only stop state");
    drop(packer);

    let socket_path = home.root().join("run/capsules/example.sock");
    std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
    let _socket = UnixListener::bind(&socket_path).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("special inside admitted durable namespace must fail before projection restore");
    };
    assert!(
        error.to_string().contains("unadmitted special entry"),
        "{error}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stop_preflight_retains_regular_file_when_special_comes_later() {
    use std::os::unix::net::UnixListener;

    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let regular = home.root().join("regular");
    std::fs::write(&regular, b"must survive failed retirement").unwrap();
    let socket_path = home.root().join("run/other.sock");
    std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
    let _socket = UnixListener::bind(&socket_path).unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("root special must stop complete-root retirement");
    };
    assert!(error.to_string().contains("special entry"), "{error}");
    assert_eq!(
        std::fs::read(&regular).unwrap(),
        b"must survive failed retirement"
    );
    assert!(socket_path.symlink_metadata().is_ok());
}

#[test]
fn projection_restore_paths_stay_inside_runtime_root() {
    let root = tempfile::tempdir().unwrap();
    let sentinel = root.path().parent().unwrap().join(format!(
        "astrid-1833-outside-{}",
        root.path().file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&sentinel, b"keep-me").unwrap();
    let absolute = sentinel.to_str().expect("utf-8 sentinel path");
    for name in [absolute, "/tmp/x", "../x", r"..\x", "foo/../../x"] {
        let error = confined_projection_path(root.path(), name).expect_err(name);
        let message = error.to_string();
        assert!(
            message.contains("escaped runtime root")
                || message.contains("non-normal path component"),
            "{name}: {message}"
        );
        assert!(
            !root.path().join("x").exists(),
            "{name} wrote inside the root"
        );
    }
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep-me");
    let ok = confined_projection_path(root.path(), "etc/authz.conf").unwrap();
    assert!(ok.starts_with(root.path()));
    let _ = std::fs::remove_file(&sentinel);
}

#[tokio::test]
async fn restore_rejects_absolute_and_traversal_catalog_names() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let sentinel = home_dir.path().parent().unwrap().join(format!(
        "astrid-1833-restore-{}",
        home_dir.path().file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&sentinel, b"keep-me").unwrap();
    let absolute = sentinel.to_str().expect("utf-8 sentinel path").to_owned();
    for name in [
        absolute,
        "/tmp/x".to_owned(),
        "../x".to_owned(),
        r"..\x".to_owned(),
    ] {
        let content_name = ContentName::new(name.clone()).unwrap();
        store
            .content()
            .put(&StateOwner::System, &content_name, b"escaped")
            .unwrap();
        store.content().flush().unwrap();
        let error = restore_projection(&home, &store, store.content().as_ref())
            .expect_err("escaped catalog name must not restore");
        let message = error.to_string();
        assert!(
            message.contains("escaped runtime root")
                || message.contains("non-normal path component"),
            "{name}: {message}"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep-me");
        assert!(!home.root().join("x").exists());
        assert!(
            store
                .content()
                .delete(&StateOwner::System, &content_name)
                .unwrap()
        );
        store.content().flush().unwrap();
    }
    let _ = std::fs::remove_file(&sentinel);
}

#[cfg(unix)]
#[test]
fn rebind_staging_generation_rejects_symlink_without_touching_target() {
    let home_dir = tempfile::tempdir().unwrap();
    let generations = home_dir.path().join("var/content-staging/generations");
    std::fs::create_dir_all(&generations).unwrap();
    let external_dir = tempfile::tempdir().unwrap();
    let external = external_dir.path().join("crafted.sealed");
    let crafted = vec![0xa5_u8; 96];
    std::fs::write(&external, &crafted).unwrap();
    let projected = generations.join("x.sealed");
    std::os::unix::fs::symlink(&external, &projected).unwrap();

    let error = crate::principal_state::rebind_staging_generation(&projected)
        .expect_err("redirected staged generation must be rejected");
    assert!(
        error.to_string().contains("redirected") || error.to_string().contains("symbolic link"),
        "{error}"
    );
    assert_eq!(std::fs::read(&external).unwrap(), crafted);
}

#[tokio::test]
async fn retiring_stop_retains_unreceipted_host_file() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let receipted = home.root().join("etc/receipted.conf");
    std::fs::create_dir_all(receipted.parent().unwrap()).unwrap();
    std::fs::write(&receipted, b"receipted\n").unwrap();
    running
        .publish_runtime_projection(&home)
        .expect("publish receipted projection");
    let entries = active_projection_entries(&home, &running).unwrap();
    let retiring = receipt_ingest(&home, ReceiptPhase::Retiring, &entries, None).unwrap();
    running
        .replace_contiguous_files_removing_exact(StateOwner::System, [retiring], &[], None)
        .unwrap();
    running.content().flush().unwrap();
    let extra = home.root().join("etc/unreceipted.conf");
    std::fs::write(&extra, b"do-not-delete\n").unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("RETIRING stop must not delete unreceipted host files");
    };
    assert!(
        error.to_string().contains("unreceipted host file"),
        "{error}"
    );
    assert_eq!(std::fs::read(&extra).unwrap(), b"do-not-delete\n");
}

#[tokio::test]
async fn failed_restore_keeps_later_volume_entries_and_never_adopts_partial_host_tree() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let malformed = ContentName::new("var/content-staging/generations/x.sealed").unwrap();
    let later = ContentName::new("var/content-staging/generations/z.sealed").unwrap();
    packer
        .content()
        .put(&StateOwner::System, &malformed, &[0xa5_u8; 80])
        .unwrap();
    packer
        .content()
        .put(&StateOwner::System, &later, b"later-generation")
        .unwrap();
    packer.content().flush().unwrap();
    packer.establish_runtime_projection_receipt(&home).unwrap();
    drop(packer);
    astrid_core::dirs::retire_projection_root(home.root()).unwrap();

    let Err(first) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("malformed earlier generation must fail restore");
    };
    assert!(first.to_string().contains("staged footer"), "{first}");
    assert!(
        !home
            .root()
            .join("var/content-staging/generations/x.sealed")
            .exists(),
        "failed restore rolled back its partial host file"
    );
    assert!(
        !home
            .root()
            .join("var/content-staging/generations/z.sealed")
            .exists()
    );

    let Err(second) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("retry must restore, not adopt partial host state");
    };
    assert!(second.to_string().contains("staged footer"), "{second}");
    assert!(
        !home
            .root()
            .join("var/content-staging/generations/z.sealed")
            .exists()
    );

    let inspector = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        inspector
            .content()
            .read(&StateOwner::System, &later)
            .unwrap(),
        Some(b"later-generation".to_vec())
    );
}

#[tokio::test]
async fn pack_open_staging_journal_without_receipt_retires_to_volume() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);
    assert_stopped_volume_only(&home);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    std::fs::write(&intent, b"pack-open journal").unwrap();
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("enumerated staging journal is not a receipt-less projection");
    drop(packer);
    assert_stopped_volume_only(&home);
}

#[tokio::test]
async fn non_journal_bootstrap_file_without_receipt_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let layout = home.root().join("etc/layout-version");
    std::fs::create_dir_all(layout.parent().unwrap()).unwrap();
    std::fs::write(&layout, b"2\n").unwrap();
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("non-journal bootstrap file must not be admitted without ACTIVE");
    };
    assert!(
        error
            .to_string()
            .contains("active projection receipt is missing"),
        "{error}"
    );
    assert_eq!(std::fs::read(&layout).unwrap(), b"2\n");
}

#[tokio::test]
async fn pack_open_staging_journal_sibling_file_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    let sibling = home.root().join("var/content-staging/sibling.log");
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    std::fs::write(&intent, b"pack-open journal").unwrap();
    std::fs::write(&sibling, b"do-not-admit").unwrap();
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("journal sibling must not be admitted without ACTIVE");
    };
    assert!(
        error
            .to_string()
            .contains("active projection receipt is missing"),
        "{error}"
    );
    assert!(
        intent.is_file(),
        "pack-open must not delete the enumerated journal before failing closed"
    );
    assert_eq!(std::fs::read(&sibling).unwrap(), b"do-not-admit");
}

#[cfg(unix)]
#[tokio::test]
async fn pack_open_staging_journal_sibling_symlink_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    let sibling = home.root().join("var/content-staging/link");
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    std::fs::write(&intent, b"pack-open journal").unwrap();
    std::os::unix::fs::symlink(&intent, &sibling).unwrap();
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("journal sibling symlink must not be admitted without ACTIVE");
    };
    let message = error.to_string();
    assert!(
        message.contains("symbolic link")
            || message.contains("active projection receipt is missing"),
        "{message}"
    );
    assert!(
        intent.is_file(),
        "pack-open must not delete the enumerated journal before failing closed"
    );
    assert!(sibling.symlink_metadata().unwrap().file_type().is_symlink());
}

#[cfg(unix)]
#[tokio::test]
async fn pack_open_staging_journal_symlink_sentinel_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    let target = home.root().join("astrid.volume");
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &intent).unwrap();
    let Err(error) = open_runtime_principal_store_for_pack(&home, unlimited_quota()).await else {
        panic!("symlink staging journal must not open for pack");
    };
    let message = error.to_string();
    assert!(
        message.contains("not a regular file") || message.contains("redirected"),
        "{message}"
    );
    assert!(intent.symlink_metadata().unwrap().file_type().is_symlink());
}

#[tokio::test]
async fn pack_open_staging_journal_directory_sentinel_fails_closed() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    std::fs::create_dir_all(&intent).unwrap();
    let Err(error) = open_runtime_principal_store_for_pack(&home, unlimited_quota()).await else {
        panic!("directory staging journal must not open for pack");
    };
    let message = error.to_string();
    assert!(
        message.contains("not a regular file") || message.contains("redirected"),
        "{message}"
    );
    assert!(intent.is_dir());
}

#[cfg(unix)]
#[tokio::test]
async fn pack_open_staging_journal_socket_sentinel_fails_closed() {
    use std::os::unix::fs::FileTypeExt as _;
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(running);
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack initial volume-only stop");
    drop(packer);

    let intent = home.root().join(STAGING_JOURNAL_PROJECTION);
    std::fs::create_dir_all(intent.parent().unwrap()).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(&intent).unwrap();
    let Err(error) = open_runtime_principal_store_for_pack(&home, unlimited_quota()).await else {
        panic!("socket staging journal must not open for pack");
    };
    let message = error.to_string();
    assert!(
        message.contains("not a regular file") || message.contains("redirected"),
        "{message}"
    );
    assert!(intent.symlink_metadata().unwrap().file_type().is_socket());
}

async fn assert_existing_volume_bootstrap_fails_closed(relative: &str, host_bytes: &[u8]) {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let active_name = ContentName::new(ACTIVE_PROJECTION_NAME).unwrap();
    assert!(
        running
            .content()
            .delete(&StateOwner::System, &active_name)
            .unwrap()
    );
    running.content().flush().unwrap();
    drop(running);
    std::fs::remove_dir_all(home.content_staging_path()).unwrap();

    let path = home.root().join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, host_bytes).unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("receipt-less bootstrap on an existing volume must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("active projection receipt is missing"),
        "{error}"
    );

    let inspector = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    assert!(
        inspector
            .content()
            .describe(&StateOwner::System, &active_name)
            .unwrap()
            .is_none(),
        "failed reopen must not mint ACTIVE"
    );
    let name = ContentName::new(relative).unwrap();
    assert_ne!(
        inspector
            .content()
            .read(&StateOwner::System, &name)
            .unwrap(),
        Some(host_bytes.to_vec()),
        "host bootstrap bytes acquired volume authority"
    );
}

#[tokio::test]
async fn existing_volume_receiptless_bootstrap_sentinels_fail_closed() {
    assert_existing_volume_bootstrap_fails_closed("etc/layout-version", b"rogue-layout").await;
    assert_existing_volume_bootstrap_fails_closed("keys/runtime.key", b"rogue-runtime-key").await;
}

#[tokio::test]
async fn first_open_allows_bootstrap_sentinels_before_volume_exists() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    home.ensure().unwrap();
    let layout = home.layout_version_path();
    let key = home.runtime_key_path();
    std::fs::create_dir_all(layout.parent().unwrap()).unwrap();
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(&layout, b"2").unwrap();
    std::fs::write(&key, b"first-runtime-key").unwrap();
    assert!(!home.storage_volume_path().exists());

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let layout_name = ContentName::new("etc/layout-version").unwrap();
    let key_name = ContentName::new(RUNTIME_KEY_PROJECTION).unwrap();
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &layout_name)
            .unwrap(),
        Some(b"2".to_vec())
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &key_name)
            .unwrap(),
        Some(b"first-runtime-key".to_vec())
    );
}

#[tokio::test]
async fn restore_rebinds_staging_journal_before_new_seal() {
    let home_dir = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let first_owner = test_owner("restore-journal");
    let first_name = ContentName::new("workspace/restore-first.txt").unwrap();
    let second_name = ContentName::new("workspace/restore-second.txt").unwrap();
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let mut writer = running
        .staging()
        .begin(first_owner, first_name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"first pending record").unwrap();
    writer.seal().unwrap();
    let journal = home.root().join(STAGING_JOURNAL_PROJECTION);
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack staged journal into the volume");
    drop(packer);
    assert!(!journal.exists());

    let restored = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let ready = restored.staging().ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].name(), &first_name);
    let mut writer = restored
        .staging()
        .begin(first_owner, second_name.clone(), ChunkingProfile::ASTRID_V1)
        .unwrap();
    writer.write_all(b"second pending record").unwrap();
    writer.seal().unwrap();
    let ready = restored.staging().ready().unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!(ready[0].name(), &first_name);
    assert_eq!(ready[1].name(), &second_name);
    drop(restored);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let ready = reopened.staging().ready().unwrap();
    assert_eq!(
        ready
            .iter()
            .map(ReadyStagedContent::name)
            .collect::<Vec<_>>(),
        vec![&first_name, &second_name]
    );
}
