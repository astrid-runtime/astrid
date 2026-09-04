use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use super::*;
use crate::principal_state::open_runtime_principal_store_for_pack;
use crate::volume::{AstridVolume as _, HostedFileVolume};
use crate::{AstridFilesystem, FilesystemPath, KvQuotaResolver, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

#[test]
fn excludes_windows_separator_paths() {
    for path in ["volume", "volume\\compacting", "run\\system.sock"] {
        let normalized = normalize_relative_path(path);
        assert!(is_excluded(&normalized), "path was not excluded: {path}");
    }
    assert_eq!(
        normalize_relative_path("run\\system.ready"),
        "run/system.ready"
    );
}

#[test]
fn excludes_paths_only_at_exact_or_directory_boundaries() {
    for path in [
        "volume",
        "volume/compacting",
        "volume2",
        "volumetric.txt",
        "volume.previous",
        "var/principal-store",
        "var/principal-store/agent.json",
        "var/principal-store2",
        "var/principal-store2/agent.json",
        "run/capsulesX",
        "run/capsulesX/example/component.wasm",
        "run/capsules/example/component.wasm",
    ] {
        let normalized = normalize_relative_path(path);
        let excluded = is_excluded(&normalized);
        let expected = !matches!(
            path,
            "volume2"
                | "volumetric.txt"
                | "volume.previous"
                | "var/principal-store2"
                | "var/principal-store2/agent.json"
                | "run/capsules/example/component.wasm"
        );
        assert_eq!(excluded, expected, "unexpected admission for {path}");
    }
    assert!(!is_excluded("run/capsules"));
}

#[test]
fn excludes_only_named_transaction_paths() {
    for path in [
        MIGRATING_VOLUME,
        "etc/.layout-version.next",
        "var/migrations/.layout-v1-to-v2.intent.next",
        "var/migrations/.layout-v1-to-v2.retiring.next",
        "var/migrations/.layout-v1-to-v2.complete.next",
    ] {
        assert!(is_excluded(path), "transaction path was admitted: {path}");
    }

    for path in [
        "etc/user.next",
        "etc/user.migrating",
        "var/user.next",
        "var/user.migrating",
        "astrid.migrating.previous",
        "etc/.layout-version.next.old",
    ] {
        assert!(!is_excluded(path), "ordinary path was excluded: {path}");
    }
}

#[test]
fn allows_run_capsule_projections() {
    let normalized = normalize_relative_path("run/capsules/example/component.wasm");
    assert!(!is_excluded(&normalized));
    assert!(!is_excluded("run"));
    assert!(!is_excluded("run/capsules"));

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("run/capsules/example/component.wasm");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"run-capsule").unwrap();
    let entries = scan(directory.path()).unwrap();
    assert_eq!(entries.len(), 1, "scan entries: {entries:?}");
    assert_eq!(
        entries[0].name().as_str(),
        "run/capsules/example/component.wasm"
    );
}

fn durable_files(wasm_hash: &str, wasm: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        (format!("bin/{wasm_hash}.wasm"), wasm.to_vec()),
        (
            "wit/astrid-contracts.wit".to_owned(),
            b"package astrid:contracts;".to_vec(),
        ),
        ("etc/layout-version".to_owned(), b"2".to_vec()),
        ("keys/runtime.key".to_owned(), b"runtime-key".to_vec()),
        ("var/content-staging/payload".to_owned(), b"staged".to_vec()),
        ("var/config.json".to_owned(), b"{\"durable\":true}".to_vec()),
        ("var/migrations/marker".to_owned(), b"migration".to_vec()),
    ]
}

#[tokio::test]
async fn admits_runtime_tree_and_reopens_from_preclose_volume_copy() {
    let source = tempfile::tempdir().unwrap();
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    home.ensure().unwrap();
    let wasm = b"\0asm\x01\0\0\0runtime-wasm-unique".to_vec();
    let wasm_hash = blake3::hash(&wasm).to_hex().to_string();
    let durable = durable_files(&wasm_hash, &wasm);
    for (relative, bytes) in &durable {
        let path = source.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    for relative in [
        "volume",
        "volume.compacting",
        "volume.previous",
        "run/system.sock",
    ] {
        let path = source.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"host-only").unwrap();
    }

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    store.admit_runtime_tree(source.path()).unwrap();

    let names = store
        .content()
        .list(&StateOwner::System)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name().as_str().to_owned())
        .collect::<Vec<_>>();
    let mut expected_names = durable
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    expected_names.push("var/content-staging/intents.v1.log".to_owned());
    expected_names.extend(["volume.compacting", "volume.previous"].map(str::to_owned));
    expected_names.sort();
    assert_eq!(names, expected_names);

    let copied_home_dir = tempfile::tempdir().unwrap();
    let copied_home = AstridHome::from_path(copied_home_dir.path());
    copied_home.ensure().unwrap();
    std::fs::copy(
        home.storage_volume_path(),
        copied_home.storage_volume_path(),
    )
    .unwrap();
    let volume = HostedFileVolume::open(copied_home.storage_volume_path()).unwrap();
    assert!(
        volume
            .list_regions("representations/blobs/loose")
            .unwrap()
            .is_empty()
    );
    drop(volume);

    let reopened = open_runtime_principal_store(&copied_home, unlimited_quota())
        .await
        .unwrap();
    let filesystem = AstridFilesystem::new(reopened.content(), StateOwner::System);
    let expected_count = durable.len();
    let mut reconstructed = BTreeMap::new();
    for (name, bytes) in durable {
        let path = FilesystemPath::new(name).unwrap();
        let entry = filesystem.stat(&path).unwrap();
        let actual = filesystem.read(&path, 0, entry.logical_bytes()).unwrap();
        let expected_digest = Sha256::digest(&bytes);
        assert_eq!(Sha256::digest(&actual), expected_digest);
        reconstructed.insert(path.as_str().to_owned(), actual);
    }
    assert_eq!(reconstructed.len(), expected_count);
}

#[cfg(unix)]
#[test]
fn rejects_redirects_before_publication() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("redirect")).unwrap();
    let error = scan(root.path()).unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
}

#[cfg(unix)]
#[test]
fn skips_special_entries_without_failing_scan() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("run")).unwrap();
    std::fs::write(root.path().join("regular"), b"durable").unwrap();
    let _socket = UnixListener::bind(root.path().join("run/other.sock")).unwrap();

    let entries = scan(root.path()).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["regular"]
    );
}

#[tokio::test]
async fn preserves_runtime_key_across_initialization_and_restart() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let key_path = home.runtime_key_path();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    std::fs::write(&key_path, b"original-runtime-key").unwrap();

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&key_path).unwrap(), b"original-runtime-key");
    let runtime_key = ContentName::new(RUNTIME_KEY_PROJECTION).unwrap();
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &runtime_key)
            .unwrap()
            .is_some()
    );
    drop(store);

    let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .pack_and_retire_runtime_projection(&home)
        .expect("pack runtime key");
    drop(store);
    assert!(!key_path.exists());
    assert!(!home.keys_dir().exists());
    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1);
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new(CANONICAL_VOLUME)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            stopped[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&key_path).unwrap(), b"original-runtime-key");
    drop(reopened);
}

#[tokio::test]
async fn packs_trust_projection_and_excludes_run_on_clean_stop() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let trust = home.root().join("trust/test.pub");
    std::fs::create_dir_all(trust.parent().unwrap()).unwrap();
    std::fs::write(&trust, b"ed25519:test").unwrap();
    let transient = home.run_dir().join("system.pid");
    std::fs::create_dir_all(transient.parent().unwrap()).unwrap();
    std::fs::write(&transient, b"pid").unwrap();

    drop(store);
    let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .pack_and_retire_runtime_projection(&home)
        .expect("pack running projection");
    assert!(!trust.exists());
    assert!(!home.run_dir().exists());

    let catalog = store
        .content()
        .list(&StateOwner::System)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name().as_str().to_owned())
        .collect::<Vec<_>>();
    assert!(catalog.iter().any(|name| name == "trust/test.pub"));
    assert!(!catalog.iter().any(|name| name.starts_with("run/")));

    drop(store);
    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert!(trust.is_file(), "trusted pin must be mounted on restart");
    assert!(!home.run_dir().exists());
    reopened
        .pack_and_retire_runtime_projection(&home)
        .expect("retire restarted projection");

    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1);
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new("astrid.volume")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            stopped[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn clean_stop_restores_capsules_and_layout_receipts_on_restart() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);

    let capsule = home
        .home_dir()
        .join("default/.local/capsules/example/capsule.json");
    let receipt = home.migrations_dir().join("layout-v1-to-v2.complete");
    let retirement = home.migrations_dir().join("layout-v1-to-v2.retiring");
    std::fs::create_dir_all(capsule.parent().unwrap()).unwrap();
    std::fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    std::fs::write(&capsule, br#"{"id":"example"}"#).unwrap();
    std::fs::write(&receipt, b"layout-v1-to-v2\n").unwrap();
    std::fs::write(&retirement, b"retirement-source\n").unwrap();

    let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .pack_and_retire_runtime_projection(&home)
        .expect("pack capsule and receipt");
    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1);
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new(CANONICAL_VOLUME)
    );
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&capsule).unwrap(), br#"{"id":"example"}"#);
    assert_eq!(std::fs::read(&receipt).unwrap(), b"layout-v1-to-v2\n");
    assert_eq!(std::fs::read(&retirement).unwrap(), b"retirement-source\n");
    reopened
        .pack_and_retire_runtime_projection(&home)
        .expect("retire restarted projection");
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
}

#[tokio::test]
async fn preserves_ordinary_suffix_files_across_clean_stop() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();

    let next_path = home.root().join("etc/user.next");
    let migrating_path = home.root().join("etc/user.migrating");
    std::fs::create_dir_all(next_path.parent().unwrap()).unwrap();
    std::fs::write(&next_path, b"queued-by-user").unwrap();
    std::fs::write(&migrating_path, b"kept-by-user").unwrap();

    drop(store);
    let store = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .pack_and_retire_runtime_projection(&home)
        .expect("pack ordinary suffix files");

    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1);
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new(CANONICAL_VOLUME)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            stopped[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&next_path).unwrap(), b"queued-by-user");
    assert_eq!(std::fs::read(&migrating_path).unwrap(), b"kept-by-user");
    drop(reopened);
}

#[tokio::test]
async fn reopen_admits_surviving_projection_appended_after_last_pack() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();

    let log_path = home.root().join("log/daemon.log");
    let config_path = home.root().join("etc/authz.conf");
    std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
    std::fs::write(&log_path, b"generation-1\n").unwrap();
    std::fs::write(&config_path, b"allow=generation-1\n").unwrap();
    drop(store);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack baseline running projection");
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
    drop(packer);

    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&log_path).unwrap(), b"generation-1\n");
    {
        use std::io::Write as _;

        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        log.write_all(b"generation-2\n").unwrap();
        log.flush().unwrap();
    }
    std::fs::write(&config_path, b"allow=generation-2\n").unwrap();
    drop(running);

    #[cfg(unix)]
    let _socket = {
        use std::os::unix::net::UnixListener;

        let socket_path = home.root().join(SOCKET_PATH);
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        UnixListener::bind(socket_path).unwrap()
    };

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&log_path).unwrap(),
        b"generation-1\ngeneration-2\n"
    );
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        b"allow=generation-2\n"
    );
    drop(reopened);
}

#[cfg(unix)]
#[tokio::test]
async fn surviving_redirect_fails_closed_before_restore() {
    use std::os::unix::fs::symlink;

    let home_dir = tempfile::tempdir().unwrap();
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

    let home_dir = tempfile::tempdir().unwrap();
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

#[cfg(unix)]
#[tokio::test]
async fn special_inside_run_capsules_fails_closed_before_restore() {
    use std::os::unix::net::UnixListener;

    let home_dir = tempfile::tempdir().unwrap();
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
