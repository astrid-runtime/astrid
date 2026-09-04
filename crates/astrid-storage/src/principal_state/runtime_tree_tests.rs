use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::Arc;

use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::principal_state::open_runtime_principal_store_for_pack;
use crate::principal_state::runtime_tests::test_owner;
use crate::volume::{AstridVolume as _, HostedFileVolume};
use crate::{
    AstridFilesystem, ChunkingProfile, FilesystemPath, KvQuotaResolver, ReadyStagedContent,
    open_runtime_principal_store,
};
use astrid_core::dirs::AstridHome;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

fn write_active_identity_receipt(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    name: &ContentName,
    file: Option<&str>,
) {
    let descriptor = store
        .content()
        .describe(&StateOwner::System, name)
        .unwrap()
        .expect("receipt entry is durable");
    let entry = if let Some(file) = file {
        json!({
            "name": name.as_str(),
            "file": file,
            "logical_bytes": descriptor.logical_bytes(),
        })
    } else {
        json!({
            "name": name.as_str(),
            "logical_bytes": descriptor.logical_bytes(),
        })
    };
    let receipt = json!({
        "schema": 1,
        "phase": "active",
        "root": home.root().canonicalize().unwrap().into_os_string().into_string().unwrap(),
        "entries": [entry],
    });
    let receipt_name = ContentName::new("run/.active-projection-v1.json").unwrap();
    store
        .content()
        .put(
            &StateOwner::System,
            &receipt_name,
            receipt.to_string().as_bytes(),
        )
        .unwrap();
    store.content().flush().unwrap();
}

fn assert_stopped_volume_only(home: &AstridHome) {
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
    expected_names.push("run/.active-projection-v1.json".to_owned());
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
    let relocated_layout = copied_home.root().join("etc/layout-version");
    let relocated_key = copied_home.root().join("keys/runtime.key");
    std::fs::create_dir_all(relocated_layout.parent().unwrap()).unwrap();
    std::fs::create_dir_all(relocated_key.parent().unwrap()).unwrap();
    std::fs::write(&relocated_layout, b"host-bootstrap-not-authority").unwrap();
    std::fs::write(&relocated_key, b"host-key-not-authority").unwrap();
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
    assert_eq!(
        std::fs::read(&relocated_layout).unwrap(),
        b"2",
        "bootstrap host bytes must not replace volume authority"
    );
    assert_eq!(
        std::fs::read(&relocated_key).unwrap(),
        b"runtime-key",
        "bootstrap host bytes must not replace volume authority"
    );
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
    let active_name = ContentName::new("run/.active-projection-v1.json").unwrap();
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &active_name)
            .unwrap()
            .is_some(),
        "startup must retain its active receipt"
    );
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
    let active_name = ContentName::new("run/.active-projection-v1.json").unwrap();
    assert!(
        store
            .content()
            .describe(&StateOwner::System, &active_name)
            .unwrap()
            .is_none(),
        "clean stop retained active recovery state"
    );
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
async fn clean_stop_reconciles_deleted_runtime_file_and_does_not_resurrect_it() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let config_path = home.root().join("etc/user.conf");
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(&config_path, b"user-config").unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack created file");
    drop(packer);

    let restarted = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&config_path).unwrap(), b"user-config");
    drop(restarted);

    std::fs::remove_file(&config_path).unwrap();
    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("atomically reconcile deleted file");
    let config_name = ContentName::new("etc/user.conf").unwrap();
    assert!(
        packer
            .content()
            .describe(&StateOwner::System, &config_name)
            .unwrap()
            .is_none(),
        "deleted durable name remained in catalog"
    );
    drop(packer);

    let remaining = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        remaining
            .iter()
            .map(std::fs::DirEntry::file_name)
            .collect::<Vec<_>>(),
        [std::ffi::OsString::from("astrid.volume")]
    );

    let restarted = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert!(!config_path.exists(), "deleted file resurrected on restart");
    drop(restarted);
}

#[tokio::test]
async fn arbitrary_host_projection_without_active_receipt_fails_closed() {
    let home_dir = tempfile::tempdir().unwrap();
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
        .expect("create clean stopped volume");
    drop(packer);

    let rogue = home.root().join("etc/user.conf");
    std::fs::create_dir_all(rogue.parent().unwrap()).unwrap();
    std::fs::write(&rogue, b"not a surviving projection").unwrap();
    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("arbitrary preboot host file must not acquire catalog authority");
    };
    assert!(
        error
            .to_string()
            .contains("active projection receipt is missing"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&rogue).unwrap(),
        b"not a surviving projection"
    );
}

#[tokio::test]
async fn active_projection_publication_rotates_receipt_inventory() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let old_path = home.root().join("etc/old.conf");
    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    std::fs::write(&old_path, b"old\n").unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    packer
        .pack_and_retire_runtime_projection(&home)
        .expect("pack old generation");
    drop(packer);

    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let old_name = ContentName::new("etc/old.conf").unwrap();
    let old_id = running
        .content()
        .describe(&StateOwner::System, &old_name)
        .unwrap()
        .expect("old generation is published")
        .file();
    let new_path = home.root().join("etc/new.conf");
    std::fs::write(&new_path, b"new\n").unwrap();
    std::fs::remove_file(&old_path).unwrap();
    drop(running);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let receipt = super::super::runtime_tree::active::read(&home, &reopened)
        .unwrap()
        .expect("active receipt");
    assert_eq!(receipt.phase(), super::ReceiptPhase::Active);
    assert!(receipt.contains_inventory_name("etc/new.conf"));
    assert!(!receipt.contains_inventory_name("etc/old.conf"));
    let new_name = ContentName::new("etc/new.conf").unwrap();
    let new_id = reopened
        .content()
        .describe(&StateOwner::System, &new_name)
        .unwrap()
        .expect("new generation is published")
        .file();
    assert_ne!(old_id, new_id, "same-size mutation reused file identity");
    assert_eq!(
        receipt.inventory_identity("etc/new.conf").unwrap(),
        Some(new_id)
    );
    assert_eq!(
        reopened
            .content()
            .read(&StateOwner::System, &new_name)
            .unwrap(),
        Some(b"new\n".to_vec())
    );
}

#[tokio::test]
async fn relocated_volume_rejects_host_files_beyond_trusted_bootstrap() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let copy_dir = tempfile::tempdir().unwrap();
    let copy_home = AstridHome::from_path(copy_dir.path());
    copy_home.ensure().unwrap();
    std::fs::copy(home.storage_volume_path(), copy_home.storage_volume_path()).unwrap();
    drop(running);
    let layout = copy_home.root().join("etc/layout-version");
    std::fs::create_dir_all(layout.parent().unwrap()).unwrap();
    std::fs::write(&layout, b"2").unwrap();
    let rogue = copy_home.root().join("etc/user.conf");
    std::fs::write(&rogue, b"arbitrary-not-authority").unwrap();

    let Err(error) = open_runtime_principal_store(&copy_home, unlimited_quota()).await else {
        panic!("relocated receipt must not admit arbitrary host files");
    };
    assert!(
        error
            .to_string()
            .contains("relocated active receipt is permitted only"),
        "{error}"
    );
    assert_eq!(std::fs::read(&rogue).unwrap(), b"arbitrary-not-authority");
}

#[cfg(unix)]
#[tokio::test]
async fn retiring_failure_restores_published_inventory_and_reactivates() {
    use std::os::unix::net::UnixListener;

    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let first = home.root().join("etc/retire-a.conf");
    let second = home.root().join("etc/retire-b.conf");
    std::fs::create_dir_all(first.parent().unwrap()).unwrap();
    std::fs::write(&first, b"published-a\n").unwrap();
    std::fs::write(&second, b"published-b\n").unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let socket_path = home.root().join("run/other.sock");
    std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
    let _socket = UnixListener::bind(&socket_path).unwrap();
    let error = packer
        .pack_and_retire_runtime_projection(&home)
        .expect_err("complete preflight must reject the later special");
    assert!(error.to_string().contains("special entry"), "{error}");
    drop(packer);

    // Simulate a mid-retire race after the RETIRING inventory is durable.
    std::fs::remove_file(&first).unwrap();

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let receipt = super::super::runtime_tree::active::read(&home, &reopened)
        .unwrap()
        .expect("restart must establish fresh ACTIVE authority");
    assert_eq!(receipt.phase(), super::ReceiptPhase::Active);
    assert!(receipt.contains_inventory_name("etc/retire-a.conf"));
    assert!(receipt.contains_inventory_name("etc/retire-b.conf"));
    assert_eq!(std::fs::read(&first).unwrap(), b"published-a\n");
    assert_eq!(std::fs::read(&second).unwrap(), b"published-b\n");
}

#[tokio::test]
async fn active_receipt_never_materializes_and_malformed_receipt_fails_closed() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let receipt_path = home.root().join("run/.active-projection-v1.json");
    assert!(!receipt_path.try_exists().unwrap());
    let receipt_name = ContentName::new("run/.active-projection-v1.json").unwrap();
    running
        .content()
        .put(&StateOwner::System, &receipt_name, b"{bad")
        .unwrap();
    drop(running);

    let Err(error) = open_runtime_principal_store(&home, unlimited_quota()).await else {
        panic!("malformed active receipt must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("parse active projection receipt"),
        "{error}"
    );
    assert!(!receipt_path.try_exists().unwrap());
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
    assert_stopped_volume_only(&home);
    drop(store);

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&next_path).unwrap(), b"queued-by-user");
    assert_eq!(std::fs::read(&migrating_path).unwrap(), b"kept-by-user");
    drop(reopened);
}

#[tokio::test]
async fn missing_active_receipt_stop_retains_surviving_host_files() {
    let home_dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(home_dir.path());
    let running = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let trust = home.root().join("trust/recovery.pub");
    std::fs::create_dir_all(trust.parent().unwrap()).unwrap();
    std::fs::write(&trust, b"ed25519:recovery").unwrap();

    // Host publication without an ACTIVE rotation must not become a stop
    // admission path. Missing receipt fails closed and retains host bytes.
    let active_name = ContentName::new(ACTIVE_PROJECTION_NAME).unwrap();
    assert!(
        running
            .content()
            .delete(&StateOwner::System, &active_name)
            .unwrap()
    );
    running.content().flush().unwrap();
    drop(running);

    let packer = open_runtime_principal_store_for_pack(&home, unlimited_quota())
        .await
        .unwrap();
    let Err(error) = packer.pack_and_retire_runtime_projection(&home) else {
        panic!("missing ACTIVE receipt must not retire surviving host files");
    };
    assert!(
        error
            .to_string()
            .contains("active projection receipt is missing"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&trust).unwrap(),
        b"ed25519:recovery".as_slice()
    );
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

#[tokio::test]
async fn active_receipt_missing_object_identity_fails_closed() {
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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

#[cfg(unix)]
#[tokio::test]
async fn stop_preflight_retains_regular_file_when_special_comes_later() {
    use std::os::unix::net::UnixListener;

    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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

#[tokio::test]
async fn retiring_stop_retains_unreceipted_host_file() {
    let home_dir = tempfile::tempdir().unwrap();
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
    let retiring = receipt_ingest(&home, ReceiptPhase::Retiring, &entries).unwrap();
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
async fn pack_open_staging_journal_without_receipt_retires_to_volume() {
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
    let home_dir = tempfile::tempdir().unwrap();
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
