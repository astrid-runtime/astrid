use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use crate::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

#[tokio::test]
async fn replacement_key_cannot_seed_missing_volume_identity() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("no authoritative runtime key"));
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
}

#[tokio::test]
async fn active_projection_cannot_be_reclassified_as_stopped_key_recovery() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    store.establish_runtime_projection_receipt(&home).unwrap();
    drop(store);
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("not a stopped projection"));
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
}

#[tokio::test]
async fn stopped_volume_recovers_replacement_key_without_changing_identity() {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[7; 32])
        .unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);

    // Published stopped-install code recreated this directory with the umask
    // and generated a new private key before the daemon admitted its volume.
    std::fs::create_dir(home.keys_dir()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.keys_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();

    home.ensure().expect("recognize stopped-key recovery shape");
    assert!(home.validate_runtime_identity_provisioning().is_err());
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
    let name = ContentName::new(format!(
        "run/.recovered-runtime-keys/{}.key",
        blake3::hash(&[9; 32]).to_hex()
    ))
    .unwrap();
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(vec![9; 32]),
        "replacement bytes remain durable evidence, never runtime identity"
    );
    assert!(!home.root().join(name.as_str()).exists());
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);

    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
    assert_eq!(
        store.content().read(&StateOwner::System, &name).unwrap(),
        Some(vec![9; 32])
    );
    store.pack_and_retire_runtime_projection(&home).unwrap();
}
