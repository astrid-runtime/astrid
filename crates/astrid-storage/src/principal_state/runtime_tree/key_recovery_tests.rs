use std::sync::Arc;

use astrid_core::dirs::AstridHome;

use crate::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};

fn quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

#[tokio::test]
async fn interrupted_key_recovery_resumes_after_first_projected_file() {
    interrupted_recovery(RestoreCut::FirstProjectedFile).await;
}

#[tokio::test]
async fn interrupted_key_recovery_resumes_before_projection() {
    interrupted_recovery(RestoreCut::BeforeProjection).await;
}

#[tokio::test]
async fn interrupted_key_recovery_resumes_after_sentinel_directory_creation() {
    interrupted_recovery(RestoreCut::SentinelDirectory).await;
}

#[cfg(unix)]
#[tokio::test]
async fn interrupted_key_recovery_resumes_with_atomic_sentinel_staging() {
    interrupted_recovery(RestoreCut::SentinelStaging).await;
}

enum RestoreCut {
    BeforeProjection,
    SentinelDirectory,
    #[cfg(unix)]
    SentinelStaging,
    FirstProjectedFile,
}

#[tokio::test]
async fn empty_sentinel_directory_without_recovery_intent_is_rejected() {
    reject_sentinel_without_intent(false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn atomic_sentinel_staging_without_recovery_intent_is_rejected() {
    reject_sentinel_without_intent(true).await;
}

async fn reject_sentinel_without_intent(staging: bool) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[7; 32])
        .unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    drop(store);
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
    let staged = home
        .root()
        .join("etc/.astrid-private-00000000000040008000000000000001");
    if staging {
        astrid_core::platform_fs::atomic_write_private_file(&staged, b"incomplete").unwrap();
    }
    home.ensure().unwrap();
    let error = open_runtime_principal_store(&home, quota())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("no durable recovery intent"));
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [9; 32]);
    if staging {
        assert_eq!(std::fs::read(staged).unwrap(), b"incomplete");
    }
}

async fn interrupted_recovery(cut: RestoreCut) {
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path());
    home.ensure().unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[7; 32])
        .unwrap();
    let store = open_runtime_principal_store(&home, quota()).await.unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    astrid_core::platform_fs::ensure_private_directory(&home.keys_dir()).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&home.runtime_key_path(), &[9; 32])
        .unwrap();

    // Stop at the production boundary after durable evidence preservation,
    // then materialize only one real volume-owned file. Drop the store without
    // graceful retirement, as an interrupted restore would leave it.
    assert!(super::key_recovery::recover(&home, &store).unwrap());
    match cut {
        RestoreCut::BeforeProjection => {},
        RestoreCut::SentinelDirectory => {
            // The real projection writer creates its private parent before
            // creating and renaming the atomic layout-version file.
            astrid_core::platform_fs::ensure_private_directory(&home.root().join("etc")).unwrap();
        },
        #[cfg(unix)]
        RestoreCut::SentinelStaging => {
            let staged = home
                .root()
                .join("etc/.astrid-private-00000000000040008000000000000001");
            // These deliberately incomplete bytes must never become the
            // layout version or any admitted System-owned content.
            astrid_core::platform_fs::atomic_write_private_file(&staged, b"incomplete").unwrap();
        },
        RestoreCut::FirstProjectedFile => {
            let sentinel = ContentName::new("etc/layout-version").unwrap();
            let bytes = store
                .content()
                .read(&StateOwner::System, &sentinel)
                .unwrap()
                .unwrap();
            super::write_projection_file(home.root(), sentinel.as_str(), &bytes).unwrap();
        },
    }
    drop(store);

    home.ensure().unwrap();
    let store = open_runtime_principal_store(&home, quota())
        .await
        .expect("resume interrupted recovery from durable volume intent");
    assert_eq!(std::fs::read(home.runtime_key_path()).unwrap(), [7; 32]);
    assert!(
        store
            .content()
            .describe(
                &StateOwner::System,
                &ContentName::new("etc/.astrid-private-00000000000040008000000000000001").unwrap()
            )
            .unwrap()
            .is_none()
    );
    let evidence = ContentName::new(format!(
        "run/.recovered-runtime-keys/{}.key",
        blake3::hash(&[9; 32]).to_hex()
    ))
    .unwrap();
    assert_eq!(
        store
            .content()
            .read(&StateOwner::System, &evidence)
            .unwrap(),
        Some(vec![9; 32])
    );
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert_eq!(std::fs::read_dir(home.root()).unwrap().count(), 1);
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
    // The default daemon boot takes its singleton lock before opening storage.
    // Its private lock directory is ephemeral, not a surviving projection.
    let boot_run = home.root().join("run");
    astrid_core::platform_fs::ensure_private_directory(&boot_run).unwrap();
    astrid_core::platform_fs::atomic_write_private_file(&boot_run.join("system.lock"), b"")
        .unwrap();
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
