//! Guard views exercise the real RETIRING publication and interrupted deletion.

use std::{path::Path, sync::Arc};

use super::*;
use crate::{KvQuotaResolver, open_runtime_principal_store};

async fn fixture() -> (
    crate::test_directory::TestDirectory,
    AstridHome,
    super::super::RuntimePrincipalStore,
) {
    let directory = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(directory.path());
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    let store = open_runtime_principal_store(&home, quota).await.unwrap();
    let writer = astrid_core::platform_fs::PrivateFileProjection::open(home.root()).unwrap();
    writer
        .write(Path::new("config.toml"), b"owned generation")
        .unwrap();
    writer.sync().unwrap();
    drop(writer);
    astrid_core::platform_fs::create_private_directory(&home.log_dir()).unwrap();
    astrid_core::dirs::interrupt_retirement_before_unlink_once(home.root(), Path::new("log"))
        .unwrap();
    assert!(store.pack_and_retire_runtime_projection(&home).is_err());
    (directory, home, store)
}

#[tokio::test]
async fn recovery_view_caps_reads_and_excludes_noninventoried_names() {
    let (_directory, home, store) = fixture().await;
    let content = store.content();
    let recovery = authenticate(&home, &content).unwrap();
    let name = ContentName::new("config.toml").unwrap();
    assert!(recovery.read(&name, 1).is_err());
    assert_eq!(
        recovery.describe(&name).unwrap().unwrap().logical_bytes(),
        16
    );
    assert_eq!(
        recovery.read(&name, 16).unwrap(),
        Some(b"owned generation".to_vec())
    );
    assert!(
        recovery
            .read(&active::active_projection_name().unwrap(), u64::MAX)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn recovery_guard_rejects_a_foreign_root_before_exposing_content() {
    let (_directory, _home, store) = fixture().await;
    let other = crate::test_directory::temporary().unwrap();
    let home = AstridHome::from_path(other.path());
    assert!(authenticate(&home, &store.content()).is_err());
}

#[tokio::test]
async fn recovery_guard_requires_complete_current_inventory() {
    let (_directory, home, store) = fixture().await;
    // A historical subset receipt can still parse, but cannot authorize boot
    // recovery after a materializable generation was added to the catalogue.
    store
        .content()
        .put(
            &StateOwner::System,
            &ContentName::new("extra.bin").unwrap(),
            b"new",
        )
        .unwrap();
    let error = authenticate(&home, &store.content())
        .err()
        .expect("incomplete receipt must fail");
    assert!(
        error.to_string().contains("does not cover extra.bin"),
        "{error}"
    );
}
