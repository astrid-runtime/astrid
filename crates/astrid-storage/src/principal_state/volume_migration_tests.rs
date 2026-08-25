use std::sync::Arc;

use super::{KvQuotaResolver, StateOwner, open_runtime_principal_store};
use astrid_core::dirs::AstridHome;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

#[tokio::test]
async fn promotes_released_volume_path_before_opening() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(store);

    let canonical = home.storage_volume_path();
    let legacy = home.legacy_storage_volume_path();
    std::fs::rename(&canonical, &legacy).unwrap();
    assert!(!canonical.exists());
    assert!(legacy.is_file());

    let reopened = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    drop(reopened);

    assert!(canonical.is_file());
    assert!(!legacy.exists());
}

#[test]
fn rejects_conflicting_canonical_and_legacy_volume_paths() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    home.ensure().unwrap();

    std::fs::write(home.storage_volume_path(), b"canonical").unwrap();
    std::fs::write(home.legacy_storage_volume_path(), b"legacy").unwrap();

    let error = super::volume_migration::existing_volume_available(&home).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("both canonical and legacy volumes")
    );
    assert!(home.storage_volume_path().is_file());
    assert!(home.legacy_storage_volume_path().is_file());
}
