//! Import evidence captured from the published v0.10.4 macOS release asset.

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{StateOwner, open_runtime_principal_store};
use crate::KvQuotaResolver;
use astrid_core::dirs::{AstridHome, LEGACY_LAYOUT_VERSION};

#[derive(Deserialize)]
struct StateDbFixture {
    files: Vec<FixtureFile>,
}

#[derive(Deserialize)]
struct FixtureFile {
    path: String,
    sha256: String,
    base64: String,
}

fn write_released_home(home: &AstridHome) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(home.profiles_dir()).unwrap();
    std::fs::write(home.layout_version_path(), b"1").unwrap();
    std::fs::write(
        home.profile_path(&astrid_core::PrincipalId::default()),
        include_bytes!("../../fixtures/v0.10.4-macos-aarch64/default.toml"),
    )
    .unwrap();
    let fixture: StateDbFixture = serde_json::from_slice(include_bytes!(
        "../../fixtures/v0.10.4-macos-aarch64/state-db.json"
    ))
    .unwrap();
    fixture
        .files
        .into_iter()
        .map(|file| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(file.base64)
                .unwrap();
            assert_eq!(hex::encode(Sha256::digest(&bytes)), file.sha256);
            let target = home.state_db_path().join(&file.path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, &bytes).unwrap();
            (file.path, bytes)
        })
        .collect()
}

fn assert_fixture_identity() {
    let source: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../fixtures/v0.10.4-macos-aarch64/source.json"
    ))
    .unwrap();
    assert_eq!(source["release"], "v0.10.4");
    assert_eq!(
        source["asset_sha256"],
        "f03fda82dd7c0396b613a91e02624e28c84d422a2cc5cf918503b0e2b4bae849"
    );
}

#[tokio::test]
async fn published_v0104_home_imports_without_mutating_legacy_bytes() {
    assert_fixture_identity();
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let source_files = write_released_home(&home);
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path())
            .unwrap()
            .trim(),
        LEGACY_LAYOUT_VERSION
    );
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) => Some(u64::MAX),
        })
    });

    let store = open_runtime_principal_store(&home, quota).await.unwrap();

    assert!(
        store
            .kv()
            .get("system:identity", "link/cli/local",)
            .await
            .unwrap()
            .is_some()
    );
    for (relative, expected) in source_files {
        assert_eq!(
            std::fs::read(home.state_db_path().join(relative)).unwrap(),
            expected
        );
    }
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path())
            .unwrap()
            .trim(),
        LEGACY_LAYOUT_VERSION
    );
    assert!(
        home.principal_store_path()
            .join("migration.complete")
            .is_file()
    );
}

#[test]
fn fixture_paths_are_portable_relative_names() {
    let fixture: StateDbFixture = serde_json::from_slice(include_bytes!(
        "../../fixtures/v0.10.4-macos-aarch64/state-db.json"
    ))
    .unwrap();
    assert!(fixture.files.iter().all(|file| {
        let path = Path::new(&file.path);
        !path.is_absolute()
            && !path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
    }));
}
