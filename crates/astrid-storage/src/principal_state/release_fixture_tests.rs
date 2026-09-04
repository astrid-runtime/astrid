//! Import evidence captured from the published v0.10.4 macOS release asset.

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{StateOwner, open_runtime_principal_store};
use crate::KvQuotaResolver;
use astrid_core::dirs::{AstridHome, LEGACY_LAYOUT_VERSION, LayoutMigrationTarget};

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

fn unbounded_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

async fn pack_home_to_volume_only(home: &AstridHome) {
    let packer = crate::principal_state::open_runtime_principal_store_for_pack(
        home,
        Arc::new(|_: &StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    packer
        .pack_and_retire_runtime_projection(home)
        .expect("pack post-cutover projection");
    drop(packer);

    let stopped = std::fs::read_dir(home.root())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(stopped.len(), 1);
    assert_eq!(
        stopped[0].file_name(),
        std::ffi::OsStr::new("astrid.volume")
    );
}

async fn assert_reopened_cutover_inventory(home: &AstridHome) {
    let reopened = open_runtime_principal_store(home, Arc::new(|_: &StateOwner| Ok(None)))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path())
            .unwrap()
            .trim(),
        astrid_core::dirs::LAYOUT_VERSION
    );
    assert!(
        home.migrations_dir()
            .join("layout-v1-to-v2.complete")
            .is_file()
    );
    assert!(
        reopened
            .kv()
            .get("system:identity", "link/cli/local")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reopened
            .kv()
            .get("system:identity", "post-cutover")
            .await
            .unwrap(),
        Some(b"live-volume-write".to_vec())
    );
}

#[tokio::test]
async fn published_v0104_home_imports_verifies_and_retires_legacy_store() {
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
    for (relative, expected) in &source_files {
        assert_eq!(
            std::fs::read(home.state_db_path().join(relative)).unwrap(),
            expected.as_slice()
        );
    }
    let migration_target = LayoutMigrationTarget::new(
        super::RUNTIME_STORE_FORMAT_ID,
        "v0.10.4-release-fixture-test-binary",
    )
    .unwrap();
    home.begin_layout_v2_migration(&migration_target).unwrap();
    let store = open_runtime_principal_store(&home, unbounded_quota())
        .await
        .unwrap();

    assert!(
        store
            .kv()
            .get("system:identity", "link/cli/local",)
            .await
            .unwrap()
            .is_some()
    );
    assert!(home.storage_volume_path().is_file());
    assert!(home.principal_store_path().is_dir());
    home.complete_layout_v2(&migration_target).unwrap();
    assert!(!home.state_db_path().exists());
    assert!(!home.root().join("srv").exists());
    assert!(
        home.migrations_dir()
            .join("layout-v1-to-v2.complete")
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(home.layout_version_path()).unwrap(),
        astrid_core::dirs::LAYOUT_VERSION
    );
    assert!(
        home.profile_path(&astrid_core::PrincipalId::default())
            .is_file()
    );

    // The receipt proves the cutover that allowed legacy retirement. It must
    // not freeze the live destination at that historical byte identity.
    store
        .kv()
        .set(
            "system:identity",
            "post-cutover",
            b"live-volume-write".to_vec(),
        )
        .await
        .unwrap();

    // Kernel boot establishes ACTIVE, completes layout v2, then republishes
    // host records written by that completion. Storage-only cutover follows
    // the same sequence so pack-only stop can retire the live tree.
    store
        .establish_runtime_projection_receipt(&home)
        .expect("establish ACTIVE after layout cutover");
    store
        .publish_runtime_projection(&home)
        .expect("publish post-cutover host projection");

    drop(store);
    home.ensure().unwrap();

    // A pre-repair stop could retire the post-cutover host records without
    // ever packing them. The next boot then saw the stale layout-one intent
    // and rejected the legitimate restart.
    pack_home_to_volume_only(&home).await;
    assert_reopened_cutover_inventory(&home).await;
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
