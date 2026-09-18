//! Concurrent projection repair for published capsule caches.

use std::sync::Arc;
use std::thread;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;

use crate::Kernel;

fn publish_env_capsule(kernel: &Arc<Kernel>, name: &str) {
    let dir = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[env.temperature]\ntype = \"string\"\n"
        ),
    )
    .unwrap();
    let home = kernel.astrid_home.clone();
    let storage = kernel
        .principal_store
        .as_ref()
        .map(|store| Arc::new(store.clone()));
    let source = PrincipalId::default();
    thread::spawn(move || {
        astrid_capsule_install::install_from_local_path_for_principal(
            &dir,
            &home,
            astrid_capsule_install::InstallOptions {
                storage,
                ..Default::default()
            },
            &source,
        )
    })
    .join()
    .unwrap()
    .unwrap();
}

fn published_target(
    kernel: &Kernel,
    principal: &PrincipalId,
    capsule: &str,
) -> (
    std::path::PathBuf,
    astrid_storage::CapsulePackageSnapshot,
    astrid_capsule_types::manifest::CapsuleManifest,
) {
    let uid = kernel.principal_directory.uid_for(principal).unwrap();
    let owner = astrid_storage::StateOwner::Principal(uid);
    let store = kernel.principal_store.as_ref().expect("principal store");
    let snapshot = store
        .capsules()
        .get_snapshot(&owner, capsule)
        .unwrap()
        .expect("snapshot");
    let package =
        astrid_capsule_install::read_verified_durable_package_for_owner(store, &owner, capsule)
            .unwrap()
            .expect("package");
    let digest = blake3::hash(&snapshot.package().archive)
        .to_hex()
        .to_string();
    let target = astrid_capsule_install::resolve_cache_target_dir(
        &kernel.astrid_home,
        uid,
        capsule,
        &digest,
        false,
        None,
        kernel.workspace_layout(),
    )
    .expect("cache target");
    (target, snapshot, package.manifest().clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_repair_of_missing_projection_converges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let capsule = "concurrent-repair";
    publish_env_capsule(&kernel, capsule);
    let principal = PrincipalId::default();
    let (target, snapshot, manifest) = published_target(&kernel, &principal, capsule);
    if target.exists() {
        std::fs::remove_dir_all(&target).expect("clear projection");
    }

    let workers = (0..8).map(|_| {
        let kernel = Arc::clone(&kernel);
        let target = target.clone();
        let principal = principal.clone();
        let snapshot = snapshot.clone();
        let manifest = manifest.clone();
        thread::spawn(move || {
            kernel.ensure_published_materialization(&target, &principal, &manifest, &snapshot)
        })
    });
    let results: Vec<_> = workers.map(|worker| worker.join().expect("join")).collect();
    for result in &results {
        assert!(
            result.is_ok(),
            "concurrent repair must not fail: {result:?}"
        );
    }
    kernel
        .verify_published_materialization(&target, &principal, &manifest, &snapshot)
        .expect("canonical projection");
    assert!(target.join("Capsule.toml").is_file());
}
