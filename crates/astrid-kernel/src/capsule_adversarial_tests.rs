//! RED tests for capsule materialization, portal selection, and package
//! integrity boundaries. These intentionally describe the secure behavior
//! expected from the kernel/install split; production fixes land separately.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use astrid_capsule::context::WorkspaceSource;
use astrid_capsule::registry::{RuntimeScope, WasmHash};
use astrid_capsule_install::{
    AuthorityDecision, CapsuleMeta, authorize_install, canonical_capsule_archive,
    inspect_directory_for_principal_in_workspace, materialize_capsule_package, publish_package,
    resolve_cache_target_dir,
};
use astrid_capsule_types::CapsuleId;
use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_storage::CapsulePackage;

/// `build_capsule_runtime` records only the uniquely named test capsule. A
/// global slot keeps the capture independent of Tokio worker-thread hops.
static WORKSPACE_SOURCE_CAPTURE: OnceLock<Mutex<Option<WorkspaceSource>>> = OnceLock::new();

fn workspace_source_capture() -> &'static Mutex<Option<WorkspaceSource>> {
    WORKSPACE_SOURCE_CAPTURE.get_or_init(|| Mutex::new(None))
}

pub(super) fn record_workspace_source(capsule_name: &str, source: &WorkspaceSource) {
    if capsule_name != "hosted-portal-runtime-selection" {
        return;
    }
    *workspace_source_capture()
        .lock()
        .expect("workspace source capture lock") = Some(source.clone());
}

pub(super) fn publish_without_running_lifecycle(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    source: &Path,
) -> anyhow::Result<()> {
    let layout = WorkspaceLayout::default();
    let inspection = inspect_directory_for_principal_in_workspace(
        source,
        &kernel.astrid_home,
        principal,
        false,
        None,
        &layout,
    )?;
    let authority = authorize_install(
        &inspection,
        &AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        },
    )?;
    let archive = canonical_capsule_archive(source)?;
    let manifest = astrid_capsule::discovery::load_manifest(&source.join("Capsule.toml"))?;
    let component = manifest
        .components
        .first()
        .ok_or_else(|| anyhow::anyhow!("test capsule has no component"))?;
    let wasm_hash = blake3::hash(&std::fs::read(source.join(&component.path))?)
        .to_hex()
        .to_string();
    let metadata = CapsuleMeta {
        version: inspection.version.clone(),
        wasm_hash: Some(wasm_hash),
        ..Default::default()
    };
    let package = CapsulePackage::new(
        archive,
        serde_json::to_vec(&metadata)?,
        serde_json::to_vec(&authority)?,
    );
    let uid = kernel
        .principal_directory
        .uid_for(principal)
        .map_err(|error| anyhow::anyhow!("test principal has no durable UID: {error}"))?;
    let store = std::sync::Arc::new(
        kernel
            .principal_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test kernel has no durable principal store"))?
            .clone(),
    );
    publish_package(&store, uid, inspection.capsule_id.as_str(), &package)
}

fn take_workspace_source() -> Option<WorkspaceSource> {
    workspace_source_capture()
        .lock()
        .expect("workspace source capture lock")
        .take()
}

async fn seed_isolated_principal(
    kernel: &crate::Kernel,
    home: &AstridHome,
    name: &str,
    uid: [u8; 32],
) -> PrincipalId {
    let principal = PrincipalId::new(name).unwrap();
    kernel
        .identity_store
        .create_principal(principal.clone(), uid)
        .await
        .unwrap();
    astrid_core::profile::PrincipalProfile::default()
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            home, &principal,
        ))
        .unwrap();
    principal
}

fn scratch_home() -> (tempfile::TempDir, AstridHome) {
    let dir = tempfile::tempdir().expect("capsule adversarial tempdir");
    let home = AstridHome::from_path(dir.path());
    (dir, home)
}

fn write_manifest(root: &Path, name: &str) {
    std::fs::write(
        root.join("Capsule.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n"),
    )
    .expect("write capsule manifest");
}

fn write_component_source(root: &Path, name: &str, wit: Option<&[u8]>) -> Vec<u8> {
    std::fs::create_dir_all(root).expect("create component source");
    std::fs::write(
        root.join("Capsule.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n"),
    )
    .expect("write manifest");
    let wasm = wat::parse_str("(component)").expect("parse test component");
    std::fs::write(root.join("main.wasm"), &wasm).expect("write component");
    if let Some(wit) = wit {
        std::fs::create_dir_all(root.join("wit")).expect("create WIT directory");
        std::fs::write(root.join("wit/api.wit"), wit).expect("write WIT");
    }
    wasm
}

fn publish_component_source(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    root: &Path,
    wit: Option<&[u8]>,
) -> anyhow::Result<astrid_storage::CapsulePackage> {
    publish_component_source_at(kernel, principal, root, wit.map(|bytes| ("api.wit", bytes)))
}

fn publish_component_source_at(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    root: &Path,
    wit: Option<(&str, &[u8])>,
) -> anyhow::Result<astrid_storage::CapsulePackage> {
    let layout = WorkspaceLayout::default();
    let inspection = inspect_directory_for_principal_in_workspace(
        root,
        &kernel.astrid_home,
        principal,
        false,
        None,
        &layout,
    )?;
    let authority = authorize_install(
        &inspection,
        &AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        },
    )?;
    let archive = canonical_capsule_archive(root)?;
    let manifest = astrid_capsule::discovery::load_manifest(&root.join("Capsule.toml"))?;
    let component = manifest
        .components
        .first()
        .ok_or_else(|| anyhow::anyhow!("test capsule has no component"))?;
    let wasm_hash = blake3::hash(&std::fs::read(root.join(&component.path))?)
        .to_hex()
        .to_string();
    let mut wit_files = HashMap::new();
    if let Some((relative, wit)) = wit {
        wit_files.insert(relative.to_owned(), blake3::hash(wit).to_hex().to_string());
    }
    let metadata = CapsuleMeta {
        version: inspection.version.clone(),
        wasm_hash: Some(wasm_hash),
        wit_files,
        ..Default::default()
    };
    let package = astrid_storage::CapsulePackage::new(
        archive,
        serde_json::to_vec(&metadata)?,
        serde_json::to_vec(&authority)?,
    );
    let uid = kernel
        .principal_directory
        .uid_for(principal)
        .map_err(|error| anyhow::anyhow!("test principal has no durable UID: {error}"))?;
    let store = std::sync::Arc::new(
        kernel
            .principal_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test kernel has no durable principal store"))?
            .clone(),
    );
    publish_package(&store, uid, inspection.capsule_id.as_str(), &package)?;
    Ok(package)
}

fn durable_target(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    package: &astrid_storage::CapsulePackage,
    name: &str,
) -> std::path::PathBuf {
    let uid = kernel.principal_directory.uid_for(principal).unwrap();
    let digest = blake3::hash(&package.archive).to_hex().to_string();
    resolve_cache_target_dir(
        &kernel.astrid_home,
        uid,
        name,
        &digest,
        false,
        None,
        &WorkspaceLayout::default(),
    )
    .expect("durable cache target")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_portal_discovery_and_runtime_keep_the_selected_hosted_portal() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;

    // The selected project portal is distinct from the runtime's canonical
    // durable workspace and carries a marker that must not be discarded.
    let portal = tempfile::tempdir().expect("portal tempdir");
    let layout = WorkspaceLayout::default();
    let portal_capsules = layout.capsules_dir(portal.path());
    std::fs::create_dir_all(&portal_capsules).expect("create selected portal capsules");
    std::fs::write(portal.path().join("portal-marker"), b"selected portal").unwrap();
    let portal_capsule = portal_capsules.join("portal-capsule");
    std::fs::create_dir_all(&portal_capsule).unwrap();
    write_manifest(&portal_capsule, "portal-capsule");
    let _ = take_workspace_source();

    let discovered = astrid_capsule::discovery::discover_manifests_in_workspace(
        None,
        Some(portal.path()),
        &layout,
    );
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].0.package.name, "portal-capsule");
    assert_eq!(
        std::fs::canonicalize(&discovered[0].1).expect("canonical discovered capsule path"),
        std::fs::canonicalize(&portal_capsule).expect("canonical selected capsule path")
    );

    // Drive the real kernel runtime-construction path with a static capsule so
    // no guest WASM is needed. The source directory itself identifies the
    // selected workspace portal; construction must preserve that source.
    let mut manifest = CapsuleManifest::default();
    manifest.package.name = "hosted-portal-runtime-selection".to_owned();
    manifest.package.version = "1.0.0".to_owned();
    let id = CapsuleId::new(manifest.package.name.clone()).unwrap();
    let runtime_id = kernel
        .capsules
        .write()
        .await
        .reserve_runtime_id(
            id,
            WasmHash::synthetic(&manifest.package.name, &manifest.package.version),
            RuntimeScope::Principal(astrid_core::PrincipalUid::from_bytes([0xA7; 32])),
        )
        .unwrap();

    let runtime = kernel
        .build_capsule_runtime(
            manifest,
            &portal_capsule,
            Some(&PrincipalId::default()),
            runtime_id,
        )
        .await;
    let Some(mut capsule) = runtime.ok() else {
        // An implementation may reject a portal it cannot isolate. That is
        // secure; only a successful load is required to preserve the selected
        // HostedPortal source.
        return;
    };
    let captured = take_workspace_source().expect("runtime source capture");
    match captured {
        WorkspaceSource::HostedPortal(root) => assert_eq!(
            std::fs::canonicalize(root).expect("canonical runtime workspace source"),
            std::fs::canonicalize(portal.path()).expect("canonical selected portal root")
        ),
        other @ WorkspaceSource::Astrid => {
            panic!("workspace runtime must retain the selected HostedPortal, got {other:?}")
        },
    }
    capsule.unload().await.expect("unload static test capsule");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_materialized_component_and_meta_hash_are_rejected_by_kernel() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().expect("source tempdir");
    std::fs::write(
        source.path().join("Capsule.toml"),
        "[package]\nname = \"tamper-materialization\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n",
    )
    .unwrap();
    let trusted_wasm = b"trusted component bytes";
    std::fs::write(source.path().join("main.wasm"), trusted_wasm).unwrap();

    let layout = WorkspaceLayout::default();
    let inspection = inspect_directory_for_principal_in_workspace(
        source.path(),
        &home,
        &principal,
        false,
        None,
        &layout,
    )
    .unwrap();
    let authority = authorize_install(
        &inspection,
        &AuthorityDecision::ExplicitApproval {
            content_digest: inspection.content_digest.clone(),
        },
    )
    .unwrap();
    let archive = canonical_capsule_archive(source.path()).unwrap();
    let metadata = CapsuleMeta {
        version: "1.0.0".to_owned(),
        wasm_hash: Some(blake3::hash(trusted_wasm).to_hex().to_string()),
        ..Default::default()
    };
    let package = CapsulePackage::new(
        archive.clone(),
        serde_json::to_vec(&metadata).unwrap(),
        serde_json::to_vec(&authority).unwrap(),
    );
    let uid = kernel
        .principal_directory
        .uid_for(&principal)
        .expect("default principal UID");
    let store = std::sync::Arc::new(
        kernel
            .principal_store
            .as_ref()
            .expect("test kernel durable store")
            .clone(),
    );
    publish_package(&store, uid, "tamper-materialization", &package).unwrap();

    let archive_digest = blake3::hash(&archive).to_hex().to_string();
    let target = resolve_cache_target_dir(
        &home,
        uid,
        "tamper-materialization",
        &archive_digest,
        false,
        None,
        &layout,
    )
    .unwrap();
    materialize_capsule_package(&package, &target).unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml"))
        .expect("materialized manifest");
    assert!(
        kernel
            .verify_registry_materialization(&target, &principal, &manifest)
            .unwrap(),
        "untampered durable materialization should verify"
    );

    // Leave Capsule.toml and the component path unchanged, but replace both
    // the executable bytes and the cache's metadata pointer. A durable archive
    // digest alone cannot authorize this cache projection.
    let malicious_wasm = b"attacker component bytes";
    let malicious_hash = blake3::hash(malicious_wasm).to_hex().to_string();
    std::fs::write(target.join("main.wasm"), malicious_wasm).unwrap();
    std::fs::create_dir_all(home.bin_dir()).unwrap();
    std::fs::write(
        home.bin_dir().join(format!("{malicious_hash}.wasm")),
        malicious_wasm,
    )
    .unwrap();
    let mut tampered_meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(target.join("meta.json")).unwrap()).unwrap();
    tampered_meta["wasm_hash"] = serde_json::Value::String(malicious_hash);
    std::fs::write(
        target.join("meta.json"),
        serde_json::to_vec(&tampered_meta).unwrap(),
    )
    .unwrap();

    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .expect_err("tampered materialization must fail closed");
    assert!(
        error.to_string().contains("WASM")
            || error.to_string().contains("metadata")
            || error.to_string().contains("materialization"),
        "unexpected tamper rejection: {error:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_activation_remains_principal_scoped_after_upgrade() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal_a = seed_isolated_principal(&kernel, &home, "activation-a", [0x83; 32]).await;
    let principal_b = seed_isolated_principal(&kernel, &home, "activation-b", [0x84; 32]).await;

    let write_source = |name: &str, version: &str, wasm: &[u8]| {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("Capsule.toml"),
            format!(
                "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n"
            ),
        )
        .unwrap();
        std::fs::write(source.path().join("main.wasm"), wasm).unwrap();
        source
    };
    let wasm = wat::parse_str("(component)").unwrap();
    let old_source = write_source("isolated-upgrade", "1.0.0", &wasm);
    let new_source = write_source("isolated-upgrade", "1.1.0", &wasm);
    let b_source = write_source("principal-b-package", "1.0.0", &wasm);
    publish_without_running_lifecycle(&kernel, &principal_a, old_source.path()).unwrap();
    publish_without_running_lifecycle(&kernel, &principal_b, b_source.path()).unwrap();

    let old_paths = kernel.durable_principal_capsule_paths(&principal_a);
    assert_eq!(old_paths.len(), 1);
    assert!(old_paths[0].join("main.wasm").is_file());
    assert_eq!(std::fs::read(old_paths[0].join("main.wasm")).unwrap(), wasm);

    let store = kernel.principal_store.clone().unwrap();
    let b_uid = kernel.principal_directory.uid_for(&principal_b).unwrap();
    let before_b = store
        .capsules()
        .get_snapshot(
            &astrid_storage::StateOwner::Principal(b_uid),
            "principal-b-package",
        )
        .unwrap()
        .unwrap();

    publish_without_running_lifecycle(&kernel, &principal_a, new_source.path()).unwrap();
    std::fs::write(old_paths[0].join("main.wasm"), b"stale hostile bytes").unwrap();

    let upgraded_paths = kernel.durable_principal_capsule_paths(&principal_a);
    assert_eq!(upgraded_paths.len(), 1);
    assert_ne!(upgraded_paths[0], old_paths[0]);
    assert_eq!(
        std::fs::read(upgraded_paths[0].join("main.wasm")).unwrap(),
        wasm
    );

    let after_b = store
        .capsules()
        .get_snapshot(
            &astrid_storage::StateOwner::Principal(b_uid),
            "principal-b-package",
        )
        .unwrap()
        .unwrap();
    assert_eq!(before_b, after_b);
    let b_paths = kernel.durable_principal_capsule_paths(&principal_b);
    assert_eq!(b_paths.len(), 1);
    assert_eq!(std::fs::read(b_paths[0].join("main.wasm")).unwrap(), wasm);
    let a_uid = kernel.principal_directory.uid_for(&principal_a).unwrap();
    assert!(
        store
            .capsules()
            .remove(
                &astrid_storage::StateOwner::Principal(a_uid),
                "isolated-upgrade",
            )
            .unwrap()
    );
    assert!(
        kernel
            .durable_principal_capsule_paths(&principal_a)
            .is_empty()
    );
    let after_removal_b = store
        .capsules()
        .get_snapshot(
            &astrid_storage::StateOwner::Principal(b_uid),
            "principal-b-package",
        )
        .unwrap()
        .unwrap();
    assert_eq!(before_b, after_removal_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materialized_authority_bytes_are_exactly_verified() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    let wasm = write_component_source(source.path(), "authority-projection", None);
    let package = publish_component_source(&kernel, &principal, source.path(), None).unwrap();
    let target = durable_target(&kernel, &principal, &package, "authority-projection");
    materialize_capsule_package(&package, &target).unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml")).unwrap();
    kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap();
    std::fs::write(target.join("authority.json"), b"{}").unwrap();
    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap_err();
    assert!(error.to_string().contains("authority"), "{error:#}");
    assert_eq!(std::fs::read(target.join("main.wasm")).unwrap(), wasm);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materialized_wit_bytes_are_exactly_verified() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    let wit = b"package astrid:test;";
    write_component_source(source.path(), "wit-projection", Some(wit));
    let package = publish_component_source(&kernel, &principal, source.path(), Some(wit)).unwrap();
    let target = durable_target(&kernel, &principal, &package, "wit-projection");
    materialize_capsule_package(&package, &target).unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml")).unwrap();
    kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap();
    std::fs::write(target.join("wit/api.wit"), b"package hostile:evil;").unwrap();
    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap_err();
    assert!(
        error.to_string().contains("differs from durable archive"),
        "{error:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_wit_ancestors_activate_from_a_durable_package() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    write_component_source(source.path(), "nested-wit-projection", None);
    let wit = b"package astrid:contracts;";
    let wit_relative = "deps/astrid-contracts/astrid-contracts.wit";
    std::fs::create_dir_all(
        source
            .path()
            .join("wit")
            .join(wit_relative)
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(source.path().join("wit").join(wit_relative), wit).unwrap();
    publish_component_source_at(
        &kernel,
        &principal,
        source.path(),
        Some((wit_relative, wit)),
    )
    .unwrap();

    let targets = kernel.durable_principal_capsule_paths(&principal);
    assert_eq!(targets.len(), 1);
    assert!(targets[0].join("wit").is_dir());
    assert!(targets[0].join("wit/deps").is_dir());
    assert!(targets[0].join("wit/deps/astrid-contracts").is_dir());
    assert_eq!(
        std::fs::read(targets[0].join("wit").join(wit_relative)).unwrap(),
        wit
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_directories_activate_and_survive_durable_activation() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    write_component_source(source.path(), "empty-directory-projection", None);
    std::fs::create_dir_all(source.path().join("empty/nested")).unwrap();
    let package = publish_component_source_at(&kernel, &principal, source.path(), None).unwrap();
    let target = durable_target(&kernel, &principal, &package, "empty-directory-projection");
    let targets = kernel.durable_principal_capsule_paths(&principal);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], target);
    assert!(targets[0].join("empty").is_dir());
    assert!(targets[0].join("empty/nested").is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materialized_extra_file_is_rejected() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    write_component_source(source.path(), "extra-projection", None);
    let package = publish_component_source(&kernel, &principal, source.path(), None).unwrap();
    let target = durable_target(&kernel, &principal, &package, "extra-projection");
    materialize_capsule_package(&package, &target).unwrap();
    std::fs::write(target.join("extra.txt"), b"hostile").unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml")).unwrap();
    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap_err();
    assert!(error.to_string().contains("inventory"), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materialized_extra_directory_is_rejected() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    write_component_source(source.path(), "extra-directory-projection", None);
    let package = publish_component_source(&kernel, &principal, source.path(), None).unwrap();
    let target = durable_target(&kernel, &principal, &package, "extra-directory-projection");
    materialize_capsule_package(&package, &target).unwrap();
    std::fs::create_dir_all(target.join("extra/nested")).unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml")).unwrap();
    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap_err();
    assert!(error.to_string().contains("inventory"), "{error:#}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materialized_child_symlink_is_rejected() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let source = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("hostile.wasm"), b"outside").unwrap();
    write_component_source(source.path(), "redirect-projection", None);
    let package = publish_component_source(&kernel, &principal, source.path(), None).unwrap();
    let target = durable_target(&kernel, &principal, &package, "redirect-projection");
    materialize_capsule_package(&package, &target).unwrap();
    std::fs::remove_file(target.join("main.wasm")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("hostile.wasm"),
        target.join("main.wasm"),
    )
    .unwrap();
    let manifest = astrid_capsule::discovery::load_manifest(&target.join("Capsule.toml")).unwrap();
    let error = kernel
        .verify_registry_materialization(&target, &principal, &manifest)
        .unwrap_err();
    assert!(error.to_string().contains("redirect"), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_runtime_durable_upgrade_materializes_a_new_live_source() {
    let (_home_temp, home) = scratch_home();
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let principal = PrincipalId::default();
    let old_source = tempfile::tempdir().unwrap();
    let old_wasm = write_component_source(old_source.path(), "live-upgrade", None);
    let old_package =
        publish_component_source(&kernel, &principal, old_source.path(), None).unwrap();
    let old_target = durable_target(&kernel, &principal, &old_package, "live-upgrade");
    materialize_capsule_package(&old_package, &old_target).unwrap();
    let old_hash = blake3::hash(&old_wasm).to_hex().to_string();
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .content()
        .put(
            &astrid_storage::StateOwner::System,
            &astrid_storage::ContentName::new(format!("bin/{old_hash}.wasm")).unwrap(),
            &old_wasm,
        )
        .unwrap();

    crate::Kernel::load_capsule(&kernel, old_target.clone(), &principal)
        .await
        .expect("load published old generation");
    let id = CapsuleId::from_static("live-upgrade");
    let running_old = kernel
        .capsules
        .read()
        .await
        .get_for(&principal, &id)
        .expect("old runtime is live");
    assert_eq!(
        std::fs::read(running_old.source_dir().unwrap().join("main.wasm")).unwrap(),
        old_wasm
    );

    let new_source = tempfile::tempdir().unwrap();
    let new_wasm = wat::parse_str("(component)").unwrap();
    std::fs::write(new_source.path().join("Capsule.toml"), "[package]\nname = \"live-upgrade\"\nversion = \"1.1.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n").unwrap();
    std::fs::write(new_source.path().join("main.wasm"), &new_wasm).unwrap();
    publish_component_source(&kernel, &principal, new_source.path(), None).unwrap();
    let new_hash = blake3::hash(&new_wasm).to_hex().to_string();
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .content()
        .put(
            &astrid_storage::StateOwner::System,
            &astrid_storage::ContentName::new(format!("bin/{new_hash}.wasm")).unwrap(),
            &new_wasm,
        )
        .unwrap();

    kernel
        .restart_capsule(&id, &principal, None)
        .await
        .expect("same runtime stays live across durable upgrade");
    let upgraded = kernel
        .capsules
        .read()
        .await
        .get_for(&principal, &id)
        .expect("upgraded runtime is live");
    let upgraded_dir = upgraded.source_dir().expect("runtime source is durable");
    assert_ne!(upgraded_dir, old_target);
    assert_eq!(
        std::fs::read(upgraded_dir.join("main.wasm")).unwrap(),
        new_wasm
    );
    assert_eq!(
        std::fs::read(old_target.join("main.wasm")).unwrap(),
        old_wasm
    );
}
