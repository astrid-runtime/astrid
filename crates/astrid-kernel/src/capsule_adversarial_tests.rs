//! RED tests for capsule materialization, portal selection, and package
//! integrity boundaries. These intentionally describe the secure behavior
//! expected from the kernel/install split; production fixes land separately.

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
