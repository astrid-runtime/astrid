//! Daemon-backed filtered-refresh generation CAS.

use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{
    CapsuleInstallAuthority, InstalledCapsuleGeneration, InstalledCapsuleIdentity, KernelResponse,
};
use astrid_storage::StateOwner;

use super::install::{InstallCapsuleRequest, handle_install_capsule};
use super::installed_identity;

const CAPSULE_ID: &str = "cas-demo";

fn write_cas_demo(root: &std::path::Path) {
    std::fs::create_dir_all(root).expect("capsule source");
    std::fs::write(
        root.join("Capsule.toml"),
        "[package]\nname = \"cas-demo\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n",
    )
    .expect("manifest");
    let wasm = wat::parse_str("(component)").expect("parse test component");
    std::fs::write(root.join("main.wasm"), wasm).expect("component");
}

fn identity_generation(response: KernelResponse) -> InstalledCapsuleGeneration {
    match response {
        KernelResponse::InstalledCapsuleIdentity(Some(InstalledCapsuleIdentity {
            generation,
            ..
        })) => generation,
        other => panic!("expected installed identity, got {other:?}"),
    }
}

async fn install(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    source: &str,
    expected_generation: Option<&InstalledCapsuleGeneration>,
) -> KernelResponse {
    handle_install_capsule(
        kernel,
        InstallCapsuleRequest {
            caller,
            requested_target: None,
            source,
            workspace: false,
            provenance: None,
            authority: CapsuleInstallAuthority::ExplicitApproval,
            env: &[],
            expected_generation,
            batch_member: None,
        },
    )
    .await
}

#[tokio::test]
async fn filtered_refresh_preserves_env_and_fail_closes_stale_generation() {
    let directory = tempfile::tempdir().expect("test home");
    let home = AstridHome::from_path(directory.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    let caller = PrincipalId::default();
    let source_dir = directory.path().join("cas-demo");
    write_cas_demo(&source_dir);
    let source = source_dir.to_str().expect("utf8 source");

    let first = install(&kernel, &caller, source, None).await;
    assert!(
        matches!(first, KernelResponse::Success(_)),
        "WAT component must install and activate: {first:?}"
    );

    let observed = identity_generation(installed_identity::handle(&kernel, &caller, CAPSULE_ID));
    let uid = kernel
        .principal_directory
        .uid_for(&caller)
        .expect("admitted caller uid");
    let namespace = astrid_storage::env::principal_capsule_namespace(uid, CAPSULE_ID);
    let key = astrid_storage::env::env_key("PLAIN");
    kernel
        .kv
        .set(&namespace, &key, b"keep-me".to_vec())
        .await
        .expect("set independent env");

    let refresh = install(&kernel, &caller, source, Some(&observed)).await;
    assert!(
        matches!(refresh, KernelResponse::Success(_)),
        "matching generation must refresh: {refresh:?}"
    );
    assert_eq!(
        kernel.kv.get(&namespace, &key).await.expect("read env"),
        Some(b"keep-me".to_vec()),
        "empty-env refresh must preserve independently written env"
    );

    kernel
        .principal_store
        .as_ref()
        .expect("principal store")
        .capsules()
        .remove(&StateOwner::Principal(uid), CAPSULE_ID)
        .expect("remove installed package");

    let conflict = install(&kernel, &caller, source, Some(&observed)).await;
    match conflict {
        KernelResponse::Error(error) => {
            assert!(
                error.contains("capsule package conflict for cas-demo"),
                "stale generation must fail closed before activation: {error}"
            );
        },
        other => panic!("expected generation conflict, got {other:?}"),
    }
}
