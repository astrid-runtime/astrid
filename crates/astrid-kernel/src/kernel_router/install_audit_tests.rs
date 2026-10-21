//! A daemon install records the capsule's code identity: a `CapsuleInstalled`
//! entry and a `CapsuleLoaded` entry binding the wasm and manifest hashes and
//! the engine profile.

use std::path::{Path, PathBuf};

use astrid_audit::AuditAction;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{CapsuleInstallAuthority, KernelResponse};
use astrid_crypto::ContentHash;

use super::admin::seed_operator;
use super::install::{InstallCapsuleRequest, handle_install_capsule};
use super::install_env_activation_tests::write_runtime_signing_key;

const MANIFEST: &str = "[package]\nname = \"audited-install\"\nversion = \"1.2.3\"\n\n[[component]]\nid = \"main\"\nfile = \"component.wasm\"\n";

/// Write and sign a minimal one-component capsule archive; returns the
/// archive path and the component bytes.
fn signed_archive(kernel: &crate::Kernel, work: &Path) -> (PathBuf, Vec<u8>) {
    let source = work.join("audited-install");
    std::fs::create_dir_all(&source).expect("capsule source");
    std::fs::write(source.join("Capsule.toml"), MANIFEST).expect("manifest");
    let wasm = wat::parse_str("(component)").expect("component wasm");
    std::fs::write(source.join("component.wasm"), &wasm).expect("wasm");
    let bytes =
        astrid_capsule_install::canonical_capsule_archive(&source).expect("canonical archive");
    let archive = work.join("audited-install.capsule");
    std::fs::write(&archive, bytes).expect("write archive");
    astrid_build::artifact::sign_archive(&archive, kernel.runtime_key.as_ref()).expect("sign");
    (archive, wasm)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_records_installed_and_loaded_code_identity() {
    let directory = tempfile::tempdir().expect("home");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(directory.path())).await;
    seed_operator(&kernel).await;
    write_runtime_signing_key(&kernel);
    let work = directory.path().join("src");
    std::fs::create_dir_all(&work).expect("source work");
    let (archive, wasm) = signed_archive(&kernel, &work);
    let source = archive.to_string_lossy().into_owned();
    let caller = PrincipalId::default();

    let response = handle_install_capsule(
        &kernel,
        InstallCapsuleRequest {
            caller: &caller,
            requested_target: None,
            source: &source,
            workspace: false,
            provenance: None,
            authority: CapsuleInstallAuthority::Automatic,
            env: &[],
            expected_generation: None,
            batch_member: None,
        },
    )
    .await;
    assert!(
        matches!(response, KernelResponse::Success(_)),
        "{response:?}"
    );

    let entries = kernel
        .audit_log
        .get_principal_entries(&kernel.session_id, Some(&caller))
        .await
        .expect("entries");
    let wasm_hash = Some(ContentHash::hash(&wasm));
    let manifest_hash = Some(ContentHash::hash(MANIFEST.as_bytes()));

    let installed = entries
        .iter()
        .find_map(|entry| match &entry.action {
            AuditAction::CapsuleInstalled {
                capsule_id,
                version,
                target_principal,
                wasm_hash,
                manifest_hash,
            } if capsule_id == "audited-install" => Some((
                version.clone(),
                target_principal.clone(),
                *wasm_hash,
                *manifest_hash,
            )),
            _ => None,
        })
        .expect("install recorded");
    assert_eq!(
        installed,
        (
            "1.2.3".to_owned(),
            Some(caller.clone()),
            wasm_hash,
            manifest_hash
        )
    );

    let loaded = entries
        .iter()
        .find_map(|entry| match &entry.action {
            AuditAction::CapsuleLoaded {
                capsule_id,
                wasm_hash,
                manifest_hash,
                engine_profile,
                trigger,
                ..
            } if capsule_id == "audited-install" => Some((
                *wasm_hash,
                *manifest_hash,
                engine_profile.clone(),
                trigger.clone(),
            )),
            _ => None,
        })
        .expect("load recorded");
    assert_eq!(
        loaded,
        (
            wasm_hash,
            manifest_hash,
            format!("wasm:{}", astrid_capsule::engine::wasm::COMPILED_ENGINE_ABI),
            "load".to_owned()
        )
    );
}
