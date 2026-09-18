//! Capsule install must stage complete env before a single activation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{
    CapsuleInstallAuthority, CapsuleInstallEnv, EnvStorageScope, EnvValueKind, KernelResponse,
};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};

use super::admin::{dispatch_as_operator, seed_operator};
use super::install::{InstallCapsuleRequest, handle_install_capsule};

fn write_runtime_signing_key(kernel: &crate::Kernel) {
    let path = kernel.astrid_home.runtime_key_path();
    std::fs::create_dir_all(kernel.astrid_home.keys_dir()).expect("keys directory");
    std::fs::write(&path, kernel.runtime_key.secret_key_bytes()).expect("runtime key bytes");
    astrid_core::platform_fs::restrict_private_file(&path).expect("restrict runtime key");
}

fn write_env_capsule_source(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).expect("capsule source");
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n\n[env.PLAIN]\ntype = \"text\"\n\n[env.SECRET]\ntype = \"secret\"\n\n[[component]]\nid = \"main\"\nfile = \"component.wasm\"\n"
        ),
    )
    .expect("manifest");
    let wasm = wat::parse_str("(component)").expect("component wasm");
    std::fs::write(dir.join("component.wasm"), wasm).expect("wasm");
}

fn signed_capsule_archive(kernel: &crate::Kernel, work: &Path, name: &str) -> PathBuf {
    let source = work.join(name);
    write_env_capsule_source(&source, name);
    let bytes =
        astrid_capsule_install::canonical_capsule_archive(&source).expect("canonical archive");
    let archive = work.join(format!("{name}.capsule"));
    std::fs::write(&archive, bytes).expect("write archive");
    astrid_build::artifact::sign_archive(&archive, kernel.runtime_key.as_ref()).expect("sign");
    archive
}

fn env_pair(plain: &str, secret: &str) -> Vec<CapsuleInstallEnv> {
    vec![
        CapsuleInstallEnv {
            key: "PLAIN".into(),
            value: plain.into(),
            kind: EnvValueKind::Text,
        },
        CapsuleInstallEnv {
            key: "SECRET".into(),
            value: secret.into(),
            kind: EnvValueKind::Secret,
        },
    ]
}

async fn take_loaded_events(
    events: &mut astrid_events::EventReceiver,
    first: Duration,
    extra: Duration,
) -> usize {
    match tokio::time::timeout(first, events.recv()).await {
        Err(_) => 0,
        Ok(None) => panic!("capsules_loaded bus closed"),
        Ok(Some(_)) => {
            let mut count: usize = 1;
            while tokio::time::timeout(extra, events.recv())
                .await
                .is_ok_and(|event| event.is_some())
            {
                count = count.saturating_add(1);
            }
            count
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_applies_complete_env_before_one_activation() {
    let directory = tempfile::tempdir().expect("home");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(directory.path())).await;
    seed_operator(&kernel).await;
    write_runtime_signing_key(&kernel);

    let work = directory.path().join("src");
    std::fs::create_dir_all(&work).expect("source work");
    let archive = signed_capsule_archive(&kernel, &work, "env-once-ok");
    let source = archive.to_string_lossy().into_owned();
    let env = env_pair("first-plain", "first-secret");
    let caller = PrincipalId::default();

    let mut loaded = kernel
        .event_bus
        .subscribe_topic("astrid.v1.capsules_loaded");
    let response = handle_install_capsule(
        &kernel,
        InstallCapsuleRequest {
            caller: &caller,
            requested_target: None,
            source: &source,
            workspace: false,
            provenance: None,
            authority: CapsuleInstallAuthority::Automatic,
            env: &env,
            batch_member: None,
        },
    )
    .await;
    assert!(
        matches!(response, KernelResponse::Success(_)),
        "{response:?}"
    );
    assert_eq!(
        take_loaded_events(
            &mut loaded,
            Duration::from_secs(10),
            Duration::from_millis(150)
        )
        .await,
        1,
        "first install must activate exactly once"
    );

    let uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let plain = kernel
        .kv
        .get(
            &astrid_storage::env::principal_capsule_namespace(uid, "env-once-ok"),
            &astrid_storage::env::env_key("PLAIN"),
        )
        .await
        .unwrap();
    assert_eq!(plain.as_deref(), Some(b"first-plain".as_slice()));
    let secret = kernel
        .kv
        .get(
            &astrid_storage::env::system_secret_namespace("env-once-ok"),
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
        )
        .await
        .unwrap();
    assert_eq!(secret.as_deref(), Some(b"first-secret".as_slice()));

    let set = dispatch_as_operator(
        &kernel,
        &caller,
        AdminRequestKind::EnvSet {
            principal: caller.clone(),
            capsule: "env-once-ok".into(),
            key: "PLAIN".into(),
            value: "second-plain".into(),
            kind: EnvValueKind::Text,
            scope: EnvStorageScope::Agent,
            append: false,
        },
    )
    .await;
    assert!(matches!(set, AdminResponseBody::Success(_)), "{set:?}");
    assert_eq!(
        take_loaded_events(
            &mut loaded,
            Duration::from_secs(10),
            Duration::from_millis(150)
        )
        .await,
        1,
        "later explicit EnvSet must reload exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_unsigned_install_rolls_back_staged_env_without_activation() {
    let directory = tempfile::tempdir().expect("home");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(directory.path())).await;
    seed_operator(&kernel).await;
    write_runtime_signing_key(&kernel);

    let caller = PrincipalId::default();
    let uid = kernel.principal_directory.uid_for(&caller).unwrap();
    let name = "env-once-fail";
    kernel
        .kv
        .set(
            &astrid_storage::env::principal_capsule_namespace(uid, name),
            &astrid_storage::env::env_key("PLAIN"),
            b"prior-plain".to_vec(),
        )
        .await
        .unwrap();
    kernel
        .kv
        .set(
            &astrid_storage::env::system_secret_namespace(name),
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
            b"prior-secret".to_vec(),
        )
        .await
        .unwrap();

    let source_dir = directory.path().join(name);
    write_env_capsule_source(&source_dir, name);
    let source = source_dir.to_string_lossy().into_owned();
    let env = env_pair("staged-plain", "staged-secret");

    let mut loaded = kernel
        .event_bus
        .subscribe_topic("astrid.v1.capsules_loaded");
    let response = handle_install_capsule(
        &kernel,
        InstallCapsuleRequest {
            caller: &caller,
            requested_target: None,
            source: &source,
            workspace: false,
            provenance: None,
            authority: CapsuleInstallAuthority::Automatic,
            env: &env,
            batch_member: None,
        },
    )
    .await;
    match response {
        KernelResponse::Error(error) => {
            assert!(error.contains("install failed:"), "{error}");
            assert!(
                error.contains("unsigned") || error.contains("explicit local approval is required"),
                "{error}"
            );
        },
        other => panic!("expected unsigned rejection, got {other:?}"),
    }
    assert_eq!(
        take_loaded_events(
            &mut loaded,
            Duration::from_millis(150),
            Duration::from_millis(150)
        )
        .await,
        0,
        "failed install must not activate"
    );

    let plain = kernel
        .kv
        .get(
            &astrid_storage::env::principal_capsule_namespace(uid, name),
            &astrid_storage::env::env_key("PLAIN"),
        )
        .await
        .unwrap();
    assert_eq!(plain.as_deref(), Some(b"prior-plain".as_slice()));
    let secret = kernel
        .kv
        .get(
            &astrid_storage::env::system_secret_namespace(name),
            &format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX),
        )
        .await
        .unwrap();
    assert_eq!(secret.as_deref(), Some(b"prior-secret".as_slice()));
}
