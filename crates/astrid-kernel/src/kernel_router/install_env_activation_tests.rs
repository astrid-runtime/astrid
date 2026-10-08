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

pub(super) fn write_runtime_signing_key(kernel: &crate::Kernel) {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_install_cannot_overwrite_another_principals_shared_secret() {
    check_shared_secret_install_authority(&["self:capsule:install"], false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_secret_install_requires_global_env_write_not_self_env_write() {
    check_shared_secret_install_authority(&["self:capsule:install", "self:env:write"], false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_secret_install_preserves_authorized_operator_updates() {
    check_shared_secret_install_authority(&["self:capsule:install", "env:write"], true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_env_authority_does_not_substitute_for_install_authority() {
    check_shared_secret_install_authority(&["env:write"], false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_only_self_install_preserves_shared_secret_without_global_env_authority() {
    check_install_authority(&["self:capsule:install"], true, None).await;
}

async fn check_shared_secret_install_authority(grants: &[&str], allowed: bool) {
    check_secret_install_authority(grants, allowed, "self-secret").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_install_cannot_delete_shared_secret_with_empty_value() {
    check_secret_install_authority(&["self:capsule:install"], false, "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_empty_secret_install_rolls_back_when_activation_requires_it() {
    check_secret_install_authority(&["self:capsule:install", "env:write"], false, "").await;
}

async fn check_secret_install_authority(grants: &[&str], allowed: bool, secret: &str) {
    check_install_authority(grants, allowed, Some(secret)).await;
}

async fn check_install_authority(grants: &[&str], allowed: bool, secret: Option<&str>) {
    use astrid_core::kernel_api::KernelRequest;
    use astrid_core::profile::PrincipalProfile;

    let directory = tempfile::tempdir().expect("home");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(directory.path())).await;
    seed_operator(&kernel).await;
    write_runtime_signing_key(&kernel);
    let caller = PrincipalId::new("self-installer").unwrap();
    kernel
        .principal_directory
        .register(
            caller.clone(),
            astrid_core::PrincipalUid::from_bytes([23; 32]),
        )
        .unwrap();
    PrincipalProfile {
        groups: Vec::new(),
        grants: grants.iter().map(|grant| (*grant).to_owned()).collect(),
        ..PrincipalProfile::default()
    }
    .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &caller))
    .unwrap();
    kernel.profile_cache.invalidate(&caller);
    assert!(super::authorize_request(&kernel, &caller, None, "capsule:install").is_err());

    let work = directory.path().join("src");
    std::fs::create_dir_all(&work).unwrap();
    let archive = signed_capsule_archive(&kernel, &work, "isolation-secret");
    let namespace = astrid_storage::env::system_secret_namespace("isolation-secret");
    let key = format!("{}SECRET", astrid_storage::env::SECRET_KEY_PREFIX);
    let existing = b"operator-provisioned-site-secret";
    kernel
        .kv
        .set(&namespace, &key, existing.to_vec())
        .await
        .unwrap();
    let request = KernelRequest::InstallCapsule {
        source: archive.to_string_lossy().into_owned(),
        workspace: false,
        target_principal: None,
        provenance: None,
        authority: CapsuleInstallAuthority::Automatic,
        env: env_pair("self-text", secret.unwrap_or_default())
            .into_iter()
            .filter(|value| secret.is_some() || value.kind == EnvValueKind::Text)
            .collect(),
        expected_generation: None,
        batch: None,
    };
    let topic = astrid_events::ipc::Topic::from_raw("astrid.v1.request.install");
    let response_topic = super::response_topic_for(&topic);
    let mut responses = kernel.event_bus.subscribe_topic(response_topic.as_str());
    // Exercise the real management dispatcher, including its capability check.
    super::handle_request(
        &kernel,
        &mut super::ManagementRateLimiter::new(),
        &mut super::install_batch::InstallBatchRegistry::default(),
        topic,
        caller,
        None,
        request,
    )
    .await;
    let event = tokio::time::timeout(Duration::from_secs(1), responses.recv())
        .await
        .expect("terminal install response")
        .expect("response bus remains open");
    assert_secret_install_response(&event, grants, allowed);
    let uid = astrid_core::PrincipalUid::from_bytes([23; 32]);
    let agent_env = astrid_storage::env::principal_capsule_namespace(uid, "isolation-secret");
    assert_eq!(
        kernel
            .kv
            .get(&agent_env, &astrid_storage::env::env_key("PLAIN"))
            .await
            .unwrap()
            .as_deref(),
        allowed.then_some(b"self-text".as_slice()),
        "a rejected shared-secret install must not stage principal env"
    );
    assert_eq!(
        kernel.kv.get(&namespace, &key).await.unwrap().as_deref(),
        if allowed && secret.is_some() {
            secret.filter(|value| !value.is_empty()).map(str::as_bytes)
        } else {
            Some(existing.as_slice())
        },
        "self-install authority must not overwrite a host-wide credential"
    );
}

fn assert_secret_install_response(
    event: &astrid_events::AstridEvent,
    grants: &[&str],
    allowed: bool,
) {
    let astrid_events::AstridEvent::Ipc { message, .. } = event else {
        panic!("expected IPC response");
    };
    let astrid_events::ipc::IpcPayload::RawJson(value) = &message.payload else {
        panic!("expected JSON response");
    };
    let response: KernelResponse = serde_json::from_value(value.clone()).unwrap();
    if allowed {
        assert!(
            matches!(response, KernelResponse::Success(_)),
            "{response:?}"
        );
    } else {
        let KernelResponse::Error(error) = response else {
            panic!("expected install refusal: {response:?}");
        };
        if grants.contains(&"env:write") && grants.contains(&"self:capsule:install") {
            assert!(error.contains("not configured"), "{error}");
        } else {
            assert!(
                error.contains("capability") || error.contains("permission"),
                "{error}"
            );
        }
    }
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
            expected_generation: None,
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
            expected_generation: None,
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
