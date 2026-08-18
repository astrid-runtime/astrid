//! Atomic derived-principal provisioning tests (#1217).

use std::sync::Arc;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::{CapsuleManifest, PackageDef};
use astrid_capsule::registry::WasmHash;
use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_RESTRICTED};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminResponseBody, AgentDeriveRequest};
use astrid_storage::ScopedKvStore;
use astrid_storage::env::{SECRET_KEY_PREFIX, principal_secret_namespace};

use crate::Kernel;

struct ReadyCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

impl ReadyCapsule {
    fn new(name: &str) -> Self {
        Self {
            id: CapsuleId::new(name).unwrap(),
            manifest: CapsuleManifest {
                package: PackageDef {
                    name: name.to_owned(),
                    version: "1.0.0".to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }
}

#[async_trait::async_trait]
impl Capsule for ReadyCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }

    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }

    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        Ok(())
    }
}

async fn fixture() -> (tempfile::TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().unwrap();
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let admin = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..Default::default()
    };
    admin
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .unwrap();
    kernel.profile_cache.invalidate(&PrincipalId::default());
    (dir, kernel)
}

fn seed_capsule(kernel: &Kernel, source: &PrincipalId, capsule: &str) {
    // Principal capsule authority is now the UID-bound durable registry.  The
    // test source tree is only an untrusted install input; it must not seed a
    // legacy `home://` directory and then expect discovery to trust it.
    let dir = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources")
        .join(capsule);
    std::fs::create_dir_all(&dir).unwrap();
    let env = if capsule == "provider" {
        "\n[env.API_KEY]\ntype = \"secret\"\n"
    } else {
        ""
    };
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            "[package]\nname = \"{capsule}\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\n{env}"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("main.wasm"), b"\0asm\r\0\x01\0").unwrap();
    publish_capsule_source(kernel, source, &dir);
}

fn publish_capsule_source(kernel: &Kernel, source: &PrincipalId, dir: &std::path::Path) {
    let dir = dir.to_path_buf();
    let home = kernel.astrid_home.clone();
    let storage = kernel
        .principal_store
        .as_ref()
        .map(|store| Arc::new(store.clone()));
    let source = source.clone();
    std::thread::spawn(move || {
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
    .expect("publish test capsule thread")
    .expect("publish test capsule to durable registry");
}

async fn seed_source_state(kernel: &Kernel, source: &PrincipalId) {
    let source_secrets = ScopedKvStore::new(
        Arc::clone(&kernel.kv),
        principal_secret_namespace(
            kernel.principal_directory.uid_for(source).unwrap(),
            "provider",
        ),
    )
    .unwrap();
    source_secrets
        .set(
            &format!("{SECRET_KEY_PREFIX}API_KEY"),
            b"selected-secret".to_vec(),
        )
        .await
        .unwrap();
    kernel
        .kv
        .set("default:capsule:provider", "model", b"selected".to_vec())
        .await
        .unwrap();
    kernel
        .kv
        .set("default:capsule:unrelated", "private", b"excluded".to_vec())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_materializes_only_named_capsules_and_state() {
    let (_dir, kernel) = fixture().await;
    let source = PrincipalId::default();
    for capsule in ["harness", "provider", "unrelated"] {
        seed_capsule(&kernel, &source, capsule);
    }
    seed_source_state(&kernel, &source).await;
    let derived = PrincipalId::new("triage").unwrap();
    {
        let mut registry = kernel.capsules.write().await;
        for capsule in ["harness", "provider"] {
            registry
                .register_for(
                    Box::new(ReadyCapsule::new(capsule)),
                    WasmHash::synthetic(capsule, "1.0.0"),
                    &derived,
                )
                .unwrap();
        }
    }
    let response = super::agent_derive::agent_derive_from_req(
        &kernel,
        AgentDeriveRequest {
            name: "triage".into(),
            source: source.clone(),
            load_capsules: vec!["harness".into(), "provider".into()],
            allow_capsules: Vec::new(),
            inherit_capsule_state: vec!["provider".into()],
            network_egress: vec!["api.example.com:443".into()],
        },
    )
    .await;
    assert!(
        matches!(response, AdminResponseBody::Success(_)),
        "derive failed: {response:?}"
    );

    let profile = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &derived,
    ))
    .unwrap();
    assert_eq!(profile.groups, vec![BUILTIN_RESTRICTED.to_string()]);
    assert!(profile.grants.is_empty());
    assert!(profile.capsules.is_empty());
    assert_eq!(profile.network.egress, vec!["api.example.com:443"]);

    let derived_uid = kernel.principal_directory.uid_for(&derived).unwrap();
    let owner = astrid_storage::StateOwner::Principal(derived_uid);
    let registry = kernel.principal_store.as_ref().unwrap().capsules();
    assert!(registry.get(&owner, "harness").unwrap().is_some());
    assert!(registry.get(&owner, "provider").unwrap().is_some());
    assert!(registry.get(&owner, "unrelated").unwrap().is_none());
    assert!(!kernel.astrid_home.principal_home(&derived).root().exists());
    assert_eq!(
        kernel
            .kv
            .get("triage:capsule:provider", "model")
            .await
            .unwrap(),
        Some(b"selected".to_vec())
    );
    assert!(
        kernel
            .kv
            .get("triage:capsule:unrelated", "private")
            .await
            .unwrap()
            .is_none()
    );
    let derived_secrets = ScopedKvStore::new(
        Arc::clone(&kernel.kv),
        principal_secret_namespace(derived_uid, "provider"),
    )
    .unwrap();
    assert_eq!(
        derived_secrets
            .get(&format!("{SECRET_KEY_PREFIX}API_KEY"))
            .await
            .unwrap()
            .as_deref(),
        Some(b"selected-secret".as_slice())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_rejects_state_or_tool_capsules_outside_loaded_set() {
    let (_dir, kernel) = fixture().await;
    let response = super::agent_derive::agent_derive_from_req(
        &kernel,
        AgentDeriveRequest {
            name: "bad".into(),
            source: PrincipalId::default(),
            load_capsules: vec!["harness".into()],
            allow_capsules: vec!["shell".into()],
            inherit_capsule_state: Vec::new(),
            network_egress: Vec::new(),
        },
    )
    .await;
    assert!(matches!(response, AdminResponseBody::Error(_)));
    assert!(
        !PrincipalProfile::path_for(&kernel.astrid_home, &PrincipalId::new("bad").unwrap())
            .exists()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_rejects_invalid_shape_without_leaving_identity_artifacts() {
    let (_dir, kernel) = fixture().await;
    seed_capsule(&kernel, &PrincipalId::default(), "harness");
    seed_capsule(&kernel, &PrincipalId::default(), "host-mcp");
    let host_mcp_manifest = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources/host-mcp/Capsule.toml");
    std::fs::write(
        &host_mcp_manifest,
        "[package]\nname = \"host-mcp\"\nversion = \"1.0.0\"\n\n[[mcp_server]]\nid = \"legacy\"\ntype = \"stdio\"\ncommand = \"echo\"\n",
    )
    .unwrap();
    publish_capsule_source(
        &kernel,
        &PrincipalId::default(),
        host_mcp_manifest.parent().unwrap(),
    );

    let cases = [
        (
            "duplicate",
            AgentDeriveRequest {
                name: "duplicate".into(),
                source: PrincipalId::default(),
                load_capsules: vec!["harness".into(), "harness".into()],
                allow_capsules: Vec::new(),
                inherit_capsule_state: Vec::new(),
                network_egress: Vec::new(),
            },
        ),
        (
            "malformed-egress",
            AgentDeriveRequest {
                name: "malformed-egress".into(),
                source: PrincipalId::default(),
                load_capsules: vec!["harness".into()],
                allow_capsules: Vec::new(),
                inherit_capsule_state: Vec::new(),
                network_egress: vec!["api.example.com".into()],
            },
        ),
        (
            "anonymous",
            AgentDeriveRequest {
                name: "anonymous".into(),
                source: PrincipalId::default(),
                load_capsules: vec!["harness".into()],
                allow_capsules: Vec::new(),
                inherit_capsule_state: Vec::new(),
                network_egress: Vec::new(),
            },
        ),
        (
            "native-engine",
            AgentDeriveRequest {
                name: "native-engine".into(),
                source: PrincipalId::default(),
                load_capsules: vec!["host-mcp".into()],
                allow_capsules: Vec::new(),
                inherit_capsule_state: Vec::new(),
                network_egress: Vec::new(),
            },
        ),
    ];

    for (name, request) in cases {
        let response = super::agent_derive::agent_derive_from_req(&kernel, request).await;
        assert!(matches!(response, AdminResponseBody::Error(_)));
        let principal = PrincipalId::new(name).unwrap();
        assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists());
        assert!(
            !kernel
                .astrid_home
                .keys_dir()
                .join(format!("{principal}.key"))
                .exists()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_rolls_back_when_required_capsule_cannot_load() {
    let (_dir, kernel) = fixture().await;
    let source = PrincipalId::default();
    let install = kernel
        .astrid_home
        .run_dir()
        .join("test-install-sources/broken-harness");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::write(
        install.join("Capsule.toml"),
        r#"[package]
name = "broken-harness"
version = "1.0.0"

[[component]]
id = "main"
file = "missing.wasm"
"#,
    )
    .unwrap();
    std::fs::write(install.join("missing.wasm"), b"not-a-wasm-component").unwrap();
    crate::capsule_adversarial_tests::publish_without_running_lifecycle(&kernel, &source, &install)
        .expect("publish broken capsule fixture without lifecycle execution");

    let response = super::agent_derive::agent_derive_from_req(
        &kernel,
        AgentDeriveRequest {
            name: "broken-worker".into(),
            source,
            load_capsules: vec!["broken-harness".into()],
            allow_capsules: Vec::new(),
            inherit_capsule_state: Vec::new(),
            network_egress: Vec::new(),
        },
    )
    .await;
    let AdminResponseBody::Error(error) = response else {
        panic!("broken required capsule must fail derivation")
    };
    assert!(error.contains("failed to load"), "got: {error}");

    let principal = PrincipalId::new("broken-worker").unwrap();
    assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &principal).exists());
    assert!(
        kernel
            .identity_store
            .resolve("cli", principal.as_str())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !kernel
            .astrid_home
            .principal_home(&principal)
            .root()
            .exists()
    );
}
