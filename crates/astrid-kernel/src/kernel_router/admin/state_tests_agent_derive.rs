//! Atomic derived-principal provisioning tests (#1217).

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::{BUILTIN_ADMIN, BUILTIN_RESTRICTED};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminResponseBody, AgentDeriveRequest};
use astrid_storage::{FileSecretStore, SecretStore};

use crate::Kernel;

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
    kernel
        .identity_store
        .create_principal(PrincipalId::default(), [7; 32])
        .await
        .unwrap();
    (dir, kernel)
}

fn seed_capsule(kernel: &Kernel, source: &PrincipalId, capsule: &str) {
    let dir = kernel
        .astrid_home
        .principal_home(source)
        .capsules_dir()
        .join(capsule);
    std::fs::create_dir_all(&dir).unwrap();
    let env = if capsule == "provider" {
        "\n[env.API_KEY]\ntype = \"secret\"\n"
    } else {
        ""
    };
    std::fs::write(
        dir.join("Capsule.toml"),
        format!("[package]\nname = \"{capsule}\"\nversion = \"1.0.0\"\n{env}"),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_materializes_only_named_capsules_and_state() {
    let (_dir, kernel) = fixture().await;
    let source = PrincipalId::default();
    for capsule in ["harness", "provider", "unrelated"] {
        seed_capsule(&kernel, &source, capsule);
    }
    let source_env = kernel.astrid_home.principal_home(&source).env_dir();
    std::fs::create_dir_all(&source_env).unwrap();
    std::fs::write(
        source_env.join("provider.env.json"),
        br#"{"api_key":"secret"}"#,
    )
    .unwrap();
    std::fs::write(
        source_env.join("unrelated.env.json"),
        br#"{"private":"data"}"#,
    )
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
    let source_secrets = FileSecretStore::new(
        kernel
            .astrid_home
            .secrets_dir()
            .join(source.as_str())
            .join("provider"),
    );
    source_secrets.set("API_KEY", "selected-secret").unwrap();

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
    assert!(matches!(response, AdminResponseBody::Success(_)));

    let derived = PrincipalId::new("triage").unwrap();
    let profile = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &derived,
    ))
    .unwrap();
    assert_eq!(profile.groups, vec![BUILTIN_RESTRICTED.to_string()]);
    assert!(profile.grants.is_empty());
    assert!(profile.capsules.is_empty());
    assert_eq!(profile.network.egress, vec!["api.example.com:443"]);

    let home = kernel.astrid_home.principal_home(&derived);
    assert!(home.capsules_dir().join("harness").exists());
    assert!(home.capsules_dir().join("provider").exists());
    assert!(!home.capsules_dir().join("unrelated").exists());
    assert!(home.env_dir().join("provider.env.json").exists());
    assert!(!home.env_dir().join("unrelated.env.json").exists());
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
    let derived_secrets = FileSecretStore::new(
        kernel
            .astrid_home
            .secrets_dir()
            .join(derived.as_str())
            .join("provider"),
    );
    assert_eq!(
        derived_secrets.get("API_KEY").unwrap().as_deref(),
        Some("selected-secret")
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
        .principal_home(&PrincipalId::default())
        .capsules_dir()
        .join("host-mcp/Capsule.toml");
    std::fs::write(
        host_mcp_manifest,
        "[package]\nname = \"host-mcp\"\nversion = \"1.0.0\"\n\n[[mcp_server]]\nid = \"legacy\"\ntype = \"stdio\"\ncommand = \"echo\"\n",
    )
    .unwrap();

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
