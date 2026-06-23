use std::path::PathBuf;
use std::sync::Arc;

use astrid_capsule::context::CapsuleContext;
use astrid_capsule::loader::CapsuleLoader;
use astrid_capsule::manifest::{CapabilitiesDef, CapsuleManifest, ComponentDef, PackageDef};
use astrid_events::EventBus;
use astrid_mcp::testing::test_secure_mcp_client;
use astrid_storage::{MemoryKvStore, ScopedKvStore};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
#[expect(clippy::too_many_lines)]
async fn test_wasm_capsule_e2e_env_config_injection() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test-all-endpoints.wasm");

    if !fixture_path.exists() {
        eprintln!(
            "Skipping test: Fixture not found at {}",
            fixture_path.display()
        );
        return;
    }

    let mut env = std::collections::HashMap::new();
    env.insert(
        "test_key".into(),
        astrid_capsule::manifest::EnvDef {
            env_type: "string".into(),
            default: Some(json!("default_value")),
            request: None,
            description: None,
            enum_values: vec![],
            placeholder: None,
            options_from: None,
            scope: astrid_capsule::manifest::EnvScope::default(),
        },
    );
    env.insert(
        "injected_key".into(),
        astrid_capsule::manifest::EnvDef {
            env_type: "secret".into(),
            default: None,
            request: None,
            description: None,
            enum_values: vec![],
            placeholder: None,
            options_from: None,
            scope: astrid_capsule::manifest::EnvScope::default(),
        },
    );

    let manifest = CapsuleManifest {
        package: PackageDef {
            name: "test-plugin".into(),
            version: "0.1.0".into(),
            description: None,
            authors: vec![],
            repository: None,
            homepage: None,
            documentation: None,
            license: None,
            license_file: None,
            readme: None,
            keywords: vec![],
            categories: vec![],
            astrid_version: None,
            publish: None,
            include: None,
            exclude: None,
            metadata: None,
        },
        components: vec![ComponentDef {
            id: "default".to_string(),
            path: fixture_path.clone(),
            hash: None,
            r#type: "executable".to_string(),
            link: vec![],
            capabilities: None,
        }],
        imports: std::collections::HashMap::new(),
        exports: std::collections::HashMap::new(),
        capabilities: CapabilitiesDef {
            net: vec![],
            net_bind: vec![],
            net_connect: vec![],
            kv: vec!["*".into()],
            fs_read: vec![],
            fs_write: vec![],
            host_process: vec![],
            allow_persistent: false,
            uplink: false,
            identity: vec![],
            allow_prompt_injection: false,
        },
        env,
        context_files: vec![],
        commands: vec![],
        mcp_servers: vec![],
        skills: vec![],
        uplinks: vec![],
        publishes: ::std::collections::HashMap::new(),
        subscribes: ::std::collections::HashMap::new(),
        tools: ::std::vec::Vec::new(),
    };

    let loader = CapsuleLoader::new(
        test_secure_mcp_client(),
        astrid_capsule::FuelLedger::default(),
        astrid_capsule::FuelRateLimiter::default(),
        astrid_capsule::MemoryLedger::default(),
        astrid_capsule::CapsuleRuntimeLimits::default(),
    );
    let mut capsule = loader
        .create_capsule(manifest, fixture_path.parent().unwrap().to_path_buf())
        .unwrap();

    let kv = ScopedKvStore::new(Arc::new(MemoryKvStore::new()), "test-plugin").unwrap();
    // Inject a value into the KV store for the engine to read
    kv.set("injected_key", b"injected_value".to_vec())
        .await
        .unwrap();

    let event_bus = Arc::new(EventBus::with_capacity(128));
    let ctx = CapsuleContext::new(
        astrid_core::PrincipalId::default(),
        std::env::current_dir().unwrap(),
        None,
        kv.clone(),
        event_bus.clone(),
        None,
    );

    capsule.load(&ctx).await.unwrap();

    let _ = capsule;
}
