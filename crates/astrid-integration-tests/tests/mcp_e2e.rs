use std::path::PathBuf;
use std::sync::Arc;

use astrid_capsule::context::CapsuleContext;
use astrid_capsule::loader::CapsuleLoader;
use astrid_capsule::manifest::{CapabilitiesDef, CapsuleManifest, McpServerDef, PackageDef};
use astrid_events::EventBus;
use astrid_mcp::testing::test_secure_mcp_client;
use astrid_storage::{MemoryKvStore, ScopedKvStore};

#[tokio::test]
async fn test_mcp_host_engine_capability_validation() {
    let manifest = CapsuleManifest {
        package: PackageDef {
            name: "test-mcp".into(),
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
        components: vec![],
        imports: std::collections::HashMap::new(),
        exports: std::collections::HashMap::new(),
        capabilities: CapabilitiesDef {
            net: vec![],
            net_bind: vec![],
            net_connect: vec![],
            kv: vec![],
            fs_read: vec![],
            fs_write: vec![],
            host_process: vec!["npx".into()], // Only "npx" is allowed
            uplink: false,
            identity: vec![],
            allow_prompt_injection: false,
        },
        env: std::collections::HashMap::default(),
        context_files: vec![],
        commands: vec![],
        mcp_servers: vec![McpServerDef {
            id: "denied-mcp".into(),
            description: None,
            server_type: Some("stdio".into()),
            command: Some("python3".into()), // "python3" is NOT allowed
            args: vec!["server.py".into()],
        }],
        skills: vec![],
        uplinks: vec![],
        topics: vec![],
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
        .create_capsule(manifest, PathBuf::from("/tmp"))
        .unwrap();

    let kv = ScopedKvStore::new(Arc::new(MemoryKvStore::new()), "test-mcp").unwrap();
    let event_bus = Arc::new(EventBus::with_capacity(128));
    let ctx = CapsuleContext::new(
        astrid_core::PrincipalId::default(),
        std::env::current_dir().unwrap(),
        None,
        kv.clone(),
        event_bus.clone(),
        None,
    );

    let result = capsule.load(&ctx).await;

    // The load should fail because the second MCP server ("denied-mcp") requests "python3",
    // which is not in the `host_process` capability array!
    assert!(result.is_err(), "Load should fail due to capability denial");
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains("Security Check Failed"));
    assert!(err_str.contains("host_process capability for 'python3' was not declared"));
}
