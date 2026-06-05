use std::path::PathBuf;
use std::sync::Arc;

use astrid_capsule::capsule::CapsuleState;
use astrid_capsule::loader::CapsuleLoader;
use astrid_capsule::manifest::{CapabilitiesDef, CapsuleManifest, ComponentDef, PackageDef};
use astrid_events::EventBus;
use astrid_mcp::testing::test_secure_mcp_client;
use astrid_storage::{MemoryKvStore, ScopedKvStore};

use astrid_capsule::context::CapsuleContext;

async fn setup_test_capsule(
    fs_read_caps: Vec<String>,
    fs_write_caps: Vec<String>,
    net_caps: Vec<String>,
) -> Option<(Box<dyn astrid_capsule::capsule::Capsule>, tempfile::TempDir)> {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test-all-endpoints.wasm");

    if !fixture_path.exists() {
        eprintln!(
            "Skipping test: Fixture not found at {}",
            fixture_path.display()
        );
        return None;
    }

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
            net: net_caps,
            net_bind: vec![],
            net_connect: vec![],
            kv: vec!["*".into()],
            fs_read: fs_read_caps,
            fs_write: fs_write_caps,
            host_process: vec![],
            uplink: false,
            ipc_publish: vec![],
            ipc_subscribe: vec!["test.*".into()],
            identity: vec![],
            allow_prompt_injection: false,
        },
        env: std::collections::HashMap::default(),
        context_files: vec![],
        commands: vec![],
        mcp_servers: vec![],
        skills: vec![],
        uplinks: vec![],
        interceptors: vec![],
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
        .create_capsule(manifest, fixture_path.parent().unwrap().to_path_buf())
        .expect("Failed to create capsule");

    let temp_workspace = tempfile::tempdir().unwrap();

    let kv = ScopedKvStore::new(Arc::new(MemoryKvStore::new()), "test-plugin").unwrap();
    let event_bus = Arc::new(EventBus::with_capacity(128));
    let ctx = CapsuleContext::new(
        astrid_core::PrincipalId::default(),
        temp_workspace.path().to_path_buf(),
        None,
        kv.clone(),
        event_bus.clone(),
        None,
    );

    capsule.load(&ctx).await.expect("Failed to load capsule");
    assert_eq!(capsule.state(), CapsuleState::Ready);

    Some((capsule, temp_workspace))
}

/// Like `setup_test_capsule` but with a separate home root directory for
/// testing the `home://` VFS scheme end-to-end.
async fn setup_test_capsule_with_home(
    fs_read_caps: Vec<String>,
    fs_write_caps: Vec<String>,
) -> Option<(
    Box<dyn astrid_capsule::capsule::Capsule>,
    tempfile::TempDir,
    tempfile::TempDir,
)> {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test-all-endpoints.wasm");

    if !fixture_path.exists() {
        eprintln!(
            "Skipping test: Fixture not found at {}",
            fixture_path.display()
        );
        return None;
    }

    let manifest = CapsuleManifest {
        package: PackageDef {
            name: "test-plugin-home".into(),
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
            fs_read: fs_read_caps,
            fs_write: fs_write_caps,
            host_process: vec![],
            uplink: false,
            ipc_publish: vec![],
            ipc_subscribe: vec![],
            identity: vec![],
            allow_prompt_injection: false,
        },
        env: std::collections::HashMap::default(),
        context_files: vec![],
        commands: vec![],
        mcp_servers: vec![],
        skills: vec![],
        uplinks: vec![],
        interceptors: vec![],
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
        .create_capsule(manifest, fixture_path.parent().unwrap().to_path_buf())
        .expect("Failed to create capsule");

    let temp_workspace = tempfile::tempdir().unwrap();
    let temp_home = tempfile::tempdir().unwrap();

    let kv = ScopedKvStore::new(Arc::new(MemoryKvStore::new()), "test-plugin-home").unwrap();
    let event_bus = Arc::new(EventBus::with_capacity(128));
    let ctx = CapsuleContext::new(
        astrid_core::PrincipalId::default(),
        temp_workspace.path().to_path_buf(),
        Some(temp_home.path().to_path_buf()),
        kv.clone(),
        event_bus.clone(),
        None,
    );

    capsule.load(&ctx).await.expect("Failed to load capsule");
    assert_eq!(capsule.state(), CapsuleState::Ready);

    Some((capsule, temp_workspace, temp_home))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_basic_log() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_malicious_log_rejected() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_malicious_kv_rejected() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_ipc_limits() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_vfs_path_traversal() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_http_security_gate() {
    let Some((_capsule, _tmp)) =
        setup_test_capsule(vec![], vec![], vec!["api.github.com".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_malicious_http_headers() {
    let Some((_capsule, _tmp)) = setup_test_capsule(vec![], vec![], vec!["*".into()]).await else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_vfs_legitimate_rw() {
    let Some((_capsule, _temp_dir)) =
        setup_test_capsule(vec!["/".into()], vec!["/".into()], vec!["*".into()]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_home_vfs_read() {
    let Some((_capsule, _temp_ws, _temp_home)) =
        setup_test_capsule_with_home(vec!["cwd://".into(), "home://".into()], vec![]).await
    else {
        return;
    };
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "tool dispatch migrating to IPC convention"]
async fn test_wasm_capsule_e2e_home_vfs_denied_without_capability() {
    let Some((_capsule, _temp_ws, _temp_home)) =
        setup_test_capsule_with_home(vec!["cwd://".into()], vec![]).await
    else {
        return;
    };
}
