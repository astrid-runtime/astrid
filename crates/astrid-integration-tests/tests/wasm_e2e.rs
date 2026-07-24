use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_capsule::capsule::CapsuleState;
use astrid_capsule::loader::CapsuleLoader;
use astrid_capsule::manifest::{
    CapabilitiesDef, CapsuleManifest, ComponentDef, PackageDef, SubscribeDef,
};
use astrid_events::EventBus;
use astrid_mcp::testing::test_secure_mcp_client;
use astrid_storage::{MemoryKvStore, ScopedKvStore};

use astrid_capsule::context::CapsuleContext;

fn build_test_manifest(
    name: &str,
    fixture_path: &Path,
    fs_read_caps: Vec<String>,
    fs_write_caps: Vec<String>,
    net_caps: Vec<String>,
    subscribes: HashMap<String, SubscribeDef>,
) -> CapsuleManifest {
    CapsuleManifest {
        package: PackageDef {
            name: name.into(),
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
            path: fixture_path.to_path_buf(),
            hash: None,
            r#type: "executable".to_string(),
            link: vec![],
            capabilities: None,
        }],
        imports: HashMap::new(),
        exports: HashMap::new(),
        capabilities: CapabilitiesDef {
            net: net_caps,
            net_bind: vec![],
            bind_workers: None,
            net_connect: vec![],
            kv: vec!["*".into()],
            fs_read: fs_read_caps,
            fs_write: fs_write_caps,
            host_process: vec![],
            allow_persistent: false,
            uplink: false,
            identity: vec![],
            allow_prompt_injection: false,
        },
        env: HashMap::default(),
        context_files: vec![],
        commands: vec![],
        mcp_servers: vec![],
        skills: vec![],
        uplinks: vec![],
        publishes: HashMap::new(),
        subscribes,
        tools: vec![],
    }
}

fn default_loader() -> CapsuleLoader {
    CapsuleLoader::new(
        test_secure_mcp_client(),
        astrid_capsule::FuelLedger::default(),
        astrid_capsule::FuelRateLimiter::default(),
        astrid_capsule::MemoryLedger::default(),
        astrid_capsule::CapsuleRuntimeLimits::default(),
        astrid_capsule::HttpLimits::default(),
    )
}

fn fixture_path() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("test-all-endpoints.wasm");
    if path.exists() {
        Some(path)
    } else {
        eprintln!("Skipping test: Fixture not found at {}", path.display());
        None
    }
}

async fn setup_test_capsule(
    fs_read_caps: Vec<String>,
    fs_write_caps: Vec<String>,
    net_caps: Vec<String>,
) -> Option<(Box<dyn astrid_capsule::capsule::Capsule>, tempfile::TempDir)> {
    let fp = fixture_path()?;
    // Subscribe ACL: the `[subscribe]` keys are the only IPC-subscribe
    // declaration (the legacy `ipc_subscribe` array is gone). A handler-less
    // `wit = "opaque"` entry is ACL-only.
    let subscribes = HashMap::from([(
        "test.*".to_string(),
        SubscribeDef {
            wit: "opaque".to_string(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            handler: None,
            priority: None,
        },
    )]);
    let manifest = build_test_manifest(
        "test-plugin",
        &fp,
        fs_read_caps,
        fs_write_caps,
        net_caps,
        subscribes,
    );
    let mut capsule = default_loader()
        .create_capsule(manifest, fp.parent().unwrap().to_path_buf())
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
    let fp = fixture_path()?;
    let manifest = build_test_manifest(
        "test-plugin-home",
        &fp,
        fs_read_caps,
        fs_write_caps,
        vec![],
        HashMap::new(),
    );
    let mut capsule = default_loader()
        .create_capsule(manifest, fp.parent().unwrap().to_path_buf())
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
