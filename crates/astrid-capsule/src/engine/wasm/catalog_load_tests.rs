use std::sync::Arc;

use super::*;
use crate::context::CapsuleContext;
use crate::engine::ExecutionEngine;
use astrid_core::dirs::AstridHome;
use astrid_storage::{KvQuotaResolver, StateOwner};

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|owner: &StateOwner| {
        Ok(match owner {
            StateOwner::System => None,
            StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
        })
    })
}

#[tokio::test]
async fn bound_load_refuses_host_wasm_when_catalog_entry_is_missing_or_tampered() {
    let component_bytes = wat::parse_str("(component)").expect("valid component");
    let expected_hash = blake3::hash(&component_bytes).to_hex().to_string();

    for catalog_bytes in [None, Some(b"tampered catalog bytes".as_slice())] {
        let capsule_dir = tempfile::tempdir().expect("capsule directory");
        let home_dir = tempfile::tempdir().expect("home directory");
        let workspace_dir = tempfile::tempdir().expect("workspace directory");
        let home = AstridHome::from_path(home_dir.path());
        home.ensure().expect("ensure home");

        std::fs::write(
            capsule_dir.path().join("Capsule.toml"),
            "[package]\nname = \"catalog-load\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"component.wasm\"\n",
        )
        .expect("manifest");
        std::fs::write(capsule_dir.path().join("component.wasm"), &component_bytes)
            .expect("component");
        std::fs::write(
            capsule_dir.path().join("meta.json"),
            serde_json::json!({"wasm_hash": expected_hash}).to_string(),
        )
        .expect("metadata");

        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("principal store");
        let host_component = home.bin_dir().join(format!("{expected_hash}.wasm"));
        std::fs::create_dir_all(host_component.parent().unwrap()).expect("bin directory");
        std::fs::write(&host_component, &component_bytes).expect("host projection");
        drop(store);

        // An active run may legitimately create a new projected component.
        // The regression starts from that recovered generation and then makes
        // its catalog authority missing or corrupt, proving the host copy is
        // still not selected.
        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("recover active projection");
        let name = astrid_storage::ContentName::new(format!("bin/{expected_hash}.wasm"))
            .expect("catalog name");
        if catalog_bytes.is_none() {
            store
                .content()
                .delete(&StateOwner::System, &name)
                .expect("remove catalog authority");
        }
        if let Some(bytes) = catalog_bytes {
            store
                .content()
                .put(&StateOwner::System, &name, bytes)
                .expect("tampered catalog entry");
        }

        let manifest = crate::discovery::load_manifest(&capsule_dir.path().join("Capsule.toml"))
            .expect("manifest loads");
        let mut engine = WasmEngine::new(
            manifest,
            capsule_dir.path().to_path_buf(),
            crate::FuelLedger::default(),
            crate::FuelRateLimiter::default(),
            crate::MemoryLedger::default(),
            limits::CapsuleRuntimeLimits::default(),
            limits::HttpLimits::default(),
        );
        let kv = astrid_storage::ScopedKvStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            "catalog-load",
        )
        .expect("test KV");
        let ctx = CapsuleContext::new(
            astrid_core::PrincipalId::new("catalog-loader").expect("principal"),
            workspace_dir.path().to_path_buf(),
            Some(home.root().to_path_buf()),
            kv,
            Arc::new(astrid_events::EventBus::new()),
            None,
        )
        .with_principal_storage(store, astrid_storage::PrincipalDirectory::default());

        let error = engine
            .load(&ctx)
            .await
            .expect_err("bound load must not use a host projection");
        assert!(matches!(
            error,
            crate::error::CapsuleError::UnsupportedEntryPoint(message)
                if message.contains("refusing to load from a host path")
        ));
    }
}

#[tokio::test]
async fn load_refuses_a_component_reserved_for_a_different_storage_owner() {
    let capsule = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let bytes = wat::parse_str("(component)").unwrap();
    let manifest: CapsuleManifest = toml::from_str(
        r#"
        [package]
        name = "owner-test"
        version = "1.0.0"
        [[component]]
        id = "main"
        file = "main.wasm"
    "#,
    )
    .unwrap();
    std::fs::write(capsule.path().join("main.wasm"), &bytes).unwrap();
    std::fs::write(
        capsule.path().join("meta.json"),
        serde_json::json!({"wasm_hash":blake3::hash(&bytes).to_hex().to_string()}).to_string(),
    )
    .unwrap();
    let runtime = crate::registry::RuntimeId::for_test_scope(
        crate::capsule::CapsuleId::from_static("owner-test"),
        1,
        crate::registry::RuntimeScope::Principal(astrid_core::PrincipalUid::from_bytes([1; 32])),
    );
    let mut engine = WasmEngine::new(
        manifest,
        capsule.path().to_owned(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        limits::CapsuleRuntimeLimits::default(),
        limits::HttpLimits::default(),
    )
    .with_runtime_id(Some(runtime));
    let owner = astrid_core::PrincipalId::default();
    let kv = astrid_storage::ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "owner-test",
    )
    .unwrap();
    let ctx = CapsuleContext::new(
        owner.clone(),
        workspace.path().to_owned(),
        None,
        kv,
        Arc::new(astrid_events::EventBus::new()),
        None,
    );
    ctx.principal_directory
        .register(owner, astrid_core::PrincipalUid::from_bytes([2; 32]))
        .unwrap();
    let result = engine.load(&ctx).await;
    assert!(
        matches!(result, Err(CapsuleError::UnsupportedEntryPoint(reason)) if reason == "principal runtime owner changed before mount setup")
    );
}
