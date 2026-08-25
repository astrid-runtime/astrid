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

        // These host copies prove that a bound load cannot silently select a
        // projection when the authoritative catalog is absent or corrupt.
        std::fs::create_dir_all(home.bin_dir()).expect("bin directory");
        std::fs::write(
            home.bin_dir().join(format!("{expected_hash}.wasm")),
            &component_bytes,
        )
        .expect("host projection");

        let store = astrid_storage::open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("principal store");
        if let Some(bytes) = catalog_bytes {
            let name = astrid_storage::ContentName::new(format!("bin/{expected_hash}.wasm"))
                .expect("catalog name");
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
