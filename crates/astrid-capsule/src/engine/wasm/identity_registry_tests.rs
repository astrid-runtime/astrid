//! The production Store factory must give each Store its own identity maps.
use std::sync::Arc;

use astrid_core::principal::PrincipalId;

use super::*;
use crate::context::CapsuleContext;
use crate::engine::ExecutionEngine;

#[tokio::test]
async fn production_factory_isolates_equal_resource_reps() {
    let wasm = wat::parse_str("(component)").expect("component");
    let capsule_dir = tempfile::tempdir().expect("capsule dir");
    let workspace = tempfile::tempdir().expect("workspace");
    std::fs::write(
        capsule_dir.path().join("Capsule.toml"),
        "[package]\nname = \"identity-pool\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"component.wasm\"\n",
    )
    .expect("manifest");
    std::fs::write(capsule_dir.path().join("component.wasm"), &wasm).expect("component");
    let wasm_hash = blake3::hash(&wasm).to_hex().to_string();
    std::fs::write(
        capsule_dir.path().join("meta.json"),
        serde_json::json!({"wasm_hash": wasm_hash}).to_string(),
    )
    .expect("metadata");
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(workspace.path())
        .status()
        .expect("git init makes the portal git-managed so load does not touch an Astrid home");

    let manifest = crate::discovery::load_manifest(&capsule_dir.path().join("Capsule.toml"))
        .expect("manifest loads");
    let limits = limits::CapsuleRuntimeLimits {
        instance_pool_size: 2,
        ..limits::CapsuleRuntimeLimits::default()
    };
    let mut engine = WasmEngine::new(
        manifest,
        capsule_dir.path().to_path_buf(),
        crate::FuelLedger::default(),
        crate::FuelRateLimiter::default(),
        crate::MemoryLedger::default(),
        limits,
        limits::HttpLimits::default(),
    );
    let kv = astrid_storage::ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "identity-pool",
    )
    .expect("kv");
    let ctx = CapsuleContext::new(
        PrincipalId::new("identity-pool").expect("principal"),
        workspace.path().to_path_buf(),
        None,
        kv,
        Arc::new(astrid_events::EventBus::new()),
        None,
    );

    engine.load(&ctx).await.expect("production factory loads");
    {
        let pool = engine.pool.as_ref().expect("pooled capsule");
        let (mut first, mut second) = pool.two_factory_states();
        let first_rep = first.resource_table.push(()).expect("first rep").rep();
        let second_rep = second.resource_table.push(()).expect("second rep").rep();
        assert_eq!(
            first_rep, second_rep,
            "fresh resource tables allocate the same first rep"
        );

        let alice = PrincipalId::new("alice").expect("alice");
        let bob = PrincipalId::new("bob").expect("bob");
        first.bind_connection_principal(first_rep, alice.clone(), None);
        second.bind_connection_principal(second_rep, bob.clone(), None);
        assert_eq!(
            first
                .connection_principals
                .get(&first_rep)
                .expect("alice binding")
                .principal
                .as_str(),
            "alice"
        );
        assert_eq!(
            second
                .connection_principals
                .get(&second_rep)
                .expect("bob binding")
                .principal
                .as_str(),
            "bob"
        );

        first.client_connections.insert(first_rep, alice);
        second.client_connections.insert(second_rep, bob);
        assert_eq!(
            first
                .client_connections
                .get(&first_rep)
                .expect("alice client")
                .as_str(),
            "alice"
        );
        assert_eq!(
            second
                .client_connections
                .get(&second_rep)
                .expect("bob client")
                .as_str(),
            "bob"
        );
    }
    engine.unload().await.expect("unload");
}
