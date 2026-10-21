//! Install and upgrade execute against the same user debt as active capsules.

use super::*;
use crate::user_cpu::tests::accounting;
use astrid_core::PrincipalId;
use std::collections::HashMap;
use std::time::Duration;

fn config(root: &Path, export: &str) -> LifecycleConfig {
    let wasm_bytes = wat::parse_str(format!(
        r#"(component
        (core module $m
            (memory 1)
            (func (export "run")
                (memory.fill (i32.const 0) (i32.const 7) (i32.const 4096))))
        (core instance $i (instantiate $m))
        (func (export "{export}") (canon lift (core func $i "run"))))"#
    ))
    .unwrap();
    let backend = Arc::new(astrid_storage::MemoryKvStore::new());
    let kv = astrid_storage::ScopedKvStore::new(backend.clone(), "lifecycle-cpu").unwrap();
    let secrets = astrid_storage::ScopedKvStore::new(backend, "secrets").unwrap();
    LifecycleConfig {
        wasm_bytes,
        capsule_id: crate::capsule::CapsuleId::new("cpu-hook").unwrap(),
        workspace_root: root.to_path_buf(),
        home_root: None,
        kv,
        event_bus: astrid_events::EventBus::with_capacity(16),
        config: HashMap::new(),
        secret_store: astrid_storage::build_secret_store(
            "cpu-hook",
            secrets,
            tokio::runtime::Handle::current(),
        ),
        http_limits: limits::HttpLimits::default(),
        audit_sink: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_and_upgrade_cancellation_preserve_shared_user_debt() {
    for (phase, export) in [
        (LifecyclePhase::Install, "astrid-install"),
        (LifecyclePhase::Upgrade, "astrid-upgrade"),
    ] {
        let accounting = accounting().await;
        let principal = PrincipalId::new("user-1-agent-1").unwrap();
        let throttle = accounting.configured_throttle(&principal, 0).await.unwrap();
        let peer = accounting
            .configured_throttle(&PrincipalId::new("user-1-agent-2").unwrap(), 0)
            .await
            .unwrap()
            .unwrap();
        let other = accounting
            .configured_throttle(&PrincipalId::new("user-2-agent-1").unwrap(), 0)
            .await
            .unwrap()
            .unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            run_lifecycle_for_principal(
                config(workspace.path(), export),
                phase,
                None,
                LifecyclePrincipalContext::new(principal).with_execution_throttle(throttle),
            ),
        )
        .await;
        assert!(
            result.is_err(),
            "{export} must wait for bulk-operation repayment, got {result:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.wait())
                .await
                .is_err(),
            "{export} cancelled hook lost user debt"
        );
        assert!(
            other.delay().is_zero(),
            "{export} charged an unrelated user"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_lifecycle_keeps_existing_unconfigured_behavior() {
    let workspace = tempfile::tempdir().unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        run_lifecycle_for_principal(
            config(workspace.path(), "astrid-install"),
            LifecyclePhase::Install,
            None,
            LifecyclePrincipalContext::new(PrincipalId::default()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
}
