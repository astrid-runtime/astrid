use std::sync::Arc;

use astrid_capsule::capsule::{Capsule, CapsuleState, InterceptResult};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::registry::WasmHash;
use astrid_capsule_types::CapsuleId;
use astrid_capsule_types::manifest::CapsuleManifest;
use astrid_core::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use serde_json::json;

use super::test_kernel_with_home;

fn scratch_home() -> (tempfile::TempDir, astrid_core::dirs::AstridHome) {
    let dir = tempfile::tempdir().expect("scratch directory");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    (dir, home)
}

struct SnapshotCapsule {
    id: CapsuleId,
    tool_name: String,
}

struct StalledCapsule {
    id: CapsuleId,
    tool_name: String,
    stall: Arc<std::sync::atomic::AtomicBool>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl Capsule for SnapshotCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        static MANIFEST: std::sync::OnceLock<CapsuleManifest> = std::sync::OnceLock::new();
        MANIFEST.get_or_init(CapsuleManifest::default)
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

    async fn invoke_interceptor(
        &self,
        action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        assert_eq!(action, "tool_describe");
        Ok(InterceptResult::Continue(
            serde_json::to_vec(&json!({
                "tools": [{
                    "name": self.tool_name,
                    "description": "",
                    "input_schema": {},
                }]
            }))
            .expect("serialize descriptor"),
        ))
    }
}

#[async_trait::async_trait]
impl Capsule for StalledCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        static MANIFEST: std::sync::OnceLock<CapsuleManifest> = std::sync::OnceLock::new();
        MANIFEST.get_or_init(CapsuleManifest::default)
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

    async fn invoke_interceptor(
        &self,
        action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        assert_eq!(action, "tool_describe");
        if !self.stall.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        Ok(InterceptResult::Continue(
            serde_json::to_vec(&json!({
                "tools": [{
                    "name": self.tool_name,
                    "description": "",
                    "input_schema": {},
                }]
            }))
            .expect("serialize descriptor"),
        ))
    }
}

fn write_profile(home: &astrid_core::dirs::AstridHome, principal: &PrincipalId, capsules: &[&str]) {
    PrincipalProfile {
        capsules: capsules
            .iter()
            .map(|capsule| (*capsule).to_string())
            .collect(),
        ..PrincipalProfile::default()
    }
    .save_to_path(&PrincipalProfile::path_for(home, principal))
    .expect("save profile");
}

fn names(snapshot: &super::mcp_snapshot::McpToolSnapshot) -> std::collections::BTreeSet<String> {
    snapshot
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn delayed_snapshot_completion_cannot_publish_over_newer_mutation() {
    let (_dir, home) = scratch_home();
    let kernel = test_kernel_with_home(home.clone()).await;
    let alice = PrincipalId::new("alice").expect("alice principal");
    write_profile(&home, &alice, &["tool-alpha"]);

    let alpha_id = CapsuleId::new("tool-alpha").expect("alpha id");
    let alpha = Arc::new(StalledCapsule {
        id: alpha_id.clone(),
        tool_name: "captured".to_string(),
        stall: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        started: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
    });
    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register_for(
                Box::new(StalledCapsule {
                    id: alpha.clone().id().clone(),
                    tool_name: alpha.tool_name.clone(),
                    stall: Arc::clone(&alpha.stall),
                    started: Arc::clone(&alpha.started),
                    release: Arc::clone(&alpha.release),
                }),
                WasmHash::from_raw("alpha-alice"),
                &alice,
            )
            .expect("register stalled capsule");
    }

    let delayed = tokio::spawn({
        let kernel = Arc::clone(&kernel);
        let alice = alice.clone();
        async move { kernel.refresh_mcp_snapshot(&alice).await }
    });
    alpha.started.notified().await;

    {
        let mut registry = kernel.capsules.write().await;
        let _ = registry
            .unregister_for(&alice, &alpha_id)
            .expect("replace stalled capsule");
        registry
            .register_for(
                Box::new(SnapshotCapsule {
                    id: alpha_id.clone(),
                    tool_name: "current".to_string(),
                }),
                WasmHash::from_raw("alpha-alice-replacement"),
                &alice,
            )
            .expect("register current capsule");
    }
    let newer_epoch = kernel
        .refresh_mcp_snapshot(&alice)
        .await
        .expect("current refresh");
    alpha.release.notify_one();
    let delayed_result = delayed
        .await
        .expect("delayed task joins")
        .expect_err("delayed capture is stale");
    assert!(delayed_result.to_string().contains("superseded"));

    let snapshot = kernel.mcp_snapshot_for(&alice).await.expect("snapshot");
    assert_eq!(snapshot.epoch, newer_epoch);
    assert_eq!(
        names(&snapshot),
        std::collections::BTreeSet::from(["current".into()])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_cross_capsule_names_fail_closed_and_retain_prior_snapshot() {
    let (_dir, home) = scratch_home();
    let kernel = test_kernel_with_home(home.clone()).await;
    let alice = PrincipalId::new("alice").expect("alice principal");
    write_profile(&home, &alice, &["tool-alpha"]);

    let alpha_id = CapsuleId::new("tool-alpha").expect("alpha id");
    let beta_id = CapsuleId::new("tool-beta").expect("beta id");
    {
        let mut registry = kernel.capsules.write().await;
        for id in [&alpha_id, &beta_id] {
            registry
                .register_for(
                    Box::new(SnapshotCapsule {
                        id: id.clone(),
                        tool_name: "shared".to_string(),
                    }),
                    WasmHash::from_raw(id.as_str()),
                    &alice,
                )
                .expect("register capsule");
        }
    }
    let good_epoch = kernel
        .refresh_mcp_snapshot(&alice)
        .await
        .expect("one allowed surface");

    write_profile(&home, &alice, &["tool-alpha", "tool-beta"]);
    kernel.profile_cache.invalidate(&alice);
    let duplicate = kernel
        .refresh_mcp_snapshot(&alice)
        .await
        .expect_err("duplicate MCP names fail closed");
    assert!(duplicate.to_string().contains("duplicate MCP tool name"));

    let retained = kernel.mcp_snapshot_for(&alice).await.expect("old snapshot");
    assert_eq!(retained.epoch, good_epoch);
    assert_eq!(
        retained
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec!["shared"]
    );
}

async fn register_lifecycle_capsules(
    kernel: &crate::Kernel,
    principals: &[&PrincipalId],
    alpha: &CapsuleId,
    beta: &CapsuleId,
) {
    let mut registry = kernel.capsules.write().await;
    for principal in principals {
        registry
            .register_for(
                Box::new(SnapshotCapsule {
                    id: alpha.clone(),
                    tool_name: "alpha".to_string(),
                }),
                WasmHash::from_raw(format!("alpha-{}", principal.as_str())),
                principal,
            )
            .expect("register alpha");
        registry
            .register_for(
                Box::new(SnapshotCapsule {
                    id: beta.clone(),
                    tool_name: "beta".to_string(),
                }),
                WasmHash::from_raw(format!("beta-{}", principal.as_str())),
                principal,
            )
            .expect("register beta");
    }
}

async fn assert_refresh(
    kernel: &crate::Kernel,
    principal: &PrincipalId,
    label: &'static str,
    expected_epoch: u64,
    tools: &[&str],
) {
    let epoch = kernel.refresh_mcp_snapshot(principal).await.expect(label);
    assert_eq!(epoch.get(), expected_epoch);
    let snapshot = kernel.mcp_snapshot_for(principal).await.expect(label);
    let expected = tools.iter().map(|tool| (*tool).to_string()).collect();
    assert_eq!(names(&snapshot), expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_intersect_grants_and_advance_for_lifecycle_changes() {
    let (_dir, home) = scratch_home();
    let kernel = test_kernel_with_home(home.clone()).await;
    let alice = PrincipalId::new("alice").expect("alice principal");
    let bob = PrincipalId::new("bob").expect("bob principal");
    write_profile(&home, &alice, &["tool-alpha"]);
    write_profile(&home, &bob, &["tool-beta"]);

    let alpha = CapsuleId::new("tool-alpha").expect("alpha id");
    let beta = CapsuleId::new("tool-beta").expect("beta id");
    register_lifecycle_capsules(&kernel, &[&alice, &bob], &alpha, &beta).await;
    assert_refresh(&kernel, &alice, "load snapshot", 1, &["alpha"]).await;
    assert_refresh(&kernel, &bob, "bob snapshot", 1, &["beta"]).await;

    write_profile(&home, &alice, &["tool-alpha", "tool-beta"]);
    kernel.profile_cache.invalidate(&alice);
    assert_refresh(&kernel, &alice, "grant snapshot", 2, &["alpha", "beta"]).await;

    write_profile(&home, &alice, &["tool-beta"]);
    kernel.profile_cache.invalidate(&alice);
    assert_refresh(&kernel, &alice, "revoke snapshot", 3, &["beta"]).await;

    {
        let mut registry = kernel.capsules.write().await;
        let _ = registry
            .unregister_for(&alice, &beta)
            .expect("replace removal");
        registry
            .register_for(
                Box::new(SnapshotCapsule {
                    id: beta.clone(),
                    tool_name: "beta-replaced".to_string(),
                }),
                WasmHash::from_raw("beta-alice-replacement"),
                &alice,
            )
            .expect("register replacement");
    }
    assert_refresh(
        &kernel,
        &alice,
        "replacement snapshot",
        4,
        &["beta-replaced"],
    )
    .await;

    {
        let mut registry = kernel.capsules.write().await;
        let _ = registry
            .unregister_for(&alice, &beta)
            .expect("unload removal");
    }
    assert_refresh(&kernel, &alice, "valid empty view", 5, &[]).await;
}
