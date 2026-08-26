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
async fn snapshots_intersect_grants_and_advance_for_lifecycle_changes() {
    let (_dir, home) = scratch_home();
    let kernel = test_kernel_with_home(home.clone()).await;
    let alice = PrincipalId::new("alice").expect("alice principal");
    let bob = PrincipalId::new("bob").expect("bob principal");
    write_profile(&home, &alice, &["tool-alpha"]);
    write_profile(&home, &bob, &["tool-beta"]);

    let alpha = CapsuleId::new("tool-alpha").expect("alpha id");
    let beta = CapsuleId::new("tool-beta").expect("beta id");
    {
        let mut registry = kernel.capsules.write().await;
        for principal in [&alice, &bob] {
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

    let epoch = kernel
        .refresh_mcp_snapshot(&alice)
        .await
        .expect("load snapshot");
    assert_eq!(epoch.get(), 1);
    let alice_snapshot = kernel
        .mcp_snapshot_for(&alice)
        .await
        .expect("alice snapshot");
    assert_eq!(
        names(&alice_snapshot),
        std::collections::BTreeSet::from(["alpha".into()])
    );

    let bob_epoch = kernel
        .refresh_mcp_snapshot(&bob)
        .await
        .expect("bob snapshot");
    assert_eq!(bob_epoch.get(), 1);
    let bob_snapshot = kernel.mcp_snapshot_for(&bob).await.expect("bob snapshot");
    assert_eq!(
        names(&bob_snapshot),
        std::collections::BTreeSet::from(["beta".into()])
    );

    write_profile(&home, &alice, &["tool-alpha", "tool-beta"]);
    kernel.profile_cache.invalidate(&alice);
    assert_eq!(
        kernel
            .refresh_mcp_snapshot(&alice)
            .await
            .expect("grant snapshot")
            .get(),
        2
    );
    assert_eq!(
        names(&kernel.mcp_snapshot_for(&alice).await.expect("grant view")),
        std::collections::BTreeSet::from(["alpha".into(), "beta".into()])
    );

    write_profile(&home, &alice, &["tool-beta"]);
    kernel.profile_cache.invalidate(&alice);
    assert_eq!(
        kernel
            .refresh_mcp_snapshot(&alice)
            .await
            .expect("revoke snapshot")
            .get(),
        3
    );
    assert_eq!(
        names(&kernel.mcp_snapshot_for(&alice).await.expect("revoke view")),
        std::collections::BTreeSet::from(["beta".into()])
    );

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
    assert_eq!(
        kernel
            .refresh_mcp_snapshot(&alice)
            .await
            .expect("replacement snapshot")
            .get(),
        4
    );
    assert_eq!(
        names(
            &kernel
                .mcp_snapshot_for(&alice)
                .await
                .expect("replacement view")
        ),
        std::collections::BTreeSet::from(["beta-replaced".into()])
    );

    {
        let mut registry = kernel.capsules.write().await;
        let _ = registry
            .unregister_for(&alice, &beta)
            .expect("unload removal");
    }
    assert_eq!(
        kernel
            .refresh_mcp_snapshot(&alice)
            .await
            .expect("unload snapshot")
            .get(),
        5
    );
    let empty = kernel
        .mcp_snapshot_for(&alice)
        .await
        .expect("valid empty view");
    assert_eq!(empty.epoch.get(), 5);
    assert!(empty.tools.is_empty());
}
