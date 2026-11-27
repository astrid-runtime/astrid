use super::{RestartOutcome, unload_replaced_runtime};
use astrid_capsule::capsule::{Capsule, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule_types::{
    CapsuleId,
    error::{CapsuleError, CapsuleResult},
    manifest::CapsuleManifest,
};
use std::sync::Arc;

struct UnloadProbe {
    id: CapsuleId,
    manifest: CapsuleManifest,
    result: Option<CapsuleResult<()>>,
}

#[async_trait::async_trait]
impl Capsule for UnloadProbe {
    fn id(&self) -> &CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> CapsuleState {
        CapsuleState::Ready
    }
    async fn load(&mut self, _: &CapsuleContext) -> CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> CapsuleResult<()> {
        self.result
            .take()
            .expect("exclusive unload should run once")
    }
}

#[tokio::test]
async fn published_replacement_reports_the_actual_exclusive_unload_result() {
    let id = CapsuleId::from_static("restart-probe");
    for fails in [false, true] {
        let result = if fails {
            Err(CapsuleError::ExecutionFailed("old engine cleanup".into()))
        } else {
            Ok(())
        };
        let mut previous: Arc<dyn Capsule> = Arc::new(UnloadProbe {
            id: id.clone(),
            manifest: CapsuleManifest::default(),
            result: Some(result),
        });
        let outcome = unload_replaced_runtime(&id, &mut previous).await;
        if fails {
            assert!(
                matches!(outcome, RestartOutcome::OldInstanceUnloadFailed(CapsuleError::ExecutionFailed(reason)) if reason == "old engine cleanup")
            );
        } else {
            assert!(matches!(outcome, RestartOutcome::Clean));
        }
    }
}
