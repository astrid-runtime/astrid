//! Exercise the kernel's dispatcher control, not only the queue helper.
use super::*;
use astrid_capsule::{
    capsule::{Capsule, CapsuleState, InterceptResult},
    context::CapsuleContext,
    dispatcher::EventDispatcher,
    error::CapsuleResult,
    registry::WasmHash,
};
use astrid_capsule_types::{
    CapsuleId,
    manifest::{CapsuleManifest, SubscribeDef},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct IdleCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
    invoked: Arc<tokio::sync::Notify>,
    unloaded: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Capsule for IdleCapsule {
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
        self.unloaded.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn invoke_interceptor(
        &self,
        _: &str,
        _: &[u8],
        _: Option<&astrid_events::IpcMessage>,
    ) -> CapsuleResult<InterceptResult> {
        self.invoked.notify_one();
        Ok(InterceptResult::Continue(Vec::new()))
    }
}

#[tokio::test]
async fn shutdown_wakes_idle_gateless_dispatcher_before_closing_storage() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path());
    let kernel = test_kernel_with_home(home).await;
    let invoked = Arc::new(tokio::sync::Notify::new());
    let unloaded = Arc::new(AtomicBool::new(false));
    let mut manifest = CapsuleManifest::default();
    manifest.subscribes.insert(
        "fixture.shutdown".into(),
        SubscribeDef {
            wit: "opaque".into(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            handler: Some("handle".into()),
            priority: Some(100),
        },
    );
    kernel
        .capsules
        .write()
        .await
        .register_for(
            Box::new(IdleCapsule {
                id: CapsuleId::from_static("idle-shutdown"),
                manifest,
                invoked: invoked.clone(),
                unloaded: unloaded.clone(),
            }),
            WasmHash::from_raw("idle-shutdown"),
            &astrid_core::PrincipalId::default(),
        )
        .unwrap();
    let dispatcher = EventDispatcher::new(kernel.capsules.clone(), kernel.event_bus.clone());
    assert!(kernel.dispatcher_control.set(dispatcher.control()).is_ok());
    let mut run = Box::pin(dispatcher.run());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(run.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let dispatch = tokio::spawn(run);
    let message = astrid_events::IpcMessage::new(
        astrid_events::ipc::Topic::from_raw("fixture.shutdown"),
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    )
    .with_principal("default");
    kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("fixture"),
        message,
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), invoked.notified())
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        kernel.shutdown(Some("idle dispatcher regression".into())),
    )
    .await
    .unwrap();
    assert!(unloaded.load(Ordering::SeqCst));
    tokio::time::timeout(std::time::Duration::from_secs(1), dispatch)
        .await
        .unwrap()
        .unwrap();
    assert!(
        kernel
            .kv
            .set("shutdown-regression", "late", Vec::new())
            .await
            .is_err()
    );
}
