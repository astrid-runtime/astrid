use std::path::Path;
use std::sync::Arc;

use crate::engine::wasm::{
    PrincipalInvocationTracker,
    bindings::astrid::uplink::host::{ErrorCode, Host, UplinkProfile},
    test_fixtures::minimal_host_state,
};
use crate::security::CapsuleSecurityGate;
use astrid_core::PrincipalId;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};

/// Observe the real registration while its asynchronous policy check is in flight.
struct RetireDuringPolicy {
    tracker: Arc<PrincipalInvocationTracker>,
    caller: PrincipalId,
}

#[async_trait::async_trait]
impl CapsuleSecurityGate for RetireDuringPolicy {
    async fn check_http_request(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        unreachable!()
    }
    async fn check_file_read(&self, _: &str, _: &str, _: Option<&Path>) -> Result<(), String> {
        unreachable!()
    }
    async fn check_file_write(&self, _: &str, _: &str, _: Option<&Path>) -> Result<(), String> {
        unreachable!()
    }
    async fn check_host_process(&self, _: &str, _: &str) -> Result<(), String> {
        unreachable!()
    }

    async fn check_uplink_register(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        self.tracker.retire(&self.caller);
        tokio::select! {
            biased;
            () = self.tracker.wait_for_quiescence(&self.caller) => panic!("registration must still count as active"),
            () = std::future::ready(()) => Ok(()),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_drains_before_retirement_and_late_sends_are_refused() {
    let tracker = Arc::new(PrincipalInvocationTracker::default());
    let caller = PrincipalId::new("alice").unwrap();
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.system_runtime = true;
    state.principal_invocations = Some(Arc::clone(&tracker));
    state.install_recv_invocation_context(
        &IpcMessage::new(
            Topic::from_raw("uplink.test"),
            IpcPayload::RawJson(serde_json::Value::Null),
            uuid::Uuid::new_v4(),
        )
        .with_principal(caller.to_string()),
    );
    assert_ne!(state.principal, caller);
    assert_eq!(state.effective_principal(), caller);
    state.has_uplink_capability = true;
    state.security = Some(Arc::new(RetireDuringPolicy {
        tracker: Arc::clone(&tracker),
        caller: caller.clone(),
    }));
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    state.inbound_tx = Some(tx);
    let id = state
        .uplink_register("chat".into(), " CHAT ".into(), UplinkProfile::Chat)
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tracker.wait_for_quiescence(&caller),
    )
    .await
    .unwrap();
    assert!(matches!(
        state.uplink_register("second".into(), "chat".into(), UplinkProfile::Chat),
        Err(ErrorCode::CapabilityDenied)
    ));
    assert_eq!(state.uplinks().len(), 1);
    assert!(matches!(
        state.uplink_send(id.clone(), "user".into(), "late".into()),
        Err(ErrorCode::CapabilityDenied)
    ));
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    tracker.resume(&caller);
    assert!(
        state
            .uplink_send(id.clone(), "user".into(), "live".into())
            .unwrap()
    );
    let message = rx.try_recv().unwrap();
    assert_eq!(message.uplink_id.to_string(), id);
    assert_eq!(message.platform, "chat");
    assert_eq!(message.platform_user_id, "user");
    assert_eq!(message.content, "live");
}
