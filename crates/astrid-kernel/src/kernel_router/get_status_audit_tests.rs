//! Liveness probes must not mill the audit chain; denies stay durable.

use super::*;

use astrid_core::profile::PrincipalProfile;
use std::sync::Arc;

async fn roundtrip(
    kernel: &Arc<crate::Kernel>,
    suffix: &str,
    principal: &PrincipalId,
    request: KernelRequest,
) -> KernelResponse {
    let request_topic = Topic::kernel_request(suffix);
    let response_topic = Topic::kernel_response(suffix);
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());
    let payload = serde_json::to_value(request).expect("serialize");
    let mut message = IpcMessage::new(
        request_topic,
        IpcPayload::RawJson(payload),
        kernel.session_id.0,
    );
    message.principal = Some(principal.to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message,
    });
    let value = astrid_runtime::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("response");
            if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                && let IpcPayload::RawJson(value) = &message.payload
            {
                return value.clone();
            }
        }
    })
    .await
    .expect("kernel response within 2s");
    serde_json::from_value(value).expect("typed response")
}

async fn seeded_kernel() -> (
    tempfile::TempDir,
    Arc<crate::Kernel>,
    PrincipalId,
    PrincipalId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;

    let admin = PrincipalId::default();
    let profile = PrincipalProfile {
        groups: vec!["admin".to_string()],
        ..Default::default()
    };
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &admin);
    profile.save_to_path(&path).expect("seed admin");
    kernel.profile_cache.invalidate(&admin);

    let restricted = PrincipalId::new("restricted").expect("restricted");
    let restricted_profile = PrincipalProfile {
        groups: vec!["restricted".to_string()],
        ..Default::default()
    };
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &restricted);
    restricted_profile
        .save_to_path(&path)
        .expect("seed restricted");
    kernel.profile_cache.invalidate(&restricted);

    drop(spawn_kernel_router(Arc::clone(&kernel)));
    (dir, kernel, admin, restricted)
}

fn admin_method_count(
    entries: &[astrid_audit::AuditEntry],
    principal: &PrincipalId,
    method: &str,
) -> usize {
    entries
        .iter()
        .filter(|entry| {
            entry.principal.as_ref() == Some(principal)
                && matches!(
                    &entry.action,
                    AuditAction::AdminRequest { method: name, .. } if name == method
                )
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn get_status_success_is_not_a_durable_admin_row_deny_is() {
    let (_dir, kernel, admin, restricted) = seeded_kernel().await;
    let ok = roundtrip(&kernel, "get_status_ok", &admin, KernelRequest::GetStatus).await;
    assert!(
        matches!(ok, KernelResponse::Status(_)),
        "admin `GetStatus` must succeed: {ok:?}"
    );
    let denied = roundtrip(
        &kernel,
        "get_status_denied",
        &restricted,
        KernelRequest::GetStatus,
    )
    .await;
    assert!(
        matches!(denied, KernelResponse::Error(_)),
        "restricted `GetStatus` must deny: {denied:?}"
    );

    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit");
    assert_eq!(
        admin_method_count(&entries, &admin, "GetStatus"),
        0,
        "successful `GetStatus` must not mint AdminRequest rows: {entries:?}"
    );
    assert_eq!(
        admin_method_count(&entries, &restricted, "GetStatus"),
        1,
        "denied `GetStatus` must mint one AdminRequest row: {entries:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_agent_readiness_success_is_not_a_durable_admin_row_deny_is() {
    let (_dir, kernel, admin, restricted) = seeded_kernel().await;
    let ok = roundtrip(
        &kernel,
        "get_ready_ok",
        &admin,
        KernelRequest::GetAgentReadiness,
    )
    .await;
    assert!(
        matches!(ok, KernelResponse::AgentReadiness(_)),
        "admin `GetAgentReadiness` must succeed: {ok:?}"
    );
    let denied = roundtrip(
        &kernel,
        "get_ready_denied",
        &restricted,
        KernelRequest::GetAgentReadiness,
    )
    .await;
    assert!(
        matches!(denied, KernelResponse::Error(_)),
        "restricted `GetAgentReadiness` must deny: {denied:?}"
    );

    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit");
    assert_eq!(
        admin_method_count(&entries, &admin, "GetAgentReadiness"),
        0,
        "successful `GetAgentReadiness` must not mint AdminRequest rows: {entries:?}"
    );
    assert_eq!(
        admin_method_count(&entries, &restricted, "GetAgentReadiness"),
        1,
        "denied `GetAgentReadiness` must mint one AdminRequest row: {entries:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_capsule_metadata_success_stays_a_durable_admin_row() {
    let (_dir, kernel, admin, _) = seeded_kernel().await;
    let ok = roundtrip(
        &kernel,
        "get_meta_ok",
        &admin,
        KernelRequest::GetCapsuleMetadata,
    )
    .await;
    assert!(
        matches!(ok, KernelResponse::CapsuleMetadata(_)),
        "admin `GetCapsuleMetadata` must succeed: {ok:?}"
    );

    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit");
    assert_eq!(
        admin_method_count(&entries, &admin, "GetCapsuleMetadata"),
        1,
        "successful `GetCapsuleMetadata` must stay a durable AdminRequest row: {entries:?}"
    );
}
