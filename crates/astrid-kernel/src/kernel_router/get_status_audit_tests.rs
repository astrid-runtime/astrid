//! GetStatus must not mill the audit chain; denies stay durable.

use super::*;

use astrid_core::profile::PrincipalProfile;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread")]
async fn get_status_success_is_not_a_durable_admin_row_deny_is() {
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

    async fn roundtrip(
        kernel: &Arc<crate::Kernel>,
        suffix: &str,
        principal: &PrincipalId,
    ) -> KernelResponse {
        let request_topic = Topic::kernel_request(suffix);
        let response_topic = Topic::kernel_response(suffix);
        let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());
        let payload = serde_json::to_value(KernelRequest::GetStatus).expect("serialize");
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
        .expect("GetStatus within 2s");
        serde_json::from_value(value).expect("typed response")
    }

    let ok = roundtrip(&kernel, "get_status_ok", &admin).await;
    assert!(
        matches!(ok, KernelResponse::Status(_)),
        "admin GetStatus must succeed: {ok:?}"
    );
    let denied = roundtrip(&kernel, "get_status_denied", &restricted).await;
    assert!(
        matches!(denied, KernelResponse::Error(_)),
        "restricted GetStatus must deny: {denied:?}"
    );

    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit");
    let get_status = |principal: &PrincipalId| {
        entries
            .iter()
            .filter(|entry| {
                entry.principal.as_ref() == Some(principal)
                    && matches!(
                        &entry.action,
                        AuditAction::AdminRequest { method, .. } if method == "GetStatus"
                    )
            })
            .count()
    };
    assert_eq!(
        get_status(&admin),
        0,
        "successful GetStatus must not mint AdminRequest rows: {entries:?}"
    );
    assert_eq!(
        get_status(&restricted),
        1,
        "denied GetStatus must mint one AdminRequest row: {entries:?}"
    );
}
