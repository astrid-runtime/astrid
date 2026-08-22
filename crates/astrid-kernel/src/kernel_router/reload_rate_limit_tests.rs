//! Spawn-router must load home `[rate_limits].capsule_reload_per_min`.
//!
//! Isolation-only `from_kernel_honors_home_capsule_reload_cap` still passes if
//! `spawn_kernel_router` constructs `ManagementRateLimiter::new()` because the
//! compiled default is 14.

use super::*;

use astrid_config::types::RateLimitsConfig;
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
    let value = astrid_runtime::time::timeout(std::time::Duration::from_secs(10), async {
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
    .expect("kernel response within 10s");
    serde_json::from_value(value).expect("typed response")
}

fn is_rate_limited(response: &KernelResponse) -> bool {
    matches!(
        response,
        KernelResponse::Error(reason) if reason.starts_with("Rate limited:")
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn spawn_kernel_router_honors_home_capsule_reload_cap() {
    assert_eq!(
        RateLimitsConfig::DEFAULT_CAPSULE_RELOAD_PER_MIN,
        RateLimitsConfig::CORE_SET_CAPSULE_COUNT.saturating_mul(2),
        "this test is the spawn-path falsifier only if ::new() still admits 8"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    std::fs::write(
        kernel.astrid_home.root().join("config.toml"),
        "[rate_limits]\ncapsule_reload_per_min = 7\n",
    )
    .expect("write home rate-limit config");

    let caller = PrincipalId::new("operator").expect("principal");
    let profile = PrincipalProfile {
        grants: vec!["self:capsule:reload".to_string()],
        ..Default::default()
    };
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &caller))
        .expect("seed reload grant");
    kernel.profile_cache.invalidate(&caller);

    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let cap = RateLimitsConfig::CORE_SET_CAPSULE_COUNT;
    for i in 0..cap {
        let response = roundtrip(
            &kernel,
            &format!("reload-{i}"),
            &caller,
            KernelRequest::ReloadCapsule {
                id: "astrid-capsule-openai-compat".into(),
            },
        )
        .await;
        assert!(
            !is_rate_limited(&response),
            "reload {n} of {cap} must be admitted by spawn_kernel_router; got {response:?}",
            n = i + 1
        );
    }

    let limited = roundtrip(
        &kernel,
        "reload-over-cap",
        &caller,
        KernelRequest::ReloadCapsule {
            id: "astrid-capsule-openai-compat".into(),
        },
    )
    .await;
    assert!(
        matches!(
            limited,
            KernelResponse::Error(ref reason)
                if reason == "Rate limited: max 7 ReloadCapsule requests per minute"
        ),
        "8th ReloadCapsule must rate-limit at the home knob; got {limited:?}"
    );
}
