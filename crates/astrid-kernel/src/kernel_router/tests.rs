//! Tests for `kernel_router/mod.rs`. Split out to keep `mod.rs` under the
//! 1000-line CI threshold. Included as a `tests` submodule of `kernel_router`.

use super::*;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::{CapsuleManifest, CommandDef, PackageDef, SubscribeDef};
use astrid_capsule::registry::WasmHash;
use astrid_core::kernel_api::CommandKind;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use std::sync::atomic::AtomicBool;

use super::test_util::all_kernel_request_variants;

struct InventoryCapsule {
    id: CapsuleId,
    manifest: CapsuleManifest,
}

impl InventoryCapsule {
    fn new(name: &str, command: &str) -> Self {
        Self {
            id: CapsuleId::new(name).expect("valid capsule id"),
            manifest: CapsuleManifest {
                package: PackageDef {
                    name: name.to_string(),
                    version: "0.0.1".to_string(),
                    description: None,
                    authors: Vec::new(),
                    repository: None,
                    homepage: None,
                    documentation: None,
                    license: None,
                    license_file: None,
                    readme: None,
                    keywords: Vec::new(),
                    categories: Vec::new(),
                    astrid_version: None,
                    publish: None,
                    include: None,
                    exclude: None,
                    metadata: None,
                },
                commands: vec![CommandDef {
                    name: command.to_string(),
                    description: Some(format!("{name} command")),
                    file: None,
                    kind: CommandKind::default(),
                }],
                ..Default::default()
            },
        }
    }

    fn with_subscribe(mut self, topic: &str) -> Self {
        self.manifest.subscribes.insert(
            topic.to_string(),
            SubscribeDef {
                wit: "opaque".to_string(),
                version: None,
                tag: None,
                rev: None,
                branch: None,
                path: None,
                handler: Some("handle".to_string()),
                priority: None,
            },
        );
        self
    }
}

#[async_trait::async_trait]
impl Capsule for InventoryCapsule {
    fn id(&self) -> &CapsuleId {
        &self.id
    }

    fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
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
}

#[test]
fn response_topic_for_maps_request_to_response() {
    // A kernel request topic maps to the correlated response topic so a reply
    // lands on the channel the client is waiting on. Regression: the rate-limit
    // path previously derived the topic with a no-op
    // `replace("kernel.request.", "kernel.response.")` — which never matched the
    // real `astrid.v1.request.*` topics — and published the error back on the
    // request topic, so rate-limited clients timed out.
    assert_eq!(
        response_topic_for("astrid.v1.request.status.abc123"),
        "astrid.v1.response.status.abc123",
    );
    assert_eq!(
        response_topic_for("astrid.v1.request.reload_capsule.c-1"),
        "astrid.v1.response.reload_capsule.c-1",
    );
    // A non-request topic is returned unchanged.
    assert_eq!(response_topic_for("client.v1.connect"), "client.v1.connect");
}

#[test]
fn audit_topic_const_matches_constructor() {
    // The audit wire string is published via `Topic::audit_entry()`, but the
    // `pub const AUDIT_TOPIC` is the named cross-crate anchor that the capsule's
    // `audit_topic_literal_pinned` test and the gateway SSE consumer mirror.
    // Pin the two so a rename in one place can never silently leave the other
    // (and thus the audit firehose scoping) pointing at a stale topic.
    assert_eq!(Topic::audit_entry().as_str(), AUDIT_TOPIC);
}

#[test]
fn rate_limiter_allows_within_limit() {
    let mut limiter = ManagementRateLimiter::new();
    for _ in 0..5 {
        assert!(limiter.check("ReloadCapsules", 5));
    }
    // 6th should be rejected
    assert!(!limiter.check("ReloadCapsules", 5));
}

#[test]
fn rate_limiter_independent_buckets() {
    let mut limiter = ManagementRateLimiter::new();
    // Fill ReloadCapsules
    for _ in 0..5 {
        assert!(limiter.check("ReloadCapsules", 5));
    }
    assert!(!limiter.check("ReloadCapsules", 5));

    // InstallCapsule should still be allowed
    assert!(limiter.check("InstallCapsule", 10));
}

#[test]
fn topic_readiness_rate_limit_is_independent_per_caller() {
    let mut limiter = ManagementRateLimiter::new();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();

    for _ in 0..30 {
        assert!(limiter.check_for_caller("EnsureTopicReady", &alice, 30));
    }
    assert!(!limiter.check_for_caller("EnsureTopicReady", &alice, 30));
    assert!(limiter.check_for_caller("EnsureTopicReady", &bob, 30));
}

#[test]
fn full_reload_guard_coalesces_until_finished() {
    let in_flight = AtomicBool::new(false);

    assert!(try_start_full_reload(&in_flight));
    assert!(
        !try_start_full_reload(&in_flight),
        "second full reload should be coalesced while first is in flight"
    );

    drop(FullReloadGuard(&in_flight));
    assert!(
        try_start_full_reload(&in_flight),
        "new full reload may start after the previous reload finishes"
    );
}

#[test]
fn rate_limiter_sliding_window_eviction() {
    let mut limiter = ManagementRateLimiter::new();
    // Fill the bucket
    for _ in 0..5 {
        assert!(limiter.check("ReloadCapsules", 5));
    }
    assert!(!limiter.check("ReloadCapsules", 5));

    // Manually set all timestamps to 61 seconds ago to simulate expiry.
    if let Some(timestamps) = limiter.buckets.get_mut("ReloadCapsules") {
        let past = Instant::now()
            .checked_sub(std::time::Duration::from_secs(61))
            .unwrap();
        for ts in timestamps.iter_mut() {
            *ts = past;
        }
    }

    // Should be allowed again after old entries are evicted
    assert!(limiter.check("ReloadCapsules", 5));
}

#[test]
fn rate_limiter_sliding_window_prevents_boundary_burst() {
    let mut limiter = ManagementRateLimiter::new();
    // Fill 5 requests
    for _ in 0..5 {
        assert!(limiter.check("ReloadCapsules", 5));
    }

    // Move only 3 of the 5 timestamps to the past (beyond 60s window).
    // This simulates partial window expiry - only 3 slots should free up.
    if let Some(timestamps) = limiter.buckets.get_mut("ReloadCapsules") {
        let past = Instant::now()
            .checked_sub(std::time::Duration::from_secs(61))
            .unwrap();
        for ts in timestamps.iter_mut().take(3) {
            *ts = past;
        }
    }

    // Should allow exactly 3 more (the evicted slots), not 5
    for _ in 0..3 {
        assert!(limiter.check("ReloadCapsules", 5));
    }
    assert!(!limiter.check("ReloadCapsules", 5));
}

#[test]
fn rate_limit_for_request_returns_correct_limits() {
    let (name, limit) = rate_limit_for_request(&KernelRequest::ReloadCapsules);
    assert_eq!(name, "ReloadCapsules");
    assert_eq!(limit, Some(5));

    let (name, limit) = rate_limit_for_request(&KernelRequest::ListCapsules);
    assert_eq!(name, "ListCapsules");
    assert_eq!(limit, None);

    let (name, limit) = rate_limit_for_request(&KernelRequest::EnsureTopicReady {
        topic: "service.v1.request".into(),
    });
    assert_eq!(name, "EnsureTopicReady");
    assert_eq!(limit, Some(30));
}

// ── Capability mapping (issue #670) ──────────────────────────────

#[test]
fn required_capability_every_variant_has_non_empty_mapping() {
    for req in all_kernel_request_variants() {
        let cap = required_capability(&req, AuthorityScope::Self_);
        assert!(
            !cap.is_empty(),
            "required_capability returned empty for {req:?}"
        );
    }
}

#[test]
fn required_capability_mapping_per_variant_self_scope() {
    assert_eq!(
        required_capability(
            &KernelRequest::Shutdown { reason: None },
            AuthorityScope::Self_
        ),
        "system:shutdown"
    );
    assert_eq!(
        required_capability(&KernelRequest::GetStatus, AuthorityScope::Self_),
        "system:status"
    );
    assert_eq!(
        required_capability(&KernelRequest::ReloadCapsules, AuthorityScope::Self_),
        "self:capsule:reload"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::UnloadCapsule { id: String::new() },
            AuthorityScope::Self_
        ),
        "self:capsule:remove"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::InstallCapsule {
                source: String::new(),
                workspace: false
            },
            AuthorityScope::Self_
        ),
        "self:capsule:install"
    );
    assert_eq!(
        required_capability(&KernelRequest::ListCapsules, AuthorityScope::Self_),
        "self:capsule:list"
    );
    assert_eq!(
        required_capability(&KernelRequest::GetCommands, AuthorityScope::Self_),
        "self:capsule:list"
    );
    assert_eq!(
        required_capability(&KernelRequest::GetCapsuleMetadata, AuthorityScope::Self_),
        "self:capsule:list"
    );
    assert_eq!(
        required_capability(&KernelRequest::GetAgentReadiness, AuthorityScope::Self_),
        "self:capsule:list"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::EnsureTopicReady {
                topic: "service.v1.request".into(),
            },
            AuthorityScope::Self_,
        ),
        "self:capsule:list"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::ApproveCapability {
                request_id: String::new(),
                signature: String::new(),
            },
            AuthorityScope::Self_
        ),
        "self:approval:respond"
    );
}

#[test]
fn required_capability_mapping_global_scope() {
    // Global scope strips the `self:` prefix from capsule operations
    // (Layer 6 will start using this when cross-agent variants land).
    assert_eq!(
        required_capability(&KernelRequest::ReloadCapsules, AuthorityScope::Global),
        "capsule:reload"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::UnloadCapsule { id: String::new() },
            AuthorityScope::Global
        ),
        "capsule:remove"
    );
    assert_eq!(
        required_capability(
            &KernelRequest::InstallCapsule {
                source: String::new(),
                workspace: false
            },
            AuthorityScope::Global
        ),
        "capsule:install"
    );
    assert_eq!(
        required_capability(&KernelRequest::ListCapsules, AuthorityScope::Global),
        "capsule:list"
    );
    assert_eq!(
        required_capability(&KernelRequest::GetAgentReadiness, AuthorityScope::Global),
        "capsule:list"
    );
    // system:* variants are scope-invariant.
    assert_eq!(
        required_capability(
            &KernelRequest::Shutdown { reason: None },
            AuthorityScope::Global
        ),
        "system:shutdown"
    );
}

#[test]
fn resolve_scope_defaults_to_self_except_daemon_capsule_lifecycle() {
    let caller = PrincipalId::new("alice").unwrap();
    for req in all_kernel_request_variants() {
        if matches!(
            req,
            KernelRequest::ReloadCapsules
                | KernelRequest::InstallCapsule {
                    workspace: false,
                    ..
                }
        ) {
            continue;
        }
        assert_eq!(
            resolve_scope(&req, &caller),
            AuthorityScope::Self_,
            "scope should default to Self_ for {req:?}"
        );
    }
}

#[test]
fn resolve_scope_treats_daemon_capsule_lifecycle_as_global() {
    let caller = PrincipalId::new("alice").unwrap();
    for req in [
        KernelRequest::ReloadCapsules,
        KernelRequest::InstallCapsule {
            source: "/tmp/demo.capsule".to_string(),
            workspace: false,
        },
    ] {
        assert_eq!(
            resolve_scope(&req, &caller),
            AuthorityScope::Global,
            "full-daemon lifecycle should be global for {req:?}"
        );
    }
}

#[test]
fn resolve_scope_treats_single_capsule_reload_and_unload_as_self() {
    let caller = PrincipalId::new("alice").unwrap();
    for req in [
        KernelRequest::ReloadCapsule {
            id: "demo".to_string(),
        },
        KernelRequest::UnloadCapsule {
            id: "demo".to_string(),
        },
    ] {
        assert_eq!(
            resolve_scope(&req, &caller),
            AuthorityScope::Self_,
            "single-capsule lifecycle should target caller view for {req:?}"
        );
    }
}

#[test]
fn resolve_scope_treats_workspace_capsule_install_as_self() {
    let caller = PrincipalId::new("alice").unwrap();
    assert_eq!(
        resolve_scope(
            &KernelRequest::InstallCapsule {
                source: "/tmp/demo.capsule".to_string(),
                workspace: true,
            },
            &caller,
        ),
        AuthorityScope::Self_
    );
}

// ── Caller resolution ────────────────────────────────────────────

#[test]
fn resolve_caller_uses_ipc_principal_when_present() {
    let mut msg = IpcMessage::new(
        Topic::kernel_request("system"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    msg.principal = Some("alice".to_string());
    let caller = resolve_caller(&msg).expect("valid caller");
    assert_eq!(caller.as_str(), "alice");
}

#[test]
fn resolve_caller_rejects_missing_principal() {
    let msg = IpcMessage::new(
        Topic::kernel_request("system"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    assert_eq!(resolve_caller(&msg), Err(CallerResolutionError::Missing));
}

#[test]
fn resolve_caller_rejects_invalid_principal() {
    let mut msg = IpcMessage::new(
        Topic::kernel_request("system"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    msg.principal = Some("alice@evil.example".to_string());
    assert_eq!(resolve_caller(&msg), Err(CallerResolutionError::Invalid));
}

#[tokio::test(flavor = "multi_thread")]
async fn management_router_denies_missing_and_invalid_principals_deterministically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    for (suffix, principal) in [
        ("missing_caller", None),
        ("invalid_caller", Some("alice@evil.example")),
    ] {
        let request_topic = Topic::kernel_request(suffix);
        let response_topic = Topic::kernel_response(suffix);
        let mut receiver = kernel.event_bus.subscribe_topic(response_topic.as_str());
        let payload = serde_json::to_value(KernelRequest::GetStatus).expect("serialize request");
        let mut message = IpcMessage::new(
            request_topic,
            IpcPayload::RawJson(payload),
            kernel.session_id.0,
        );
        message.principal = principal.map(str::to_string);
        let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new("test"),
            message,
        });

        let value = astrid_runtime::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let event = receiver.recv().await.expect("response event");
                if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                    && let IpcPayload::RawJson(value) = &message.payload
                {
                    return value.clone();
                }
            }
        })
        .await
        .expect("management denial within 2s");
        let response: KernelResponse = serde_json::from_value(value).expect("typed response");
        assert!(matches!(
            response,
            KernelResponse::Error(ref reason) if reason == MANAGEMENT_CALLER_REQUIRED
        ));
        assert_eq!(kernel.total_connection_count(), 0);
    }
}

// ── Agent-loop readiness dispatch (roundtrip) ────────────────────

/// Driving `GetAgentReadiness` through the live management router must
/// return a `KernelResponse::AgentReadiness`, not an error or a wrong
/// variant. Mirrors the `enforcement_tests::send_admin` pattern but on the
/// `astrid.v1.request.*` management plane (not `astrid.v1.admin.*`).
#[tokio::test(flavor = "multi_thread")]
async fn get_agent_readiness_returns_readiness_response() {
    use astrid_core::profile::PrincipalProfile;

    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;

    // Seed the default principal as admin so it satisfies the
    // `self:capsule:list` gate (the lightweight test constructor does not
    // admin-seed the default profile).
    let caller = PrincipalId::default();
    let profile = PrincipalProfile {
        groups: vec!["admin".to_string()],
        ..Default::default()
    };
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &caller);
    profile.save_to_path(&path).expect("seed admin profile");
    kernel.profile_cache.invalidate(&caller);

    // The test constructor only spawns the admin router; spin up the
    // management-API router so `astrid.v1.request.*` traffic is serviced.
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let request_topic = Topic::kernel_request("agent_readiness");
    let response_topic = Topic::kernel_response("agent_readiness");
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());

    let payload =
        serde_json::to_value(KernelRequest::GetAgentReadiness).expect("serialize request");
    let mut msg = IpcMessage::new(
        request_topic,
        IpcPayload::RawJson(payload),
        kernel.session_id.0,
    );
    msg.principal = Some(caller.as_str().to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });

    let value = astrid_runtime::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("response event");
            if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                && let IpcPayload::RawJson(val) = &message.payload
            {
                return val.clone();
            }
        }
    })
    .await
    .expect("readiness response within 2s");

    let resp: KernelResponse =
        serde_json::from_value(value).expect("response deserializes as KernelResponse");
    // An empty registry isn't ready, but the point is the dispatch path
    // returns the readiness variant rather than erroring or timing out.
    match resp {
        KernelResponse::AgentReadiness(r) => {
            assert!(!r.ready, "empty capsule set must not be ready");
            assert!(r.prompt_subscribers.is_empty());
            assert!(r.response_publishers.is_empty());
        },
        other => panic!("expected AgentReadiness, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn capsule_inventory_requests_are_filtered_to_callers_grants() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;

    let caller = PrincipalId::new("alice").expect("valid principal");
    seed_capsule_inventory_profile(&kernel, &caller, &["allowed"]).await;
    assert_capsule_inventory_surface(
        &kernel,
        &caller,
        "granted",
        &["allowed"],
        &["allowed-cmd"],
        &["allowed"],
        &["allowed"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn list_capsules_uses_materialized_inventory_without_runtime_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let caller = PrincipalId::new("alice").expect("valid principal");
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:capsule:list".to_string()],
            capsules: vec!["installed-only".to_string()],
            ..Default::default()
        },
    );
    write_inventory_manifest(&kernel, &caller, "installed-only", "installed-only-cmd");

    let response = request_kernel(
        &kernel,
        &caller,
        "materialized_inventory_list_capsules",
        KernelRequest::ListCapsules,
    )
    .await;
    let KernelResponse::Success(value) = response else {
        panic!("expected materialized inventory list success, got {response:?}");
    };
    let capsules: Vec<String> = serde_json::from_value(value).expect("capsule list shape");
    assert_eq!(capsules, ["installed-only"]);
    assert!(
        kernel.capsules.read().await.list_for(&caller).is_empty(),
        "listing materialized inventory must not synchronously load capsule runtimes"
    );
}

#[test]
fn topic_readiness_accepts_only_bounded_exact_topics() {
    assert!(is_exact_topic("astrid.v1.request.mcp.tools.list"));
    assert!(!is_exact_topic("astrid.v1.request.mcp.*"));
    assert!(!is_exact_topic("astrid..request"));
    assert!(!is_exact_topic(&"x".repeat(257)));
}

#[tokio::test(flavor = "multi_thread")]
async fn topic_readiness_warms_only_the_callers_dispatch_view() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let caller = PrincipalId::new("codex-code").expect("valid principal");
    let admin = PrincipalId::new("global-admin").expect("valid principal");
    let topic = "astrid.v1.request.mcp.tools.list";

    {
        let mut registry = kernel.capsules.write().await;
        registry
            .register(Box::new(
                InventoryCapsule::new("broker", "broker-cmd").with_subscribe(topic),
            ))
            .expect("register shared broker runtime");
    }
    seed_profile(
        &kernel,
        &admin,
        &PrincipalProfile {
            grants: vec!["*".to_string()],
            ..Default::default()
        },
    );
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:capsule:list".to_string()],
            capsules: vec!["broker".to_string()],
            ..Default::default()
        },
    );
    let capsule_dir = kernel
        .astrid_home
        .principal_home(&caller)
        .capsules_dir()
        .join("broker");
    std::fs::create_dir_all(&capsule_dir).expect("create broker install directory");
    std::fs::write(
        capsule_dir.join("Capsule.toml"),
        format!(
            r#"[package]
name = "broker"
version = "0.0.1"

[subscribe]
"{topic}" = {{ wit = "opaque", handler = "handle" }}
"#
        ),
    )
    .expect("write broker manifest");
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let admin_response = request_kernel(
        &kernel,
        &admin,
        "admin_topic_readiness",
        KernelRequest::EnsureTopicReady {
            topic: topic.to_string(),
        },
    )
    .await;
    let KernelResponse::Success(admin_readiness) = admin_response else {
        panic!("expected admin readiness response, got {admin_response:?}");
    };
    assert_eq!(admin_readiness["ready"], false);

    assert!(
        kernel.capsules.read().await.list_for(&caller).is_empty(),
        "the selected principal starts cold"
    );
    let caller_response = request_kernel(
        &kernel,
        &caller,
        "caller_topic_readiness",
        KernelRequest::EnsureTopicReady {
            topic: topic.to_string(),
        },
    )
    .await;
    let KernelResponse::Success(caller_readiness) = caller_response else {
        panic!("expected caller readiness response, got {caller_response:?}");
    };
    assert_eq!(caller_readiness["topic"], topic);
    assert_eq!(caller_readiness["ready"], true);
    let broker_id = CapsuleId::new("broker").expect("valid broker id");
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&caller, &broker_id)
            .is_some(),
        "readiness returns only after the caller view is registered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn topic_readiness_rejects_manifest_only_handler_when_capsule_fails_to_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let caller = PrincipalId::new("codex-code").expect("valid principal");
    let topic = "astrid.v1.request.mcp.tools.list";

    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:capsule:list".to_string()],
            capsules: vec!["broken-broker".to_string()],
            ..Default::default()
        },
    );
    let capsule_dir = kernel
        .astrid_home
        .principal_home(&caller)
        .capsules_dir()
        .join("broken-broker");
    std::fs::create_dir_all(&capsule_dir).expect("create broken broker directory");
    std::fs::write(
        capsule_dir.join("Capsule.toml"),
        format!(
            r#"[package]
name = "broken-broker"
version = "0.0.1"

[[component]]
id = "main"
file = "missing.wasm"

[subscribe]
"{topic}" = {{ wit = "opaque", handler = "handle" }}
"#
        ),
    )
    .expect("write broken broker manifest");
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let response = request_kernel(
        &kernel,
        &caller,
        "broken_broker_topic_readiness",
        KernelRequest::EnsureTopicReady {
            topic: topic.to_string(),
        },
    )
    .await;
    let KernelResponse::Success(readiness) = response else {
        panic!("expected readiness response, got {response:?}");
    };
    assert_eq!(readiness["ready"], false);
    let broker_id = CapsuleId::new("broken-broker").expect("valid capsule id");
    assert!(
        kernel
            .capsules
            .read()
            .await
            .get_for(&caller, &broker_id)
            .is_none(),
        "a manifest is not ready unless its runtime loaded and registered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ungranted_capsule_inventory_requests_do_not_inherit_default_surface() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let ungranted = PrincipalId::new("bob").expect("valid principal");
    seed_capsule_inventory_profile(&kernel, &ungranted, &[]).await;
    assert_capsule_inventory_surface(&kernel, &ungranted, "ungranted", &[], &[], &[], &[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn capsule_visibility_precomputes_admin_and_capsule_grants() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let admin = PrincipalId::new("capsule-admin").expect("valid principal");
    let global_lister = PrincipalId::new("capsule-lister").expect("valid principal");
    let limited = PrincipalId::new("capsule-limited").expect("valid principal");
    seed_profile(
        &kernel,
        &admin,
        &PrincipalProfile {
            grants: vec!["*".to_string()],
            capsules: Vec::new(),
            ..Default::default()
        },
    );
    seed_profile(
        &kernel,
        &global_lister,
        &PrincipalProfile {
            grants: vec!["capsule:list".to_string()],
            capsules: Vec::new(),
            ..Default::default()
        },
    );
    seed_profile(
        &kernel,
        &limited,
        &PrincipalProfile {
            grants: vec!["self:capsule:list".to_string()],
            capsules: vec!["allowed".to_string()],
            ..Default::default()
        },
    );

    let allowed = CapsuleId::new("allowed").expect("valid capsule id");
    let default_only = CapsuleId::new("default-only").expect("valid capsule id");
    let admin_authorization =
        authorize_request(&kernel, &admin, None, "self:capsule:list").expect("authorize admin");
    let global_lister_authorization =
        authorize_request(&kernel, &global_lister, None, "capsule:list")
            .expect("authorize global lister");
    let limited_authorization =
        authorize_request(&kernel, &limited, None, "self:capsule:list").expect("authorize limited");
    let admin_visibility = CapsuleVisibility::new(&admin_authorization);
    let global_lister_visibility = CapsuleVisibility::new(&global_lister_authorization);
    let limited_visibility = CapsuleVisibility::new(&limited_authorization);

    assert!(admin_visibility.allows(&allowed));
    assert!(admin_visibility.allows(&default_only));
    assert!(global_lister_visibility.allows(&allowed));
    assert!(global_lister_visibility.allows(&default_only));
    assert!(limited_visibility.allows(&allowed));
    assert!(!limited_visibility.allows(&default_only));
}

#[tokio::test(flavor = "multi_thread")]
async fn device_scope_attenuates_every_capsule_inventory_surface() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let caller = PrincipalId::new("device-scoped-admin").expect("valid principal");
    seed_capsule_inventory_profile(&kernel, &caller, &["allowed"]).await;
    let devices = seed_inventory_device_scopes(&kernel, &caller);

    let global_capsules = &["allowed", "default-only"];
    let global_commands = &["allowed-cmd", "default-only-cmd"];
    let scoped_capsules = &["allowed"];
    let scoped_commands = &["allowed-cmd"];

    assert_capsule_inventory_surface_for_device(
        &kernel,
        &caller,
        None,
        "unattenuated_admin",
        global_capsules,
        global_commands,
        global_capsules,
        global_capsules,
    )
    .await;
    assert_capsule_inventory_surface_for_device(
        &kernel,
        &caller,
        Some(&devices.full),
        "full_device_admin",
        global_capsules,
        global_commands,
        global_capsules,
        global_capsules,
    )
    .await;
    assert_capsule_inventory_surface_for_device(
        &kernel,
        &caller,
        Some(&devices.self_only),
        "self_only_device_admin",
        scoped_capsules,
        scoped_commands,
        scoped_capsules,
        scoped_capsules,
    )
    .await;
    assert_capsule_inventory_surface_for_device(
        &kernel,
        &caller,
        Some(&devices.denied_global_list),
        "global_list_denied_device_admin",
        scoped_capsules,
        scoped_commands,
        scoped_capsules,
        scoped_capsules,
    )
    .await;
    assert_capsule_inventory_surface_for_device(
        &kernel,
        &caller,
        Some(&devices.global_list),
        "global_list_device_admin",
        global_capsules,
        global_commands,
        global_capsules,
        global_capsules,
    )
    .await;

    let response = request_kernel_for_device(
        &kernel,
        &caller,
        Some("0000000000000000"),
        "unknown_device_inventory",
        KernelRequest::ListCapsules,
    )
    .await;
    assert!(matches!(response, KernelResponse::Error(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn capsule_visibility_uses_the_authorized_device_scope_snapshot() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let caller = PrincipalId::new("device-snapshot-admin").expect("valid principal");
    let devices = seed_inventory_device_scopes(&kernel, &caller);
    let authorization = authorize_request(
        &kernel,
        &caller,
        Some(&devices.global_list),
        "self:capsule:list",
    )
    .expect("authorize inventory request");

    let allowed = CapsuleId::new("default-only").expect("valid capsule id");
    assert!(CapsuleVisibility::new(&authorization).allows(&allowed));

    let mut revoked = authorization.profile.as_ref().clone();
    revoked.auth.public_keys.clear();
    seed_profile(&kernel, &caller, &revoked);
    authorize_request(
        &kernel,
        &caller,
        Some(&devices.global_list),
        "self:capsule:list",
    )
    .expect_err("a later request must observe the revoked device");

    assert!(
        CapsuleVisibility::new(&authorization).allows(&allowed),
        "the in-flight request must keep the authority snapshot already audited as allowed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn device_scope_denials_do_not_expose_key_resolution() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let caller = PrincipalId::new("device-denial-oracle").expect("valid principal");
    let devices = seed_inventory_device_scopes(&kernel, &caller);
    let required = "capsule:list";

    let scoped = authorize_request(
        &kernel,
        &caller,
        Some(&devices.denied_global_list),
        required,
    )
    .expect_err("known scoped device must be denied")
    .to_string();
    let malformed = authorize_request(&kernel, &caller, Some("not-a-key-id"), required)
        .expect_err("malformed device id must be denied")
        .to_string();
    let unknown = authorize_request(&kernel, &caller, Some("0000000000000000"), required)
        .expect_err("unknown device id must be denied")
        .to_string();

    let mut revoked_profile = kernel
        .profile_cache
        .resolve(&caller)
        .expect("resolve device profile")
        .as_ref()
        .clone();
    revoked_profile.auth.public_keys.clear();
    seed_profile(&kernel, &caller, &revoked_profile);
    let revoked = authorize_request(
        &kernel,
        &caller,
        Some(&devices.denied_global_list),
        required,
    )
    .expect_err("revoked device id must be denied")
    .to_string();

    assert_eq!(malformed, scoped);
    assert_eq!(unknown, scoped);
    assert_eq!(revoked, scoped);
}

struct InventoryDeviceScopes {
    full: String,
    self_only: String,
    global_list: String,
    denied_global_list: String,
}

fn seed_inventory_device_scopes(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
) -> InventoryDeviceScopes {
    let full = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
    let self_only = DeviceKey::new(
        "b".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let global_list = DeviceKey::new(
        "c".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string(), "capsule:list".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let denied_global_list = DeviceKey::new(
        "d".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["*".to_string()],
            deny: vec!["capsule:list".to_string()],
        },
        None,
        0,
    );
    let devices = InventoryDeviceScopes {
        full: full.key_id.clone(),
        self_only: self_only.key_id.clone(),
        global_list: global_list.key_id.clone(),
        denied_global_list: denied_global_list.key_id.clone(),
    };
    let mut profile = PrincipalProfile {
        grants: vec!["*".to_string()],
        capsules: vec!["allowed".to_string()],
        ..Default::default()
    };
    profile.auth.methods.push(AuthMethod::Keypair);
    profile.auth.public_keys = vec![full, self_only, global_list, denied_global_list];
    seed_profile(kernel, caller, &profile);
    devices
}

async fn kernel_with_inventory_capsules() -> (tempfile::TempDir, Arc<crate::Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;

    {
        let mut reg = kernel.capsules.write().await;
        reg.register(Box::new(InventoryCapsule::new("allowed", "allowed-cmd")))
            .expect("register allowed capsule");
        reg.register(Box::new(InventoryCapsule::new(
            "default-only",
            "default-only-cmd",
        )))
        .expect("register default-only capsule");
    }

    drop(spawn_kernel_router(Arc::clone(&kernel)));
    (dir, kernel)
}

async fn seed_capsule_inventory_profile(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    capsules: &[&str],
) {
    let profile = PrincipalProfile {
        grants: vec!["self:capsule:list".to_string()],
        capsules: capsules
            .iter()
            .map(|capsule| (*capsule).to_string())
            .collect(),
        ..Default::default()
    };
    seed_profile(kernel, principal, &profile);
    let mut reg = kernel.capsules.write().await;
    for capsule in capsules {
        let id = CapsuleId::new(*capsule).expect("valid capsule id");
        let hash = astrid_capsule::registry::WasmHash::synthetic(capsule, "0.0.1");
        if reg.get_for(principal, &id).is_none() {
            // Mirror the production load path: if a runtime for this hash already
            // exists (e.g. registered under `default`), add THIS principal's view
            // via `register_existing` rather than a cross-owner `register_for`,
            // which the registry now rejects (#1069 host-state isolation).
            if reg.contains_hash(&hash) {
                reg.register_existing(&id, &hash, principal)
                    .expect("seed capsule view (shared)");
            } else {
                reg.register_for(
                    Box::new(InventoryCapsule::new(capsule, &format!("{capsule}-cmd"))),
                    hash,
                    principal,
                )
                .expect("seed capsule view");
            }
        }
    }
}

fn seed_profile(kernel: &Arc<crate::Kernel>, principal: &PrincipalId, profile: &PrincipalProfile) {
    let path = PrincipalProfile::path_for(&kernel.astrid_home, principal);
    profile.save_to_path(&path).expect("seed profile");
    kernel.profile_cache.invalidate(principal);
}

fn write_inventory_manifest(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    command: &str,
) {
    let dir = kernel
        .astrid_home
        .principal_home(principal)
        .capsules_dir()
        .join(capsule);
    std::fs::create_dir_all(&dir).expect("create capsule dir");
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            r#"[package]
name = "{capsule}"
version = "0.0.1"

[[component]]
id = "main"
file = "{capsule}.wasm"

[[command]]
name = "{command}"
kind = "cli"
description = "{capsule} command"
"#
        ),
    )
    .expect("write capsule manifest");
}

async fn assert_capsule_inventory_surface(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    label: &str,
    expected_capsules: &[&str],
    expected_commands: &[&str],
    expected_metadata: &[&str],
    expected_readiness: &[&str],
) {
    assert_capsule_inventory_surface_for_device(
        kernel,
        caller,
        None,
        label,
        expected_capsules,
        expected_commands,
        expected_metadata,
        expected_readiness,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn assert_capsule_inventory_surface_for_device(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    label: &str,
    expected_capsules: &[&str],
    expected_commands: &[&str],
    expected_metadata: &[&str],
    expected_readiness: &[&str],
) {
    let list = request_kernel_for_device(
        kernel,
        caller,
        device_key_id,
        &format!("{label}_list_capsules"),
        KernelRequest::ListCapsules,
    )
    .await;
    let KernelResponse::Success(value) = list else {
        panic!("expected {label} capsule list success, got {list:?}");
    };
    let capsules: Vec<String> = serde_json::from_value(value).expect("capsule list shape");
    assert_eq!(capsules, expected_capsules);

    let commands = request_kernel_for_device(
        kernel,
        caller,
        device_key_id,
        &format!("{label}_commands"),
        KernelRequest::GetCommands,
    )
    .await;
    let KernelResponse::Commands(commands) = commands else {
        panic!("expected {label} commands response, got {commands:?}");
    };
    let command_names: Vec<_> = commands.iter().map(|cmd| cmd.name.as_str()).collect();
    assert_eq!(command_names, expected_commands);

    let metadata = request_kernel_for_device(
        kernel,
        caller,
        device_key_id,
        &format!("{label}_metadata"),
        KernelRequest::GetCapsuleMetadata,
    )
    .await;
    let KernelResponse::CapsuleMetadata(metadata) = metadata else {
        panic!("expected {label} metadata response, got {metadata:?}");
    };
    let metadata_names: Vec<_> = metadata.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(metadata_names, expected_metadata);

    let readiness = request_kernel_for_device(
        kernel,
        caller,
        device_key_id,
        &format!("{label}_readiness"),
        KernelRequest::GetAgentReadiness,
    )
    .await;
    let KernelResponse::AgentReadiness(readiness) = readiness else {
        panic!("expected {label} readiness response, got {readiness:?}");
    };
    assert_eq!(readiness.loaded_capsules, expected_readiness);
}

async fn request_kernel(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    suffix: &str,
    request: KernelRequest,
) -> KernelResponse {
    request_kernel_for_device(kernel, caller, None, suffix, request).await
}

async fn request_kernel_for_device(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    suffix: &str,
    request: KernelRequest,
) -> KernelResponse {
    let request_topic = Topic::kernel_request(format!("{suffix}.{}", uuid::Uuid::new_v4()));
    let response_topic = response_topic_for(request_topic.as_str());
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());
    let payload = serde_json::to_value(request).expect("serialize request");
    let mut msg = IpcMessage::new(
        request_topic,
        IpcPayload::RawJson(payload),
        kernel.session_id.0,
    );
    msg.principal = Some(caller.as_str().to_string());
    msg.device_key_id = device_key_id.map(str::to_owned);
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });

    astrid_runtime::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("response event");
            if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                && let IpcPayload::RawJson(val) = &message.payload
            {
                return serde_json::from_value(val.clone())
                    .expect("response deserializes as KernelResponse");
            }
        }
    })
    .await
    .expect("kernel response within 2s")
}

/// The in-process readiness probe the gateway uses for the prompt fail-fast
/// must reflect the live registry with NO capability check or socket round-trip
/// — that is what makes the fail-fast fire for every authenticated prompt
/// caller, single- and multi-tenant alike, not only `capsule:list` holders. A
/// kernel with no capsules loaded can't serve a chat turn, so the probe reports
/// not-ready. Regression guard: this would have failed when the prompt path
/// went through the capability-gated `GetAgentReadiness` request as the caller.
#[tokio::test]
async fn agent_readiness_probe_reflects_loaded_registry_without_capability() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;

    // No admin seeding, no router — the probe is a direct in-process read.
    let report = kernel.agent_readiness_probe().probe().await;
    assert!(
        !report.ready,
        "empty registry must not be ready: {report:?}"
    );
    assert!(
        report.prompt_subscribers.is_empty(),
        "no capsule subscribes the prompt topic"
    );
}

/// The capsule-topic probe answers from the live registry without a
/// capability check. An empty registry has no subscriber for any topic, so
/// the gateway's session-list gate degrades to `501` rather than waiting out
/// a bus timeout. Mirrors the readiness-probe in-process pattern.
#[tokio::test]
async fn capsule_topic_probe_reflects_loaded_registry_without_capability() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;

    let probe = kernel.capsule_topic_probe();
    assert!(
        !probe.is_subscribed("session.v1.request.list").await,
        "empty registry must have no subscriber for the session list verb"
    );
}

#[tokio::test]
async fn capsule_topic_probe_can_target_exact_capsule_in_principal_view() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::new("regular-user").expect("valid principal");
    let topic = "session.v1.request.list";

    {
        let mut registry = kernel.capsules.write().await;
        let hostile = InventoryCapsule::new("astrid-capsule-adversarial", "adversarial")
            .with_subscribe(topic);
        registry
            .register_for(
                Box::new(hostile),
                WasmHash::synthetic("astrid-capsule-adversarial", "0.0.1"),
                &principal,
            )
            .expect("register hostile fixture");
    }

    let probe = kernel.capsule_topic_probe();
    let hostile_key = format!(
        "{}{}\0{}\0{}",
        crate::SCOPED_TOPIC_PROBE_SENTINEL,
        principal,
        "astrid-capsule-adversarial",
        topic
    );
    let session_key = format!(
        "{}{}\0{}\0{}",
        crate::SCOPED_TOPIC_PROBE_SENTINEL,
        principal,
        "astrid-capsule-session",
        topic
    );

    assert!(
        probe.is_subscribed(&hostile_key).await,
        "exact hostile capsule probe should see the hostile subscriber"
    );
    assert!(
        !probe.is_subscribed(&session_key).await,
        "session readiness must not be satisfied by a different capsule with the same topic"
    );
}
