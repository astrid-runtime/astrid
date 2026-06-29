//! Tests for `kernel_router/mod.rs`. Split out to keep `mod.rs` under the
//! 1000-line CI threshold. Included as a `tests` submodule of `kernel_router`.

use super::*;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::{CapsuleManifest, CommandDef, PackageDef};
use astrid_core::kernel_api::CommandKind;
use astrid_core::profile::PrincipalProfile;

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
}

// ── Capability mapping (issue #670) ──────────────────────────────

fn all_request_variants() -> Vec<KernelRequest> {
    vec![
        KernelRequest::Shutdown { reason: None },
        KernelRequest::GetStatus,
        KernelRequest::ReloadCapsules,
        KernelRequest::ReloadCapsule {
            id: "x".to_string(),
        },
        KernelRequest::UnloadCapsule {
            id: "x".to_string(),
        },
        KernelRequest::InstallCapsule {
            source: "x".to_string(),
            workspace: false,
        },
        KernelRequest::ListCapsules,
        KernelRequest::GetCommands,
        KernelRequest::GetCapsuleMetadata,
        KernelRequest::GetAgentReadiness,
        KernelRequest::ApproveCapability {
            request_id: "r".to_string(),
            signature: "s".to_string(),
        },
    ]
}

#[test]
fn required_capability_every_variant_has_non_empty_mapping() {
    for req in all_request_variants() {
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
    for req in all_request_variants() {
        if matches!(
            req,
            KernelRequest::ReloadCapsules
                | KernelRequest::ReloadCapsule { .. }
                | KernelRequest::UnloadCapsule { .. }
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
        KernelRequest::ReloadCapsule {
            id: "demo".to_string(),
        },
        KernelRequest::UnloadCapsule {
            id: "demo".to_string(),
        },
        KernelRequest::InstallCapsule {
            source: "/tmp/demo.capsule".to_string(),
            workspace: false,
        },
    ] {
        assert_eq!(
            resolve_scope(&req, &caller),
            AuthorityScope::Global,
            "daemon capsule lifecycle should be global for {req:?}"
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
    let caller = resolve_caller(&msg);
    assert_eq!(caller.as_str(), "alice");
}

#[test]
fn resolve_caller_falls_back_to_default_when_missing() {
    let msg = IpcMessage::new(
        Topic::kernel_request("system"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    let caller = resolve_caller(&msg);
    assert_eq!(caller, PrincipalId::default());
}

#[test]
fn resolve_caller_falls_back_to_default_on_invalid_principal() {
    let mut msg = IpcMessage::new(
        Topic::kernel_request("system"),
        IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::nil(),
    );
    // Invalid principal chars → PrincipalId::new fails → fall back.
    msg.principal = Some("alice@evil.example".to_string());
    let caller = resolve_caller(&msg);
    assert_eq!(caller, PrincipalId::default());
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

    let value = tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
    seed_capsule_inventory_profile(&kernel, &caller, &["allowed"]);
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
async fn ungranted_capsule_inventory_requests_do_not_inherit_default_surface() {
    let (_dir, kernel) = kernel_with_inventory_capsules().await;
    let ungranted = PrincipalId::new("bob").expect("valid principal");
    seed_capsule_inventory_profile(&kernel, &ungranted, &[]);
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
    let admin_visibility = CapsuleVisibility::new(&kernel, &admin);
    let global_lister_visibility = CapsuleVisibility::new(&kernel, &global_lister);
    let limited_visibility = CapsuleVisibility::new(&kernel, &limited);

    assert!(admin_visibility.allows(&allowed));
    assert!(admin_visibility.allows(&default_only));
    assert!(global_lister_visibility.allows(&allowed));
    assert!(global_lister_visibility.allows(&default_only));
    assert!(limited_visibility.allows(&allowed));
    assert!(!limited_visibility.allows(&default_only));
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

fn seed_capsule_inventory_profile(
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
}

fn seed_profile(kernel: &Arc<crate::Kernel>, principal: &PrincipalId, profile: &PrincipalProfile) {
    let path = PrincipalProfile::path_for(&kernel.astrid_home, principal);
    profile.save_to_path(&path).expect("seed profile");
    kernel.profile_cache.invalidate(principal);
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
    let list = request_kernel(
        kernel,
        caller,
        &format!("{label}_list_capsules"),
        KernelRequest::ListCapsules,
    )
    .await;
    let KernelResponse::Success(value) = list else {
        panic!("expected {label} capsule list success, got {list:?}");
    };
    let capsules: Vec<String> = serde_json::from_value(value).expect("capsule list shape");
    assert_eq!(capsules, expected_capsules);

    let commands = request_kernel(
        kernel,
        caller,
        &format!("{label}_commands"),
        KernelRequest::GetCommands,
    )
    .await;
    let KernelResponse::Commands(commands) = commands else {
        panic!("expected {label} commands response, got {commands:?}");
    };
    let command_names: Vec<_> = commands.iter().map(|cmd| cmd.name.as_str()).collect();
    assert_eq!(command_names, expected_commands);

    let metadata = request_kernel(
        kernel,
        caller,
        &format!("{label}_metadata"),
        KernelRequest::GetCapsuleMetadata,
    )
    .await;
    let KernelResponse::CapsuleMetadata(metadata) = metadata else {
        panic!("expected {label} metadata response, got {metadata:?}");
    };
    let metadata_names: Vec<_> = metadata.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(metadata_names, expected_metadata);

    let readiness = request_kernel(
        kernel,
        caller,
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
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
