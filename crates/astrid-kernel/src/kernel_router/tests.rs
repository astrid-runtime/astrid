//! Tests for `kernel_router/mod.rs`. Split out to keep `mod.rs` under the
//! 1000-line CI threshold. Included as a `tests` submodule of `kernel_router`.

use super::*;

use astrid_capsule::capsule::{Capsule, CapsuleId, CapsuleState};
use astrid_capsule::context::CapsuleContext;
use astrid_capsule::error::CapsuleResult;
use astrid_capsule::manifest::{CapsuleManifest, CommandDef, ExportDef, PackageDef, SubscribeDef};
use astrid_capsule::registry::WasmHash;
use astrid_core::kernel_api::CommandKind;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use astrid_events::kernel_api::{PROJECTION_NAME_DIAGNOSTIC_METHOD, ProjectionNamePolicyPreset};
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

    fn with_export(mut self, namespace: &str, interface: &str, version: &str) -> Self {
        self.manifest
            .exports
            .entry(namespace.to_string())
            .or_default()
            .insert(
                interface.to_string(),
                ExportDef {
                    version: semver::Version::parse(version).expect("valid export version"),
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
fn rate_limit_for_request_returns_correct_limits() {
    let (name, limit) = rate_limit_for_request(&KernelRequest::ReloadCapsules);
    assert_eq!(name, "ReloadCapsules");
    assert_eq!(limit, Some(5));

    let (name, limit) = rate_limit_for_request(&KernelRequest::ListCapsules);
    assert_eq!(name, "ListCapsules");
    assert_eq!(limit, None);
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
                workspace: false,
                target_principal: None,
                provenance: None,
                authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
                env: Vec::new(),
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
                workspace: false,
                target_principal: None,
                provenance: None,
                authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
                env: Vec::new(),
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
fn resolve_scope_defaults_to_self_for_caller_owned_lifecycle() {
    let caller = PrincipalId::new("alice").unwrap();
    for req in all_kernel_request_variants() {
        if matches!(req, KernelRequest::ReloadCapsules) {
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
fn resolve_scope_requires_global_authority_only_for_cross_principal_install() {
    let caller = PrincipalId::new("alice").unwrap();
    assert_eq!(
        resolve_scope(&KernelRequest::ReloadCapsules, &caller),
        AuthorityScope::Global
    );
    let self_install = KernelRequest::InstallCapsule {
        source: "/tmp/demo.capsule".to_string(),
        workspace: false,
        target_principal: None,
        provenance: None,
        authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
        env: Vec::new(),
    };
    assert_eq!(resolve_scope(&self_install, &caller), AuthorityScope::Self_);
    let cross_install = KernelRequest::InstallCapsule {
        source: "/tmp/demo.capsule".to_string(),
        workspace: false,
        target_principal: Some(PrincipalId::new("bob").unwrap()),
        provenance: None,
        authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
        env: Vec::new(),
    };
    assert_eq!(
        resolve_scope(&cross_install, &caller),
        AuthorityScope::Global
    );
    for req in [self_install, cross_install] {
        let expected = if matches!(
            &req,
            KernelRequest::InstallCapsule {
                target_principal: Some(_),
                ..
            }
        ) {
            AuthorityScope::Global
        } else {
            AuthorityScope::Self_
        };
        assert_eq!(
            resolve_scope(&req, &caller),
            expected,
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
                target_principal: None,
                provenance: None,
                authority: astrid_core::kernel_api::CapsuleInstallAuthority::default(),
                env: Vec::new(),
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

#[tokio::test(flavor = "multi_thread")]
async fn projection_name_diagnostic_uses_named_wire_and_system_status_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let caller = PrincipalId::new("alice").expect("valid principal");
    seed_profile(&kernel, &caller, &PrincipalProfile::default());
    let request_topic = Topic::kernel_request("projection_names.test");
    let response_topic = Topic::kernel_response("projection_names.test");
    let mut receiver = kernel.event_bus.subscribe_topic(response_topic.as_str());
    let mut message = IpcMessage::new(
        request_topic,
        IpcPayload::RawJson(serde_json::json!({
            "method": PROJECTION_NAME_DIAGNOSTIC_METHOD,
            "params": { "policy": ProjectionNamePolicyPreset::WindowsCaselessV1 },
        })),
        kernel.session_id.0,
    );
    message.principal = Some(caller.to_string());
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
    .expect("projection diagnostic response within 2s");
    let response: KernelResponse = serde_json::from_value(value).expect("typed kernel response");
    assert!(
        matches!(response, KernelResponse::Error(reason) if reason.contains("system:status")),
        "a caller without system:status must be rejected"
    );
}

fn assert_authorization_denied(response: &KernelResponse, context: &str) {
    assert!(
        matches!(
            response,
            KernelResponse::Error(reason) if !reason.starts_with("Rate limited:")
        ),
        "{context} must receive an authorization denial, got {response:?}"
    );
}

fn assert_shutdown_admitted(response: &KernelResponse, context: &str) {
    assert!(
        matches!(
            response,
            KernelResponse::Success(value)
                if value == &serde_json::json!({"status": "shutting_down"})
        ),
        "{context} must be admitted, got {response:?}"
    );
}

fn assert_shutdown_rate_limited(response: &KernelResponse, context: &str) {
    assert!(
        matches!(
            response,
            KernelResponse::Error(reason)
                if reason == "Rate limited: max 1 Shutdown requests per minute"
        ),
        "{context} must consume the shared principal budget, got {response:?}"
    );
}

async fn assert_shutdown_signaled(
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    context: &str,
) {
    if !*shutdown_rx.borrow() {
        astrid_runtime::time::timeout(std::time::Duration::from_secs(2), shutdown_rx.changed())
            .await
            .expect("shutdown signal within 2s")
            .expect("shutdown sender remains alive");
    }
    assert!(*shutdown_rx.borrow(), "{context} must signal shutdown");
}

async fn assert_shutdown_audit_rows(
    kernel: &crate::Kernel,
    restricted: &PrincipalId,
    operator: &PrincipalId,
) {
    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit entries");
    let shutdowns_for = |principal: &PrincipalId| {
        entries
            .iter()
            .filter(|entry| {
                entry.principal.as_ref() == Some(principal)
                    && matches!(
                        &entry.action,
                        AuditAction::AdminRequest { method, .. } if method == "Shutdown"
                    )
            })
            .collect::<Vec<_>>()
    };
    let operator_shutdowns = shutdowns_for(operator);
    assert_eq!(
        operator_shutdowns.len(),
        2,
        "one audit row must be recorded for each authorized shutdown attempt"
    );
    assert!(
        operator_shutdowns
            .iter()
            .all(|entry| matches!(&entry.authorization, AuthorizationProof::System { .. })),
        "both attempts passed capability authorization"
    );
    assert_eq!(
        operator_shutdowns
            .iter()
            .filter(|entry| matches!(&entry.outcome, AuditOutcome::Success { .. }))
            .count(),
        1,
        "only the admitted shutdown may be audited as successful"
    );
    assert_eq!(
        operator_shutdowns
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.outcome,
                    AuditOutcome::Failure { error }
                        if error == "Rate limited: max 1 Shutdown requests per minute"
                )
            })
            .count(),
        1,
        "the rejected attempt must produce exactly one rate-limit failure audit row"
    );

    let restricted_shutdowns = shutdowns_for(restricted);
    assert_eq!(
        restricted_shutdowns.len(),
        1,
        "the denied shutdown must produce exactly one audit row"
    );
    let restricted_shutdown = restricted_shutdowns
        .first()
        .expect("one restricted shutdown audit row");
    assert!(matches!(
        &restricted_shutdown.authorization,
        AuthorizationProof::Denied { .. }
    ));
    assert!(matches!(
        &restricted_shutdown.outcome,
        AuditOutcome::Failure { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_shutdown_does_not_consume_an_authorized_principals_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let restricted = PrincipalId::new("restricted").expect("valid principal");
    let operator = PrincipalId::new("operator").expect("valid principal");

    seed_profile(&kernel, &restricted, &PrincipalProfile::default());
    seed_profile(
        &kernel,
        &operator,
        &PrincipalProfile {
            grants: vec!["system:shutdown".to_string()],
            ..Default::default()
        },
    );
    let mut shutdown_rx = kernel.shutdown_tx.subscribe();
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let denied = request_kernel(
        &kernel,
        &restricted,
        "restricted_shutdown",
        KernelRequest::Shutdown {
            reason: Some("must be denied".to_string()),
        },
    )
    .await;
    assert_authorization_denied(&denied, "restricted caller");
    assert!(
        !*shutdown_rx.borrow(),
        "denied shutdown must not signal daemon shutdown"
    );

    let admitted = request_kernel(
        &kernel,
        &operator,
        "operator_shutdown",
        KernelRequest::Shutdown {
            reason: Some("authorized".to_string()),
        },
    )
    .await;
    assert_shutdown_admitted(&admitted, "authorized shutdown");
    assert_shutdown_signaled(&mut shutdown_rx, "authorized shutdown").await;

    let limited = request_kernel(
        &kernel,
        &operator,
        "operator_shutdown_again",
        KernelRequest::Shutdown {
            reason: Some("must be rate limited".to_string()),
        },
    )
    .await;
    assert_shutdown_rate_limited(&limited, "authorized principal's second shutdown");
    assert_shutdown_audit_rows(&kernel, &restricted, &operator).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn authorization_denial_does_not_precharge_a_later_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::new("new-operator").expect("valid principal");

    seed_profile(&kernel, &principal, &PrincipalProfile::default());
    let mut shutdown_rx = kernel.shutdown_tx.subscribe();
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let denied = request_kernel(
        &kernel,
        &principal,
        "pre_grant_shutdown",
        KernelRequest::Shutdown {
            reason: Some("not authorized yet".to_string()),
        },
    )
    .await;
    assert_authorization_denied(&denied, "pre-grant request");
    assert!(!*shutdown_rx.borrow(), "denied shutdown must not signal");

    seed_profile(
        &kernel,
        &principal,
        &PrincipalProfile {
            grants: vec!["system:shutdown".to_string()],
            ..Default::default()
        },
    );
    let admitted = request_kernel(
        &kernel,
        &principal,
        "post_grant_shutdown",
        KernelRequest::Shutdown {
            reason: Some("newly authorized".to_string()),
        },
    )
    .await;
    assert_shutdown_admitted(&admitted, "newly authorized shutdown after denial");
    assert_shutdown_signaled(&mut shutdown_rx, "newly authorized shutdown").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_scope_denial_does_not_consume_the_principals_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::new("device-scoped-operator").expect("valid principal");
    let full = DeviceKey::new("e".repeat(64), DeviceScope::Full, None, 0);
    let attenuated = DeviceKey::new(
        "f".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string()],
            deny: Vec::new(),
        },
        None,
        0,
    );
    let full_key_id = full.key_id.clone();
    let attenuated_key_id = attenuated.key_id.clone();

    seed_profile(
        &kernel,
        &principal,
        &PrincipalProfile {
            grants: vec!["system:shutdown".to_string()],
            auth: astrid_core::profile::AuthConfig {
                methods: vec![AuthMethod::Keypair],
                public_keys: vec![full, attenuated],
            },
            ..Default::default()
        },
    );
    let mut shutdown_rx = kernel.shutdown_tx.subscribe();
    drop(spawn_kernel_router(Arc::clone(&kernel)));

    let denied = request_kernel_for_device(
        &kernel,
        &principal,
        Some(&attenuated_key_id),
        "attenuated_device_shutdown",
        KernelRequest::Shutdown {
            reason: Some("device scope must deny".to_string()),
        },
    )
    .await;
    assert_authorization_denied(&denied, "attenuated device");
    assert!(
        !*shutdown_rx.borrow(),
        "device-scope denial must not signal daemon shutdown"
    );

    let admitted = request_kernel_for_device(
        &kernel,
        &principal,
        Some(&full_key_id),
        "full_device_shutdown",
        KernelRequest::Shutdown {
            reason: Some("full device authority".to_string()),
        },
    )
    .await;
    assert_shutdown_admitted(&admitted, "fully authorized device shutdown");
    assert_shutdown_signaled(&mut shutdown_rx, "fully authorized device shutdown").await;

    let limited = request_kernel_for_device(
        &kernel,
        &principal,
        Some(&full_key_id),
        "full_device_shutdown_again",
        KernelRequest::Shutdown {
            reason: Some("must be rate limited".to_string()),
        },
    )
    .await;
    assert_shutdown_rate_limited(&limited, "authorized device's second shutdown");
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
    kernel
        .identity_store
        .create_principal(caller.clone(), [0x31; 32])
        .await
        .expect("seed durable caller identity");
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
            // Mirror production authority isolation: immutable bytes may have
            // the same hash, but each principal owns a distinct executable
            // runtime and mutable guest state.
            reg.register_for(
                Box::new(InventoryCapsule::new(capsule, &format!("{capsule}-cmd"))),
                hash,
                principal,
            )
            .expect("seed principal capsule runtime");
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
        .run_dir()
        .join("test-install-sources")
        .join(capsule);
    std::fs::create_dir_all(&dir).expect("create capsule dir");
    std::fs::write(
        dir.join("Capsule.toml"),
        format!(
            r#"[package]
name = "{capsule}"
version = "0.0.1"
"#
        ),
    )
    .expect("write capsule manifest");
    let _ = command;
    let home = kernel.astrid_home.clone();
    let storage = kernel
        .principal_store
        .as_ref()
        .map(|store| Arc::new(store.clone()));
    let principal = principal.clone();
    std::thread::spawn(move || {
        astrid_capsule_install::install_from_local_path_for_principal(
            &dir,
            &home,
            astrid_capsule_install::InstallOptions {
                storage,
                ..Default::default()
            },
            &principal,
        )
    })
    .join()
    .expect("publish inventory capsule thread")
    .expect("publish inventory capsule to durable registry");
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

    let source_id = {
        let mut registry = kernel.capsules.write().await;
        let provider =
            InventoryCapsule::new("test-topic-provider", "provider").with_subscribe(topic);
        let hash = WasmHash::synthetic("test-topic-provider", "0.0.1");
        registry
            .register_for(Box::new(provider), hash.clone(), &principal)
            .expect("register provider fixture");
        registry
            .source_id_for(&principal, &CapsuleId::from_static("test-topic-provider"))
            .expect("provider source id")
    };

    let probe = kernel.capsule_topic_probe();
    let provider_key = format!(
        "{}{}\0{}\0{}",
        crate::SCOPED_TOPIC_PROBE_SENTINEL,
        principal,
        "test-topic-provider",
        topic
    );
    let other_key = format!(
        "{}{}\0{}\0{}",
        crate::SCOPED_TOPIC_PROBE_SENTINEL,
        principal,
        "test-other-provider",
        topic
    );
    let any_provider_key = format!(
        "{}{}\0{}",
        crate::SCOPED_TOPIC_PROBE_SENTINEL,
        principal,
        topic
    );

    assert!(
        probe.is_subscribed(&provider_key).await,
        "exact provider probe should see the subscriber"
    );
    assert!(
        !probe.is_subscribed(&other_key).await,
        "an unrelated package name must not match the exact probe"
    );
    assert_eq!(
        probe.subscriber_source_ids(&any_provider_key).await,
        vec![source_id],
        "topic discovery must return the loaded provider's kernel-stamped source identity"
    );
}

#[tokio::test]
async fn capsule_service_probe_accepts_only_one_compatible_interface_provider() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = astrid_core::dirs::AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::new("regular-user").expect("valid principal");
    let topic = "session.v1.request.list";
    let provider_source = {
        let mut registry = kernel.capsules.write().await;
        let provider = InventoryCapsule::new("renamed-session-provider", "session")
            .with_subscribe(topic)
            .with_export("astrid", "session", "1.0.0");
        let provider_hash = WasmHash::synthetic("renamed-session-provider", "0.0.1");
        registry
            .register_for(Box::new(provider), provider_hash.clone(), &principal)
            .expect("register provider fixture");
        let provider_source = registry
            .source_id_for(
                &principal,
                &CapsuleId::from_static("renamed-session-provider"),
            )
            .expect("provider source id");

        let unrelated =
            InventoryCapsule::new("topic-only-adversary", "adversary").with_subscribe(topic);
        let unrelated_hash = WasmHash::synthetic("topic-only-adversary", "0.0.1");
        registry
            .register_for(Box::new(unrelated), unrelated_hash.clone(), &principal)
            .expect("register unrelated fixture");
        provider_source
    };

    let probe = kernel.capsule_topic_probe();
    let service_key = format!(
        "{}{}\0astrid\0session\0^1.0\0{}",
        crate::SCOPED_SERVICE_PROBE_SENTINEL,
        principal,
        topic
    );
    assert!(probe.is_subscribed(&service_key).await);
    assert_eq!(
        probe.subscriber_source_ids(&service_key).await,
        vec![provider_source],
        "a topic-only capsule must not become an authenticated service provider"
    );

    {
        let mut registry = kernel.capsules.write().await;
        let duplicate = InventoryCapsule::new("duplicate-session-provider", "duplicate")
            .with_subscribe(topic)
            .with_export("astrid", "session", "1.2.0");
        let duplicate_hash = WasmHash::synthetic("duplicate-session-provider", "0.0.1");
        registry
            .register_for(Box::new(duplicate), duplicate_hash.clone(), &principal)
            .expect("register duplicate fixture");
    }

    assert!(
        !probe.is_subscribed(&service_key).await,
        "ambiguous providers must fail closed"
    );
    assert!(probe.subscriber_source_ids(&service_key).await.is_empty());
}
