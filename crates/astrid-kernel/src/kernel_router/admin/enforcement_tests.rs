//! Layer 5/6 enforcement-preamble tests (issue #672 follow-up).
//!
//! Two tiers:
//!
//! - **`enabled`-flag enforcement.** A principal with `enabled = false`
//!   on its profile must be denied every management API call —
//!   including admin topics they would otherwise be authorized for —
//!   at the Layer 5 `authorize_request` preamble. Pre-Layer-6 the flag
//!   was set on disk but never honored.
//! - **Audit params capture.** Every `AuditAction::AdminRequest` entry
//!   should carry the request payload (`params: Some(value)`) so
//!   forensic replay doesn't require diffing `profile.toml` /
//!   `groups.toml` snapshots.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditOutcome, AuthorizationProof};
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::kernel_api::{AdminKernelRequest, AdminRequestKind};
use tempfile::TempDir;

use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

/// Seed a principal profile on disk under `kernel.astrid_home`.
fn seed_profile(kernel: &Arc<Kernel>, principal: &PrincipalId, profile: &PrincipalProfile) {
    let path = PrincipalProfile::path_for(&kernel.astrid_home, principal);
    profile.save_to_path(&path).expect("seed profile");
    kernel.profile_cache.invalidate(principal);
}

/// Synthesize an admin IPC message and publish it on the bus, returning
/// a receiver subscribed to the matching response topic. Lets us drive
/// the full `spawn_admin_router` → `handle_admin_request` flow in tests
/// without hand-rolling the dispatcher invocation.
async fn send_admin(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    suffix: &str,
    req: AdminKernelRequest,
) -> serde_json::Value {
    send_admin_with_raw_principal(kernel, Some(caller.as_str()), suffix, req).await
}

async fn send_admin_with_raw_principal(
    kernel: &Arc<Kernel>,
    principal: Option<&str>,
    suffix: &str,
    req: AdminKernelRequest,
) -> serde_json::Value {
    let topic = Topic::admin_request(suffix);
    let response_topic = Topic::admin_response(suffix);
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());

    let payload = serde_json::to_value(&req).expect("serialize admin request");
    let mut msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), kernel.session_id.0);
    msg.principal = principal.map(str::to_string);
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });

    // Wait briefly for the response. The admin router is spawned at
    // kernel construction time so this should fire on the next tokio
    // tick; a 2-second timeout keeps misbehaving tests from hanging CI.

    astrid_runtime::time::timeout(std::time::Duration::from_secs(2), async {
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
    .expect("admin response within 2s")
}

// ── enabled-flag enforcement (Layer 5 preamble + Layer 6 admin) ──

#[tokio::test(flavor = "multi_thread")]
async fn disabled_principal_denied_on_admin_topic() {
    let (_dir, kernel) = fixture().await;

    // Seed a disabled admin. Without the enabled gate this principal
    // would still satisfy `caps:grant` via group membership; with the
    // gate they are denied up front and the response carries the
    // `PrincipalDisabled` error message.
    let profile = PrincipalProfile {
        groups: vec!["admin".to_string()],
        enabled: false,
        ..Default::default()
    };
    let caller = pid("locked_out_admin");
    seed_profile(&kernel, &caller, &profile);

    // Create a separate principal we can target for caps.grant — not
    // strictly needed since the request is rejected before it reaches
    // the handler, but the wire shape must be valid.
    let target_profile = PrincipalProfile {
        groups: vec!["restricted".to_string()],
        ..Default::default()
    };
    seed_profile(&kernel, &pid("target_user"), &target_profile);

    let resp = send_admin(
        &kernel,
        &caller,
        "caps.grant",
        AdminRequestKind::CapsGrant {
            principal: pid("target_user"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        }
        .into(),
    )
    .await;

    assert_eq!(resp["status"], "Error");
    let err_msg = resp["data"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("agent is disabled") || err_msg.contains("disabled"),
        "expected disabled-principal error, got: {err_msg}"
    );

    // Target's profile must not have been mutated — preamble denied
    // before any handler ran.
    let after = kernel.profile_cache.resolve(&pid("target_user")).unwrap();
    assert!(
        after.grants.is_empty(),
        "disabled-principal request must not mutate target: {:?}",
        after.grants
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enabled_principal_proceeds_through_admin_topic() {
    let (_dir, kernel) = fixture().await;

    // Sanity: same setup with `enabled = true` succeeds.
    let profile = PrincipalProfile {
        groups: vec!["admin".to_string()],
        enabled: true,
        ..Default::default()
    };
    let caller = pid("active_admin");
    seed_profile(&kernel, &caller, &profile);

    let target_profile = PrincipalProfile {
        groups: vec!["restricted".to_string()],
        ..Default::default()
    };
    seed_profile(&kernel, &pid("target_user"), &target_profile);

    let resp = send_admin(
        &kernel,
        &caller,
        "caps.grant",
        AdminRequestKind::CapsGrant {
            principal: pid("target_user"),
            capabilities: vec!["self:capsule:install".into()],
            unsafe_admin: false,
        }
        .into(),
    )
    .await;
    assert_eq!(resp["status"], "Success", "got: {resp}");

    let after = kernel.profile_cache.resolve(&pid("target_user")).unwrap();
    assert_eq!(after.grants, vec!["self:capsule:install".to_string()]);
}

// ── Audit params capture (forensic replay invariant) ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_request_audit_includes_params_payload() {
    let (_dir, kernel) = fixture().await;

    let admin = PrincipalProfile {
        groups: vec!["admin".to_string()],
        ..Default::default()
    };
    seed_profile(&kernel, &PrincipalId::default(), &admin);

    let target = PrincipalProfile {
        groups: vec!["restricted".to_string()],
        ..Default::default()
    };
    seed_profile(&kernel, &pid("target_user"), &target);

    // Drive a caps.grant via the IPC dispatcher so the audit entry is
    // appended through the production code path.
    let resp = send_admin(
        &kernel,
        &PrincipalId::default(),
        "caps.grant",
        AdminRequestKind::CapsGrant {
            principal: pid("target_user"),
            capabilities: vec!["self:capsule:install".into(), "self:capsule:list".into()],
            unsafe_admin: false,
        }
        .into(),
    )
    .await;
    assert_eq!(resp["status"], "Success", "got: {resp}");

    // Read the audit chain back: the most recent AdminRequest entry
    // for `admin.caps.grant` must carry `params` with the granted
    // capability list. Without this, forensic replay can only diff
    // profile.toml snapshots — much harder.
    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit chain");
    let found = entries
        .iter()
        .rev()
        .find_map(|e| match &e.action {
            AuditAction::AdminRequest { method, params, .. } if method == "admin.caps.grant" => {
                Some(params.clone())
            },
            _ => None,
        })
        .expect("admin.caps.grant audit entry");
    let params = found.expect("audit entry must carry params");
    assert_eq!(params["method"], "CapsGrant");
    let caps = &params["params"]["capabilities"];
    assert_eq!(caps[0], "self:capsule:install");
    assert_eq!(caps[1], "self:capsule:list");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_request_id_is_echoed_back_on_response() {
    let (_dir, kernel) = fixture().await;

    let admin = PrincipalProfile {
        groups: vec!["admin".to_string()],
        ..Default::default()
    };
    seed_profile(&kernel, &PrincipalId::default(), &admin);

    let resp = send_admin(
        &kernel,
        &PrincipalId::default(),
        "agent.list",
        AdminKernelRequest::with_request_id("req-correlate-42", AdminRequestKind::AgentList),
    )
    .await;
    assert_eq!(resp["request_id"], "req-correlate-42");
    assert_eq!(resp["status"], "AgentList");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_request_id_echoed_on_deny_path_too() {
    let (_dir, kernel) = fixture().await;

    // Disabled admin — Layer 5 preamble denies, response should still
    // carry the request_id so the client can match it to its in-flight
    // request.
    let admin = PrincipalProfile {
        groups: vec!["admin".to_string()],
        enabled: false,
        ..Default::default()
    };
    let caller = pid("disabled_admin");
    seed_profile(&kernel, &caller, &admin);

    let resp = send_admin(
        &kernel,
        &caller,
        "agent.list",
        AdminKernelRequest::with_request_id("req-deny-correlate", AdminRequestKind::AgentList),
    )
    .await;
    assert_eq!(resp["request_id"], "req-deny-correlate");
    assert_eq!(resp["status"], "Error");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_router_denies_missing_and_invalid_principals_deterministically() {
    let (_dir, kernel) = fixture().await;

    for (suffix, principal) in [
        ("caller.missing", None),
        ("caller.invalid", Some("alice@evil.example")),
    ] {
        let request_id = format!("req-{suffix}");
        let response = send_admin_with_raw_principal(
            &kernel,
            principal,
            suffix,
            AdminKernelRequest::with_request_id(&request_id, AdminRequestKind::AgentList),
        )
        .await;
        assert_eq!(response["request_id"], request_id);
        assert_eq!(response["status"], "Error");
        assert_eq!(response["data"], super::super::MANAGEMENT_CALLER_REQUIRED);
    }
}

// ── Per-device scope attenuation at the cap-gate ────────────────────

/// Like [`send_admin`] but stamps a host-derived `device_key_id` on the IPC
/// message — modelling a request that authenticated with a specific registered
/// device (socket per-connection registry or gateway-signed scoped bearer). A
/// `None` here is the unattenuated full-principal request.
async fn send_admin_scoped(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    device_key_id: Option<&str>,
    suffix: &str,
    req: AdminKernelRequest,
) -> serde_json::Value {
    let topic = Topic::admin_request(suffix);
    let response_topic = Topic::admin_response(suffix);
    let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());

    let payload = serde_json::to_value(&req).expect("serialize admin request");
    let mut msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), kernel.session_id.0);
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
                return val.clone();
            }
        }
    })
    .await
    .expect("admin response within 2s")
}

#[derive(Clone, Copy)]
enum PairIssueAuditExpectation {
    Success,
    Denied,
    BadInput,
}

async fn assert_pair_issue_audit(
    kernel: &Arc<Kernel>,
    expected_capability: &str,
    expectation: PairIssueAuditExpectation,
) {
    let entries = kernel
        .audit_log
        .get_session_entries(&kernel.session_id)
        .await
        .expect("read audit chain");
    let pair_entries = entries
        .iter()
        .filter(|entry| {
            matches!(
                &entry.action,
                AuditAction::AdminRequest { method, .. }
                    if method == "admin.auth.pair.issue"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pair_entries.len(),
        1,
        "pair issuance must produce exactly one terminal audit row"
    );
    let entry = pair_entries[0];
    let AuditAction::AdminRequest {
        required_capability,
        ..
    } = &entry.action
    else {
        unreachable!("filtered to pair issue audit rows")
    };
    assert_eq!(required_capability, expected_capability);
    match expectation {
        PairIssueAuditExpectation::Success => {
            assert!(matches!(
                &entry.authorization,
                AuthorizationProof::System { .. }
            ));
            assert!(matches!(&entry.outcome, AuditOutcome::Success { .. }));
        },
        PairIssueAuditExpectation::Denied => {
            assert!(matches!(
                &entry.authorization,
                AuthorizationProof::Denied { .. }
            ));
            assert!(matches!(&entry.outcome, AuditOutcome::Failure { .. }));
        },
        PairIssueAuditExpectation::BadInput => {
            assert!(matches!(
                &entry.authorization,
                AuthorizationProof::System { .. }
            ));
            assert!(matches!(&entry.outcome, AuditOutcome::Failure { .. }));
        },
    }
}

/// Seed a principal that holds `self:auth:pair` and registers two devices: a
/// Full-scope device and a use-only device whose scope denies `self:auth:pair`.
/// Returns `(full_key_id, scoped_key_id)`.
fn seed_principal_with_devices(kernel: &Arc<Kernel>, principal: &PrincipalId) -> (String, String) {
    use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope};

    let mut profile = PrincipalProfile {
        grants: vec!["self:*".to_string()],
        enabled: true,
        ..Default::default()
    };
    profile.auth.methods.push(AuthMethod::Keypair);

    // A Full-scope device (unattenuated) and a use-only device that denies the
    // pair capability. Distinct dummy pubkeys → distinct deterministic key_ids.
    let full = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
    let scoped = DeviceKey::new(
        "b".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".to_string()],
            deny: vec!["self:auth:pair".to_string()],
        },
        None,
        0,
    );
    let full_id = full.key_id.clone();
    let scoped_id = scoped.key_id.clone();
    profile.auth.public_keys = vec![full, scoped];

    seed_profile(kernel, principal, &profile);
    (full_id, scoped_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn device_scope_denies_pair_issue_but_full_device_and_none_allow() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("paired_user");
    let (full_id, scoped_id) = seed_principal_with_devices(&kernel, &caller);

    // Full PairDeviceIssue is gated by pair-admin, which `self:*` admits.
    let req = || {
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: Some("test".into()),
            scope: astrid_events::kernel_api::PairScopeArg::Full,
        }
        .into()
    };

    // 1. No device scope (full-principal request) → ALLOWED. The handler runs
    //    and returns a PairToken.
    let resp = send_admin_scoped(&kernel, &caller, None, "auth.pair.issue", req()).await;
    assert_eq!(
        resp["status"], "PairToken",
        "an unattenuated request must be allowed: {resp}"
    );

    // 2. A Full-scope device → ALLOWED (Full is equivalent to no attenuation).
    let resp = send_admin_scoped(&kernel, &caller, Some(&full_id), "auth.pair.issue", req()).await;
    assert_eq!(
        resp["status"], "PairToken",
        "a full-scope device must be allowed: {resp}"
    );

    // 3. The use-only device (deny: self:auth:pair) → DENIED, even though the
    //    SAME principal holds `self:auth:pair`. This is the headline guarantee:
    //    a paired device cannot exceed its scope.
    let resp =
        send_admin_scoped(&kernel, &caller, Some(&scoped_id), "auth.pair.issue", req()).await;
    assert_eq!(
        resp["status"], "Error",
        "a use-only device must be denied at the cap-gate: {resp}"
    );
    let err = resp["data"].as_str().unwrap_or_default();
    assert!(
        err.contains("outside the authenticating device's scope") || err.contains("device"),
        "deny must be a device-scope denial, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_device_key_id_fails_closed() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("paired_user");
    let _ = seed_principal_with_devices(&kernel, &caller);

    // A request naming a device key the principal does not have (revoked or
    // never registered) must FAIL CLOSED — never fall back to the principal's
    // full authority. The principal holds `self:auth:pair`, so a fallback would
    // wrongly allow.
    let resp = send_admin_scoped(
        &kernel,
        &caller,
        Some("deadbeefdeadbeef"),
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Full,
        }
        .into(),
    )
    .await;
    assert_eq!(
        resp["status"], "Error",
        "an unresolved device_key_id must fail closed: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pair_mint_without_admin_capability_audits_denial() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("pair_issue_only");
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:auth:pair".into()],
            enabled: true,
            ..Default::default()
        },
    );

    let response = send_admin(
        &kernel,
        &caller,
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Full,
        }
        .into(),
    )
    .await;
    assert_eq!(response["status"], "Error", "got: {response}");
    assert_pair_issue_audit(
        &kernel,
        "self:auth:pair:admin",
        PairIssueAuditExpectation::Denied,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn scoped_issuer_full_mint_structural_denial_is_audited() {
    use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope};

    let (_dir, kernel) = fixture().await;
    let caller = pid("scoped_pair_admin");
    let device = DeviceKey::new(
        "c".repeat(64),
        DeviceScope::Scoped {
            allow: vec!["self:*".into()],
            deny: vec![],
        },
        None,
        0,
    );
    let device_id = device.key_id.clone();
    let mut profile = PrincipalProfile {
        grants: vec!["self:*".into()],
        enabled: true,
        ..Default::default()
    };
    profile.auth.methods.push(AuthMethod::Keypair);
    profile.auth.public_keys.push(device);
    seed_profile(&kernel, &caller, &profile);

    let response = send_admin_scoped(
        &kernel,
        &caller,
        Some(&device_id),
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Full,
        }
        .into(),
    )
    .await;
    assert_eq!(response["status"], "Error", "got: {response}");
    assert_pair_issue_audit(
        &kernel,
        "self:auth:pair:admin",
        PairIssueAuditExpectation::Denied,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn universal_pair_mint_subset_denial_is_audited() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("bounded_pair_admin");
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:auth:pair:admin".into()],
            enabled: true,
            ..Default::default()
        },
    );

    let response = send_admin(
        &kernel,
        &caller,
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Explicit {
                allow: vec!["*".into()],
                deny: vec![],
            },
        }
        .into(),
    )
    .await;
    assert_eq!(response["status"], "Error", "got: {response}");
    assert_pair_issue_audit(
        &kernel,
        "self:auth:pair:admin",
        PairIssueAuditExpectation::Denied,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_pair_scope_audits_bad_input_not_permission_denial() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("malformed_pair_scope");
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["self:auth:pair".into(), "self:capsule:reload".into()],
            enabled: true,
            ..Default::default()
        },
    );

    let response = send_admin(
        &kernel,
        &caller,
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Explicit {
                allow: vec!["self:capsule:reload".into()],
                deny: vec!["self:capsule;install".into()],
            },
        }
        .into(),
    )
    .await;
    assert_eq!(response["status"], "Error", "got: {response}");
    assert_pair_issue_audit(
        &kernel,
        "self:auth:pair",
        PairIssueAuditExpectation::BadInput,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_full_pair_mint_audits_pair_admin_allow() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("unattenuated_pair_admin");
    seed_profile(
        &kernel,
        &caller,
        &PrincipalProfile {
            grants: vec!["*".into()],
            enabled: true,
            ..Default::default()
        },
    );

    let response = send_admin(
        &kernel,
        &caller,
        "auth.pair.issue",
        AdminRequestKind::PairDeviceIssue {
            expires_secs: Some(300),
            label: None,
            scope: astrid_events::kernel_api::PairScopeArg::Full,
        }
        .into(),
    )
    .await;
    assert_eq!(response["status"], "PairToken", "got: {response}");
    assert_pair_issue_audit(
        &kernel,
        "self:auth:pair:admin",
        PairIssueAuditExpectation::Success,
    )
    .await;
}
