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

use astrid_audit::AuditAction;
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::ipc::{IpcMessage, IpcPayload};
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
    let topic = format!("astrid.v1.admin.{suffix}");
    let response_topic = format!("astrid.v1.admin.response.{suffix}");
    let mut rx = kernel.event_bus.subscribe_topic(&response_topic);

    let payload = serde_json::to_value(&req).expect("serialize admin request");
    let mut msg = IpcMessage::new(topic, IpcPayload::RawJson(payload), kernel.session_id.0);
    msg.principal = Some(caller.as_str().to_string());
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: msg,
    });

    // Wait briefly for the response. The admin router is spawned at
    // kernel construction time so this should fire on the next tokio
    // tick; a 2-second timeout keeps misbehaving tests from hanging CI.
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), async {
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
    .expect("admin response within 2s");

    response
}

// ── enabled-flag enforcement (Layer 5 preamble + Layer 6 admin) ──

#[tokio::test(flavor = "multi_thread")]
async fn disabled_principal_denied_on_admin_topic() {
    let (_dir, kernel) = fixture().await;

    // Seed a disabled admin. Without the enabled gate this principal
    // would still satisfy `caps:grant` via group membership; with the
    // gate they are denied up front and the response carries the
    // `PrincipalDisabled` error message.
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["admin".to_string()];
    profile.enabled = false;
    let caller = pid("locked_out_admin");
    seed_profile(&kernel, &caller, &profile);

    // Create a separate principal we can target for caps.grant — not
    // strictly needed since the request is rejected before it reaches
    // the handler, but the wire shape must be valid.
    let mut target_profile = PrincipalProfile::default();
    target_profile.groups = vec!["restricted".to_string()];
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
    let mut profile = PrincipalProfile::default();
    profile.groups = vec!["admin".to_string()];
    profile.enabled = true;
    let caller = pid("active_admin");
    seed_profile(&kernel, &caller, &profile);

    let mut target_profile = PrincipalProfile::default();
    target_profile.groups = vec!["restricted".to_string()];
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

    let mut admin = PrincipalProfile::default();
    admin.groups = vec!["admin".to_string()];
    seed_profile(&kernel, &PrincipalId::default(), &admin);

    let mut target = PrincipalProfile::default();
    target.groups = vec!["restricted".to_string()];
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

    let mut admin = PrincipalProfile::default();
    admin.groups = vec!["admin".to_string()];
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
    let mut admin = PrincipalProfile::default();
    admin.groups = vec!["admin".to_string()];
    admin.enabled = false;
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
