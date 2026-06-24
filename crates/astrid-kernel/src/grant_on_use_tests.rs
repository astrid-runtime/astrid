//! Tests for the grant-on-first-use consent handler (issue #998).
//!
//! These drive the real handler through a `test_kernel_with_home` fixture:
//! seed a principal's on-disk profile WITHOUT the capsule, publish a
//! `GrantRequired` on `astrid.v1.approval`, then publish the consent response
//! on the per-request response topic, and assert the on-disk grant set
//! converges (or does not) per the decision.

use std::sync::Arc;
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::{AstridEvent, EventMetadata};

use super::is_approved;
use crate::Kernel;

/// Build a kernel rooted at a fresh tempdir and spawn the grant-on-use handler.
/// Returns the tempdir (kept alive), the home, and the kernel.
async fn fixture() -> (tempfile::TempDir, AstridHome, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home.clone()).await;
    drop(crate::grant_on_use::spawn_grant_on_use_handler(Arc::clone(
        &kernel,
    )));
    (dir, home, kernel)
}

/// Write a principal profile to disk so `require_principal_exists` passes.
fn seed_profile(home: &AstridHome, principal: &str, capsules: &[&str]) {
    let pid = PrincipalId::new(principal).expect("valid principal");
    let profile = PrincipalProfile {
        capsules: capsules.iter().map(|c| (*c).to_string()).collect(),
        ..PrincipalProfile::default()
    };
    let path = PrincipalProfile::path_for(home, &pid);
    std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir profiles");
    profile.save_to_path(&path).expect("save profile");
}

/// Read a principal's persisted capsule grant set straight off disk (bypassing
/// any cache), so we observe what `save_to_path` actually wrote.
fn on_disk_capsules(home: &AstridHome, principal: &str) -> Vec<String> {
    let pid = PrincipalId::new(principal).expect("valid principal");
    let path = PrincipalProfile::path_for(home, &pid);
    if !path.exists() {
        return Vec::new();
    }
    PrincipalProfile::load_from_path(&path)
        .expect("load profile")
        .capsules
}

/// Publish a `GrantRequired` exactly as the dispatcher would.
fn publish_grant_required(kernel: &Kernel, request_id: &str, principal: &str, capsule_id: &str) {
    let payload = IpcPayload::GrantRequired {
        request_id: request_id.to_string(),
        principal: principal.to_string(),
        capsule_id: capsule_id.to_string(),
    };
    let message = IpcMessage::new(Topic::approval_request(), payload, uuid::Uuid::nil());
    kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("test-dispatcher"),
    });
}

/// Publish a consent response on the per-request response topic (the
/// ACL-authorized path the broker/uplink uses).
fn publish_response(kernel: &Kernel, request_id: &str, decision: &str) {
    let topic = Topic::approval_response(request_id);
    let payload = IpcPayload::ApprovalResponse {
        request_id: request_id.to_string(),
        decision: decision.to_string(),
        reason: None,
    };
    let message = IpcMessage::new(topic, payload, uuid::Uuid::nil());
    kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("test-broker"),
    });
}

/// Poll the on-disk grant set until it contains `capsule` or the deadline
/// elapses. Returns whether the capsule landed.
async fn wait_for_grant(home: &AstridHome, principal: &str, capsule: &str) -> bool {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .expect("deadline overflow");
    while Instant::now() < deadline {
        if on_disk_capsules(home, principal)
            .iter()
            .any(|c| c == capsule)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Give the observer task time to see the `GrantRequired` and subscribe to the
/// response topic before the response is published (avoids the publish/subscribe
/// race the handler is designed around).
async fn settle() {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Assert the grant does NOT land within a bounded window — for deny / timeout /
/// uncorrelated cases, where convergence to "no grant" is the post-condition.
async fn assert_no_grant(home: &AstridHome, principal: &str, capsule: &str) {
    // Long enough that an erroneous grant would have flushed to disk, far short
    // of the 60s response timeout so the test stays fast.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !on_disk_capsules(home, principal)
            .iter()
            .any(|c| c == capsule),
        "{principal} must NOT have been granted {capsule}"
    );
}

#[test]
fn approve_set_matches_host_approval() {
    // The exact approve set replicated from host/approval.rs::decision_from_str.
    assert!(is_approved("approve"));
    assert!(is_approved("approve_session"));
    assert!(is_approved("approve_always"));
    // Everything else — deny, unknown, empty — is NOT an approve.
    assert!(!is_approved("deny"));
    assert!(!is_approved("reject"));
    assert!(!is_approved(""));
    assert!(!is_approved("APPROVE"));
}

/// Test #2: APPROVE grants the capsule end-to-end. After the response the
/// principal's persisted grant set contains the capsule, the cache was
/// invalidated, and `is_capsule_allowed` reflects the new grant.
#[tokio::test]
async fn approve_grants_capsule_end_to_end() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-approve-1";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;
    publish_response(&kernel, rid, "approve");

    assert!(
        wait_for_grant(&home, "x", "cap").await,
        "APPROVE must grant `cap` to principal `x`"
    );

    // The cache reflects the grant (it was invalidated on the grant path).
    let pid = PrincipalId::new("x").unwrap();
    let resolved = kernel.profile_cache.resolve(&pid).expect("resolve profile");
    assert!(
        resolved.capsules.iter().any(|c| c == "cap"),
        "profile cache must reflect the granted capsule after invalidation"
    );

    // And the access resolver now allows the principal/capsule pair.
    let access_resolver = astrid_capsule::CapsuleAccessResolver::new(
        Arc::clone(&kernel.profile_cache),
        Arc::clone(&kernel.groups),
    );
    let capsule_id = astrid_capsule::capsule::CapsuleId::new("cap").expect("capsule id");
    assert!(
        access_resolver.is_capsule_allowed(Some("x"), &capsule_id),
        "is_capsule_allowed must be true for the freshly granted capsule"
    );
}

/// Test #3a: DENY → no grant.
#[tokio::test]
async fn deny_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-deny-1";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;
    publish_response(&kernel, rid, "deny");

    assert_no_grant(&home, "x", "cap").await;
}

/// Test #3a': an unknown decision string is treated as a deny → no grant.
#[tokio::test]
async fn unknown_decision_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-unknown-1";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;
    publish_response(&kernel, rid, "maybe-later");

    assert_no_grant(&home, "x", "cap").await;
}

/// Test #3b: no response at all → no grant (relies on the bounded awaiter; we
/// assert no grant shortly after, well before the 60s timeout).
#[tokio::test]
async fn no_response_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-noresp-1";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;
    // Deliberately publish NO response.

    assert_no_grant(&home, "x", "cap").await;
}

/// Test #3c: a response on a `request_id` that was never emitted as a
/// `GrantRequired` drives no grant (no correlation exists).
#[tokio::test]
async fn uncorrelated_response_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    // No GrantRequired was ever published for this request id.
    publish_response(&kernel, "rid-never-emitted", "approve");

    assert_no_grant(&home, "x", "cap").await;
}

/// Test #4: SECURITY — the grant target is the correlated principal, not any
/// field the response could supply. `ApprovalResponse` carries only
/// `{request_id, decision, reason}` — there is no principal field, so the target
/// is structurally un-spoofable: it is fixed by the `request_id → (principal,
/// capsule)` correlation captured from the kernel-observed `GrantRequired`.
///
/// We assert the correlation-keyed behaviour: a `GrantRequired` for `x` plus a
/// `GrantRequired` for `y` on a DIFFERENT request id; when only `x`'s response
/// arrives, `x` is granted and `y` is NOT.
#[tokio::test]
async fn grant_lands_on_correlated_principal_only() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);
    seed_profile(&home, "y", &[]);

    let rid_x = "rid-x";
    let rid_y = "rid-y";
    publish_grant_required(&kernel, rid_x, "x", "cap");
    publish_grant_required(&kernel, rid_y, "y", "cap");
    settle().await;

    // Only x's consent arrives.
    publish_response(&kernel, rid_x, "approve");

    assert!(
        wait_for_grant(&home, "x", "cap").await,
        "x's response must grant x"
    );
    assert!(
        !on_disk_capsules(&home, "y").iter().any(|c| c == "cap"),
        "y must NOT be granted when only x's response arrives (correlation-keyed)"
    );
}

/// Test #5: SECURITY — the handler reacts ONLY to a correctly-topic'd
/// `ApprovalResponse` on `astrid.v1.approval.response.<rid>`. A "response"
/// delivered to a DIFFERENT topic, or a non-`ApprovalResponse` payload on the
/// response topic, drives no grant. Response authenticity rides on the
/// publish-ACL for that topic (only the uplink/broker may publish there), which
/// the handler trusts without a separate provenance check — exactly as
/// `host/approval.rs` does; this asserts the kernel's half of that guarantee.
#[tokio::test]
async fn response_on_wrong_topic_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-wrongtopic";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;

    // Publish an "approve" ApprovalResponse, but on the WRONG topic (the
    // broadcast approval topic, not the per-request response topic). The
    // per-request awaiter is subscribed to `...response.<rid>` only, so it
    // never observes this — no grant.
    let payload = IpcPayload::ApprovalResponse {
        request_id: rid.to_string(),
        decision: "approve".to_string(),
        reason: None,
    };
    let message = IpcMessage::new(Topic::approval_request(), payload, uuid::Uuid::nil());
    kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("test-forger"),
    });

    assert_no_grant(&home, "x", "cap").await;
}

/// Test #5': a non-`ApprovalResponse` payload on the correct response topic is
/// ignored — the handler matches only `ApprovalResponse`.
#[tokio::test]
async fn non_approval_payload_on_response_topic_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-wrongpayload";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;

    // Right topic, wrong payload type — must not be honoured as consent.
    let topic = Topic::approval_response(rid);
    let payload = IpcPayload::Custom {
        data: serde_json::json!({ "decision": "approve" }),
    };
    let message = IpcMessage::new(topic, payload, uuid::Uuid::nil());
    kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("test-forger"),
    });

    assert_no_grant(&home, "x", "cap").await;
}

/// SECURITY: a `GrantRequired` published from a NON-kernel source (the host
/// stamps every capsule publish with the capsule's own non-nil UUID) is ignored,
/// even with a valid approve. `from_json_value` would let a capsule holding
/// `astrid.v1.approval` publish-ACL craft a typed `GrantRequired` with an
/// attacker-chosen target; the observer honours only kernel-originated signals
/// (nil `source_id`, which a capsule cannot forge), so no grant lands.
#[tokio::test]
async fn grant_required_from_non_kernel_source_does_not_grant() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &[]);

    let rid = "rid-forged-source";
    // A capsule-style (non-nil) source_id — what the host would stamp on a
    // capsule's publish; the kernel dispatcher always uses nil.
    let payload = IpcPayload::GrantRequired {
        request_id: rid.to_string(),
        principal: "x".to_string(),
        capsule_id: "cap".to_string(),
    };
    let message = IpcMessage::new(
        Topic::approval_request(),
        payload,
        uuid::Uuid::from_u128(0x1234_5678),
    );
    kernel.event_bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("test-malicious-capsule"),
    });
    settle().await;
    // Even a valid approve on the attacker-known response topic must not grant,
    // because the GrantRequired was never honoured (non-kernel source).
    publish_response(&kernel, rid, "approve");

    assert_no_grant(&home, "x", "cap").await;
}

/// Fail-closed: an APPROVE for a principal with NO profile on disk is a no-op,
/// never a create. (`require_principal_exists` rejects it.)
#[tokio::test]
async fn approve_for_nonexistent_principal_does_not_create() {
    let (_dir, home, kernel) = fixture().await;
    // Deliberately do NOT seed any profile for `ghost`.

    let rid = "rid-ghost";
    publish_grant_required(&kernel, rid, "ghost", "cap");
    settle().await;
    publish_response(&kernel, rid, "approve");

    tokio::time::sleep(Duration::from_millis(400)).await;
    let pid = PrincipalId::new("ghost").unwrap();
    let path = PrincipalProfile::path_for(&home, &pid);
    assert!(
        !path.exists(),
        "a grant for a non-existent principal must NOT materialize a profile"
    );
}

/// Idempotent: an APPROVE for a capsule the principal ALREADY holds leaves the
/// grant set unchanged (no duplicate) and does not error.
#[tokio::test]
async fn approve_already_granted_is_idempotent() {
    let (_dir, home, kernel) = fixture().await;
    seed_profile(&home, "x", &["cap"]);

    let rid = "rid-idem";
    publish_grant_required(&kernel, rid, "x", "cap");
    settle().await;
    publish_response(&kernel, rid, "approve");

    tokio::time::sleep(Duration::from_millis(400)).await;
    let caps = on_disk_capsules(&home, "x");
    assert_eq!(
        caps.iter().filter(|c| c.as_str() == "cap").count(),
        1,
        "an already-granted capsule must not be duplicated"
    );
}
