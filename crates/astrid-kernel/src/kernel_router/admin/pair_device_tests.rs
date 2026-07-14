//! Acceptance tests for per-device capability scope on pairing.
//!
//! These drive the kernel/handler path end-to-end (real `Kernel`, profiles on
//! disk, the same `handlers::dispatch_with_device` the IPC router uses) and
//! prove the no-escalation guarantees the feature exists to provide:
//!
//! * a `use-only` device cannot mint pair-tokens (cap-gate denial), but the
//!   same principal can from a full device;
//! * an over-broad requested scope is rejected at issue time (subset check);
//! * a scoped issuer is denied minting a `Full` token (full-mint gate) and the
//!   stored child scope inherits the issuer's denies (monotonic narrowing);
//! * list/revoke round-trip, and a revoked device fails closed at the gate;
//! * audit params carry the scope / `key_id` but never a raw key or token.
//!
//! The HTTP-bearer half of the cross-transport guarantees lives in the gateway
//! crate's `tests/router.rs`; the socket/kernel half is here plus the existing
//! `enforcement_tests` device-scope cases.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{
    AuthMethod, DeviceKey, DeviceScope, PrincipalProfile, device_key_id_fingerprint,
};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, DeviceKeyInfo, PairScopeArg};
use tempfile::TempDir;

use super::handlers;
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

/// Seed `principal` holding `grants`, enabled, with the supplied device keys.
fn seed(kernel: &Arc<Kernel>, principal: &PrincipalId, grants: &[&str], devices: Vec<DeviceKey>) {
    seed_policy(kernel, principal, grants, &[], devices);
}

fn seed_policy(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    grants: &[&str],
    revokes: &[&str],
    devices: Vec<DeviceKey>,
) {
    let mut profile = PrincipalProfile {
        grants: grants.iter().map(|g| (*g).to_string()).collect(),
        revokes: revokes.iter().map(|r| (*r).to_string()).collect(),
        enabled: true,
        ..Default::default()
    };
    if !devices.is_empty() {
        profile.auth.methods.push(AuthMethod::Keypair);
        profile.auth.public_keys = devices;
    }
    let path = PrincipalProfile::path_for(&kernel.astrid_home, principal);
    profile.save_to_path(&path).expect("seed profile");
    kernel.profile_cache.invalidate(principal);
}

/// Read a principal's profile back from disk (post-mutation assertions).
fn load(kernel: &Arc<Kernel>, principal: &PrincipalId) -> PrincipalProfile {
    let path = PrincipalProfile::path_for(&kernel.astrid_home, principal);
    PrincipalProfile::load_from_path(&path).expect("load profile")
}

fn full_device(seed_byte: char) -> DeviceKey {
    DeviceKey::new(seed_byte.to_string().repeat(64), DeviceScope::Full, None, 0)
}

fn scoped_device(seed_byte: char, allow: &[&str], deny: &[&str]) -> DeviceKey {
    DeviceKey::new(
        seed_byte.to_string().repeat(64),
        DeviceScope::Scoped {
            allow: allow.iter().map(|s| (*s).to_string()).collect(),
            deny: deny.iter().map(|s| (*s).to_string()).collect(),
        },
        None,
        0,
    )
}

fn issue(scope: PairScopeArg) -> AdminRequestKind {
    AdminRequestKind::PairDeviceIssue {
        expires_secs: Some(300),
        label: Some("dev".into()),
        scope,
    }
}

async fn assert_missing_device_rejects_broad_mints(
    kernel: &Arc<Kernel>,
    caller: &PrincipalId,
    device_key_id: &str,
) {
    for scope in [
        PairScopeArg::Full,
        PairScopeArg::Explicit {
            allow: vec!["*".into()],
            deny: vec![],
        },
    ] {
        let response =
            handlers::dispatch_with_device(kernel, caller, Some(device_key_id), issue(scope)).await;
        assert!(
            matches!(response, AdminResponseBody::Error(_)),
            "a missing issuer device must not mint broad authority: {response:?}"
        );
    }
}

// ── Criterion 2: a full device (full-principal) can re-issue ──────────

#[tokio::test(flavor = "multi_thread")]
async fn full_device_can_issue_full_token() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("full_issuer");
    // `self:*` subsumes both the issue cap and the full-mint admin cap.
    seed(&kernel, &caller, &["self:*"], vec![]);

    let resp =
        handlers::dispatch_with_device(&kernel, &caller, None, issue(PairScopeArg::Full)).await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "a full-authority principal must be able to mint a Full token: {resp:?}"
    );
}

// ── Criterion 7: full-mint gate — a Scoped-only issuer is denied Full ─

#[tokio::test(flavor = "multi_thread")]
async fn scoped_device_cannot_mint_full_even_when_admin_cap_admitted() {
    // No-escalation: a device authenticating under its OWN scope cannot mint a
    // Full (unattenuated) child — even a degenerate `allow self:*, deny []`
    // scope that admits every cap. A Full child applies NO attenuation, so it
    // would escape the issuer's denies (deny-inheritance only narrows scoped
    // children). Minting "no restrictions" requires the issuer to itself be
    // unattenuated; a scoped device must mint a scoped child instead.
    let (_dir, kernel) = fixture().await;
    let caller = pid("scoped_issuer");
    let dev = scoped_device('a', &["self:*"], &[]); // effectively allow-all
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["self:*"], vec![dev]);

    let resp =
        handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), issue(PairScopeArg::Full))
            .await;
    match resp {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("scoped device cannot mint a full-scope"),
            "a scoped device must be denied a Full mint on scoped-ness grounds: {msg}"
        ),
        other => panic!("scoped issuer must be denied a Full mint, got: {other:?}"),
    }

    // It CAN, however, mint a scoped child (the deny-inheritance path).
    let ok = issue(PairScopeArg::Explicit {
        allow: vec!["self:*".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), ok).await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "a scoped device must still be able to mint a scoped child: {resp:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_admin_principal_denied_full_mint() {
    // The admin-cap gate, reachable only for an UNATTENUATED issuer (no device
    // scope / Full device): a principal that holds the issue cap `self:auth:pair`
    // but NOT `self:auth:pair:admin` cannot mint a Full token — it may only mint
    // scoped ones.
    let (_dir, kernel) = fixture().await;
    let caller = pid("issue_only");
    seed(&kernel, &caller, &["self:auth:pair"], vec![]);

    let resp =
        handlers::dispatch_with_device(&kernel, &caller, None, issue(PairScopeArg::Full)).await;
    match resp {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("self:auth:pair:admin"),
            "full-mint denial must name the admin cap: {msg}"
        ),
        other => panic!("a non-admin principal must be denied a Full mint, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn full_scope_device_can_mint_full() {
    // The common case is unchanged: a `full`-preset device (DeviceScope::Full,
    // NOT Scoped) whose principal holds the admin cap mints Full fine.
    let (_dir, kernel) = fixture().await;
    let caller = pid("full_device_issuer");
    let dev = full_device('a');
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["self:*"], vec![dev]);

    let resp =
        handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), issue(PairScopeArg::Full))
            .await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "a full-scope device can mint Full: {resp:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_or_revoked_issuer_device_cannot_mint_broad_authority() {
    let (_dir, kernel) = fixture().await;

    let unknown_caller = pid("unknown_issuer_device");
    seed(&kernel, &unknown_caller, &["*"], vec![]);
    assert_missing_device_rejects_broad_mints(&kernel, &unknown_caller, "0000000000000000").await;
    assert_missing_device_rejects_broad_mints(&kernel, &unknown_caller, "not-a-key-id").await;

    let revoked_caller = pid("revoked_issuer_device");
    let revoked_device = full_device('f');
    let revoked_id = revoked_device.key_id.clone();
    seed(&kernel, &revoked_caller, &["*"], vec![revoked_device]);
    let response = handlers::dispatch(
        &kernel,
        &revoked_caller,
        AdminRequestKind::PairDeviceRevoke {
            principal: revoked_caller.clone(),
            key_id: revoked_id.clone(),
        },
    )
    .await;
    assert!(matches!(
        response,
        AdminResponseBody::PairDeviceRevoked { .. }
    ));
    assert_missing_device_rejects_broad_mints(&kernel, &revoked_caller, &revoked_id).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn universal_scoped_mint_requires_effective_admin_capability() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("universal_scope_without_admin");
    seed_policy(&kernel, &caller, &["*"], &["self:auth:pair:admin"], vec![]);

    let req = issue(PairScopeArg::Explicit {
        allow: vec!["*".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, None, req).await;
    match resp {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("universal `*`") && msg.contains("self:auth:pair:admin"),
            "universal scoped denial must name both the scope and required capability: {msg}"
        ),
        other => panic!("universal scoped mint without pair-admin must reject, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn universal_scoped_mint_is_accepted_with_admin_capability() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("universal_scope_with_admin");
    let dev = scoped_device('a', &["*"], &[]);
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["*"], vec![dev]);

    let req = issue(PairScopeArg::Explicit {
        allow: vec!["*".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), req).await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "an issuer effectively holding pair-admin may mint a universal scoped device: {resp:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scoped_issuer_cannot_bypass_admin_gate_with_universal_allow() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("attenuated_universal_issuer");
    let dev = scoped_device('a', &["*"], &["self:auth:pair:admin"]);
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["*"], vec![dev]);

    let req = issue(PairScopeArg::Explicit {
        allow: vec!["*".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), req).await;
    match resp {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("self:auth:pair:admin"),
            "attenuated issuer denial must name the missing effective capability: {msg}"
        ),
        other => panic!("attenuated scoped issuer must not mint universal scope, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn use_only_scope_does_not_require_admin_capability() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("self_scope_without_admin");
    seed_policy(
        &kernel,
        &caller,
        &["self:*"],
        &["self:auth:pair:admin"],
        vec![],
    );

    let req = issue(PairScopeArg::Preset {
        name: "use-only".into(),
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, None, req).await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "self:* must remain an ordinary subset-checked scoped grant: {resp:?}"
    );
}

// ── Criterion 3: over-broad requested scope rejected at issue time ────

#[tokio::test(flavor = "multi_thread")]
async fn over_broad_scope_rejected_at_issue() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("narrow_issuer");
    // Holds only `self:auth:pair` (the issue cap) and `self:capsule:reload`.
    // It does NOT hold `self:capsule:install`, so requesting it must reject.
    seed(
        &kernel,
        &caller,
        &["self:auth:pair", "self:capsule:reload"],
        vec![],
    );

    let req = issue(PairScopeArg::Explicit {
        allow: vec!["self:capsule:install".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, None, req).await;
    match resp {
        AdminResponseBody::Error(msg) => assert!(
            msg.contains("exceeds your authority") || msg.contains("self:capsule:install"),
            "over-broad scope must be rejected by the subset check: {msg}"
        ),
        other => panic!("over-broad scope must reject, got: {other:?}"),
    }

    // A scope the issuer DOES hold is accepted.
    let ok = issue(PairScopeArg::Explicit {
        allow: vec!["self:capsule:reload".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, None, ok).await;
    assert!(
        matches!(resp, AdminResponseBody::PairToken(_)),
        "a held scope must be accepted: {resp:?}"
    );
}

// ── Coordinator correction: deny-inheritance (monotonic narrowing) ────

#[tokio::test(flavor = "multi_thread")]
async fn scoped_issuer_child_inherits_issuer_denies() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("deny_inheriting_issuer");
    // The issuer authenticates with a scoped device: allow self:*, deny
    // self:capsule:install. It holds self:auth:pair (issue cap) via self:*.
    let dev = scoped_device('a', &["self:*"], &["self:capsule:install"]);
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["self:*"], vec![dev]);

    // The issuer requests a broad child: allow self:*. The stored child scope
    // must inherit the issuer's deny (self:capsule:install) so the child can
    // never exceed the parent on that cap.
    let req = issue(PairScopeArg::Explicit {
        allow: vec!["self:*".into()],
        deny: vec![],
    });
    let resp = handlers::dispatch_with_device(&kernel, &caller, Some(&dev_id), req).await;
    let token = match resp {
        AdminResponseBody::PairToken(t) => t.token,
        other => panic!("issue must succeed (allow self:* ⊆ issuer self:*): {other:?}"),
    };

    // Redeem to materialise the child device and inspect its stored scope.
    let pubkey = "c".repeat(64);
    let redeem = AdminRequestKind::PairDeviceRedeem {
        token,
        public_key: pubkey.clone(),
    };
    let resp = handlers::dispatch(&kernel, &PrincipalId::default(), redeem).await;
    assert!(
        matches!(resp, AdminResponseBody::PairTokenRedeemed(_)),
        "redeem must succeed: {resp:?}"
    );

    let profile = load(&kernel, &caller);
    let key_id = device_key_id_fingerprint(&pubkey);
    let child = profile
        .auth
        .device_by_key_id(&key_id)
        .expect("child device registered");
    match &child.scope {
        DeviceScope::Scoped { allow, deny } => {
            assert!(allow.iter().any(|a| a == "self:*"), "child keeps its allow");
            assert!(
                deny.iter().any(|d| d == "self:capsule:install"),
                "child must inherit the issuer's deny: {deny:?}"
            );
        },
        DeviceScope::Full => panic!("child must be Scoped, not Full"),
    }
}

// ── Criterion 1 (socket/kernel path): use-only denied, use cap allowed ─

#[tokio::test(flavor = "multi_thread")]
async fn use_only_device_denied_pair_issue_but_holds_use_cap() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("use_only_principal");
    // use-only device: allow self:*, deny the pair caps + delegate. The
    // principal itself holds self:* (so it COULD pair from a full device).
    let dev = scoped_device(
        'a',
        &["self:*"],
        &["self:auth:pair", "self:auth:pair:admin", "delegate:self:*"],
    );
    let dev_id = dev.key_id.clone();
    seed(&kernel, &caller, &["self:*"], vec![dev]);

    // Drive the SAME `with_device_scope` attenuation the router's cap-gate
    // (`authorize_request`) applies on the socket path. The full router-path
    // denial is also proven in `enforcement_tests` via `send_admin_scoped`.
    let profile = load(&kernel, &caller);
    let groups = kernel.groups.load_full();
    let scope = profile
        .auth
        .device_by_key_id(&dev_id)
        .unwrap()
        .scope
        .clone();
    let check =
        astrid_capabilities::CapabilityCheck::new(&profile, groups.as_ref(), caller.clone())
            .with_device_scope(&scope);
    // The use cap (an allowed self cap) is admitted by the use-only device.
    assert!(
        check.require("self:capsule:reload").is_ok(),
        "use-only device must still exercise an allowed self cap"
    );
    // The pair cap is denied by the device scope even though the principal holds it.
    assert!(
        matches!(
            check.require("self:auth:pair"),
            Err(astrid_capabilities::PermissionError::DeviceScopeDenied { .. })
        ),
        "use-only device must be denied the pair cap at the gate"
    );
}

// ── Criterion 4: list + revoke; revoked device fails closed at the gate ─

#[tokio::test(flavor = "multi_thread")]
async fn list_and_revoke_round_trip_and_fail_closed() {
    let (_dir, kernel) = fixture().await;
    let caller = pid("device_owner");
    let full = full_device('a');
    let scoped = scoped_device('b', &["self:*"], &["self:auth:pair"]);
    let full_id = full.key_id.clone();
    let scoped_id = scoped.key_id.clone();
    seed(&kernel, &caller, &["self:*"], vec![full, scoped]);

    // List returns both, with key_id + scope + label + created_at.
    let resp = handlers::dispatch(
        &kernel,
        &caller,
        AdminRequestKind::PairDeviceList {
            principal: caller.clone(),
        },
    )
    .await;
    let devices: Vec<DeviceKeyInfo> = match resp {
        AdminResponseBody::PairDeviceListed(d) => d,
        other => panic!("list must return PairDeviceListed: {other:?}"),
    };
    assert_eq!(devices.len(), 2, "both devices listed");
    assert!(devices.iter().any(|d| d.key_id == full_id));
    assert!(
        devices
            .iter()
            .any(|d| d.key_id == scoped_id && matches!(d.scope, DeviceScope::Scoped { .. })),
    );

    // Revoke the scoped device.
    let resp = handlers::dispatch(
        &kernel,
        &caller,
        AdminRequestKind::PairDeviceRevoke {
            principal: caller.clone(),
            key_id: scoped_id.clone(),
        },
    )
    .await;
    match resp {
        AdminResponseBody::PairDeviceRevoked { key_id } => assert_eq!(key_id, scoped_id),
        other => panic!("revoke must return PairDeviceRevoked: {other:?}"),
    }

    // The device is gone from the profile; the cap-gate fails closed for it.
    let profile = load(&kernel, &caller);
    assert!(
        profile.auth.device_by_key_id(&scoped_id).is_none(),
        "revoked device removed from public_keys"
    );
    assert!(
        profile.auth.device_by_key_id(&full_id).is_some(),
        "the other device remains"
    );
    // Keypair method stays because a key remains.
    assert!(profile.auth.methods.contains(&AuthMethod::Keypair));

    // Revoking the last device drops the Keypair method.
    let resp = handlers::dispatch(
        &kernel,
        &caller,
        AdminRequestKind::PairDeviceRevoke {
            principal: caller.clone(),
            key_id: full_id.clone(),
        },
    )
    .await;
    assert!(matches!(resp, AdminResponseBody::PairDeviceRevoked { .. }));
    let profile = load(&kernel, &caller);
    assert!(profile.auth.public_keys.is_empty());
    assert!(
        !profile.auth.methods.contains(&AuthMethod::Keypair),
        "last keypair removal drops the Keypair auth method"
    );

    // Revoking an unknown key_id is a clear not-found error (fail-closed).
    let resp = handlers::dispatch(
        &kernel,
        &caller,
        AdminRequestKind::PairDeviceRevoke {
            principal: caller.clone(),
            key_id: "deadbeefdeadbeef".into(),
        },
    )
    .await;
    match resp {
        AdminResponseBody::Error(msg) => {
            assert!(msg.contains("no paired device"), "not-found error: {msg}");
        },
        other => panic!("unknown key_id must error, got: {other:?}"),
    }
}

// ── Criterion 6: audit redaction — scope/key_id but never raw key/token ─

#[test]
fn audit_params_carry_scope_and_key_id_never_raw_key_or_token() {
    use super::sanitize_admin_audit_params;

    // Issue: params carry the scope, no key, no token.
    let issue_req = AdminRequestKind::PairDeviceIssue {
        expires_secs: Some(300),
        label: Some("phone".into()),
        scope: PairScopeArg::Preset {
            name: "use-only".into(),
        },
    };
    let params = sanitize_admin_audit_params(&issue_req).expect("issue params");
    let s = params.to_string();
    assert!(s.contains("use-only"), "issue audit records the scope: {s}");
    assert!(!s.contains("public_key"), "issue audit has no raw key");
    assert!(!s.contains("\"token\""), "issue audit has no raw token");

    // List: params carry the principal only.
    let list_req = AdminRequestKind::PairDeviceList {
        principal: pid("alice"),
    };
    let params = sanitize_admin_audit_params(&list_req).expect("list params");
    let s = params.to_string();
    assert!(s.contains("alice"), "list audit records the principal");
    assert!(!s.contains("public_key"), "list audit has no key material");

    // Revoke: params carry the key_id (a non-secret fingerprint), no raw key.
    let revoke_req = AdminRequestKind::PairDeviceRevoke {
        principal: pid("alice"),
        key_id: "abc123def4567890".into(),
    };
    let params = sanitize_admin_audit_params(&revoke_req).expect("revoke params");
    let s = params.to_string();
    assert!(
        s.contains("abc123def4567890"),
        "revoke audit records key_id: {s}"
    );
    assert!(!s.contains("public_key"), "revoke audit has no raw key");

    // Redeem: token + public_key are fingerprinted, never raw.
    let redeem_req = AdminRequestKind::PairDeviceRedeem {
        token: "SUPERSECRETTOKEN".into(),
        public_key: "a".repeat(64),
    };
    let params = sanitize_admin_audit_params(&redeem_req).expect("redeem params");
    let s = params.to_string();
    assert!(
        !s.contains("SUPERSECRETTOKEN"),
        "redeem audit hides raw token: {s}"
    );
    assert!(
        !s.contains(&"a".repeat(64)),
        "redeem audit hides raw public_key"
    );
    assert!(
        s.contains("token_fingerprint"),
        "redeem audit keeps a token fp"
    );
    assert!(
        s.contains("public_key_fingerprint"),
        "redeem audit keeps a key fp"
    );
}

// ── Criterion 5: legacy bare keys load as Full devices (profile level) ─

#[test]
fn legacy_bare_public_keys_load_as_full_devices() {
    // A profile.toml written with legacy bare `ed25519:<hex>` strings (or bare
    // hex) in `public_keys` must load as Full-scope devices — zero behaviour
    // change for principals that predate per-device scope.
    let toml = format!(
        "profile_version = {}\n\
         enabled = true\n\
         groups = [\"agent\"]\n\
         [auth]\n\
         methods = [\"keypair\"]\n\
         public_keys = [\"ed25519:{}\", \"{}\"]\n",
        astrid_core::profile::CURRENT_PROFILE_VERSION,
        "a".repeat(64),
        "b".repeat(64),
    );
    let profile: PrincipalProfile = toml::from_str(&toml).expect("legacy profile parses");
    assert_eq!(profile.auth.public_keys.len(), 2);
    for dev in &profile.auth.public_keys {
        assert_eq!(
            dev.scope,
            DeviceScope::Full,
            "legacy bare key must migrate to Full scope"
        );
    }
}
