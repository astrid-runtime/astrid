use std::sync::Arc;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};

use crate::Kernel;

const AUDIT_FIREHOSE_CAP: &str = "audit:read_all";

async fn fixture() -> (tempfile::TempDir, Arc<Kernel>, PrincipalId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    let principal = PrincipalId::new("audit_operator").expect("principal");
    (dir, kernel, principal)
}

fn full_device(seed: char) -> DeviceKey {
    DeviceKey::new(seed.to_string().repeat(64), DeviceScope::Full, None, 0)
}

fn scoped_device(seed: char, allow: &[&str], deny: &[&str]) -> DeviceKey {
    DeviceKey::new(
        seed.to_string().repeat(64),
        DeviceScope::Scoped {
            allow: allow.iter().map(|value| (*value).to_owned()).collect(),
            deny: deny.iter().map(|value| (*value).to_owned()).collect(),
        },
        None,
        0,
    )
}

fn seed(kernel: &Kernel, principal: &PrincipalId, devices: Vec<DeviceKey>) {
    seed_policy(
        kernel,
        principal,
        true,
        &[],
        &[AUDIT_FIREHOSE_CAP],
        &[],
        devices,
    );
}

fn seed_policy(
    kernel: &Kernel,
    principal: &PrincipalId,
    enabled: bool,
    groups: &[&str],
    grants: &[&str],
    revokes: &[&str],
    devices: Vec<DeviceKey>,
) {
    let mut profile = PrincipalProfile {
        enabled,
        groups: groups.iter().map(|value| (*value).to_owned()).collect(),
        grants: grants.iter().map(|value| (*value).to_owned()).collect(),
        revokes: revokes.iter().map(|value| (*value).to_owned()).collect(),
        ..PrincipalProfile::default()
    };
    if !devices.is_empty() {
        profile.auth.methods.push(AuthMethod::Keypair);
        profile.auth.public_keys = devices;
    }
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, principal))
        .expect("save profile");
    kernel.profile_cache.invalidate(principal);
}

#[tokio::test]
async fn no_device_uses_the_principals_effective_authority() {
    let (_dir, kernel, principal) = fixture().await;
    seed(&kernel, &principal, vec![]);

    assert!(kernel.runtime_capability_allows(&principal, None, AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn full_device_preserves_the_principals_effective_authority() {
    let (_dir, kernel, principal) = fixture().await;
    let device = full_device('a');
    let key_id = device.key_id.clone();
    seed(&kernel, &principal, vec![device]);

    assert!(kernel.runtime_capability_allows(&principal, Some(&key_id), AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn scoped_device_must_admit_the_exact_firehose_capability() {
    let (_dir, kernel, principal) = fixture().await;
    let allowed = scoped_device('a', &[AUDIT_FIREHOSE_CAP], &[]);
    let denied = scoped_device('b', &["*"], &[AUDIT_FIREHOSE_CAP]);
    let allowed_id = allowed.key_id.clone();
    let denied_id = denied.key_id.clone();
    seed(&kernel, &principal, vec![allowed, denied]);
    assert!(kernel.runtime_capability_allows(&principal, Some(&allowed_id), AUDIT_FIREHOSE_CAP));
    assert!(!kernel.runtime_capability_allows(&principal, Some(&denied_id), AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn scoped_admin_self_list_does_not_imply_audit_firehose() {
    let (_dir, kernel, principal) = fixture().await;
    let device = scoped_device('a', &["self:agent:list"], &[AUDIT_FIREHOSE_CAP]);
    let key_id = device.key_id.clone();
    seed_policy(
        &kernel,
        &principal,
        true,
        &["admin"],
        &[],
        &[],
        vec![device],
    );

    assert!(kernel.runtime_capability_allows(&principal, Some(&key_id), "self:agent:list"));
    assert!(!kernel.runtime_capability_allows(&principal, Some(&key_id), AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn malformed_and_unknown_device_ids_fail_closed() {
    let (_dir, kernel, principal) = fixture().await;
    seed(&kernel, &principal, vec![full_device('a')]);
    assert!(!kernel.runtime_capability_allows(
        &principal,
        Some("not-a-device-id"),
        AUDIT_FIREHOSE_CAP
    ));
    assert!(!kernel.runtime_capability_allows(
        &principal,
        Some("ffffffffffffffff"),
        AUDIT_FIREHOSE_CAP
    ));
}

#[tokio::test]
async fn revoked_device_id_fails_closed() {
    let (_dir, kernel, principal) = fixture().await;
    let device = full_device('a');
    let key_id = device.key_id.clone();
    seed(&kernel, &principal, vec![device]);
    assert!(kernel.runtime_capability_allows(&principal, Some(&key_id), AUDIT_FIREHOSE_CAP));

    seed(&kernel, &principal, vec![]);

    assert!(!kernel.runtime_capability_allows(&principal, Some(&key_id), AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn disabled_principal_loses_live_authority() {
    let (_dir, kernel, principal) = fixture().await;
    seed(&kernel, &principal, vec![]);
    assert!(kernel.runtime_capability_allows(&principal, None, AUDIT_FIREHOSE_CAP));

    seed_policy(
        &kernel,
        &principal,
        false,
        &[],
        &[AUDIT_FIREHOSE_CAP],
        &[],
        vec![],
    );

    assert!(!kernel.runtime_capability_allows(&principal, None, AUDIT_FIREHOSE_CAP));
}

#[tokio::test]
async fn group_authority_is_live_and_principal_revoke_wins() {
    let (_dir, kernel, principal) = fixture().await;
    seed_policy(&kernel, &principal, true, &["admin"], &[], &[], vec![]);
    assert!(kernel.runtime_capability_allows(&principal, None, AUDIT_FIREHOSE_CAP));

    seed_policy(
        &kernel,
        &principal,
        true,
        &["admin"],
        &[],
        &[AUDIT_FIREHOSE_CAP],
        vec![],
    );

    assert!(!kernel.runtime_capability_allows(&principal, None, AUDIT_FIREHOSE_CAP));
}
