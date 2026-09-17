//! Regression coverage for principal-ownership assignment.
//!
//! Planner tests pin the actor contract. Integration tests drive the real
//! admin create/clone/backfill/invite paths and fail where production
//! registers identity without [`PrincipalOwnership`].

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::BUILTIN_ADMIN;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{AuthConfig, PrincipalProfile};
use astrid_core::{
    FleetGenesis, FleetIdentity, FleetRole, FleetUid, PrincipalOwnership, PrincipalUid,
    UserGenesis, UserIdentity, UserUid,
};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_storage::FleetRecord;
use tempfile::TempDir;

use super::{
    AuthenticatedHuman, CreatedPrincipalOwnershipRequest, OwnershipPlan, OwnershipPlanningError,
    plan_created_principal_ownership,
};
use crate::Kernel;

use super::super::handlers;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
    let admin = PrincipalProfile {
        groups: vec![BUILTIN_ADMIN.to_string()],
        ..PrincipalProfile::default()
    };
    admin
        .save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .expect("seed default admin profile");
    kernel.profile_cache.invalidate(&PrincipalId::default());
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

/// Seed the credential already authenticated by the transport boundary.
/// These handler tests do not claim signature/transport coverage.
async fn delegate_device(kernel: &Kernel, user: UserUid) -> String {
    use astrid_core::profile::{DeviceKey, DeviceScope};
    let caller = PrincipalId::default();
    let path = PrincipalProfile::path_for(&kernel.astrid_home, &caller);
    let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
    let device = DeviceKey::new("ab".repeat(32), DeviceScope::Full, None, 1);
    let id = device.key_id.clone();
    profile.auth.public_keys.push(device);
    profile.save_to_path(&path).unwrap();
    kernel.profile_cache.invalidate(&caller);
    kernel
        .ownership_store
        .bind_user_device(uid_for(kernel, &caller), [0xab; 32], user, user)
        .await
        .unwrap();
    id
}

fn user(id: u128, key: u8) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(id),
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        [key; 32],
    ))
    .unwrap()
}

fn fleet_for(id: u128, creator: UserUid) -> FleetIdentity {
    FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(id),
        chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        creator,
    ))
    .unwrap()
}

fn uid_for(kernel: &Kernel, principal: &PrincipalId) -> PrincipalUid {
    kernel
        .principal_directory
        .uid_for(principal)
        .expect("resolve principal uid")
}

fn bare_create(name: &str) -> AdminRequestKind {
    AdminRequestKind::AgentCreate {
        name: name.into(),
        groups: Vec::new(),
        grants: Vec::new(),
        inherit_from: None,
        clone_from: None,
        allow_admin_clone: false,
    }
}

fn assert_success(res: &AdminResponseBody) {
    if let AdminResponseBody::Error(msg) = res {
        panic!("expected success, got Error: {msg}");
    }
}

async fn owner_of(kernel: &Kernel, principal: &PrincipalId) -> Option<PrincipalOwnership> {
    let uid = uid_for(kernel, principal);
    kernel
        .ownership_store
        .load()
        .await
        .expect("load ownership graph")
        .principal_owner(uid)
        .cloned()
}

async fn seed_user_and_fleet(kernel: &Kernel, user: &UserIdentity, fleet: &FleetIdentity) {
    kernel
        .ownership_store
        .create_user(user.clone())
        .await
        .expect("create user");
    kernel
        .ownership_store
        .create_fleet(fleet.clone())
        .await
        .expect("create fleet");
}

async fn assign(kernel: &Kernel, principal: &PrincipalId, fleet: &FleetIdentity, actor: UserUid) {
    kernel
        .ownership_store
        .assign_principal(PrincipalOwnership {
            principal_uid: uid_for(kernel, principal),
            fleet_uid: fleet.uid,
            assigned_by: actor,
        })
        .await
        .expect("assign principal");
}

/// Own `default` with `stale` as historical `assigned_by`, then demote that
/// human so only `live` remains a manager.
async fn seed_stale_assigned_live_manager(
    kernel: &Kernel,
) -> (UserIdentity, UserIdentity, FleetIdentity) {
    let stale = user(1, 0x11);
    let live = user(2, 0x22);
    let fleet = fleet_for(3, stale.uid);
    seed_user_and_fleet(kernel, &stale, &fleet).await;
    kernel
        .ownership_store
        .create_user(live.clone())
        .await
        .expect("create live user");
    kernel
        .ownership_store
        .set_membership(fleet.uid, live.uid, FleetRole::Owner, stale.uid)
        .await
        .expect("add live owner");
    assign(kernel, &PrincipalId::default(), &fleet, stale.uid).await;
    kernel
        .ownership_store
        .set_membership(fleet.uid, stale.uid, FleetRole::Member, live.uid)
        .await
        .expect("demote historical assigned_by");
    (stale, live, fleet)
}

fn plan_request<'a>(
    created: PrincipalUid,
    existing: Option<&'a PrincipalOwnership>,
    creator: Option<&'a PrincipalOwnership>,
    actor: Option<UserUid>,
    fleet: Option<&'a FleetRecord>,
) -> CreatedPrincipalOwnershipRequest<'a> {
    CreatedPrincipalOwnershipRequest {
        created,
        existing,
        creator_ownership: creator,
        actor: actor.map(|user_uid| AuthenticatedHuman { user_uid }),
        creator_fleet: fleet,
    }
}

#[test]
fn missing_authenticated_human_is_not_filled_from_assigned_by() {
    let created = PrincipalUid::from_bytes([9; 32]);
    let stale = PrincipalOwnership {
        principal_uid: PrincipalUid::from_bytes([1; 32]),
        fleet_uid: FleetUid::from_bytes([2; 32]),
        assigned_by: UserUid::from_bytes([3; 32]),
    };
    let err =
        plan_created_principal_ownership(plan_request(created, None, Some(&stale), None, None))
            .expect_err("historical assigned_by is not an actor");
    assert_eq!(err, OwnershipPlanningError::MissingAuthenticatedHuman);
}

#[tokio::test(flavor = "multi_thread")]
async fn planner_rejects_stale_assigned_by_and_preserves_existing() {
    let (_dir, kernel) = fixture().await;
    let (stale, live, fleet) = seed_stale_assigned_live_manager(&kernel).await;
    let graph = kernel.ownership_store.load().await.expect("graph");
    let creator = graph
        .principal_owner(uid_for(&kernel, &PrincipalId::default()))
        .expect("default is owned")
        .clone();
    let fleet_record = graph.fleet(fleet.uid).expect("fleet").clone();
    let created = PrincipalUid::from_bytes([9; 32]);

    assert_eq!(
        plan_created_principal_ownership(plan_request(
            created,
            None,
            Some(&creator),
            Some(stale.uid),
            Some(&fleet_record),
        ))
        .expect_err("stale assigned_by must not act"),
        OwnershipPlanningError::ActorNotLiveManager {
            user: stale.uid,
            fleet: fleet.uid,
        }
    );
    assert_eq!(
        plan_created_principal_ownership(plan_request(
            created,
            None,
            Some(&creator),
            Some(live.uid),
            Some(&fleet_record),
        ))
        .expect("live manager may assign"),
        OwnershipPlan::Assign(PrincipalOwnership {
            principal_uid: created,
            fleet_uid: fleet.uid,
            assigned_by: live.uid,
        })
    );

    let existing = PrincipalOwnership {
        principal_uid: created,
        fleet_uid: FleetUid::from_bytes([8; 32]),
        assigned_by: stale.uid,
    };
    assert_eq!(
        plan_created_principal_ownership(plan_request(
            created,
            Some(&existing),
            Some(&creator),
            None,
            Some(&fleet_record),
        ))
        .expect("already-owned assignments are preserved"),
        OwnershipPlan::Unchanged
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_assigns_to_creator_fleet_using_live_human_not_stale_assigned_by() {
    let (_dir, kernel) = fixture().await;
    let (stale, live, fleet) = seed_stale_assigned_live_manager(&kernel).await;
    let device = delegate_device(&kernel, live.uid).await;
    let created = pid("oracle-agent");
    assert_success(
        &handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&device),
            bare_create(created.as_str()),
        )
        .await,
    );
    assert!(
        kernel
            .identity_store
            .resolve("cli", created.as_str())
            .await
            .expect("resolve identity")
            .is_some(),
        "create must still register identity"
    );

    let owner = owner_of(&kernel, &created).await.expect(
        "new principals must join the creating principal's fleet; assigned_by must be the live authenticated human, not historical assigned_by or an alias-derived UserUid",
    );
    assert_eq!(owner.fleet_uid, fleet.uid);
    assert_eq!(owner.assigned_by, live.uid);
    assert_ne!(owner.assigned_by, stale.uid);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_without_current_delegation_leaves_no_identity_or_key() {
    let (_dir, kernel) = fixture().await;
    let (_, live, _) = seed_stale_assigned_live_manager(&kernel).await;
    let device = delegate_device(&kernel, live.uid).await;
    kernel
        .ownership_store
        .revoke_user_device(
            uid_for(&kernel, &PrincipalId::default()),
            [0xab; 32],
            live.uid,
        )
        .await
        .unwrap();
    for credential in [None, Some(device.as_str())] {
        let name = if credential.is_some() {
            "revoked-agent"
        } else {
            "unbound-agent"
        };
        let response = handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            credential,
            bare_create(name),
        )
        .await;
        assert!(matches!(response, AdminResponseBody::Error(_)));
        assert!(
            kernel
                .identity_store
                .resolve("cli", name)
                .await
                .unwrap()
                .is_none()
        );
        assert!(kernel.principal_directory.uid_for(&pid(name)).is_err());
        assert!(
            !kernel
                .astrid_home
                .keys_dir()
                .join(format!("{name}.key"))
                .exists()
        );
        assert!(!PrincipalProfile::path_for(&kernel.astrid_home, &pid(name)).exists());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_create_clone_joins_creator_fleet_not_source_fleet() {
    let (_dir, kernel) = fixture().await;
    let owner = user(1, 0x31);
    let creator_fleet = fleet_for(2, owner.uid);
    let source_fleet = fleet_for(3, owner.uid);
    seed_user_and_fleet(&kernel, &owner, &creator_fleet).await;
    kernel
        .ownership_store
        .create_fleet(source_fleet.clone())
        .await
        .expect("create foreign fleet");
    assign(&kernel, &PrincipalId::default(), &creator_fleet, owner.uid).await;
    let device = delegate_device(&kernel, owner.uid).await;

    let source = pid("clone-source");
    assert_success(
        &handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&device),
            bare_create(source.as_str()),
        )
        .await,
    );
    kernel
        .ownership_store
        .transfer_principal(
            uid_for(&kernel, &source),
            creator_fleet.uid,
            source_fleet.uid,
            owner.uid,
        )
        .await
        .expect("explicitly transfer clone source");

    let cloned = pid("cloned-agent");
    assert_success(
        &handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&device),
            AdminRequestKind::AgentCreate {
                name: cloned.to_string(),
                groups: Vec::new(),
                grants: Vec::new(),
                inherit_from: None,
                clone_from: Some(source.clone()),
                allow_admin_clone: false,
            },
        )
        .await,
    );
    let owner_record = owner_of(&kernel, &cloned).await.expect(
        "cloned principals must join the authenticated creator fleet, not the clone source",
    );
    assert_eq!(owner_record.fleet_uid, creator_fleet.uid);
    assert_ne!(owner_record.fleet_uid, source_fleet.uid);
    assert_eq!(owner_record.assigned_by, owner.uid);
}

#[tokio::test(flavor = "multi_thread")]
async fn keyless_backfill_preserves_existing_ownership() {
    let (_dir, kernel) = fixture().await;
    let owner = user(1, 0x41);
    let fleet = fleet_for(2, owner.uid);
    seed_user_and_fleet(&kernel, &owner, &fleet).await;
    assign(&kernel, &PrincipalId::default(), &fleet, owner.uid).await;
    let device = delegate_device(&kernel, owner.uid).await;

    let principal = pid("already-owned");
    assert_success(
        &handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&device),
            bare_create(principal.as_str()),
        )
        .await,
    );
    let before = owner_of(&kernel, &principal)
        .await
        .expect("pre-assigned ownership");

    let mut profile = PrincipalProfile::load_from_path(&PrincipalProfile::path_for(
        &kernel.astrid_home,
        &principal,
    ))
    .expect("load profile");
    profile.auth = AuthConfig::default();
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &principal))
        .expect("strip keypair");
    let _ = std::fs::remove_file(
        kernel
            .astrid_home
            .keys_dir()
            .join(format!("{principal}.key")),
    );
    kernel.profile_cache.invalidate(&principal);

    assert_success(
        &handlers::dispatch_with_device(
            &kernel,
            &PrincipalId::default(),
            Some(&device),
            bare_create(principal.as_str()),
        )
        .await,
    );
    let after = owner_of(&kernel, &principal)
        .await
        .expect("backfill must not drop ownership");
    assert_eq!(after, before);
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_redeem_assigns_to_issuer_fleet_with_captured_human() {
    let (_dir, kernel) = fixture().await;
    let issuer = user(1, 0x51);
    let fleet = fleet_for(2, issuer.uid);
    seed_user_and_fleet(&kernel, &issuer, &fleet).await;
    assign(&kernel, &PrincipalId::default(), &fleet, issuer.uid).await;
    let device = delegate_device(&kernel, issuer.uid).await;

    let result = handlers::dispatch_with_device(
        &kernel,
        &PrincipalId::default(),
        Some(&device),
        AdminRequestKind::InviteIssue {
            group: "agent".into(),
            expires_secs: Some(300),
            max_uses: 1,
            metadata: None,
        },
    )
    .await;
    let token = match result {
        AdminResponseBody::Invite(invitation) => invitation.token,
        other => panic!("expected invite, got {other:?}"),
    };
    let redeemed = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::InviteRedeem {
            token: token.clone(),
            public_key: "ab".repeat(32),
            display_name: Some("invited-oracle".into()),
        },
    )
    .await;
    let principal = match redeemed {
        AdminResponseBody::InviteRedeemed(redeemed) => redeemed.principal,
        other => panic!("expected redeem, got {other:?}"),
    };
    let owner = owner_of(&kernel, &principal).await.expect(
        "invite redeem must assign from issuer-captured human/fleet delegation, not invent a UserUid at redeem time",
    );
    assert_eq!(owner.fleet_uid, fleet.uid);
    assert_eq!(owner.assigned_by, issuer.uid);
    assert!(
        kernel
            .ownership_store
            .load()
            .await
            .unwrap()
            .user_for_device(uid_for(&kernel, &principal), &[0xab; 32])
            .is_none()
    );
    let replay = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::InviteRedeem {
            token,
            public_key: "cd".repeat(32),
            display_name: Some("replayed-invite".into()),
        },
    )
    .await;
    assert!(matches!(replay, AdminResponseBody::Error(_)));
    assert!(
        kernel
            .principal_directory
            .uid_for(&pid("replayed-invite"))
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invitation_rejects_revocation_regrant_removed_key_and_expiry_before_provisioning() {
    for scenario in [
        "revoked",
        "regranted",
        "removed-key",
        "expired",
        "transferred",
        "demoted",
    ] {
        let (_dir, kernel) = fixture().await;
        let issuer = user(51, 0x51);
        let fleet = fleet_for(52, issuer.uid);
        seed_user_and_fleet(&kernel, &issuer, &fleet).await;
        let caller = PrincipalId::default();
        assign(&kernel, &caller, &fleet, issuer.uid).await;
        let device = delegate_device(&kernel, issuer.uid).await;
        let result = handlers::dispatch_with_device(
            &kernel,
            &caller,
            Some(&device),
            AdminRequestKind::InviteIssue {
                group: "agent".into(),
                expires_secs: Some(if scenario == "expired" { 0 } else { 300 }),
                max_uses: 1,
                metadata: None,
            },
        )
        .await;
        let AdminResponseBody::Invite(invitation) = result else {
            panic!("issue failed: {result:?}");
        };
        match scenario {
            "revoked" | "regranted" => {
                kernel
                    .ownership_store
                    .revoke_user_device(uid_for(&kernel, &caller), [0xab; 32], issuer.uid)
                    .await
                    .unwrap();
                if scenario == "regranted" {
                    kernel
                        .ownership_store
                        .bind_user_device(
                            uid_for(&kernel, &caller),
                            [0xab; 32],
                            issuer.uid,
                            issuer.uid,
                        )
                        .await
                        .unwrap();
                }
            },
            "removed-key" => {
                let path = PrincipalProfile::path_for(&kernel.astrid_home, &caller);
                let mut profile = PrincipalProfile::load_from_path(&path).unwrap();
                profile.auth.public_keys.clear();
                profile.save_to_path(&path).unwrap();
                kernel.profile_cache.invalidate(&caller);
            },
            "transferred" => {
                transfer_inviter(&kernel, &caller, fleet.uid, issuer.uid).await;
            },
            "demoted" => {
                demote_inviter(&kernel, fleet.uid, issuer.uid).await;
            },
            _ => {},
        }
        let response = handlers::dispatch(
            &kernel,
            &caller,
            AdminRequestKind::InviteRedeem {
                token: invitation.token,
                public_key: "cd".repeat(32),
                display_name: Some("rejected-invite".into()),
            },
        )
        .await;
        assert!(
            matches!(response, AdminResponseBody::Error(_)),
            "{scenario}: {response:?}"
        );
        assert!(
            kernel
                .principal_directory
                .uid_for(&pid("rejected-invite"))
                .is_err(),
            "{scenario}"
        );
        assert!(
            !PrincipalProfile::path_for(&kernel.astrid_home, &pid("rejected-invite")).exists(),
            "{scenario}"
        );
    }
}

async fn demote_inviter(kernel: &Kernel, fleet: FleetUid, actor: UserUid) {
    let backup = user(54, 0x54);
    kernel
        .ownership_store
        .create_user(backup.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .set_membership(fleet, backup.uid, FleetRole::Owner, actor)
        .await
        .unwrap();
    kernel
        .ownership_store
        .set_membership(fleet, actor, FleetRole::Member, backup.uid)
        .await
        .unwrap();
}

async fn transfer_inviter(kernel: &Kernel, caller: &PrincipalId, fleet: FleetUid, actor: UserUid) {
    let other = fleet_for(53, actor);
    kernel
        .ownership_store
        .create_fleet(other.clone())
        .await
        .unwrap();
    kernel
        .ownership_store
        .transfer_principal(uid_for(kernel, caller), fleet, other.uid, actor)
        .await
        .unwrap();
}
