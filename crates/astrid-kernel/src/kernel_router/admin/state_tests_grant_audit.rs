//! Applied authority changes land on the audit chain of the principal whose
//! authority changed: capability grants and revokes, group membership, and
//! capability tokens.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditEntry};
use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    super::test_support::seed_operator(&kernel).await;
    (dir, kernel)
}

fn pid(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

async fn dispatch(kernel: &Arc<Kernel>, request: AdminRequestKind) -> AdminResponseBody {
    let response = handlers::dispatch(kernel, &PrincipalId::default(), request).await;
    assert!(
        !matches!(response, AdminResponseBody::Error(_)),
        "{response:?}"
    );
    response
}

async fn create_agent(kernel: &Arc<Kernel>, name: &str) {
    super::test_support::dispatch_as_operator(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: name.into(),
            groups: vec!["restricted".into()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
}

async fn entries(kernel: &Arc<Kernel>, principal: &str) -> Vec<AuditEntry> {
    kernel
        .audit_log
        .get_principal_entries(&kernel.session_id, Some(&pid(principal)))
        .await
        .expect("principal entries")
}

/// `(kind, granted, revoked, via)` of every `CapabilityChanged` entry.
fn grant_changes(entries: &[AuditEntry]) -> Vec<(String, Vec<String>, Vec<String>, String)> {
    entries
        .iter()
        .filter_map(|entry| match &entry.action {
            AuditAction::CapabilityChanged {
                kind,
                granted,
                revoked,
                via,
                ..
            } => Some((kind.clone(), granted.clone(), revoked.clone(), via.clone())),
            _ => None,
        })
        .collect()
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn capability_and_group_changes_are_recorded_once_applied() {
    let (_dir, kernel) = fixture().await;
    create_agent(&kernel, "grace").await;

    let grant = |capabilities: &[&str]| AdminRequestKind::CapsGrant {
        principal: pid("grace"),
        capabilities: strings(capabilities),
        unsafe_admin: false,
    };
    dispatch(&kernel, grant(&["capsule:install", "fs:read"])).await;
    // Re-granting an existing capability changes nothing and records nothing.
    dispatch(&kernel, grant(&["capsule:install"])).await;
    dispatch(
        &kernel,
        AdminRequestKind::CapsRevoke {
            principal: pid("grace"),
            capabilities: strings(&["fs:read"]),
        },
    )
    .await;
    dispatch(
        &kernel,
        AdminRequestKind::AgentModify {
            principal: pid("grace"),
            add_groups: strings(&["admin"]),
            remove_groups: strings(&["restricted"]),
            add_capsules: Vec::new(),
            remove_capsules: Vec::new(),
        },
    )
    .await;

    assert_eq!(
        grant_changes(&entries(&kernel, "grace").await),
        vec![
            (
                "capability".to_owned(),
                strings(&["capsule:install", "fs:read"]),
                Vec::new(),
                "admin.caps.grant".to_owned()
            ),
            (
                "capability".to_owned(),
                Vec::new(),
                strings(&["fs:read"]),
                "admin.caps.revoke".to_owned()
            ),
            (
                "group".to_owned(),
                strings(&["admin"]),
                strings(&["restricted"]),
                "admin.agent.modify".to_owned()
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capability_tokens_are_recorded_on_mint_and_revoke() {
    let (_dir, kernel) = fixture().await;
    create_agent(&kernel, "ivan").await;

    let minted = dispatch(
        &kernel,
        AdminRequestKind::CapsTokenMint {
            principal: pid("ivan"),
            resource: "mcp://search:*".into(),
            permission: None,
            ttl_secs: None,
        },
    )
    .await;
    let AdminResponseBody::Success(body) = minted else {
        panic!("unexpected response {minted:?}");
    };
    let token_id = body["token_id"].as_str().expect("token id").to_owned();
    dispatch(
        &kernel,
        AdminRequestKind::CapsTokenRevoke {
            token_id: token_id.clone(),
        },
    )
    .await;

    let recorded: Vec<_> = entries(&kernel, "ivan")
        .await
        .into_iter()
        .filter_map(|entry| match entry.action {
            AuditAction::CapabilityCreated {
                token_id, resource, ..
            } => Some(format!("created {} {resource}", token_id.0)),
            AuditAction::CapabilityRevoked { token_id, reason } => {
                Some(format!("revoked {} {reason}", token_id.0))
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        recorded,
        vec![
            format!("created {token_id} mcp://search:*"),
            format!("revoked {token_id} admin.caps.token.revoke"),
        ]
    );
}
