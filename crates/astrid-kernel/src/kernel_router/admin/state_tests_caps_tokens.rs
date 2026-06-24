//! Stateful admin-handler tests for capability-token lifecycle (issue #929).
//!
//! Each test builds a [`test_kernel_with_home`](crate::test_kernel_with_home)
//! rooted in a private tempdir and invokes [`super::handlers::dispatch`]
//! directly, exercising the write-lock / capability-store semantics of the
//! production path without going over IPC. The fixture seeds `default` as an
//! admin (mirroring `Kernel::new`) so dispatch carries admin authority.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_core::types::Permission;
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
use tempfile::TempDir;

use super::handlers;
use crate::Kernel;

async fn fixture() -> (TempDir, Arc<Kernel>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let kernel = crate::test_kernel_with_home(home).await;
    // Mirror production: `Kernel::new` admin-seeds the `default` principal so
    // dispatch through `default` carries admin authority.
    let mut admin = PrincipalProfile::default();
    admin.groups = vec![astrid_core::GroupName::new(astrid_core::groups::BUILTIN_ADMIN).unwrap()];
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

fn assert_success(res: &AdminResponseBody) {
    match res {
        AdminResponseBody::Success(_) => {},
        AdminResponseBody::Error(msg) => panic!("expected success, got Error: {msg}"),
        other => panic!("expected Success, got: {other:?}"),
    }
}

fn assert_error_contains(res: &AdminResponseBody, needle: &str) {
    match res {
        AdminResponseBody::Error(msg) => {
            assert!(
                msg.contains(needle),
                "expected error to contain {needle:?}, got: {msg}"
            );
        },
        other => panic!("expected Error, got: {other:?}"),
    }
}

/// Create an agent principal so a token can be minted for it.
async fn create_agent(kernel: &Arc<Kernel>, name: &str) {
    let res = handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: name.into(),
            groups: Vec::new(),
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_success(&res);
}

/// Extract the `token_id` string from a mint `Success` body.
fn token_id_of(res: &AdminResponseBody) -> String {
    match res {
        AdminResponseBody::Success(v) => v
            .get("token_id")
            .and_then(|t| t.as_str())
            .expect("token_id present")
            .to_string(),
        other => panic!("expected Success, got: {other:?}"),
    }
}

async fn mint(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    resource: &str,
    permission: Option<String>,
    ttl_secs: Option<u64>,
) -> AdminResponseBody {
    handlers::dispatch(
        kernel,
        &PrincipalId::default(),
        AdminRequestKind::CapsTokenMint {
            principal: principal.clone(),
            resource: resource.into(),
            permission,
            ttl_secs,
        },
    )
    .await
}

// ── 1. Mint creates a permanent token ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn mint_creates_permanent_token() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    create_agent(&kernel, "alice").await;

    let res = mint(&kernel, &alice, "mcp://server:tool", None, None).await;
    assert_success(&res);
    let AdminResponseBody::Success(ref body) = res else {
        unreachable!()
    };
    assert!(
        body.get("expires_at")
            .is_some_and(serde_json::Value::is_null),
        "response expires_at must be null for a permanent token, got {body:?}"
    );
    assert_eq!(
        body.get("principal").and_then(|p| p.as_str()),
        Some("alice")
    );

    // Load via the store and assert it is truly permanent + Persistent.
    let token = kernel
        .capabilities
        .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
        .expect("minted token is findable for the minted principal");
    assert!(token.expires_at.is_none(), "token must be permanent");
    assert_eq!(token.principal, alice);
    assert_eq!(token.scope, astrid_capabilities::TokenScope::Persistent);
}

// ── 2. Mint with ttl sets a non-None expiry ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn mint_with_ttl_sets_expiry() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    create_agent(&kernel, "alice").await;

    let res = mint(&kernel, &alice, "mcp://server:tool", None, Some(3600)).await;
    assert_success(&res);
    let AdminResponseBody::Success(ref body) = res else {
        unreachable!()
    };
    assert!(
        body.get("expires_at").is_some_and(|e| e.as_str().is_some()),
        "response expires_at must be a timestamp string, got {body:?}"
    );

    let token = kernel
        .capabilities
        .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
        .expect("ttl token findable");
    assert!(token.expires_at.is_some(), "token must have an expiry");
}

// ── 3. Cross-principal fail-closed ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn minted_token_is_principal_scoped() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    let bob = pid("bob");
    create_agent(&kernel, "alice").await;
    create_agent(&kernel, "bob").await;

    assert_success(&mint(&kernel, &alice, "mcp://server:tool", None, None).await);

    // Alice's token authorizes Alice...
    assert!(
        kernel
            .capabilities
            .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
            .is_some(),
        "minted principal must be authorized"
    );
    // ...but never Bob, even though the resource + permission match.
    assert!(
        kernel
            .capabilities
            .find_capability(&bob, "mcp://server:tool", Permission::Invoke)
            .is_none(),
        "cross-principal use must fail closed (issue #668)"
    );
}

// ── 4. Revoke ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn revoke_removes_authorization() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    create_agent(&kernel, "alice").await;

    let minted = mint(&kernel, &alice, "mcp://server:tool", None, None).await;
    let token_id = token_id_of(&minted);
    assert!(
        kernel
            .capabilities
            .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
            .is_some()
    );

    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::CapsTokenRevoke {
            token_id: token_id.clone(),
        },
    )
    .await;
    assert_success(&res);

    assert!(
        kernel
            .capabilities
            .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
            .is_none(),
        "revoked token must no longer authorize"
    );
}

// ── 5. List returns exactly the principal's tokens ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_only_principal_tokens() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    let bob = pid("bob");
    create_agent(&kernel, "alice").await;
    create_agent(&kernel, "bob").await;

    assert_success(&mint(&kernel, &alice, "mcp://server:a", None, None).await);
    assert_success(&mint(&kernel, &alice, "mcp://server:b", None, None).await);
    assert_success(&mint(&kernel, &bob, "mcp://server:c", None, None).await);

    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::CapsTokenList {
            principal: alice.clone(),
        },
    )
    .await;
    assert_success(&res);
    let AdminResponseBody::Success(body) = res else {
        unreachable!()
    };
    let tokens = body
        .get("tokens")
        .and_then(|t| t.as_array())
        .expect("tokens array");
    assert_eq!(
        tokens.len(),
        2,
        "alice has exactly two tokens, got {tokens:?}"
    );
    for t in tokens {
        let resource = t.get("resource").and_then(|r| r.as_str()).unwrap_or("");
        assert!(
            resource == "mcp://server:a" || resource == "mcp://server:b",
            "unexpected resource in alice's token list: {resource}"
        );
    }
}

// ── 6. Mint for non-existent principal → bad input ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn mint_rejects_unknown_principal() {
    let (_dir, kernel) = fixture().await;
    let ghost = pid("ghost");

    let res = mint(&kernel, &ghost, "mcp://server:tool", None, None).await;
    assert_error_contains(&res, "does not exist");

    // No token was created for the ghost principal.
    assert!(
        kernel
            .capabilities
            .find_capability(&ghost, "mcp://server:tool", Permission::Invoke)
            .is_none()
    );
}

// ── 7. Mint with invalid permission → bad input ───────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn mint_rejects_invalid_permission() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    create_agent(&kernel, "alice").await;

    let res = mint(
        &kernel,
        &alice,
        "mcp://server:tool",
        Some("frobnicate".into()),
        None,
    )
    .await;
    assert_error_contains(&res, "unknown permission");

    assert!(
        kernel
            .capabilities
            .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
            .is_none(),
        "no token should be minted on a bad permission"
    );
}

// ── 8. Mint with an out-of-range TTL → bad input, never a panic ────────

/// A `ttl_secs` that fits in `i64` but exceeds chrono's internal bound
/// (~9.2e15 s) must be a clean bad-input error. `chrono::Duration::seconds`
/// panics for such a value, so this locks the non-panicking `try_seconds`
/// conversion — the value below clears the `u64`→`i64` cast yet overflows
/// chrono, exercising exactly that guard.
#[tokio::test(flavor = "multi_thread")]
async fn mint_rejects_out_of_range_ttl() {
    let (_dir, kernel) = fixture().await;
    let alice = pid("alice");
    create_agent(&kernel, "alice").await;

    let res = mint(
        &kernel,
        &alice,
        "mcp://server:tool",
        None,
        Some(9_300_000_000_000_000),
    )
    .await;
    assert_error_contains(&res, "out of range");

    assert!(
        kernel
            .capabilities
            .find_capability(&alice, "mcp://server:tool", Permission::Invoke)
            .is_none(),
        "no token should be minted on an out-of-range ttl"
    );
}
