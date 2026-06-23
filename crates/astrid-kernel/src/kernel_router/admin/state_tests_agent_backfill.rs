//! `admin.agent.create` keypair-backfill tests.
//!
//! Per-connection auth (#45/#852) makes `agent.create` mint+register a
//! per-principal ed25519 keypair so the principal can sign the socket
//! handshake. Principals created BEFORE that feature are keyless and get
//! stamped the no-capability `anonymous`. The plugin's `astrid-up` re-runs
//! `agent create <p>` on every boot; a bare re-create of an existing KEYLESS
//! principal now surgically backfills the missing keypair (and only the
//! keypair), so upgraders auto-heal. A principal that already has a keypair is
//! left untouched (still errors "already exists").
//!
//! The split from `state_tests.rs` is purely mechanical — the shared fixture
//! and assertion helpers are re-defined locally so each test file is
//! self-contained (mirrors `state_tests_agent_clone.rs`).

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::groups::BUILTIN_RESTRICTED;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{AuthConfig, AuthMethod, PrincipalProfile};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody};
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

fn assert_success(res: &AdminResponseBody) {
    if let AdminResponseBody::Error(msg) = res {
        panic!("expected success, got Error: {msg}");
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

/// A bare `agent create <name>` with no shaping inputs (what `astrid-up` issues).
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

fn load(kernel: &Arc<Kernel>, name: &str) -> PrincipalProfile {
    PrincipalProfile::load_from_path(&PrincipalProfile::path_for(&kernel.astrid_home, &pid(name)))
        .expect("load profile")
}

fn key_path(kernel: &Arc<Kernel>, name: &str) -> std::path::PathBuf {
    kernel.astrid_home.keys_dir().join(format!("{name}.key"))
}

/// Strip the keypair from an existing principal IN PLACE — simulating a
/// principal created before per-connection auth landed: empty `auth.methods` /
/// `auth.public_keys` and no `keys/<p>.key`. Returns the (now keyless) profile.
fn make_keyless(kernel: &Arc<Kernel>, name: &str) -> PrincipalProfile {
    let mut profile = load(kernel, name);
    profile.auth = AuthConfig::default();
    profile
        .save_to_path(&PrincipalProfile::path_for(&kernel.astrid_home, &pid(name)))
        .expect("save keyless profile");
    let _ = std::fs::remove_file(key_path(kernel, name));
    kernel.profile_cache.invalidate(&pid(name));
    profile
}

/// An existing principal that ALREADY has a keypair is untouched: re-create
/// still errors "already exists" and the keypair is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_existing_with_keypair_still_errors() {
    let (_dir, kernel) = fixture().await;

    assert_success(
        &handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("alice")).await,
    );
    let before = load(&kernel, "alice");
    assert_eq!(before.auth.methods, vec![AuthMethod::Keypair]);
    assert_eq!(before.auth.public_keys.len(), 1);
    let key_before = std::fs::read(key_path(&kernel, "alice")).expect("key file");

    let res = handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("alice")).await;
    assert_error_contains(&res, "already exists");

    // Keypair unchanged: same public key on the profile and same secret on disk.
    let after = load(&kernel, "alice");
    assert_eq!(after.auth, before.auth, "keypair must not be re-minted");
    let key_after = std::fs::read(key_path(&kernel, "alice")).expect("key file");
    assert_eq!(key_before, key_after, "secret key must not change");
}

/// An existing KEYLESS principal (pre-feature upgrader) is healed: a bare
/// re-create backfills the keypair (success) and the profile now carries the
/// `Keypair` method + an `ed25519:` public key + a `keys/<p>.key`, while
/// groups/grants are left exactly as they were.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_keyless_backfills_keypair() {
    let (_dir, kernel) = fixture().await;

    // Create, then give it a distinctive group + grant, then strip the keypair.
    assert_success(&handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("bob")).await);
    {
        let mut p = load(&kernel, "bob");
        p.groups = vec![BUILTIN_RESTRICTED.to_string()];
        p.grants = vec!["self:capsule:list".to_string()];
        p.save_to_path(&PrincipalProfile::path_for(
            &kernel.astrid_home,
            &pid("bob"),
        ))
        .unwrap();
        kernel.profile_cache.invalidate(&pid("bob"));
    }
    let keyless = make_keyless(&kernel, "bob");
    assert!(keyless.auth.methods.is_empty());
    assert!(keyless.auth.public_keys.is_empty());
    assert!(!key_path(&kernel, "bob").exists());

    // Bare re-create heals it.
    let res = handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("bob")).await;
    assert_success(&res);
    match &res {
        AdminResponseBody::Success(v) => {
            assert_eq!(v["backfilled_keypair"], serde_json::json!(true));
        },
        other => panic!("expected Success, got: {other:?}"),
    }

    let healed = load(&kernel, "bob");
    assert_eq!(healed.auth.methods, vec![AuthMethod::Keypair]);
    assert_eq!(healed.auth.public_keys.len(), 1);
    assert!(
        healed.auth.public_keys[0]
            .ed25519_entry()
            .starts_with("ed25519:")
    );
    assert_eq!(
        healed.auth.public_keys[0].scope,
        astrid_core::profile::DeviceScope::Full,
        "backfilled key must be Full-scope"
    );
    assert!(
        healed.auth.public_keys[0].created_at > 0,
        "a freshly minted device key must carry the real mint epoch, not the \
         `0` migrated-legacy sentinel (which would show 1970 in listings/audit)"
    );
    assert!(
        key_path(&kernel, "bob").exists(),
        "keys/<p>.key must be written"
    );

    // Surgical: groups + grants are UNCHANGED — no widening.
    assert_eq!(healed.groups, vec![BUILTIN_RESTRICTED.to_string()]);
    assert_eq!(healed.grants, vec!["self:capsule:list".to_string()]);
}

/// A backfilled keyless principal that gets re-created again is now a no-op
/// error: the second re-create sees the freshly-minted keypair and errors
/// "already exists" rather than re-minting.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_keyless_backfill_is_idempotent() {
    let (_dir, kernel) = fixture().await;
    assert_success(
        &handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("carol")).await,
    );
    make_keyless(&kernel, "carol");

    assert_success(
        &handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("carol")).await,
    );
    let key_after_first = std::fs::read(key_path(&kernel, "carol")).expect("key file");

    let res = handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("carol")).await;
    assert_error_contains(&res, "already exists");
    let key_after_second = std::fs::read(key_path(&kernel, "carol")).expect("key file");
    assert_eq!(
        key_after_first, key_after_second,
        "second re-create must not re-mint"
    );
}

/// A shaping input (`--group X`) against an EXISTING principal is NOT a
/// backfill: the caller meant to create, so it still errors "already exists"
/// (the shaping input is never silently dropped), and a keyless principal is
/// left keyless — the backfill path is reserved for a bare re-create.
#[tokio::test(flavor = "multi_thread")]
async fn agent_create_existing_with_shaping_input_still_errors() {
    let (_dir, kernel) = fixture().await;
    assert_success(
        &handlers::dispatch(&kernel, &PrincipalId::default(), bare_create("dave")).await,
    );
    make_keyless(&kernel, "dave");

    let res = handlers::dispatch(
        &kernel,
        &PrincipalId::default(),
        AdminRequestKind::AgentCreate {
            name: "dave".into(),
            groups: vec![BUILTIN_RESTRICTED.to_string()],
            grants: Vec::new(),
            inherit_from: None,
            clone_from: None,
            allow_admin_clone: false,
        },
    )
    .await;
    assert_error_contains(&res, "already exists");

    // Shaping input did not trigger a backfill: still keyless.
    let still = load(&kernel, "dave");
    assert!(
        still.auth.methods.is_empty(),
        "shaping-input path must not backfill"
    );
    assert!(!key_path(&kernel, "dave").exists());
}
