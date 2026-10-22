use super::*;

use std::fs;
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::{
    CURRENT_PROFILE_VERSION, DEFAULT_MAX_BACKGROUND_PROCESSES, DEFAULT_MAX_IPC_THROUGHPUT_BYTES,
    DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_TIMEOUT_SECS, PrincipalProfile,
};

/// Fixture: tempdir-rooted cache. No process env mutation — avoids the
/// `unsafe { std::env::set_var(..) }` dance that conflicts with this
/// crate's `#![deny(unsafe_code)]`.
fn fixture() -> (tempfile::TempDir, PrincipalProfileCache) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let cache = PrincipalProfileCache::with_home(home);
    (dir, cache)
}

fn principal(name: &str) -> PrincipalId {
    PrincipalId::new(name).expect("valid principal")
}

fn command_fixture() -> (tempfile::TempDir, PrincipalProfileCache) {
    let (dir, cache) = fixture();
    for name in ["alice", "bob"] {
        PrincipalProfile::default()
            .save_to_path(&cache.astrid_home.profile_path(&principal(name)))
            .expect("create test principal");
    }
    (dir, cache)
}

#[test]
fn command_approval_does_not_recreate_deleted_principal() {
    let (_dir, cache) = command_fixture();
    let p = principal("alice");
    cache.resolve(&p).expect("prime cache");
    let path = cache.astrid_home.profile_path(&p);
    fs::remove_file(&path).expect("delete test profile");
    assert!(
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .is_err()
    );
    assert!(!path.exists(), "approval must not recreate the principal");
}

#[test]
fn command_approval_does_not_modify_disabled_principal() {
    let (_dir, cache) = command_fixture();
    let p = principal("alice");
    let path = cache.astrid_home.profile_path(&p);
    let profile = PrincipalProfile {
        enabled: false,
        ..PrincipalProfile::default()
    };
    profile.save_to_path(&path).expect("disable test principal");
    let before = fs::read(&path).expect("profile bytes");
    assert!(
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .is_err()
    );
    assert_eq!(fs::read(&path).expect("unchanged profile"), before);
}

fn write_profile(dir: &tempfile::TempDir, p: &PrincipalId, contents: &str) {
    let home = AstridHome::from_path(dir.path());
    let profiles_dir = home.profiles_dir();
    fs::create_dir_all(&profiles_dir).expect("mkdir etc/profiles");
    fs::write(home.profile_path(p), contents).expect("write profile");
}

#[test]
fn only_default_principal_may_use_missing_file_compatibility_profile() {
    let (_dir, cache) = fixture();
    let p = PrincipalId::default();

    let profile = cache.resolve(&p).expect("resolve missing");
    assert_eq!(*profile, PrincipalProfile::default());
    assert_eq!(cache.len(), 1, "missing-file path must still cache");

    // Second call: same Arc, no second disk read.
    let profile2 = cache.resolve(&p).expect("resolve cached");
    assert!(Arc::ptr_eq(&profile, &profile2));

    let alice = principal("alice");
    assert!(matches!(
        cache.resolve(&alice),
        Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert_eq!(cache.len(), 1, "failed identities must not be cached");
}

#[test]
fn populated_profile_loaded_once() {
    let (dir, cache) = fixture();
    let p = principal("bob");
    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             [quotas]\n\
             max_memory_bytes = 16777216\n\
             max_timeout_secs = 42\n\
             max_ipc_throughput_bytes = 524288\n\
             max_background_processes = 2\n\
             max_storage_bytes = 1048576\n"
        ),
    );

    let profile = cache.resolve(&p).expect("resolve populated");
    assert_eq!(profile.quotas.max_memory_bytes, 16_777_216);
    assert_eq!(profile.quotas.max_timeout_secs, 42);
    assert_eq!(profile.quotas.max_ipc_throughput_bytes, 524_288);
    assert_eq!(profile.quotas.max_background_processes, 2);
    assert_eq!(profile.quotas.max_storage_bytes, 1_048_576);
}

#[test]
fn malformed_profile_is_hard_error_no_fallback() {
    let (dir, cache) = fixture();
    let p = principal("mallory");
    write_profile(&dir, &p, "this is = = not [ valid toml");

    let err = cache
        .resolve(&p)
        .expect_err("malformed TOML must not silently fall back");
    assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
    // And crucially, it must NOT be cached as Default — the next call
    // still fails (fail-closed, no operator surprise).
    assert_eq!(cache.len(), 0);
    let err2 = cache.resolve(&p).expect_err("still fails on retry");
    assert!(matches!(err2, ProfileError::Parse(_)));
}

#[test]
fn invalid_profile_version_is_hard_error() {
    let (dir, cache) = fixture();
    let p = principal("future");
    write_profile(
        &dir,
        &p,
        &format!("profile_version = {}\n", CURRENT_PROFILE_VERSION + 1),
    );

    let err = cache.resolve(&p).expect_err("future version rejected");
    assert!(matches!(err, ProfileError::Invalid(_)), "got: {err:?}");
}

#[test]
fn two_principals_have_independent_entries() {
    let (dir, cache) = fixture();
    let a = principal("alice2");
    let b = principal("bob2");
    write_profile(
        &dir,
        &a,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             [quotas]\n\
             max_memory_bytes = 16777216\n"
        ),
    );
    write_profile(
        &dir,
        &b,
        &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
    );

    let pa = cache.resolve(&a).expect("alice");
    let pb = cache.resolve(&b).expect("bob");
    assert_eq!(pa.quotas.max_memory_bytes, 16_777_216);
    assert_eq!(pb.quotas.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);
    assert_eq!(pb.quotas.max_timeout_secs, DEFAULT_MAX_TIMEOUT_SECS);
    assert_eq!(
        pb.quotas.max_ipc_throughput_bytes,
        DEFAULT_MAX_IPC_THROUGHPUT_BYTES
    );
    assert_eq!(
        pb.quotas.max_background_processes,
        DEFAULT_MAX_BACKGROUND_PROCESSES
    );
}

#[test]
fn invalidate_forces_reload() {
    let (dir, cache) = fixture();
    let p = principal("reloader");

    write_profile(
        &dir,
        &p,
        &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
    );
    let first = cache.resolve(&p).expect("first resolve");
    assert_eq!(first.quotas.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);

    // Write a populated profile, invalidate, resolve again.
    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             [quotas]\n\
             max_memory_bytes = 8388608\n"
        ),
    );
    cache.invalidate(&p);
    let second = cache.resolve(&p).expect("second resolve");
    assert_eq!(second.quotas.max_memory_bytes, 8_388_608);
}

#[test]
fn invalidation_prevents_stale_load_publication() {
    let (dir, cache) = fixture();
    let p = principal("generation-race");
    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             enabled = true\n"
        ),
    );
    let load = cache.begin_load(&p);
    let stale = Arc::new(
        PrincipalProfile::load(&cache.astrid_home, &p).expect("load pre-invalidation profile"),
    );

    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             enabled = false\n"
        ),
    );
    cache.invalidate(&p);

    assert!(cache.publish_loaded(stale, &load).is_none());
    assert_eq!(cache.len(), 0);
    assert!(!cache.resolve(&p).expect("resolve current profile").enabled);
}

#[test]
fn invalidating_one_principal_does_not_reject_another_principal_load() {
    let (_dir, cache) = fixture();
    let alice = principal("alice-invalidation");
    let bob = principal("bob-load");
    let bob_load = cache.begin_load(&bob);
    let bob_profile = Arc::new(PrincipalProfile::default());

    cache.invalidate(&alice);

    assert!(cache.publish_loaded(bob_profile, &bob_load).is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn concurrent_readers_do_not_race() {
    // Lightweight contention check — not a loom model, just a sanity
    // check that multiple threads can `resolve()` the same principal
    // without deadlocks or panics.
    let (dir, cache) = fixture();
    let cache = Arc::new(cache);
    let p = principal("racer");
    write_profile(
        &dir,
        &p,
        &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
    );

    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&cache);
        let pid = p.clone();
        handles.push(std::thread::spawn(move || {
            let _ = c.resolve(&pid).expect("resolve");
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    assert_eq!(cache.len(), 1, "only one entry expected");
}

#[test]
fn persist_egress_appends_under_capsule_key_and_invalidates() {
    let (dir, cache) = fixture();
    let p = principal("alice");
    // Start from a profile with a pre-existing consented endpoint under a
    // DIFFERENT capsule to prove we append per-capsule, not overwrite, and
    // that the flat `egress` allowlist is left untouched.
    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             [network]\n\
             egress = [\"api.example.com:443\"]\n\
             [network.capsule_egress]\n\
             openai-compat = [\"127.0.0.1:5678\"]\n"
        ),
    );
    // Populate the cache so we can prove persist invalidates it.
    let _ = cache.resolve(&p).expect("prime cache");
    assert_eq!(cache.len(), 1);

    cache
        .persist_egress(&p, "react", "127.0.0.1:1234")
        .expect("persist egress");

    // Cache was invalidated by the persist.
    assert_eq!(cache.len(), 0, "persist_egress must invalidate the cache");

    let reloaded = cache.resolve(&p).expect("reload");
    // The flat general egress allowlist is untouched.
    assert_eq!(reloaded.network.egress, vec!["api.example.com:443"]);
    // The new grant lands ONLY under "react".
    assert_eq!(
        reloaded.network.capsule_egress.get("react"),
        Some(&vec!["127.0.0.1:1234".to_string()])
    );
    // The pre-existing "openai-compat" grant is preserved and the react
    // grant did NOT widen to it.
    assert_eq!(
        reloaded.network.capsule_egress.get("openai-compat"),
        Some(&vec!["127.0.0.1:5678".to_string()])
    );
    assert!(
        !reloaded
            .network
            .capsule_egress
            .get("openai-compat")
            .unwrap()
            .contains(&"127.0.0.1:1234".to_string()),
        "a react grant must not appear under openai-compat"
    );
}

#[test]
fn persist_egress_is_per_capsule_isolated() {
    // Spec (FIX 1b): a persisted grant for capsule "react" reaching
    // 127.0.0.1:1234 must NOT exempt capsule "openai-compat" reaching the
    // same endpoint for the same principal.
    let (_dir, cache) = fixture();
    let p = principal("alice");
    cache
        .persist_egress(&p, "react", "127.0.0.1:1234")
        .expect("persist react grant");

    let profile = cache.resolve(&p).expect("reload");
    assert_eq!(
        profile.network.capsule_egress.get("react"),
        Some(&vec!["127.0.0.1:1234".to_string()]),
        "react holds its own grant"
    );
    assert!(
        !profile.network.capsule_egress.contains_key("openai-compat"),
        "openai-compat must NOT inherit react's persisted grant"
    );
}

#[test]
fn persist_egress_is_idempotent() {
    let (_dir, cache) = fixture();
    let p = principal("bob");
    let stale_load = cache.begin_load(&p);
    // No file on disk → starts from default (empty capsule_egress).
    cache
        .persist_egress(&p, "react", "10.0.0.5:8080")
        .expect("first persist");
    assert!(!stale_load.is_current(&cache.state.read().unwrap()));
    let current_load = cache.begin_load(&p);
    // A second persist of the SAME endpoint under the SAME capsule
    // (case-insensitive) is a no-op success, not a duplicate.
    cache
        .persist_egress(&p, "react", "10.0.0.5:8080")
        .expect("idempotent persist");
    assert!(current_load.is_current(&cache.state.read().unwrap()));
    assert_eq!(cache.len(), 1, "idempotent persist refreshes the cache");

    let profile = cache.resolve(&p).expect("resolve refreshed profile");
    assert_eq!(
        profile.network.capsule_egress.get("react"),
        Some(&vec!["10.0.0.5:8080".to_string()]),
        "idempotent persist must not duplicate the entry"
    );
}

#[test]
fn persist_command_always_appends_and_invalidates() {
    let (dir, cache) = fixture();
    let p = principal("alice");
    write_profile(
        &dir,
        &p,
        &format!(
            "profile_version = {CURRENT_PROFILE_VERSION}\n\
             [network]\n\
             egress = [\"api.example.com:443\"]\n"
        ),
    );
    let _ = cache.resolve(&p).expect("prime cache");
    assert_eq!(cache.len(), 1);

    cache
        .persist_command_always(&p, "git push", Some("/tmp"))
        .expect("persist command always");

    assert_eq!(
        cache.len(),
        0,
        "persist_command_always must invalidate the cache"
    );

    let reloaded = cache.resolve(&p).expect("reload");
    assert_eq!(reloaded.network.egress, vec!["api.example.com:443"]);
    assert_eq!(reloaded.approvals.command_always.len(), 1);
    assert_eq!(reloaded.approvals.command_always[0].command, "git push");
    assert_eq!(
        reloaded.approvals.command_always[0]
            .workspace_root
            .as_deref(),
        Some("/tmp")
    );
    assert!(
        reloaded.network.capsule_egress.is_empty(),
        "command-always persist must not touch capsule_egress"
    );
}

#[test]
fn persist_command_always_is_idempotent_for_same_command_and_workspace() {
    let (_dir, cache) = command_fixture();
    let p = principal("bob");
    let stale_load = cache.begin_load(&p);
    cache
        .persist_command_always(&p, "git push", Some("/tmp"))
        .expect("first persist");
    assert!(!stale_load.is_current(&cache.state.read().unwrap()));
    let current_load = cache.begin_load(&p);
    cache
        .persist_command_always(&p, "git push", Some("/tmp"))
        .expect("idempotent persist");
    assert!(current_load.is_current(&cache.state.read().unwrap()));
    assert_eq!(cache.len(), 1, "idempotent persist refreshes the cache");

    let profile = cache.resolve(&p).expect("resolve refreshed profile");
    assert_eq!(profile.approvals.command_always.len(), 1);
    assert_eq!(profile.approvals.command_always[0].command, "git push");
}

#[test]
fn persist_command_always_isolates_workspace_and_principal() {
    let (_dir, cache) = command_fixture();
    let alice = principal("alice");
    let bob = principal("bob");
    cache
        .persist_command_always(&alice, "git push", Some("/tmp"))
        .expect("alice /tmp");
    cache
        .persist_command_always(&alice, "git push", Some("/other"))
        .expect("alice /other");
    cache
        .persist_command_always(&bob, "git push", Some("/tmp"))
        .expect("bob /tmp");

    let alice_profile = cache.resolve(&alice).expect("alice");
    let alice_workspaces: Vec<_> = alice_profile
        .approvals
        .command_always
        .iter()
        .map(|g| g.workspace_root.as_deref())
        .collect();
    assert_eq!(alice_workspaces, vec![Some("/tmp"), Some("/other")]);
    assert!(
        alice_profile
            .approvals
            .command_always
            .iter()
            .all(|g| g.command == "git push")
    );

    let bob_profile = cache.resolve(&bob).expect("bob");
    assert_eq!(bob_profile.approvals.command_always.len(), 1);
    assert_eq!(
        bob_profile.approvals.command_always[0]
            .workspace_root
            .as_deref(),
        Some("/tmp")
    );
}

#[test]
fn persist_command_always_rejects_empty_command() {
    let (_dir, cache) = fixture();
    let p = principal("alice");
    let err = cache
        .persist_command_always(&p, "   ", Some("/tmp"))
        .expect_err("empty command");
    assert!(
        matches!(&err, ProfileError::Invalid(msg) if msg.contains("command")),
        "got {err:?}"
    );
    assert_eq!(cache.len(), 0, "invalid persist must not cache");
}

#[test]
fn persist_command_always_rejects_empty_workspace() {
    let (_dir, cache) = fixture();
    let p = principal("alice");
    let err = cache
        .persist_command_always(&p, "git push", Some("   "))
        .expect_err("empty workspace");
    assert!(
        matches!(&err, ProfileError::Invalid(msg) if msg.contains("workspace_root")),
        "got {err:?}"
    );
    assert_eq!(cache.len(), 0, "invalid persist must not cache");
}

#[test]
fn persist_command_always_preserves_workspace_bytes() {
    let (_dir, cache) = command_fixture();
    let p = principal("alice");
    cache
        .persist_command_always(&p, "  git push  ", Some(" /tmp "))
        .expect("persist spaced workspace");
    cache
        .persist_command_always(&p, "git push", Some("/tmp"))
        .expect("persist distinct workspace");
    let profile = cache.resolve(&p).expect("resolve");
    assert_eq!(profile.approvals.command_always.len(), 2);
    assert_eq!(profile.approvals.command_always[0].command, "git push");
    assert_eq!(
        profile.approvals.command_always[0]
            .workspace_root
            .as_deref(),
        Some(" /tmp ")
    );
}

#[test]
fn persist_egress_then_command_always_keeps_both() {
    let (_dir, cache) = fixture();
    let p = principal("alice");
    cache
        .persist_egress(&p, "react", "127.0.0.1:1234")
        .expect("persist egress");
    cache
        .persist_command_always(&p, "git push", Some("/tmp"))
        .expect("persist command");
    let profile = cache.resolve(&p).expect("resolve");
    assert_eq!(
        profile.network.capsule_egress.get("react"),
        Some(&vec!["127.0.0.1:1234".to_string()])
    );
    assert_eq!(profile.approvals.command_always.len(), 1);
    assert_eq!(profile.approvals.command_always[0].command, "git push");
    assert_eq!(
        profile.approvals.command_always[0]
            .workspace_root
            .as_deref(),
        Some("/tmp")
    );
}

#[test]
fn deleted_alias_churn_and_failed_loads_leave_no_invalidation_history() {
    let (_directory, cache) = fixture();
    for ordinal in 0..10_000 {
        let principal = principal(&format!("retired-agent-{ordinal}"));
        cache.invalidate(&principal);
        assert!(cache.resolve(&principal).is_err());
    }
    let state = cache.state.read().unwrap();
    assert!(state.profiles.is_empty());
    assert!(
        state.loads.is_empty(),
        "completed loads must not retain aliases"
    );
}

#[test]
fn shared_load_token_lives_until_last_loader_and_cannot_publish_after_alias_reuse() {
    let (_directory, cache) = fixture();
    let principal = principal("reused-agent");
    let first = cache.begin_load(&principal);
    let stale = cache.begin_load(&principal);
    drop(first);
    assert_eq!(cache.state.read().unwrap().loads.len(), 1);
    cache.invalidate(&principal);
    let current = cache.begin_load(&principal);
    assert!(
        cache
            .publish_loaded(Arc::new(PrincipalProfile::default()), &stale)
            .is_none()
    );
    drop(stale);
    assert_eq!(cache.state.read().unwrap().loads.len(), 1);
    assert!(
        cache
            .publish_loaded(Arc::new(PrincipalProfile::default()), &current)
            .is_some()
    );
    drop(current);
    assert!(cache.state.read().unwrap().loads.is_empty());
    assert_eq!(cache.len(), 1);
}

#[test]
fn unwinding_last_profile_loader_removes_its_identity() {
    let (_directory, cache) = fixture();
    let principal = principal("panicking-loader");
    let result = std::panic::catch_unwind(|| {
        let _load = cache.begin_load(&principal);
        panic!("injected profile load panic");
    });
    assert!(result.is_err());
    assert!(cache.state.read().unwrap().loads.is_empty());
}
