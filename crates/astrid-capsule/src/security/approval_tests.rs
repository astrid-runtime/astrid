//! Tests for the install-time capability approval gate (#995).

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;

use super::*;
use crate::manifest::CapsuleManifest;

/// A manifest with the given net hosts and IPC patterns, built via the real
/// TOML deserializer so the fixtures match what `load_manifest` produces.
fn manifest_with(net: &[&str], publish: &[&str], subscribe: &[&str]) -> CapsuleManifest {
    let nets = net
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut toml = format!(
        "[package]\nname = \"test-capsule\"\nversion = \"0.1.0\"\n\n[capabilities]\nnet = [{nets}]\n"
    );
    if !publish.is_empty() {
        toml.push_str("\n[publish]\n");
        for p in publish {
            toml.push_str(&format!("\"{p}\" = {{ wit = \"opaque\" }}\n"));
        }
    }
    if !subscribe.is_empty() {
        toml.push_str("\n[subscribe]\n");
        for s in subscribe {
            toml.push_str(&format!("\"{s}\" = {{ wit = \"opaque\" }}\n"));
        }
    }
    toml::from_str(&toml).expect("fixture manifest parses")
}

// ── Fingerprint ──────────────────────────────────────────────────────────

#[test]
fn fingerprint_is_stable_across_ipc_pattern_reorder() {
    // The `[publish]`/`[subscribe]` tables are HashMap-backed, so their
    // enumeration order is unspecified; the fingerprint must not depend on it.
    let a = manifest_with(
        &["example.com"],
        &["astrid.v1.a", "astrid.v1.b", "astrid.v1.c"],
        &["client.v1.x", "client.v1.y"],
    );
    let b = manifest_with(
        &["example.com"],
        &["astrid.v1.c", "astrid.v1.a", "astrid.v1.b"],
        &["client.v1.y", "client.v1.x"],
    );
    assert_eq!(
        capability_fingerprint(&a),
        capability_fingerprint(&b),
        "fingerprint must be invariant under IPC pattern reordering"
    );
}

#[test]
fn fingerprint_changes_when_a_capability_changes() {
    let base = manifest_with(&["example.com"], &[], &[]);
    let escalated = manifest_with(&["example.com", "attacker.example.com"], &[], &[]);
    assert_ne!(
        capability_fingerprint(&base),
        capability_fingerprint(&escalated),
        "adding an egress host must change the fingerprint (forces re-approval)"
    );

    // A bool capability flip must also change it.
    let mut m_uplink = manifest_with(&["example.com"], &[], &[]);
    m_uplink.capabilities.uplink = true;
    assert_ne!(
        capability_fingerprint(&base),
        capability_fingerprint(&m_uplink),
        "toggling the uplink flag must change the fingerprint"
    );
}

#[test]
fn fingerprint_changes_when_ipc_pattern_changes() {
    let base = manifest_with(&[], &["astrid.v1.a"], &[]);
    let widened = manifest_with(&[], &["astrid.v1.a", "astrid.v1.b"], &[]);
    assert_ne!(
        capability_fingerprint(&base),
        capability_fingerprint(&widened),
        "adding an IPC publish pattern must change the fingerprint"
    );

    let sub = manifest_with(&[], &[], &["client.v1.x"]);
    assert_ne!(
        capability_fingerprint(&base),
        capability_fingerprint(&sub),
        "publish vs subscribe patterns must not collide"
    );
}

#[test]
fn fingerprint_is_deterministic_hex() {
    let m = manifest_with(&["example.com"], &["astrid.v1.a"], &["client.v1.x"]);
    let f1 = capability_fingerprint(&m);
    let f2 = capability_fingerprint(&m);
    assert_eq!(f1, f2, "same input → same fingerprint");
    assert_eq!(f1.as_str().len(), 64, "BLAKE3 hex is 64 chars");
    assert!(f1.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
}

// ── effective_capabilities (the pure load decision) ──────────────────────

#[test]
fn effective_capabilities_approved_keeps_declared() {
    let declared = CapabilitiesDef {
        net: vec!["example.com".into()],
        ..Default::default()
    };
    let effective = effective_capabilities(&declared, true);
    assert_eq!(
        effective.net,
        vec!["example.com".to_string()],
        "an approved capsule keeps its declared capabilities verbatim"
    );
}

#[test]
fn effective_capabilities_unapproved_is_empty_set() {
    // The whole point: an unapproved capsule with a hostile declared set loads
    // with the empty, fail-closed set → inert.
    let declared = CapabilitiesDef {
        net: vec!["attacker.example.com".into()],
        fs_write: vec!["*".into()],
        host_process: vec!["bash".into()],
        uplink: true,
        ..Default::default()
    };
    let effective = effective_capabilities(&declared, false);
    assert!(
        effective.held_names().is_empty(),
        "unapproved → zero capabilities"
    );
    assert!(effective.net.is_empty());
    assert!(effective.fs_write.is_empty());
    assert!(effective.host_process.is_empty());
    assert!(!effective.uplink);
}

// ── Approval store ───────────────────────────────────────────────────────

fn test_home(dir: &std::path::Path) -> AstridHome {
    AstridHome::from_path(dir)
}

#[test]
fn approve_then_is_approved_true() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();
    let fp = "abc123";

    assert!(
        !is_approved(&home, &principal, "cap", fp),
        "absent record → not approved"
    );
    approve(&home, &principal, "cap", fp).expect("approve");
    assert!(
        is_approved(&home, &principal, "cap", fp),
        "after approve with matching fingerprint → approved"
    );
}

#[test]
fn mismatched_fingerprint_is_not_approved() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();

    approve(&home, &principal, "cap", "fingerprint-v1").expect("approve");
    assert!(
        !is_approved(&home, &principal, "cap", "fingerprint-v2"),
        "a different fingerprint (escalated manifest) must NOT be approved"
    );
    assert!(
        is_approved(&home, &principal, "cap", "fingerprint-v1"),
        "the originally-approved fingerprint still matches"
    );
}

#[test]
fn absent_record_is_not_approved() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();
    assert!(!is_approved(
        &home,
        &principal,
        "never-installed",
        "anything"
    ));
}

#[test]
fn corrupt_record_is_not_approved() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();
    let dir = home.principal_home(&principal).approvals_dir();
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("cap.json"), b"{ not valid json").expect("write");
    assert!(
        !is_approved(&home, &principal, "cap", "anything"),
        "an unparseable record is fail-secure (treated as unapproved)"
    );
}

#[test]
fn approve_overwrites_existing_record() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();

    approve(&home, &principal, "cap", "old").expect("approve old");
    approve(&home, &principal, "cap", "new").expect("approve new");
    assert!(!is_approved(&home, &principal, "cap", "old"));
    assert!(is_approved(&home, &principal, "cap", "new"));
}

#[test]
fn remove_clears_approval() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();

    approve(&home, &principal, "cap", "fp").expect("approve");
    remove(&home, &principal, "cap").expect("remove");
    assert!(!is_approved(&home, &principal, "cap", "fp"));
    // Removing again is a no-op success.
    remove(&home, &principal, "cap").expect("remove-absent is ok");
}

#[test]
fn approval_is_per_principal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let alice = PrincipalId::new("alice").expect("principal");
    let bob = PrincipalId::new("bob").expect("principal");

    approve(&home, &alice, "cap", "fp").expect("approve alice");
    assert!(is_approved(&home, &alice, "cap", "fp"));
    assert!(
        !is_approved(&home, &bob, "cap", "fp"),
        "alice's approval must not leak to bob"
    );
}

#[test]
fn approval_record_lives_under_config_not_capsule_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();
    approve(&home, &principal, "cap", "fp").expect("approve");

    let ph = home.principal_home(&principal);
    let record = ph.approvals_dir().join("cap.json");
    assert!(record.exists(), "record is under .config/approvals/");
    // It must NOT be inside the capsule's own (copyable, guest-reachable) dir.
    assert!(!ph.capsules_dir().join("cap").join("cap.json").exists());
    assert!(record.starts_with(ph.config_dir()));
}

// ── path_is_in_approval_store (defense in depth) ─────────────────────────

#[test]
fn path_in_approval_store_detects_reach_in() {
    let home_root = std::path::Path::new("/home/p");
    let approvals = home_root.join(".config").join("approvals");
    assert!(path_is_in_approval_store(
        approvals.join("x.json"),
        home_root
    ));
    assert!(path_is_in_approval_store(&approvals, home_root));
    // A sibling config dir (env) is NOT the approval store.
    assert!(!path_is_in_approval_store(
        home_root.join(".config").join("env").join("x.env.json"),
        home_root
    ));
    assert!(!path_is_in_approval_store(
        home_root.join(".local").join("capsules"),
        home_root
    ));
}

// ── Grandfather migration ────────────────────────────────────────────────

/// Install a minimal on-disk capsule dir with a manifest under `principal`.
fn install_fixture_capsule(home: &AstridHome, principal: &PrincipalId, id: &str, net: &[&str]) {
    let dir = home.principal_home(principal).capsules_dir().join(id);
    std::fs::create_dir_all(&dir).expect("mkdir capsule");
    let nets = net
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        "[package]\nname = \"{id}\"\nversion = \"0.1.0\"\n\n[capabilities]\nnet = [{nets}]\n"
    );
    std::fs::write(dir.join("Capsule.toml"), toml).expect("write manifest");
}

#[test]
fn migration_approves_preexisting_capsule() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();

    install_fixture_capsule(&home, &principal, "preexisting", &["example.com"]);

    // Before migration: the on-disk capsule has no approval → would load inert.
    let manifest = crate::discovery::load_manifest(
        &home
            .principal_home(&principal)
            .capsules_dir()
            .join("preexisting")
            .join("Capsule.toml"),
    )
    .expect("load manifest");
    let fp = capability_fingerprint(&manifest);
    assert!(!is_approved(&home, &principal, "preexisting", &fp));

    migrate_grandfather_approvals(&home);

    // After migration: the capsule is approved at its current fingerprint.
    assert!(
        is_approved(&home, &principal, "preexisting", &fp),
        "grandfather migration must approve a pre-existing capsule at its current fingerprint"
    );
}

#[test]
fn migration_is_idempotent_and_does_not_reapprove_after_change() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = test_home(tmp.path());
    let principal = PrincipalId::default();
    install_fixture_capsule(&home, &principal, "cap", &["example.com"]);

    migrate_grandfather_approvals(&home);
    let marker = home.etc_dir().join(".capability-approvals-migrated");
    assert!(marker.exists(), "marker written after first run");

    // Now the capsule's manifest is escalated on disk (simulating a hostile
    // post-migration swap) and migration is run again. Because the marker is
    // present, the second run is a no-op: the escalated fingerprint stays
    // unapproved (the capsule would load inert until re-approved).
    install_fixture_capsule(
        &home,
        &principal,
        "cap",
        &["example.com", "attacker.example.com"],
    );
    migrate_grandfather_approvals(&home);

    let escalated = crate::discovery::load_manifest(
        &home
            .principal_home(&principal)
            .capsules_dir()
            .join("cap")
            .join("Capsule.toml"),
    )
    .expect("load manifest");
    let escalated_fp = capability_fingerprint(&escalated);
    assert!(
        !is_approved(&home, &principal, "cap", &escalated_fp),
        "idempotent migration must not auto-approve a post-migration escalation"
    );
}
