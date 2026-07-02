//! Tests for [`super`] — self-update / PATH-setup helpers. Kept in a
//! sibling file (via `#[path]`) so `self_update.rs` stays under the
//! per-file CI line cap.

use super::*;

#[test]
fn rc_path_guard_is_idempotent() {
    let bin = "/home/jb/.astrid/bin";
    let export = format!("export PATH=\"{bin}:$PATH\"");

    // Empty rc: nothing wired yet — must append.
    assert!(!rc_configures_path("", bin, &export));

    // After the block was written once, a second run must be a no-op.
    let after_first_write = format!("# existing\n\n# Astrid OS\n{export}\n");
    assert!(rc_configures_path(&after_first_write, bin, &export));

    // A manually-added line with different syntax but the same bin dir as
    // a whole component (bounded by `:` and newline) is recognised.
    let manual = format!("export PATH=$PATH:{bin}\n");
    assert!(rc_configures_path(&manual, bin, &export));

    // An unrelated rc must NOT be treated as configured.
    assert!(!rc_configures_path(
        "export PATH=\"/usr/bin:$PATH\"\n",
        bin,
        &export
    ));
}

#[test]
fn rc_path_guard_rejects_substring_false_positives() {
    let bin = "/home/jb/.astrid/bin";
    let export = format!("export PATH=\"{bin}:$PATH\"");

    // `.astrid/bin_backup` merely has `.astrid/bin` as a substring — the
    // real bin dir is NOT configured, so we must add the block (return
    // false), not silently skip and leave astrid off PATH.
    let backup = "export PATH=\"/home/jb/.astrid/bin_backup:$PATH\"\n";
    assert!(!rc_configures_path(backup, bin, &export));

    // `.astrid/bin/foo` continues the path with `/` — also not a match.
    let subdir = "export PATH=\"/home/jb/.astrid/bin/foo:$PATH\"\n";
    assert!(!rc_configures_path(subdir, bin, &export));

    // The bin dir as a properly-bounded token (opening `"`, closing `:`)
    // IS configured — skip.
    let bounded = "export PATH=\"/home/jb/.astrid/bin:$PATH\"\n";
    assert!(rc_configures_path(bounded, bin, &export));

    // A prefix false-positive followed by the real bounded token still
    // resolves to configured (the scan continues past the prefix match).
    let mixed = "PATH=/home/jb/.astrid/bin_backup\nPATH=/home/jb/.astrid/bin\n";
    assert!(rc_configures_path(mixed, bin, &export));
}

#[test]
fn rc_path_guard_ignores_commented_lines() {
    // These cases probe the bounded-component SCAN, so they use a manual
    // PATH line rather than the exact `export_line` (which the fast path
    // catches before the scan runs).
    let bin = "/home/jb/.astrid/bin";
    let export = format!("export PATH=\"{bin}:$PATH\"");

    // A commented-out line is inert: its bounded `bin_str` must NOT count as
    // configured, or the real PATH setup is silently skipped.
    let commented = "# PATH=/home/jb/.astrid/bin\n";
    assert!(!rc_configures_path(commented, bin, &export));

    // An inline comment after other content on the same line is still a
    // comment for this occurrence.
    let inline = "echo hi  # note: /home/jb/.astrid/bin\n";
    assert!(!rc_configures_path(inline, bin, &export));

    // The same bounded token on an ACTIVE (uncommented) line IS configured.
    let active = "PATH=/home/jb/.astrid/bin\n";
    assert!(rc_configures_path(active, bin, &export));

    // A commented occurrence followed by a real active one is configured
    // (the scan skips the comment and finds the live token).
    let both = "# PATH=/home/jb/.astrid/bin\nPATH=/home/jb/.astrid/bin\n";
    assert!(rc_configures_path(both, bin, &export));
}

#[test]
fn rc_path_guard_ignores_commented_exact_block() {
    let bin = "/home/jb/.astrid/bin";
    let export = format!("export PATH=\"{bin}:$PATH\"");

    // Our EXACT block, but commented out, is inert — the fast path must NOT
    // treat it as configured (else the real PATH setup is silently skipped).
    let commented_exact = format!("# {export}\n");
    assert!(!rc_configures_path(&commented_exact, bin, &export));

    // The same block ACTIVE (uncommented) IS configured via the fast path.
    let active_exact = format!("{export}\n");
    assert!(rc_configures_path(&active_exact, bin, &export));

    // A commented exact block followed by an active one is configured.
    let both_exact = format!("# {export}\n{export}\n");
    assert!(rc_configures_path(&both_exact, bin, &export));
}

#[test]
fn homebrew_path_is_detected() {
    assert!(is_homebrew_managed(Path::new(
        "/opt/homebrew/Cellar/astrid/0.8.0/bin/astrid"
    )));
    assert!(is_homebrew_managed(Path::new(
        "/usr/local/Cellar/astrid/0.8.0/bin/astrid"
    )));
    assert!(!is_homebrew_managed(Path::new(
        "/Users/jb/.astrid/bin/astrid"
    )));
    assert!(!is_homebrew_managed(Path::new("/usr/local/bin/astrid")));
    assert!(!is_homebrew_managed(Path::new(
        "/home/jb/.cargo/bin/astrid"
    )));
}

#[test]
fn resolve_repo_precedence_and_validation() {
    // An explicit `--source` wins over env/default and parses owner/repo.
    // (The `None` path falls through to ASTRID_UPDATE_REPO then the default
    // — not asserted here, since the env var can't be isolated under the
    // clippy ban on set_var/remove_var.)
    assert_eq!(
        resolve_repo(Some("acme/astrid")).unwrap(),
        ("acme".to_string(), "astrid".to_string())
    );
    assert!(resolve_repo(Some("no-slash")).is_err());
    assert!(resolve_repo(Some("owner/")).is_err());
    assert!(resolve_repo(Some("/repo")).is_err());
}

#[test]
fn sha256_verification_matches_and_rejects() {
    use sha2::Digest;
    let archive = b"hello astrid";
    let good = to_hex(&sha2::Sha256::digest(archive));
    let body = format!("{good}  astrid-1.0.0-x.tar.gz\n");
    verify_sha256(archive, &body, "astrid-1.0.0-x.tar.gz").expect("matching sum verifies");

    // Wrong sum -> error.
    let bad_body = format!("{}  astrid-1.0.0-x.tar.gz\n", "0".repeat(64));
    assert!(verify_sha256(archive, &bad_body, "astrid-1.0.0-x.tar.gz").is_err());
    // Missing entry -> error.
    assert!(verify_sha256(archive, "deadbeef  other.tar.gz\n", "astrid-1.0.0-x.tar.gz").is_err());
}

#[test]
fn backup_and_swap_replaces_and_keeps_backup() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("new");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();

    std::fs::write(install.join("astrid"), b"OLD").unwrap();
    std::fs::write(install.join("astrid-daemon"), b"OLD-D").unwrap();
    std::fs::write(extract.join("astrid"), b"NEW").unwrap();
    std::fs::write(extract.join("astrid-daemon"), b"NEW-D").unwrap();

    backup_and_swap(&install, &extract, MANAGED_BINARIES).unwrap();

    assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"NEW");
    assert_eq!(
        std::fs::read(install.join("astrid-daemon")).unwrap(),
        b"NEW-D"
    );
    // Previous binaries preserved for manual rollback.
    assert_eq!(std::fs::read(install.join("astrid.bak")).unwrap(), b"OLD");
    assert_eq!(
        std::fs::read(install.join("astrid-daemon.bak")).unwrap(),
        b"OLD-D"
    );
    // No staging temps left behind.
    assert!(!install.join(".astrid.new").exists());
}

#[test]
fn backup_and_swap_bails_when_archive_missing_a_binary() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("new");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();

    std::fs::write(install.join("astrid"), b"OLD").unwrap();
    std::fs::write(install.join("astrid-daemon"), b"OLD-D").unwrap();
    // Archive only ships `astrid`; `astrid-daemon` is absent.
    std::fs::write(extract.join("astrid"), b"NEW").unwrap();

    assert!(backup_and_swap(&install, &extract, MANAGED_BINARIES).is_err());

    // The completeness check runs before anything is touched: live binaries
    // are unchanged and no backups or staging temps were created.
    assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"OLD");
    assert_eq!(
        std::fs::read(install.join("astrid-daemon")).unwrap(),
        b"OLD-D"
    );
    assert!(!install.join("astrid.bak").exists());
    assert!(!install.join(".astrid.new").exists());
}

#[test]
fn post_update_sync_message_softens_version_gate() {
    use super::super::distro::validate::AstridVersionTooOld;
    use anyhow::Context as _;

    // The version-floor gate fired during the post-swap sync (old in-flight
    // process, new binary already on disk) — the user must see the benign
    // "takes effect next run" message, NOT the raw "Run `astrid update`" text.
    let gate: anyhow::Error = AstridVersionTooOld {
        req: ">=0.8.0".to_string(),
        running: "0.7.0".to_string(),
    }
    .into();
    let msg = post_update_sync_message(&gate);
    assert!(
        msg.contains("take effect")
            && msg.contains("next run")
            && !msg.contains("Run `astrid update`"),
        "version-gate failure must yield the benign restart message, got: {msg}"
    );

    // FIX F: a CONTEXT-WRAPPED gate error must still be softened. The
    // typed gate is buried under two `.context(...)` layers; the displayed
    // (outermost) message is now the context string, so a match that only
    // looked at the surface text would miss it. `post_update_sync_message`
    // walks `err.chain()` to find `AstridVersionTooOld` underneath.
    let wrapped: anyhow::Error = Err::<(), _>(anyhow::Error::from(AstridVersionTooOld {
        req: ">=0.8.0".to_string(),
        running: "0.7.0".to_string(),
    }))
    .context("re-running init after update")
    .context("syncing distro")
    .unwrap_err();
    // Guard: the outermost display text is the context, not the gate's own
    // message — so the softening must come from a chain walk, not from
    // inspecting the surface error.
    assert_eq!(wrapped.to_string(), "syncing distro");
    assert!(
        wrapped
            .chain()
            .any(<dyn std::error::Error + 'static>::is::<AstridVersionTooOld>),
        "guard: the typed gate must be reachable by walking the chain"
    );
    let msg = post_update_sync_message(&wrapped);
    assert!(
        msg.contains("take effect")
            && msg.contains("next run")
            && !msg.contains("Run `astrid update`"),
        "context-wrapped version-gate failure must still be softened, got: {msg}"
    );

    // Any OTHER sync failure keeps the generic warn path verbatim.
    let other = anyhow::anyhow!("network unreachable while fetching Distro.toml");
    let msg = post_update_sync_message(&other);
    assert!(
        msg.starts_with("Distro sync:") && msg.contains("network unreachable"),
        "non-gate failure must use the generic warn path, got: {msg}"
    );
}
