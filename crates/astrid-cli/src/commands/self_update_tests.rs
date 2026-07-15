//! Tests for [`super`] — self-update / PATH-setup helpers. Kept in a
//! sibling file (via `#[path]`) so `self_update.rs` stays under the
//! per-file CI line cap.

use super::*;

#[test]
fn installed_distro_lock_selects_skip_without_a_remote_source() {
    assert_eq!(
        distro_refresh_action(true),
        DistroRefreshAction::SkipNoProvenance,
        "a lock records an identity, not a source, so refresh must not invoke init"
    );
    assert_eq!(
        distro_refresh_action(false),
        DistroRefreshAction::NoInstalledDistro
    );
}

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
fn install_method_is_detected_per_path() {
    use InstallMethod::{Cargo, Homebrew, SelfManaged};
    assert_eq!(
        InstallMethod::detect(Path::new("/opt/homebrew/Cellar/astrid/0.9.2/bin/astrid")),
        Homebrew
    );
    assert_eq!(
        InstallMethod::detect(Path::new("/home/jb/.cargo/bin/astrid")),
        Cargo
    );
    assert_eq!(
        InstallMethod::detect(Path::new("/Users/jb/.astrid/bin/astrid")),
        SelfManaged
    );
    assert_eq!(
        InstallMethod::detect(Path::new("/usr/local/bin/astrid")),
        SelfManaged
    );
    // `.cargo` without an adjacent `bin` is NOT a cargo install (a stray dir
    // named `.cargo` elsewhere in the path must not misclassify).
    assert_eq!(
        InstallMethod::detect(Path::new("/home/jb/.cargo/registry/astrid")),
        SelfManaged
    );
}

/// REGRESSION (#1121): `--check` must report an available update for EVERY
/// install method — Homebrew and cargo included, not just self-managed. Before
/// the fix the Homebrew branch returned before the version check, so the nudge
/// never fired for brew installs. Applying (not checking) still defers external
/// managers and swaps self-managed installs in place.
#[test]
fn check_reports_update_for_all_install_methods() {
    use InstallMethod::{Cargo, Homebrew, SelfManaged};
    let older = semver::Version::parse("0.9.1").unwrap();
    let newer = semver::Version::parse("0.9.2").unwrap();

    for method in [Homebrew, Cargo, SelfManaged] {
        // `--check`: availability is reported for every method, with that
        // method's own upgrade command — never UpToDate, never a deferral.
        assert_eq!(
            plan_update(method, &older, &newer, true),
            UpdatePlan::Available {
                how: method.upgrade_command()
            },
            "check must report availability for {method:?}"
        );
        // Up to date is up to date for every method.
        assert_eq!(
            plan_update(method, &newer, &newer, true),
            UpdatePlan::UpToDate
        );
        assert_eq!(
            plan_update(method, &newer, &older, false),
            UpdatePlan::UpToDate
        );
    }

    // Applying an update (not --check): external managers defer, self-managed
    // swaps in place.
    assert_eq!(
        plan_update(Homebrew, &older, &newer, false),
        UpdatePlan::DeferToManager {
            manager: "Homebrew",
            how: "brew upgrade astrid"
        }
    );
    assert_eq!(
        plan_update(Cargo, &older, &newer, false),
        UpdatePlan::DeferToManager {
            manager: "cargo",
            how: "cargo install astrid --force"
        }
    );
    assert_eq!(
        plan_update(SelfManaged, &older, &newer, false),
        UpdatePlan::ApplyInPlace
    );
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
fn blake3_verification_matches_independent_vector() {
    let archive = b"hello astrid";
    // Independently generated with `printf %s 'hello astrid' | b3sum --no-names`.
    let good = "41251d32ddff968c23c1c83c4e7b3af8d6fef8912b4806aadec90e106a629fef";
    assert_eq!(blake3::hash(archive).to_hex().as_str(), good);
    let body = format!("{good}  astrid-1.0.0-x.tar.gz\n");
    verify_blake3(archive, &body, "astrid-1.0.0-x.tar.gz").expect("matching sum verifies");

    let asset = "astrid-1.0.0-x.tar.gz";

    // Wrong sum -> error.
    let bad_body = format!("{}  {asset}\n", "0".repeat(64));
    assert!(verify_blake3(archive, &bad_body, asset).is_err());
    // Missing entry -> error.
    let other = format!("{}  other.tar.gz\n", "0".repeat(64));
    assert!(verify_blake3(archive, &other, asset).is_err());
    // Malformed length, non-hex and uppercase encodings are rejected.
    assert!(verify_blake3(archive, &format!("{}  {asset}\n", "a".repeat(63)), asset).is_err());
    assert!(verify_blake3(archive, &format!("{}g  {asset}\n", "a".repeat(63)), asset).is_err());
    assert!(
        verify_blake3(
            archive,
            &format!("{}  {asset}\n", good.to_uppercase()),
            asset
        )
        .is_err()
    );
    // A matching checksum cannot be shadowed by a duplicate entry.
    let duplicate = format!("{good}  {asset}\n{good}  {asset}\n");
    assert!(verify_blake3(archive, &duplicate, asset).is_err());
    // Manifest validity is platform-independent: duplicates for a different
    // release asset are rejected as well.
    let duplicate_other = format!(
        "{good}  {asset}\n{}  other.tar.gz\n{}  other.tar.gz\n",
        "0".repeat(64),
        "1".repeat(64)
    );
    assert!(verify_blake3(archive, &duplicate_other, asset).is_err());

    let overlong = "a".repeat(MAX_MANIFEST_LINE_BYTES + 1);
    let error = verify_blake3(archive, &overlong, asset)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        format!("BLAKE3SUMS.txt line 1 exceeds {MAX_MANIFEST_LINE_BYTES} byte limit")
    );
}

#[test]
fn legacy_sha_only_release_is_not_accepted() {
    let release = serde_json::json!({
        "assets": [{
            "name": "SHA256SUMS.txt",
            "browser_download_url": "https://example.com/SHA256SUMS.txt"
        }]
    });
    let error = blake3_sums_url(&release).unwrap_err().to_string();
    assert!(error.contains("release has no BLAKE3SUMS.txt"));
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
