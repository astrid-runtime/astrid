//! Tests for [`super`] — self-update / PATH-setup helpers. Kept in a
//! sibling file (via `#[path]`) so `self_update/mod.rs` stays under the
//! per-file CI line cap.

use super::path_setup::{ensure_path_setup, rc_configures_path, shell_profile_setup_wanted};
use super::*;

#[test]
fn platform_target_selects_linux_libc_at_compile_time_boundary() {
    assert_eq!(
        platform_target_for("linux", "x86_64", "gnu").unwrap(),
        "x86_64-unknown-linux-gnu"
    );
    assert_eq!(
        platform_target_for("linux", "x86_64", "musl").unwrap(),
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        platform_target_for("linux", "aarch64", "gnu").unwrap(),
        "aarch64-unknown-linux-gnu"
    );
    assert_eq!(
        platform_target_for("linux", "aarch64", "musl").unwrap(),
        "aarch64-unknown-linux-musl"
    );
    assert_eq!(
        platform_target_for("macos", "aarch64", "").unwrap(),
        "aarch64-apple-darwin"
    );
    assert_eq!(
        platform_target_for("windows", "x86_64", "").unwrap(),
        "x86_64-pc-windows-msvc"
    );
    for unsupported in ["", "uclibc", "newlib"] {
        assert!(
            platform_target_for("linux", "x86_64", unsupported)
                .unwrap_err()
                .to_string()
                .contains("target environment")
        );
    }
    assert!(platform_target_for("linux", "riscv64", "musl").is_err());
}

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

/// REGRESSION (#1183): an isolated runtime must not rewrite the account's
/// shell startup file. These cases are pure, so no test reads or mutates the
/// caller's rc or process environment.
#[test]
fn shell_profile_setup_follows_astrid_home_boundary() {
    let default = Path::new("/home/jb/.astrid");
    let isolated = Path::new("/tmp/astrid-issue-1183");

    assert!(shell_profile_setup_wanted(None, Some(default)));
    assert!(
        shell_profile_setup_wanted(Some(default), Some(default)),
        "the default home keeps the account-PATH setup behavior"
    );
    assert!(!shell_profile_setup_wanted(Some(isolated), Some(default)));
    assert!(!shell_profile_setup_wanted(Some(isolated), None));
}

#[test]
fn shell_profile_setup_skips_invalid_explicit_home() {
    for invalid in ["", "relative/astrid", "/tmp/../astrid"] {
        assert!(!shell_profile_setup_wanted(Some(Path::new(invalid)), None));
    }
}

/// Exercise the real mutating function in a child process so all process-wide
/// application-home inputs can be pinned without altering the test runner.
#[cfg(unix)]
#[test]
fn ensure_path_setup_explicit_nondefault_home_subprocess() {
    const CHILD_MARKER: &str = "ASTRID_PATH_SETUP_SUBPROCESS";
    const CHILD_COMPLETION_VAR: &str = "ASTRID_PATH_SETUP_COMPLETION";
    const CHILD_COMPLETION_CONTENT: &[u8] = b"ensure_path_setup returned";
    let module_path = module_path!();
    let test_name = format!(
        "{}::ensure_path_setup_explicit_nondefault_home_subprocess",
        module_path.strip_prefix("astrid::").unwrap_or(module_path)
    );

    if std::env::var_os(CHILD_MARKER).is_some() {
        let home = PathBuf::from(std::env::var_os("HOME").expect("child HOME"));
        let astrid_home =
            PathBuf::from(std::env::var_os("ASTRID_HOME").expect("child ASTRID_HOME"));
        assert!(
            home.file_name().is_some_and(|name| name
                .to_string_lossy()
                .starts_with("astrid-path-setup-home-profile")),
            "child must run against the isolated application home"
        );
        assert!(
            astrid_home
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("astrid-path-setup-home")),
            "child must run against the isolated application home"
        );
        assert!(
            std::env::var("SHELL").is_ok_and(|shell| shell.ends_with("zsh")),
            "child must select a disposable zsh profile"
        );
        ensure_path_setup().expect("explicit isolated home must not fail PATH setup");

        let completion =
            PathBuf::from(std::env::var_os(CHILD_COMPLETION_VAR).expect("completion path"));
        std::fs::write(completion, CHILD_COMPLETION_CONTENT)
            .expect("record child completion sentinel");
        return;
    }

    let home = tempfile::Builder::new()
        .prefix("astrid-path-setup-home-profile")
        .tempdir()
        .expect("create isolated HOME");
    let astrid_home = tempfile::Builder::new()
        .prefix("astrid-path-setup-home")
        .tempdir()
        .expect("create isolated ASTRID_HOME");
    let completion = home.path().join("child-returned");

    let harness = std::env::current_exe().expect("test executable");
    assert!(
        harness
            .parent()
            .is_some_and(|parent| parent.ends_with("deps"))
            && harness
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("astrid-")),
        "child must be the hashed libtest harness, not the CLI: {}",
        harness.display()
    );
    let profile = home.path().join(".zshrc");

    // Read-only canary: if the guard regresses, it should be obvious whether
    // the real rc changed during the test rather than before it.
    let real_rc = directories::BaseDirs::new()
        .expect("resolve caller BaseDirs")
        .home_dir()
        .join(".zshrc");
    let before = std::fs::metadata(&real_rc).ok().map(|metadata| {
        (
            std::fs::read(&real_rc).expect("read rc canary"),
            metadata.modified().expect("read rc mtime"),
        )
    });

    let output = std::process::Command::new(&harness)
        .args(["--exact", test_name.as_str(), "--nocapture"])
        .env_clear()
        .env(CHILD_MARKER, "1")
        .env(CHILD_COMPLETION_VAR, &completion)
        .env("HOME", home.path())
        .env("ASTRID_HOME", astrid_home.path())
        .env("SHELL", "/bin/zsh")
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", home.path())
        .env("RUST_TEST_THREADS", "1")
        .env("RUST_BACKTRACE", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn isolated PATH-setup child");

    assert!(
        output.status.success(),
        "isolated PATH-setup child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let child_completion = std::fs::read(&completion).unwrap_or_else(|error| {
        panic!(
            "child must return from ensure_path_setup: {error}; filter={test_name}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(child_completion.as_slice(), CHILD_COMPLETION_CONTENT);
    assert!(!profile.exists(), "explicit isolated home must not edit rc");
    assert!(
        !astrid_home.path().join("bin").exists(),
        "explicit isolated home must not create its bin directory"
    );

    let after = std::fs::metadata(&real_rc).ok().map(|metadata| {
        (
            std::fs::read(&real_rc).expect("read rc canary"),
            metadata.modified().expect("read rc mtime"),
        )
    });
    assert_eq!(
        before, after,
        "real account rc content and mtime must remain unchanged"
    );
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
            plan_update(method, &older, &newer, true, UpdateChannel::Stable),
            UpdatePlan::Available {
                how: method.upgrade_command(UpdateChannel::Stable)
            },
            "check must report availability for {method:?}"
        );
        // Up to date is up to date for every method.
        assert_eq!(
            plan_update(method, &newer, &newer, true, UpdateChannel::Stable),
            UpdatePlan::UpToDate
        );
    }

    // Applying an update (not --check): external managers defer, self-managed
    // swaps in place.
    assert_eq!(
        plan_update(Homebrew, &older, &newer, false, UpdateChannel::Stable),
        UpdatePlan::DeferToManager {
            manager: "Homebrew",
            how: "brew upgrade astrid"
        }
    );
    assert_eq!(
        plan_update(Cargo, &older, &newer, false, UpdateChannel::Stable),
        UpdatePlan::DeferToManager {
            manager: "cargo",
            how: "cargo install astrid --force"
        }
    );
    assert_eq!(
        plan_update(SelfManaged, &older, &newer, false, UpdateChannel::Stable),
        UpdatePlan::ApplyInPlace
    );

    // A higher signed channel generation can deliberately point back to a
    // prior immutable release. Self-managed clients follow that rollback.
    assert_eq!(
        plan_update(SelfManaged, &newer, &older, false, UpdateChannel::Stable),
        UpdatePlan::ApplyInPlace
    );
}

#[test]
fn package_manager_commands_follow_the_signed_stable_version() {
    let older = semver::Version::parse("1.2.2").unwrap();
    let selected = semver::Version::parse("1.2.3").unwrap();
    assert_eq!(
        notice::managed_update_command(InstallMethod::Cargo, &older, &selected, "1.2.3").unwrap(),
        "cargo install astrid --version =1.2.3 --force"
    );
    assert_eq!(
        notice::managed_update_command(InstallMethod::Homebrew, &older, &selected, "1.2.3")
            .unwrap(),
        "brew upgrade astrid-runtime/tap/astrid"
    );
    assert_eq!(
        notice::managed_update_command(InstallMethod::Homebrew, &selected, &older, "1.2.2")
            .unwrap(),
        "brew reinstall astrid-runtime/tap/astrid"
    );
    assert_eq!(
        notice::managed_update_command(InstallMethod::Cargo, &selected, &older, "1.2.2").unwrap(),
        "cargo install astrid --version =1.2.2 --force"
    );
    assert!(
        notice::managed_update_command(InstallMethod::SelfManaged, &older, &selected, "1.2.3")
            .is_none()
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
fn release_asset_lookup_requires_one_exact_asset() {
    let release = serde_json::json!({
        "assets": [
            {
                "name": "astrid-1.0.0-x.tar.gz",
                "browser_download_url": "https://example.com/archive"
            },
            {
                "name": "astrid-1.0.0-x.tar.gz.sigstore.json",
                "browser_download_url": "https://example.com/bundle"
            },
            {
                "name": "BLAKE3SUMS.txt",
                "browser_download_url": "https://example.com/sums"
            }
        ]
    });
    assert_eq!(
        exact_asset_url(&release, "astrid-1.0.0-x.tar.gz").unwrap(),
        "https://example.com/archive"
    );
    assert!(exact_asset_url(&release, "astrid-1.0.0-y.tar.gz").is_err());

    let duplicate = serde_json::json!({
        "assets": [
            {
                "name": "BLAKE3SUMS.txt",
                "browser_download_url": "https://example.com/one"
            },
            {
                "name": "BLAKE3SUMS.txt",
                "browser_download_url": "https://example.com/two"
            }
        ]
    });
    assert!(exact_asset_url(&duplicate, "BLAKE3SUMS.txt").is_err());

    let oversized = serde_json::json!({
        "assets": vec![serde_json::json!({"name": "irrelevant"}); MAX_RELEASE_ASSETS + 1]
    });
    assert!(
        exact_asset_url(&oversized, "irrelevant")
            .unwrap_err()
            .to_string()
            .contains("too many assets")
    );
}

#[test]
fn publisher_bundle_and_blake3_manifest_are_both_mandatory() {
    let sha_only = serde_json::json!({
        "assets": [{
            "name": "SHA256SUMS.txt",
            "browser_download_url": "https://example.com/SHA256SUMS.txt"
        }]
    });
    assert!(matches!(
        integrity_manifest_url(&sha_only).unwrap_err(),
        UpdateStageError::Integrity(_)
    ));
    assert!(matches!(
        publisher_bundle_url(&sha_only, "astrid-1.0.0-x.tar.gz").unwrap_err(),
        UpdateStageError::PublisherAuthentication(_)
    ));
}

#[test]
fn staged_asset_selection_preserves_the_exact_failure() {
    let bundle_name = "astrid-1.0.0-x.tar.gz.sigstore.json";
    let duplicate_bundle = serde_json::json!({
        "assets": [
            {"name": bundle_name, "browser_download_url": "https://example.com/one"},
            {"name": bundle_name, "browser_download_url": "https://example.com/two"}
        ]
    });
    let error = publisher_bundle_url(&duplicate_bundle, "astrid-1.0.0-x.tar.gz")
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        format!(
            "publisher authentication failed: release contains duplicate asset '{bundle_name}'"
        )
    );

    let oversized = serde_json::json!({
        "assets": vec![serde_json::json!({"name": "irrelevant"}); MAX_RELEASE_ASSETS + 1]
    });
    assert_eq!(
        integrity_manifest_url(&oversized).unwrap_err().to_string(),
        "integrity check failed: release contains too many assets"
    );
}

#[test]
fn backup_and_swap_replaces_and_keeps_backup() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("new");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();

    let managed = super::managed_binaries_for_target("x86_64-unknown-linux-gnu");
    for name in &managed {
        std::fs::write(install.join(name), format!("OLD-{name}")).unwrap();
        std::fs::write(extract.join(name), format!("NEW-{name}")).unwrap();
    }

    backup_and_swap(&install, &extract, &managed).unwrap();

    for name in &managed {
        assert_eq!(
            std::fs::read_to_string(install.join(name)).unwrap(),
            format!("NEW-{name}")
        );
        // Previous binaries are preserved for manual rollback.
        assert_eq!(
            std::fs::read_to_string(install.join(format!("{name}.bak"))).unwrap(),
            format!("OLD-{name}")
        );
    }
    // No staging temps left behind.
    assert!(!install.join(".astrid.new").exists());
}

#[test]
fn macos_self_update_keeps_native_provider_and_lifecycle_tools_in_the_managed_set() {
    let managed = super::managed_binaries_for_target("aarch64-apple-darwin");
    assert_eq!(
        managed,
        vec![
            "astrid",
            "astrid-daemon",
            "astrid-build",
            "astrid-emit",
            "astrid-storage-provider-fskit",
            "manage-macos-fskit.sh",
            "validate-macos-fskit.sh",
        ]
    );
}

#[test]
fn macos_native_failure_restores_the_prior_managed_set() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("release");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(extract.join("macos")).unwrap();
    std::fs::create_dir_all(extract.join("AstridFS.app")).unwrap();
    let managed = super::managed_binaries_for_target("aarch64-apple-darwin");
    for name in &managed[..5] {
        std::fs::write(install.join(name), format!("OLD-{name}")).unwrap();
        std::fs::write(extract.join(name), format!("NEW-{name}")).unwrap();
    }
    for name in &managed[5..] {
        std::fs::write(extract.join("macos").join(name), format!("NEW-{name}")).unwrap();
    }

    let error =
        super::apply_authenticated_update(&install, &extract, "aarch64-apple-darwin", |_, _| {
            anyhow::bail!("injected app failure")
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("prior managed Astrid set was restored")
    );
    for name in &managed[..5] {
        assert_eq!(
            std::fs::read_to_string(install.join(name)).unwrap(),
            format!("OLD-{name}")
        );
    }
    for name in &managed[5..] {
        assert!(!install.join(name).exists());
    }
}

#[test]
fn macos_assets_are_required_before_any_managed_file_is_mutated() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("release");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();
    std::fs::write(install.join("astrid"), b"OLD").unwrap();

    assert!(
        super::apply_authenticated_update(
            &install,
            &extract,
            "aarch64-apple-darwin",
            |_, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"OLD");
    assert!(!install.join("astrid.bak").exists());
}

#[test]
fn macos_success_retains_authenticated_lifecycle_tools() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("release");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(extract.join("macos")).unwrap();
    std::fs::create_dir_all(extract.join("AstridFS.app")).unwrap();
    for name in super::managed_binaries_for_target("aarch64-apple-darwin") {
        let source = if std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
        {
            extract.join("macos").join(name)
        } else {
            extract.join(name)
        };
        std::fs::write(source, format!("NEW-{name}")).unwrap();
    }

    super::apply_authenticated_update(&install, &extract, "aarch64-apple-darwin", |_, _| Ok(()))
        .unwrap();
    for name in ["manage-macos-fskit.sh", "validate-macos-fskit.sh"] {
        assert_eq!(
            std::fs::read_to_string(install.join(name)).unwrap(),
            format!("NEW-{name}")
        );
    }
}

#[test]
fn backup_and_swap_bails_when_archive_missing_a_binary() {
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("new");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();

    let managed = super::managed_binaries_for_target("x86_64-unknown-linux-gnu");
    for name in &managed {
        std::fs::write(install.join(name), format!("OLD-{name}")).unwrap();
    }
    // Archive only ships `astrid`; the remaining managed binaries are absent.
    std::fs::write(extract.join("astrid"), b"NEW").unwrap();

    assert!(backup_and_swap(&install, &extract, &managed).is_err());

    // The completeness check runs before anything is touched: live binaries
    // are unchanged and no backups or staging temps were created.
    for name in &managed {
        assert_eq!(
            std::fs::read_to_string(install.join(name)).unwrap(),
            format!("OLD-{name}")
        );
        assert!(!install.join(format!("{name}.bak")).exists());
    }
    assert!(!install.join(".astrid.new").exists());
}

#[test]
fn linux_managed_updates_introduce_the_fuse_provider() {
    let managed = super::managed_binaries_for_target("x86_64-unknown-linux-musl");
    assert_eq!(
        managed,
        vec![
            "astrid",
            "astrid-daemon",
            "astrid-build",
            "astrid-emit",
            "astrid-storage-provider-fuse",
        ]
    );
    assert!(
        !super::managed_binaries_for_target("x86_64-apple-darwin")
            .contains(&"astrid-storage-provider-fuse")
    );

    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("bin");
    let extract = dir.path().join("new");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&extract).unwrap();
    std::fs::write(install.join("astrid"), b"OLD").unwrap();
    std::fs::write(install.join("astrid-daemon"), b"OLD-D").unwrap();
    std::fs::write(extract.join("astrid"), b"NEW").unwrap();
    std::fs::write(extract.join("astrid-daemon"), b"NEW-D").unwrap();
    std::fs::write(extract.join("astrid-build"), b"NEW-BUILD").unwrap();
    std::fs::write(extract.join("astrid-emit"), b"NEW-EMIT").unwrap();
    std::fs::write(extract.join("astrid-storage-provider-fuse"), b"NEW-FUSE").unwrap();

    super::backup_and_swap(&install, &extract, &managed).unwrap();

    assert_eq!(
        std::fs::read(install.join("astrid-storage-provider-fuse")).unwrap(),
        b"NEW-FUSE"
    );
}

#[test]
fn windows_managed_updates_include_the_native_provider_and_installer() {
    assert_eq!(
        super::managed_binaries_for_target("x86_64-pc-windows-msvc"),
        vec![
            "astrid.exe",
            "astrid-daemon.exe",
            "astrid-build.exe",
            "astrid-emit.exe",
            "astrid-storage-provider-winfsp.exe",
            "winfsp-x64.dll",
            "winfsp-2.1.25156.msi",
            "install-windows.ps1",
            "uninstall-windows.ps1",
        ]
    );
}
