//! Unit tests for the native-process sandbox wrappers (bwrap / Seatbelt).
//! Extracted from `mod.rs` to keep that file under the 1000-line CI cap.

use super::*;
use std::path::PathBuf;

/// Validates that a path is safe for interpolation into an SBPL profile string.
fn validate_sandbox_path(path: &Path) -> io::Result<()> {
    let s = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("sandbox path is not valid UTF-8: {}", path.display()),
        )
    })?;
    if s.contains(['"', '\\', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "sandbox path contains forbidden characters (double-quote, backslash, or null): {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

// --- validate_sandbox_path tests ---

#[test]
fn validate_sandbox_path_accepts_normal_path() {
    let path = PathBuf::from("/Users/agent/workspace/project");
    assert!(validate_sandbox_path(&path).is_ok());
}

#[test]
fn validate_sandbox_path_accepts_path_with_spaces() {
    let path = PathBuf::from("/Users/agent/my project/src");
    assert!(validate_sandbox_path(&path).is_ok());
}

#[test]
fn validate_sandbox_path_rejects_double_quote() {
    let path = PathBuf::from("/Users/agent/work\"inject");
    let err = validate_sandbox_path(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("forbidden characters"),
        "unexpected error message: {err}"
    );
}

#[test]
fn validate_sandbox_path_rejects_sbpl_injection_payload() {
    // Simulates an actual SBPL escape attempt.
    let path = PathBuf::from(r#"/tmp/evil") (allow file-write* (subpath "/"))"#);
    let err = validate_sandbox_path(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("forbidden characters"),
        "unexpected error message: {err}"
    );
}

#[test]
fn validate_sandbox_path_rejects_backslash() {
    let path = PathBuf::from("/tmp/work\\nspace");
    let err = validate_sandbox_path(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("forbidden characters"),
        "unexpected error message: {err}"
    );
}

#[test]
fn validate_sandbox_path_rejects_null_byte() {
    let path = PathBuf::from("/tmp/work\0space");
    let err = validate_sandbox_path(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("forbidden characters"),
        "unexpected error message: {err}"
    );
}

// --- SandboxCommand::wrap() tests ---

#[test]
fn test_wrap_rejects_non_utf8_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_bytes: &[u8] = b"/tmp/\xff\xfe/workspace";
    let bad_path = Path::new(OsStr::from_bytes(bad_bytes));
    let cmd = Command::new("echo");
    let result = SandboxCommand::wrap(cmd, bad_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not valid UTF-8"),
        "error should mention UTF-8: {err_msg}"
    );
}

#[test]
fn test_wrap_rejects_double_quote_path() {
    let bad_path = Path::new("/tmp/evil\"injection/workspace");
    let cmd = Command::new("echo");
    let result = SandboxCommand::wrap(cmd, bad_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("forbidden characters"),
        "error should mention forbidden chars: {err_msg}"
    );
}

#[test]
fn test_wrap_rejects_null_byte_path() {
    let bad_path = Path::new("/tmp/evil\0null/workspace");
    let cmd = Command::new("echo");
    let result = SandboxCommand::wrap(cmd, bad_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("forbidden characters"),
        "error should mention forbidden chars: {err_msg}"
    );
}

#[test]
fn test_wrap_rejects_backslash_path() {
    let bad_path = Path::new("/tmp/work\\nspace");
    let cmd = Command::new("echo");
    let result = SandboxCommand::wrap(cmd, bad_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("forbidden characters"),
        "error should mention forbidden chars: {err_msg}"
    );
}

#[test]
fn test_wrap_rejects_relative_path() {
    let bad_path = Path::new("relative/workspace");
    let cmd = Command::new("echo");
    let result = SandboxCommand::wrap(cmd, bad_path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("absolute path"),
        "error should mention absolute path: {err_msg}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn wrap_always_sandboxes_via_shared_profile() {
    // Regression for #855: wrap() must always produce a `sandbox-exec`
    // wrapped command — never a passthrough — on every macOS version, and
    // the profile must carry the load-bearing root-read rule whose absence
    // caused the SIGABRT that the old macOS-15+ version guard masked.
    let cmd = Command::new("echo");
    let path = PathBuf::from("/tmp/safe-workspace");
    let wrapped = SandboxCommand::wrap(cmd, &path).unwrap();

    assert_eq!(
        wrapped.get_program(),
        "sandbox-exec",
        "wrap() must wrap the command in sandbox-exec, not pass it through"
    );
    let args: Vec<_> = wrapped.get_args().collect();
    assert_eq!(args[0], "-p", "expected -p for inline profile delivery");
    let profile = args[1].to_string_lossy();
    assert!(
        profile.contains("/tmp/safe-workspace"),
        "profile should contain the worktree path"
    );
    assert!(
        profile.contains(r#"(literal "/")"#),
        "profile must allow reading the filesystem root — the rule whose \
             absence caused the SIGABRT that #855's version guard masked"
    );
    assert!(
        args.iter().any(|a| *a == "echo"),
        "the wrapped command must still invoke the original program"
    );
}

// --- wrap_with_injections() tests ---

#[test]
fn wrap_with_injections_rejects_unsafe_paths() {
    // Relative target rejected as non-absolute; a double-quote in either
    // path rejected as a forbidden char (mirrors validate_sandbox_str).
    for (source, target, needle) in [
        ("/host/snap", "relative/target", "absolute path"),
        ("/host/evil\"snap", "/etc/x", "forbidden characters"),
        ("/host/snap", "/etc/ev\"il", "forbidden characters"),
    ] {
        let inj = [RoInjection {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
        }];
        let result = SandboxCommand::wrap_with_injections(
            Command::new("echo"),
            Path::new("/tmp/ws"),
            &inj,
            &[],
        );
        let msg = result
            .expect_err("unsafe injection path must be rejected")
            .to_string();
        assert!(msg.contains(needle), "expected {needle:?} in: {msg}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn wrap_with_injections_emits_ro_bind_pair() {
    let cmd = Command::new("echo");
    let inj = [RoInjection {
        source: PathBuf::from("/host/snap"),
        target: PathBuf::from("/etc/x"),
    }];
    let wrapped =
        SandboxCommand::wrap_with_injections(cmd, Path::new("/tmp/ws"), &inj, &[]).unwrap();
    let args: Vec<String> = wrapped
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    let pos = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--ro-bind")
        .find(|(i, _)| args.get(i + 1) == Some(&"/host/snap".to_string()))
        .map(|(i, _)| i)
        .expect("wrapped command must carry the injection --ro-bind");
    assert_eq!(args[pos + 2], "/etc/x", "ro-bind target");
}

/// SECURITY: a spawned child must NOT be able to write a caller-supplied mask
/// path (the copy-on-write upper/pristine). End-to-end proof on macOS: the mask
/// deny must hold even though the masked dir sits under a broadly-writable
/// location (`/var/folders` / `/private/tmp` are in the Seatbelt write
/// allowlist) — i.e. the mask, not the location, is what denies the write.
/// The masked path is a SIBLING of the writable root (not an ancestor), so
/// `build_seatbelt_prefix`'s ancestor-filter keeps the deny.
#[cfg(target_os = "macos")]
#[test]
fn extra_mask_blocks_child_write_even_under_writable_tmp() {
    // Probe whether Seatbelt can apply a profile at all in this environment
    // (nested sandboxes deny sandbox_apply); skip rather than false-fail.
    let can_apply = std::process::Command::new("sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .is_ok_and(|s| s.success());
    if !can_apply {
        eprintln!("sandbox-exec cannot apply a profile here; skipping mask enforcement test");
        return;
    }

    // Canonicalize: macOS tempdirs live under /var/folders, a symlink to
    // /private/var/folders, and Seatbelt matches on the REAL path.
    let root = tempfile::tempdir().expect("tmp root");
    let root = std::fs::canonicalize(root.path()).expect("canonicalize tmp root");
    let merged = root.join("merged");
    let masked = root.join("masked"); // sibling of merged, both under /var/folders
    std::fs::create_dir_all(&merged).expect("mkdir merged");
    std::fs::create_dir_all(&masked).expect("mkdir masked");

    // Child 1: writing the merged (writable) root SUCCEEDS and the host sees it
    // — proving the fs host and the spawned child share one merged tree.
    let mut inner = Command::new("/usr/bin/touch");
    inner.arg(merged.join("from_child.txt"));
    let mut wrapped =
        SandboxCommand::wrap_with_injections(inner, &merged, &[], std::slice::from_ref(&masked))
            .expect("wrap");
    let status = wrapped.status().expect("spawn child 1");
    assert!(status.success(), "child write to merged should succeed");
    assert!(
        merged.join("from_child.txt").exists(),
        "the fs host sees the file the sandboxed child created in merged"
    );

    // Child 2: writing the MASKED path FAILS — the file must not appear, even
    // though the masked dir sits under a broadly-writable /var/folders location.
    let mut inner = Command::new("/usr/bin/touch");
    inner.arg(masked.join("smuggled.txt"));
    let mut wrapped =
        SandboxCommand::wrap_with_injections(inner, &merged, &[], std::slice::from_ref(&masked))
            .expect("wrap");
    let status = wrapped.status().expect("spawn child 2");
    assert!(
        !status.success(),
        "touch on a masked path must fail (Seatbelt deny)"
    );
    assert!(
        !masked.join("smuggled.txt").exists(),
        "the mask must block the child from writing the CoW upper/pristine, \
         even though it lives under a writable /var/folders location"
    );
}

/// SECURITY (fail-closed): a caller-supplied copy-on-write mask that does not
/// exist is a wiring bug, not a no-op — `wrap_with_injections` must refuse the
/// spawn rather than silently run a child without the intended deny.
/// Platform-independent: the existence check precedes the OS-specific arms.
#[test]
fn missing_extra_mask_fails_the_spawn_closed() {
    let root = tempfile::tempdir().expect("tmp root");
    let worktree = root.path().join("worktree");
    std::fs::create_dir_all(&worktree).expect("mkdir worktree");
    let absent = root.path().join("does-not-exist");

    let inner = Command::new("/usr/bin/true");
    let err =
        SandboxCommand::wrap_with_injections(inner, &worktree, &[], std::slice::from_ref(&absent))
            .expect_err("a missing mask path must fail the spawn closed");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

/// PROCESS-BYPASS FIX (the whole point of Fix #2): a spawned process whose cwd
/// is the copy-on-write `merged` tree, writing a RELATIVE path, must land in
/// `merged` and be visible to the fs host — proving the spawn runs against the
/// merged tree, not the pristine workspace. An absolute-path write can't
/// distinguish the two; a relative write resolved against cwd can. Runs on macOS.
#[cfg(target_os = "macos")]
#[test]
fn spawn_with_cwd_merged_sees_relative_write_from_fs_host() {
    let can_apply = std::process::Command::new("sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .is_ok_and(|s| s.success());
    if !can_apply {
        eprintln!("sandbox-exec cannot apply a profile here; skipping cwd/relative test");
        return;
    }

    // Canonicalize (macOS /var/folders → /private/var/folders; Seatbelt matches
    // the real path).
    let root = tempfile::tempdir().expect("tmp root");
    let merged = std::fs::canonicalize(root.path()).expect("canonicalize");

    // Spawn with cwd == merged and write a RELATIVE path.
    let mut inner = Command::new("/usr/bin/touch");
    inner.current_dir(&merged);
    inner.arg("rel.txt");
    let mut wrapped = SandboxCommand::wrap(inner, &merged).expect("wrap");
    let status = wrapped.status().expect("spawn");
    assert!(
        status.success(),
        "relative write with cwd=merged should succeed"
    );

    // The fs host (unsandboxed, reading merged directly) sees the child's file:
    // the spawned process and the fs host share ONE merged tree.
    assert!(
        merged.join("rel.txt").exists(),
        "a relative-path write by a process with cwd=merged must land in merged \
         and be visible to the fs host (process-bypass fixed)"
    );
}

// --- ProcessSandboxConfig builder tests ---

#[test]
fn test_sandbox_config_builder() {
    let config = ProcessSandboxConfig::new("/project")
        .with_network(false)
        .with_extra_read("/data")
        .with_extra_write("/output")
        .with_hidden("/home/user/.astrid");

    assert_eq!(config.writable_root, PathBuf::from("/project"));
    assert!(!config.allow_network);
    assert_eq!(config.extra_read_paths, vec![PathBuf::from("/data")]);
    assert_eq!(config.extra_write_paths, vec![PathBuf::from("/output")]);
    assert_eq!(
        config.hidden_paths,
        vec![PathBuf::from("/home/user/.astrid")]
    );
}

#[test]
fn test_sandbox_config_defaults() {
    let config = ProcessSandboxConfig::new("/project");
    assert!(config.allow_network);
    assert!(config.extra_read_paths.is_empty());
    assert!(config.extra_write_paths.is_empty());
    assert!(config.hidden_paths.is_empty());
}

// --- SandboxPolicy tests ---

#[test]
fn policy_parse_accepts_known_values() {
    assert_eq!(
        SandboxPolicy::parse("required"),
        Some(SandboxPolicy::Required)
    );
    assert_eq!(
        SandboxPolicy::parse("Required"),
        Some(SandboxPolicy::Required)
    );
    assert_eq!(SandboxPolicy::parse("OFF"), Some(SandboxPolicy::Off));
    assert_eq!(SandboxPolicy::parse("  off  "), Some(SandboxPolicy::Off));
}

#[test]
fn policy_parse_rejects_unknown_values() {
    assert_eq!(SandboxPolicy::parse(""), None);
    // The pre-#655 "warn and fall through" middle state was removed
    // intentionally — `preferred` is no longer a valid policy.
    assert_eq!(SandboxPolicy::parse("preferred"), None);
    assert_eq!(SandboxPolicy::parse("relaxed"), None);
    assert_eq!(SandboxPolicy::parse("required-ish"), None);
}

#[test]
fn policy_default_is_required() {
    assert_eq!(SandboxPolicy::default(), SandboxPolicy::Required);
}

#[test]
#[allow(unsafe_code)] // env mutation is unsafe in 2024 edition; see SAFETY note below
#[allow(clippy::disallowed_methods)] // remove_var is the point of this env-unset test
fn config_default_policy_is_required_when_env_unset() {
    // The bug from #655: a fresh `ProcessSandboxConfig::new(...)`
    // silently bypassing the sandbox. The constructor reads
    // `ASTRID_SANDBOX_POLICY` from the env, falling back to
    // `Required`. Confirm it lands on `Required` when the env var
    // is unset.
    //
    // SAFETY: `std::env::remove_var` is unsafe in 2024 edition
    // because env mutation isn't thread-safe; this test is racy if
    // another test concurrently sets the same var. None do — the
    // policy-test set is the only consumer.
    unsafe {
        std::env::remove_var("ASTRID_SANDBOX_POLICY");
    }
    let config = ProcessSandboxConfig::new("/project");
    assert_eq!(
        config.policy,
        SandboxPolicy::Required,
        "fresh config with unset env must default to Required — \
             silent unsandboxed launches are the bug from #655"
    );
}

#[test]
fn with_policy_overrides_default() {
    let config = ProcessSandboxConfig::new("/project").with_policy(SandboxPolicy::Off);
    assert_eq!(config.policy, SandboxPolicy::Off);
}

#[test]
fn sandbox_prefix_with_off_policy_returns_none_silently() {
    // `Off` short-circuits and returns None regardless of platform
    // sandbox availability.
    let config = ProcessSandboxConfig::new("/project").with_policy(SandboxPolicy::Off);
    let result = config.sandbox_prefix();
    assert!(matches!(result, Ok(None)));
}

// The Required-vs-Preferred behaviour around real bwrap availability
// is platform-specific and probe-cached, so it's covered by the
// bwrap-targeted tests below rather than reproduced here.

// --- Cross-platform sandbox_prefix() rejection tests ---

#[test]
fn test_sandbox_prefix_rejects_relative_writable_root() {
    let config = ProcessSandboxConfig::new("relative/project");
    assert!(config.sandbox_prefix().is_err());
}

#[test]
fn test_sandbox_prefix_rejects_non_utf8_writable_root() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_bytes: &[u8] = b"/tmp/\xff\xfe/workspace";
    let bad_path = PathBuf::from(OsStr::from_bytes(bad_bytes));
    let config = ProcessSandboxConfig::new(bad_path);
    let result = config.sandbox_prefix();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not valid UTF-8"));
}

#[test]
fn test_sandbox_prefix_rejects_non_utf8_extra_paths() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_bytes: &[u8] = b"/data/\xff\xfe";
    let bad_path = PathBuf::from(OsStr::from_bytes(bad_bytes));

    let config = ProcessSandboxConfig::new("/project").with_extra_read(bad_path.clone());
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_write(bad_path.clone());
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_hidden(bad_path);
    assert!(config.sandbox_prefix().is_err());
}

#[test]
fn test_sandbox_prefix_rejects_double_quote_in_paths() {
    let config = ProcessSandboxConfig::new("/project/evil\"dir");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_read("/data/evil\"path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_write("/output/evil\"path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_hidden("/hidden/evil\"path");
    assert!(config.sandbox_prefix().is_err());
}

#[test]
fn test_sandbox_prefix_rejects_backslash_in_paths() {
    let config = ProcessSandboxConfig::new("/project/evil\\dir");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_read("/data/evil\\path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_write("/output/evil\\path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_hidden("/hidden/evil\\path");
    assert!(config.sandbox_prefix().is_err());
}

#[test]
fn test_sandbox_prefix_rejects_null_byte_in_paths() {
    let config = ProcessSandboxConfig::new("/project/evil\0dir");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_read("/data/evil\0path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_extra_write("/output/evil\0path");
    assert!(config.sandbox_prefix().is_err());

    let config = ProcessSandboxConfig::new("/project").with_hidden("/hidden/evil\0path");
    assert!(config.sandbox_prefix().is_err());
}

// --- #856: sensitive Astrid-home subpaths are masked in every spawn ---

/// The masked set is `keys/`, `secrets/`, `var/` in that order. The exact
/// subset is existence-filtered (see `sensitive_astrid_paths_in`), so this
/// drives a fully-populated `tempdir` home to assert all three are emitted in
/// the documented order rather than depending on the test runner's real home.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sensitive_astrid_paths_are_keys_secrets_var() {
    let tmp = tempfile::tempdir().expect("create temp astrid home");
    let home = astrid_core::dirs::AstridHome::from_path(tmp.path());
    for dir in [home.keys_dir(), home.secrets_dir(), home.var_dir()] {
        std::fs::create_dir_all(&dir).expect("create masked dir");
    }

    let paths = SandboxCommand::sensitive_astrid_paths_in(&home);
    assert_eq!(paths.len(), 3, "exactly keys/, secrets/, var/ are masked");
    assert!(
        paths[0].ends_with("keys"),
        "first masked path is keys/: {:?}",
        paths[0]
    );
    assert!(
        paths[1].ends_with("secrets"),
        "second masked path is secrets/: {:?}",
        paths[1]
    );
    assert!(
        paths[2].ends_with("var"),
        "third masked path is var/: {:?}",
        paths[2]
    );
}

/// Regression for the fresh-install crash: `AstridHome::ensure` does NOT create
/// `secrets/` (it is made lazily on the first secret write), so on a fresh
/// install that dir is absent at spawn time. Passing a non-existent `--tmpfs`
/// target to bwrap under `--ro-bind / /` aborts every sandboxed spawn. The
/// masked set must therefore skip paths that do not exist on disk. Filtering is
/// fail-safe: an absent dir holds no bytes to leak.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sensitive_astrid_paths_skips_missing_dirs() {
    let tmp = tempfile::tempdir().expect("create temp astrid home");
    let home = astrid_core::dirs::AstridHome::from_path(tmp.path());

    // Fresh-install shape: keys/ and var/ exist (created by ensure()), but
    // secrets/ has never been written.
    std::fs::create_dir_all(home.keys_dir()).expect("create keys/");
    std::fs::create_dir_all(home.var_dir()).expect("create var/");
    assert!(
        !home.secrets_dir().exists(),
        "precondition: secrets/ absent"
    );

    let paths = SandboxCommand::sensitive_astrid_paths_in(&home);
    assert_eq!(
        paths.len(),
        2,
        "the absent secrets/ dir is filtered out: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("keys")),
        "keys/ is masked: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("var")),
        "var/ is masked: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.ends_with("secrets")),
        "the non-existent secrets/ is NOT passed to bwrap: {paths:?}"
    );

    // Once secrets/ exists (first secret written), it rejoins the masked set.
    std::fs::create_dir_all(home.secrets_dir()).expect("create secrets/");
    let paths = SandboxCommand::sensitive_astrid_paths_in(&home);
    assert_eq!(paths.len(), 3, "secrets/ rejoins once it exists: {paths:?}");
}

/// The home credential deny-list masks the well-known credential stores that
/// EXIST under the operator's home (issue #856 — a spawned agent must not read
/// `~/.ssh`, cloud creds, GPG keyrings), and never passes a non-existent path to
/// the sandbox (a missing `--tmpfs` mount point would abort the spawn).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sensitive_home_paths_masks_only_existing_credential_dirs() {
    let tmp = tempfile::tempdir().expect("create temp home");
    let home = tmp.path();
    std::fs::create_dir_all(home.join(".ssh")).expect(".ssh");
    std::fs::create_dir_all(home.join(".aws")).expect(".aws");
    std::fs::create_dir_all(home.join(".config/gcloud")).expect("gcloud");
    std::fs::write(home.join(".netrc"), b"machine x").expect(".netrc");
    // `.gnupg` / `.docker` / `.kube` deliberately absent.

    let masked = SandboxCommand::sensitive_home_paths_in(home);

    for present in [".ssh", ".aws", ".netrc", ".config/gcloud"] {
        assert!(
            masked.contains(&home.join(present)),
            "{present} must be masked: {masked:?}"
        );
    }
    for absent in [".gnupg", ".docker", ".kube"] {
        assert!(
            !masked.contains(&home.join(absent)),
            "absent {absent} must NOT be passed to the sandbox: {masked:?}"
        );
    }
}

/// A masked DIRECTORY is shadowed with `--tmpfs`, but a masked regular FILE
/// (e.g. `~/.netrc`) must use a `--ro-bind /dev/null` — `--tmpfs` on a file
/// fails `ENOTDIR` and would abort every spawn (regression guard for the #937
/// review finding).
#[cfg(target_os = "linux")]
#[test]
fn mask_arg_uses_tmpfs_for_dir_and_dev_null_bind_for_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("creddir");
    std::fs::create_dir_all(&dir).expect("create masked dir");
    let file = tmp.path().join("netrc");
    std::fs::write(&file, b"machine x").expect("create masked file");

    let mut cmd = Command::new("bwrap");
    SandboxCommand::push_mask_arg(&mut cmd, &dir);
    SandboxCommand::push_mask_arg(&mut cmd, &file);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    let dir_pos = args
        .iter()
        .position(|a| a == "--tmpfs")
        .expect("a directory is masked with --tmpfs");
    assert_eq!(args[dir_pos + 1], dir.to_string_lossy());

    let bind_pos = args
        .iter()
        .position(|a| a == "--ro-bind")
        .expect("a regular file is masked with --ro-bind /dev/null");
    assert_eq!(args[bind_pos + 1], "/dev/null");
    assert_eq!(args[bind_pos + 2], file.to_string_lossy());
}

/// On Linux the `--ro-bind / /` mount exposes the whole host FS read-only, so
/// each sensitive Astrid subpath must be overlaid with an empty tmpfs. Without
/// this a spawned agent reads `~/.astrid/keys/<principal>.key` and impersonates
/// any principal (issue #856). The masked set is existence-filtered, so this
/// asserts every path the filter actually returns is wired into the bwrap args
/// (rather than hardcoding dirs the test runner's home may not have).
#[cfg(target_os = "linux")]
#[test]
fn linux_spawn_masks_sensitive_astrid_paths_with_tmpfs() {
    let expected = SandboxCommand::sensitive_astrid_paths().expect("resolve astrid home");
    let wrapped = SandboxCommand::wrap(Command::new("echo"), Path::new("/tmp/ws")).expect("wrap");
    let args: Vec<String> = wrapped
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for path in &expected {
        let path_str = path.to_string_lossy();
        let masked = args
            .windows(2)
            .any(|w| w[0] == "--tmpfs" && w[1] == path_str);
        assert!(
            masked,
            "expected `--tmpfs {path_str}` in bwrap args: {args:?}"
        );
    }
}

/// On macOS the seatbelt profile must carry a `deny file-read*` rule for each
/// sensitive Astrid subpath. (Belt-and-suspenders: the profile already
/// default-denies anything outside its allowlist, which excludes `~/.astrid` —
/// but an explicit deny holds even if that allowlist ever widens.) The masked
/// set is existence-filtered, so this asserts every path the filter actually
/// returns appears in the profile (rather than hardcoding dirs the test
/// runner's home may not have).
#[cfg(target_os = "macos")]
#[test]
fn macos_spawn_denies_sensitive_astrid_paths_in_profile() {
    let expected = SandboxCommand::sensitive_astrid_paths().expect("resolve astrid home");
    let wrapped = SandboxCommand::wrap(Command::new("echo"), Path::new("/tmp/ws")).expect("wrap");
    let profile = wrapped
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .find(|a| a.contains("(deny default)"))
        .expect("seatbelt profile present in sandbox-exec args");
    for path in &expected {
        let rule = format!("(subpath \"{}\")", path.to_string_lossy());
        assert!(
            profile.contains(&rule),
            "expected a `(deny file-read* {rule})` rule in the profile"
        );
    }
}
