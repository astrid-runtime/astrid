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
        let result =
            SandboxCommand::wrap_with_injections(Command::new("echo"), Path::new("/tmp/ws"), &inj);
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
    let wrapped = SandboxCommand::wrap_with_injections(cmd, Path::new("/tmp/ws"), &inj).unwrap();
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sensitive_astrid_paths_are_keys_secrets_var() {
    let paths = SandboxCommand::sensitive_astrid_paths().expect("resolve astrid home");
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

/// On Linux the `--ro-bind / /` mount exposes the whole host FS read-only, so
/// each sensitive Astrid subpath must be overlaid with an empty tmpfs. Without
/// this a spawned agent reads `~/.astrid/keys/<principal>.key` and impersonates
/// any principal (issue #856).
#[cfg(target_os = "linux")]
#[test]
fn linux_spawn_masks_sensitive_astrid_paths_with_tmpfs() {
    let wrapped = SandboxCommand::wrap(Command::new("echo"), Path::new("/tmp/ws")).expect("wrap");
    let args: Vec<String> = wrapped
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for tail in ["keys", "secrets", "var"] {
        let suffix = format!("/{tail}");
        let masked = args
            .windows(2)
            .any(|w| w[0] == "--tmpfs" && w[1].ends_with(&suffix));
        assert!(
            masked,
            "expected `--tmpfs <astrid_home>/{tail}` in bwrap args: {args:?}"
        );
    }
}

/// On macOS the seatbelt profile must carry a `deny file-read*` rule for each
/// sensitive Astrid subpath. (Belt-and-suspenders: the profile already
/// default-denies anything outside its allowlist, which excludes `~/.astrid` —
/// but an explicit deny holds even if that allowlist ever widens.)
#[cfg(target_os = "macos")]
#[test]
fn macos_spawn_denies_sensitive_astrid_paths_in_profile() {
    let wrapped = SandboxCommand::wrap(Command::new("echo"), Path::new("/tmp/ws")).expect("wrap");
    let profile = wrapped
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .find(|a| a.contains("(deny default)"))
        .expect("seatbelt profile present in sandbox-exec args");
    for tail in ["keys", "secrets", "var"] {
        assert!(
            profile.contains(&format!("/{tail}\"))")),
            "expected a `(deny file-read* (subpath \"<astrid_home>/{tail}\"))` rule in the profile"
        );
    }
}
