use std::ffi::OsString;
use std::io;

use super::{ProcessSandboxConfig, SandboxPrefix, validate_sandbox_str};

impl ProcessSandboxConfig {
    pub(super) fn build_seatbelt_prefix(&self) -> io::Result<SandboxPrefix> {
        let writable_root_str = validate_sandbox_str(&self.writable_root, "writable root")?;

        // Build the network rule conditionally
        let network_rule = if self.allow_network {
            "(allow network*)"
        } else {
            ""
        };

        // Build extra read path rules
        let extra_read_rules: String = self
            .extra_read_paths
            .iter()
            .map(|p| {
                validate_sandbox_str(p, "extra read path").map(|s| format!("    (subpath \"{s}\")"))
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("\n");

        // Build extra write path rules
        let extra_write_rules: String = self
            .extra_write_paths
            .iter()
            .map(|p| {
                validate_sandbox_str(p, "extra write path")
                    .map(|s| format!("    (subpath \"{s}\")"))
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("\n");

        // Read-only file injections: allow reading the materialized literal
        // (it lives AT `target` on macOS, there being no mount namespace), and
        // append a trailing write-deny below so the child cannot modify it.
        let inject_read_rules: String = self
            .ro_injections
            .iter()
            .map(|inj| {
                validate_sandbox_str(&inj.target, "injection target")
                    .map(|s| format!("    (literal \"{s}\")"))
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("\n");

        // Trailing write-deny on each injection target. Emitted AFTER
        // `hidden_deny_rules` so it is the last match — in SBPL the last
        // matching rule wins, so this denies the write even if an
        // allow-write subpath above (e.g. the writable root) covers `target`.
        let inject_deny_rules: String = self
            .ro_injections
            .iter()
            .map(|inj| {
                validate_sandbox_str(&inj.target, "injection target")
                    .map(|s| format!("(deny file-write* (literal \"{s}\"))"))
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("\n");

        // Build deny rules for hidden paths (e.g. ~/.astrid/).
        // Skip any hidden path that is an ancestor of or equal to the
        // writable_root — the capsule must be able to access its own
        // directory, and Seatbelt deny rules block even lstat() on parent
        // paths which prevents Node.js from resolving real paths.
        let hidden_deny_rules: String = self
            .hidden_paths
            .iter()
            .filter(|p| !self.writable_root.starts_with(p.as_path()))
            .map(|p| {
                validate_sandbox_str(p, "hidden path").map(|s| {
                    format!(
                        "(deny file-read* (subpath \"{s}\"))\n\
                         (deny file-write* (subpath \"{s}\"))"
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?
            .join("\n");

        let profile = format!(
            r#"(version 1)
(deny default)
(allow process-exec*)
(allow process-fork)
{network_rule}
(allow sysctl-read)
(allow ipc-posix-shm)
(allow mach*)
(allow file-read*
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/System")
    (subpath "/Library")
    (subpath "/opt")
    (subpath "/dev")
    (subpath "{writable_root_str}")
    (subpath "/private/tmp")
    (subpath "/var/folders")
    (literal "/")
{extra_read_rules}
{inject_read_rules}
)
(allow file-write*
    (subpath "{writable_root_str}")
    (subpath "/private/tmp")
    (subpath "/var/folders")
    (literal "/dev/null")
{extra_write_rules}
)
{hidden_deny_rules}
{inject_deny_rules}"#
        );

        // Pass profile inline via -p to avoid temp file leak.
        let args = vec![OsString::from("-p"), OsString::from(&profile)];

        Ok(SandboxPrefix {
            program: OsString::from("sandbox-exec"),
            args,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seatbelt_prefix_basic() {
        let config = ProcessSandboxConfig::new("/project");
        let prefix = config.build_seatbelt_prefix().unwrap();

        assert_eq!(prefix.program, OsString::from("sandbox-exec"));
        assert_eq!(prefix.args[0], OsString::from("-p"));

        let profile = prefix.args[1].to_string_lossy().to_string();

        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow network*)"));
        assert!(profile.contains(r#"(subpath "/project")"#));
        assert!(profile.contains("(allow process-exec*)"));
    }

    #[test]
    fn test_seatbelt_prefix_no_network() {
        let config = ProcessSandboxConfig::new("/project").with_network(false);
        let prefix = config.build_seatbelt_prefix().unwrap();

        let profile = prefix.args[1].to_string_lossy().to_string();
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn test_seatbelt_prefix_extra_paths() {
        let config = ProcessSandboxConfig::new("/project")
            .with_extra_read("/data")
            .with_extra_write("/output");
        let prefix = config.build_seatbelt_prefix().unwrap();

        let profile = prefix.args[1].to_string_lossy().to_string();
        assert!(profile.contains(r#"(subpath "/data")"#));
        assert!(profile.contains(r#"(subpath "/output")"#));
    }

    #[test]
    fn test_seatbelt_prefix_hidden_paths() {
        let config = ProcessSandboxConfig::new("/project").with_hidden("/Users/testuser/.astrid");
        let prefix = config.build_seatbelt_prefix().unwrap();

        let profile = prefix.args[1].to_string_lossy().to_string();
        assert!(
            profile.contains(r#"(deny file-read* (subpath "/Users/testuser/.astrid"))"#),
            "should deny file-read for hidden path"
        );
        assert!(
            profile.contains(r#"(deny file-write* (subpath "/Users/testuser/.astrid"))"#),
            "should deny file-write for hidden path"
        );
    }

    #[test]
    fn test_seatbelt_prefix_ro_inject() {
        // The injection target must be read-allowed and write-denied, and the
        // trailing write-deny must appear AFTER the allow-write block so the
        // last-match-wins SBPL semantics keep the file unmodifiable even
        // though the writable root's allow-write covers it.
        let config = ProcessSandboxConfig::new("/project")
            .with_ro_inject("/snap/policy.json", "/etc/agent/policy.json");
        let prefix = config.build_seatbelt_prefix().unwrap();
        let profile = prefix.args[1].to_string_lossy().to_string();

        assert!(
            profile.contains(r#"(literal "/etc/agent/policy.json")"#),
            "profile must read-allow the injection target literal"
        );
        let deny = r#"(deny file-write* (literal "/etc/agent/policy.json"))"#;
        assert!(
            profile.contains(deny),
            "profile must write-deny the injection target literal"
        );

        let allow_write_pos = profile
            .find("(allow file-write*")
            .expect("profile should have an allow file-write* block");
        let deny_pos = profile
            .find(deny)
            .expect("profile should have the injection write-deny");
        assert!(
            deny_pos > allow_write_pos,
            "the injection write-deny (offset {deny_pos}) must appear after \
             the allow-write block (offset {allow_write_pos}) so last-match-wins"
        );
    }

    /// Regression test for the macOS side of #648: when the writable root is
    /// inside a hidden path, the deny rule for that path must be skipped so
    /// the capsule directory remains accessible.
    #[test]
    fn test_seatbelt_prefix_writable_inside_hidden_path() {
        let config = ProcessSandboxConfig::new("/Users/testuser/.astrid/capsules/bridge-unicity")
            .with_hidden("/Users/testuser/.astrid");
        let prefix = config.build_seatbelt_prefix().unwrap();

        let profile = prefix.args[1].to_string_lossy().to_string();
        assert!(
            !profile.contains(r#"(deny file-read* (subpath "/Users/testuser/.astrid"))"#),
            "should NOT deny file-read for hidden path that is ancestor of writable root"
        );
        assert!(
            !profile.contains(r#"(deny file-write* (subpath "/Users/testuser/.astrid"))"#),
            "should NOT deny file-write for hidden path that is ancestor of writable root"
        );
    }

    /// Locate a `node` binary for the enforcement test, or `None` to skip.
    #[cfg(target_os = "macos")]
    fn which_node() -> Option<std::path::PathBuf> {
        let out = std::process::Command::new("/usr/bin/which")
            .arg("node")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let path = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (!path.is_empty()).then(|| std::path::PathBuf::from(path))
    }

    /// Probe whether `sandbox-exec` can actually apply a profile here. Returns
    /// false inside a nested sandbox (CI, or an outer `sandbox-exec`) where
    /// `sandbox_apply` is denied, so the enforcement test skips rather than
    /// reporting a false failure for an environment constraint.
    #[cfg(target_os = "macos")]
    fn sandbox_exec_can_apply() -> bool {
        std::process::Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// End-to-end Seatbelt enforcement (#855 regression). The generated
    /// profile must let a real dynamically-linked binary (`node`) start, and
    /// the *same* profile with the root-read rule stripped must fail closed —
    /// the SIGABRT that the removed macOS-15+ version guard used to mask. This
    /// proves both that `sandbox-exec` still enforces on current macOS and that
    /// `(literal "/")` is the load-bearing rule. Skipped when `node` is absent
    /// so it never fails a host that simply lacks node; macOS-only.
    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_root_read_is_load_bearing_for_real_binary() {
        if !sandbox_exec_can_apply() {
            eprintln!(
                "sandbox-exec cannot apply a profile in this environment \
                 (nested sandbox?); skipping Seatbelt enforcement test"
            );
            return;
        }
        let Some(node) = which_node() else {
            eprintln!("node not found on PATH; skipping Seatbelt enforcement test");
            return;
        };

        let prefix = ProcessSandboxConfig::new("/tmp")
            .build_seatbelt_prefix()
            .unwrap();
        let profile = prefix.args[1].to_string_lossy().to_string();
        assert!(
            profile.contains(r#"(literal "/")"#),
            "the shared profile must carry the root-read rule"
        );

        // T1: under the real profile, node starts and runs to completion.
        let status = std::process::Command::new(&prefix.program)
            .args(&prefix.args)
            .arg(&node)
            .args(["-e", "process.stdout.write(\"ran\")"])
            .status()
            .expect("spawn sandbox-exec");
        assert!(
            status.success(),
            "node must run under the shared Seatbelt profile (got {status:?})"
        );

        // T3 contrast: strip the root-read rule and the same binary fails
        // closed instead of launching unsandboxed. `(literal "/")` is not a
        // substring of `(literal "/dev/null")`, so only the root rule is
        // removed.
        let broken = profile.replace(r#"(literal "/")"#, "");
        let status = std::process::Command::new("sandbox-exec")
            .args(["-p", &broken])
            .arg(&node)
            .args(["-e", "process.stdout.write(\"ran\")"])
            .status()
            .expect("spawn sandbox-exec");
        assert!(
            !status.success(),
            "without (literal \"/\") the profile must fail closed — node should \
             abort, not run (got {status:?})"
        );
    }
}
