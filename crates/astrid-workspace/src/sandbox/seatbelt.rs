use std::ffi::OsString;
use std::io;

use super::{ProcessSandboxConfig, SandboxPrefix, validate_sandbox_str};

/// Returns the Darwin kernel major version (e.g. 25 for macOS 15 Sequoia).
/// Used to detect macOS 15+ where `sandbox-exec` is deprecated.
pub(super) fn darwin_major_version() -> u32 {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split('.').next()?.parse().ok())
        .unwrap_or(0)
}

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
)
(allow file-write*
    (subpath "{writable_root_str}")
    (subpath "/private/tmp")
    (subpath "/var/folders")
    (literal "/dev/null")
{extra_write_rules}
)
{hidden_deny_rules}"#
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
}
