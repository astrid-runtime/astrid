use std::ffi::OsString;
use std::io;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::{
    fs::{File, OpenOptions},
    os::unix::process::CommandExt,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

use super::{ProcessSandboxConfig, SandboxPrefix};

/// Select only package-managed Linux locations. A PATH-selected binary can
/// impersonate a successful probe or omit the sandbox entirely.
const PACKAGED_BWRAP_PATHS: [&str; 3] = [
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/run/current-system/sw/bin/bwrap",
];

/// Find Bubblewrap at an absolute Linux distribution path, never via `PATH`.
#[must_use]
pub fn packaged_bwrap_path() -> Option<&'static str> {
    PACKAGED_BWRAP_PATHS
        .into_iter()
        .find(|path| Path::new(path).is_file())
}

/// A grant needs descriptor binds; older bwrap builds may only support path
/// binds. Detect that before returning a command that cannot launch safely.
pub(super) fn require_bind_fd_support() -> io::Result<()> {
    let path = packaged_bwrap_path().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "packaged Bubblewrap binary not found",
        )
    })?;
    let output = Command::new(path).arg("--help").output()?;
    let help = String::from_utf8_lossy(&output.stdout);
    if output.status.success() && help.contains("--bind-fd ") && help.contains("--ro-bind-fd ") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed bubblewrap lacks --bind-fd/--ro-bind-fd; update bubblewrap before spawning a process with home or shared paths",
        ))
    }
}

/// Open the bind source before checking its identity. A path validated first
/// could be changed to a symlink before bwrap resolves a later `--bind`.
pub(super) fn open_bind_source(path: &Path) -> io::Result<(PathBuf, File)> {
    use std::os::unix::fs::MetadataExt;

    // O_PATH pins the object without performing I/O. O_RDONLY would block on
    // a FIFO with no writer and reject a legitimate write-only grant.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let source = fd_path.read_link()?;
    if !source.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process bind source did not resolve to an absolute path",
        ));
    }
    let opened = file.metadata()?;
    let named = source.metadata()?;
    if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process bind source changed during validation",
        ));
    }
    Ok((super::resolve_sandbox_path(&source)?, file))
}

/// Keep verified bind objects open until bwrap consumes the file descriptors.
/// The command owns this closure, including its descriptors, if spawn is delayed.
#[allow(unsafe_code)]
pub(super) fn inherit_bind_sources(command: &mut Command, files: Vec<Arc<File>>) {
    if files.is_empty() {
        return;
    }
    // SAFETY: the child hook performs only async-signal-safe fcntl calls. The
    // owned descriptors stay alive in this closure until bwrap has started.
    unsafe {
        command.pre_exec(move || {
            for file in &files {
                if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Detects the Linux distro's package manager and returns install instructions
/// for bubblewrap.
fn bwrap_install_hint() -> &'static str {
    // Read /etc/os-release once — if it fails, give a generic hint.
    static HINT: OnceLock<String> = OnceLock::new();
    HINT.get_or_init(|| {
        let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        // ID= line identifies the distro family.
        let id = os_release
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("ID="))
            .unwrap_or("")
            .trim_matches('"');
        let id_like = os_release
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("ID_LIKE="))
            .unwrap_or("")
            .trim_matches('"');

        if id == "ubuntu"
            || id == "debian"
            || id == "pop"
            || id == "linuxmint"
            || id_like.contains("debian")
            || id_like.contains("ubuntu")
        {
            "Install with: sudo apt install bubblewrap".to_string()
        } else if id == "fedora"
            || id == "rhel"
            || id == "centos"
            || id == "rocky"
            || id == "alma"
            || id_like.contains("fedora")
            || id_like.contains("rhel")
        {
            "Install with: sudo dnf install bubblewrap".to_string()
        } else if id == "arch" || id == "manjaro" || id_like.contains("arch") {
            "Install with: sudo pacman -S bubblewrap".to_string()
        } else if id == "alpine" {
            "Install with: sudo apk add bubblewrap".to_string()
        } else if id == "opensuse" || id == "sles" || id_like.contains("suse") {
            "Install with: sudo zypper install bubblewrap".to_string()
        } else if id == "nixos" || id == "nix" {
            "Add bubblewrap to environment.systemPackages or use: nix-env -iA nixpkgs.bubblewrap"
                .to_string()
        } else if id == "void" {
            "Install with: sudo xbps-install bubblewrap".to_string()
        } else {
            "Install the 'bubblewrap' package using your system package manager".to_string()
        }
    })
}

/// Interprets the result of a `bwrap --unshare-user` probe command.
///
/// Returns `true` if the probe succeeded (bwrap can create user namespaces).
/// Logs a warning and returns `false` on failure.
fn interpret_bwrap_probe(result: io::Result<std::process::Output>) -> bool {
    match result {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                exit_code = output.status.code(),
                stderr = %stderr.trim(),
                "bwrap sandbox unavailable: user namespace creation failed. \
                 On Ubuntu 24.04+, this is likely caused by \
                 kernel.apparmor_restrict_unprivileged_userns=1. \
                 Install and load Ubuntu's packaged bwrap-userns-restrict \
                 AppArmor profile, then rerun astrid setup."
            );
            false
        },
        Err(e) => {
            let hint = bwrap_install_hint();
            let msg = if e.kind() == io::ErrorKind::NotFound {
                "bwrap binary not found."
            } else {
                "Failed to execute bwrap probe."
            };
            tracing::warn!(
                error = %e,
                install_hint = %hint,
                "{msg} Native subprocesses require Bubblewrap under the default sandbox policy."
            );
            false
        },
    }
}

/// Probes whether `bwrap` can create user namespaces.
///
/// Ubuntu 24.04+ sets `kernel.apparmor_restrict_unprivileged_userns = 1` by
/// default, which silently blocks `bwrap --unshare-all`. This probe runs
/// `bwrap --unshare-user --ro-bind / / -- /bin/true` once and caches the
/// result for the lifetime of the process so we don't re-probe on every
/// capsule start.
///
/// Returns `true` if bwrap is available and user namespaces work.
pub(super) fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        if unsafe_legacy_astrid_profile() {
            tracing::error!("retired Astrid AppArmor profile is attached; remove its userns grant before running native subprocesses");
            return false;
        }
        let Some(path) = packaged_bwrap_path() else {
            tracing::warn!("packaged Bubblewrap binary not found at a supported system path");
            return false;
        };
        let result = Command::new(path)
            .arg("--unshare-user")
            .arg("--ro-bind")
            .arg("/")
            .arg("/")
            .arg("--")
            .arg("/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output();
        interpret_bwrap_probe(result)
    })
}

/// The old Astrid-wide `userns` grant followed arbitrary exec children. A
/// working bwrap probe cannot certify isolation while this profile is active.
pub(super) fn unsafe_legacy_astrid_profile() -> bool {
    let Ok(current) = std::fs::read_to_string("/proc/self/attr/current") else {
        return false;
    };
    unsafe_legacy_profile_name(current.trim())
}

fn unsafe_legacy_profile_name(current: &str) -> bool {
    ["astrid", "astrid-daemon"].iter().any(|name| {
        current == *name
            || current.starts_with(&format!("{name} "))
            || current.starts_with(&format!("{name}//"))
    })
}

#[cfg(test)]
mod legacy_profile_tests {
    use super::unsafe_legacy_profile_name;

    #[test]
    fn rejects_retired_astrid_attachments_without_rejecting_bwrap() {
        for profile in [
            "astrid (unconfined)",
            "astrid-daemon (unconfined)",
            "astrid//child (enforce)",
        ] {
            assert!(unsafe_legacy_profile_name(profile));
        }
        for profile in ["unconfined", "bwrap (enforce)", "astrid-other (unconfined)"] {
            assert!(!unsafe_legacy_profile_name(profile));
        }
    }
}

impl ProcessSandboxConfig {
    pub(super) fn build_pinned_bwrap_prefix(&self) -> io::Result<SandboxPrefix> {
        let mut pins = Vec::new();
        for path in std::iter::once(&self.writable_root).chain(&self.extra_write_paths) {
            let (resolved, file) = open_bind_source(path)?;
            if let Some(root) = &self.protected_runtime_home {
                let home = astrid_core::dirs::AstridHome::from_path(root);
                super::runtime_media::validate_mcp_grants(&home, [resolved.as_path()])?;
                super::runtime_media::require_private_volume_links(&home)?;
            }
            pins.push((resolved, Arc::new(file)));
        }
        require_bind_fd_support()?;
        Ok(self.build_bwrap_prefix_with_pins(Some(&pins)))
    }

    #[cfg(test)]
    pub(super) fn build_bwrap_prefix(&self) -> SandboxPrefix {
        self.build_bwrap_prefix_with_pins(None)
    }

    fn build_bwrap_prefix_with_pins(&self, pins: Option<&[(PathBuf, Arc<File>)]>) -> SandboxPrefix {
        let mut args: Vec<OsString> = Vec::new();

        // Read-only access to host OS (for binaries like /usr/bin/node)
        args.extend(["--ro-bind", "/", "/"].map(OsString::from));
        // Standard dev + proc mounts
        args.extend(["--dev", "/dev"].map(OsString::from));
        args.extend(["--proc", "/proc"].map(OsString::from));

        // extra_read_paths are not emitted on Linux because `--ro-bind / /`
        // already grants read access to all host paths. Hidden paths override
        // via tmpfs below. On macOS, extra_read_paths are added to the
        // Seatbelt allow-list because the default policy is deny-all.

        // Disposable tmpfs for /tmp
        args.extend(["--tmpfs", "/tmp"].map(OsString::from));

        // Hidden paths: overlay with empty tmpfs.
        // These MUST come before writable bind-mounts below so that
        // bind-mounts can "punch through" the tmpfs overlay. In bwrap,
        // later mounts override earlier ones — if a writable path is inside
        // a hidden path (e.g. ~/.astrid/capsules/foo inside hidden ~/.astrid),
        // the bind-mount must come after the tmpfs to remain visible.
        for path in &self.hidden_paths {
            args.extend([OsString::from("--tmpfs"), path.as_os_str().into()]);
        }

        // Write access to the writable root (after hidden tmpfs so it punches through)
        for (index, path) in std::iter::once(&self.writable_root)
            .chain(&self.extra_write_paths)
            .enumerate()
        {
            if let Some(pins) = pins {
                let (resolved, file) = &pins[index];
                args.extend([
                    OsString::from("--bind-fd"),
                    file.as_raw_fd().to_string().into(),
                    resolved.as_os_str().into(),
                ]);
            } else {
                args.extend([
                    OsString::from("--bind"),
                    path.as_os_str().into(),
                    path.as_os_str().into(),
                ]);
            }
        }

        // Read-only file injections: bind each host-owned verified snapshot at
        // its in-sandbox target. Placed AFTER the writable --bind entries (so a
        // later writable bind can't shadow the ro-bind) and BEFORE
        // --unshare-all (so it sits within the namespace setup). The namespace
        // creates the mount point, so `target` need not exist on the host.
        for inj in &self.ro_injections {
            args.extend([
                OsString::from("--ro-bind"),
                inj.source.as_os_str().into(),
                inj.target.as_os_str().into(),
            ]);
        }

        // Drop all namespaces
        args.push(OsString::from("--unshare-all"));

        // Conditionally re-enable network
        if self.allow_network {
            args.push(OsString::from("--share-net"));
        }

        // Prevent orphan processes
        args.push(OsString::from("--die-with-parent"));

        // Separator before the inner command
        args.push(OsString::from("--"));

        SandboxPrefix {
            program: OsString::from(packaged_bwrap_path().unwrap_or(PACKAGED_BWRAP_PATHS[0])),
            args,
            bind_sources: pins
                .map(|pins| pins.iter().map(|(_, file)| Arc::clone(file)).collect())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bwrap_prefix_basic() {
        let config = ProcessSandboxConfig::new("/project");
        let prefix = config.build_bwrap_prefix();

        assert_eq!(
            prefix.program,
            OsString::from(packaged_bwrap_path().unwrap_or(PACKAGED_BWRAP_PATHS[0]))
        );

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args_str.contains(&"--ro-bind".to_string()));
        assert!(args_str.contains(&"--dev".to_string()));
        assert!(args_str.contains(&"--proc".to_string()));
        assert!(args_str.contains(&"--unshare-all".to_string()));
        assert!(args_str.contains(&"--share-net".to_string()));
        assert!(args_str.contains(&"--die-with-parent".to_string()));
        assert!(args_str.contains(&"--".to_string()));

        let bind_idx = args_str
            .iter()
            .position(|a| a == "--bind")
            .expect("should have --bind");
        assert_eq!(args_str[bind_idx + 1], "/project");
        assert_eq!(args_str[bind_idx + 2], "/project");
    }

    #[test]
    fn test_bwrap_prefix_no_network() {
        let config = ProcessSandboxConfig::new("/project").with_network(false);
        let prefix = config.build_bwrap_prefix();

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args_str.contains(&"--unshare-all".to_string()));
        assert!(!args_str.contains(&"--share-net".to_string()));
    }

    #[test]
    fn test_bwrap_prefix_hidden_paths() {
        let config = ProcessSandboxConfig::new("/project").with_hidden("/home/user/.astrid");
        let prefix = config.build_bwrap_prefix();

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        let tmpfs_positions: Vec<usize> = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--tmpfs")
            .map(|(i, _)| i)
            .collect();

        assert!(
            tmpfs_positions.len() >= 2,
            "should have at least 2 tmpfs mounts"
        );
        let hidden_tmpfs_found = tmpfs_positions
            .iter()
            .any(|&i| args_str.get(i + 1) == Some(&"/home/user/.astrid".to_string()));
        assert!(hidden_tmpfs_found, "should have tmpfs for hidden path");
    }

    /// Regression test for #648: when the writable root is inside a hidden
    /// path (e.g. ~/.astrid/capsules/foo hidden by ~/.astrid tmpfs), the
    /// writable --bind must come AFTER the hidden --tmpfs so it punches
    /// through.
    #[test]
    fn test_bwrap_prefix_writable_inside_hidden_path() {
        let config = ProcessSandboxConfig::new("/home/user/.astrid/capsules/bridge-unicity")
            .with_hidden("/home/user/.astrid");
        let prefix = config.build_bwrap_prefix();

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        let hidden_tmpfs_pos = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--tmpfs")
            .find(|(i, _)| args_str.get(i + 1) == Some(&"/home/user/.astrid".to_string()))
            .map(|(i, _)| i)
            .expect("should have --tmpfs for hidden path");

        let writable_bind_pos = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--bind")
            .find(|(i, _)| {
                args_str.get(i + 1)
                    == Some(&"/home/user/.astrid/capsules/bridge-unicity".to_string())
            })
            .map(|(i, _)| i)
            .expect("should have --bind for writable root");

        assert!(
            writable_bind_pos > hidden_tmpfs_pos,
            "writable --bind (pos {writable_bind_pos}) must come after \
             hidden --tmpfs (pos {hidden_tmpfs_pos}) so capsule dir \
             punches through the tmpfs overlay"
        );
    }

    #[test]
    fn test_bwrap_prefix_ro_inject_position() {
        // The injection --ro-bind must appear AFTER the writable --bind and
        // BEFORE --unshare-all so a later bind cannot shadow it and it sits
        // inside the namespace setup.
        let config = ProcessSandboxConfig::new("/project").with_ro_inject("/host/snap", "/etc/x");
        let prefix = config.build_bwrap_prefix();

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        let writable_bind_pos = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--bind")
            .find(|(i, _)| args_str.get(i + 1) == Some(&"/project".to_string()))
            .map(|(i, _)| i)
            .expect("should have writable --bind for /project");

        let ro_inject_pos = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--ro-bind")
            .find(|(i, _)| args_str.get(i + 1) == Some(&"/host/snap".to_string()))
            .map(|(i, _)| i)
            .expect("should have --ro-bind for the injection snapshot");

        let unshare_pos = args_str
            .iter()
            .position(|a| a == "--unshare-all")
            .expect("should have --unshare-all");

        assert_eq!(args_str[ro_inject_pos + 1], "/host/snap", "ro-bind source");
        assert_eq!(args_str[ro_inject_pos + 2], "/etc/x", "ro-bind target");
        assert!(
            ro_inject_pos > writable_bind_pos,
            "injection --ro-bind (pos {ro_inject_pos}) must come after the \
             writable --bind (pos {writable_bind_pos})"
        );
        assert!(
            ro_inject_pos < unshare_pos,
            "injection --ro-bind (pos {ro_inject_pos}) must come before \
             --unshare-all (pos {unshare_pos})"
        );
    }

    #[test]
    fn test_bwrap_prefix_extra_paths() {
        let config = ProcessSandboxConfig::new("/project")
            .with_extra_read("/data")
            .with_extra_write("/output");
        let prefix = config.build_bwrap_prefix();

        let args_str: Vec<String> = prefix
            .args
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        let bind_positions: Vec<usize> = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--bind")
            .map(|(i, _)| i)
            .collect();
        let has_output_bind = bind_positions
            .iter()
            .any(|&i| args_str.get(i + 1) == Some(&"/output".to_string()));
        assert!(has_output_bind, "should have --bind for extra write path");

        // extra_read_paths are NOT emitted as --ro-bind on Linux because
        // `--ro-bind / /` already covers all host paths.
        let ro_positions: Vec<usize> = args_str
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--ro-bind")
            .map(|(i, _)| i)
            .collect();
        let has_data_explicit = ro_positions
            .iter()
            .any(|&i| args_str.get(i + 1) == Some(&"/data".to_string()));
        assert!(
            !has_data_explicit,
            "extra_read_paths should NOT produce --ro-bind on Linux (covered by --ro-bind / /)"
        );
    }

    // --- bwrap probe interpretation tests ---

    fn mock_output(code: i32, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn test_bwrap_probe_success() {
        assert!(interpret_bwrap_probe(Ok(mock_output(0, ""))));
    }

    #[test]
    fn test_bwrap_probe_namespace_denied() {
        let result = Ok(mock_output(
            1,
            "bwrap: setting up uid map: Permission denied\n",
        ));
        assert!(!interpret_bwrap_probe(result));
    }

    #[test]
    fn test_bwrap_probe_not_found() {
        let result: io::Result<std::process::Output> = Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No such file or directory",
        ));
        assert!(!interpret_bwrap_probe(result));
    }

    #[test]
    fn test_bwrap_install_hint_returns_nonempty() {
        let hint = bwrap_install_hint();
        assert!(!hint.is_empty(), "install hint should never be empty");
        assert!(
            hint.contains("bubblewrap"),
            "install hint should mention 'bubblewrap': {hint}"
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn bind_source_opath_pins_fifo_without_waiting_for_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;

        let temp = tempfile::tempdir().expect("temporary bind source");
        let fifo = temp.path().join("grant-fifo");
        let name = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO name");
        // SAFETY: name is a NUL-terminated owned path inside the temp dir.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (resolved, pin) = open_bind_source(&fifo).expect("O_PATH must not block on FIFO");
        assert_eq!(resolved, fifo);
        assert!(
            pin.metadata()
                .expect("pinned metadata")
                .file_type()
                .is_fifo()
        );
    }
}
