//! Diagnose the native-process sandbox in the CLI and daemon contexts.
//!
//! Ubuntu's `AppArmor` restriction requires a policy for the sandbox launcher.
//! Granting `userns` to Astrid itself would also grant it to arbitrary children.

use std::fs::OpenOptions;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use anyhow::Result;
use clap::Args;
use colored::Colorize;

const UBUNTU_BWRAP_PROFILE: &str = "/usr/share/apparmor/extra-profiles/bwrap-userns-restrict";

#[derive(Args, Debug, Clone)]
#[allow(clippy::struct_excessive_bools, reason = "independent CLI flags")]
pub(crate) struct SetupArgs {
    /// Probe the CLI executable's actual Linux sandbox context.
    #[arg(long, hide = true)]
    pub probe_sandbox_context: bool,
    /// Retired: Astrid-wide `AppArmor` grants are unsafe.
    #[arg(long, hide = true)]
    pub install_apparmor_root: bool,
    /// Retired: use a protected Bubblewrap profile instead.
    #[arg(long, hide = true)]
    pub print_apparmor: bool,
    /// Retired: use a protected Bubblewrap profile instead.
    #[arg(long, hide = true)]
    pub print_apparmor_current: bool,
    /// Show operator instructions if the sandbox probe fails.
    #[arg(long)]
    pub apply: bool,
}

pub(crate) fn run(args: &SetupArgs) -> Result<ExitCode> {
    if args.probe_sandbox_context {
        return Ok(
            if astrid_workspace::sandbox::probe_native_process_sandbox() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            },
        );
    }
    if args.install_apparmor_root || args.print_apparmor || args.print_apparmor_current {
        anyhow::bail!(
            "Astrid-wide AppArmor userns profiles are unsafe; use a protected Bubblewrap profile and rerun `astrid setup`"
        );
    }

    println!("{}\n", "Astrid host setup".bold());
    let report = diagnose();
    Ok(run_report(args, &report))
}

fn run_report(args: &SetupArgs, report: &Report) -> ExitCode {
    report.print();
    if report.ready() {
        if report.os == "linux" {
            println!(
                "\n{}",
                "All checks pass for this user and environment.".green()
            );
        } else {
            println!("\n{}", "All checks pass. No host setup required.".green());
        }
        return ExitCode::SUCCESS;
    }
    if report.os == "linux" {
        if !report.fuse_helper_available || !report.fuse_device_accessible {
            println!();
            for line in fuse_guidance(report) {
                println!("{line}");
            }
        }
        if !report.bwrap_installed || !report.bwrap_bind_fd_supported {
            println!(
                "\nInstall or update Bubblewrap. On Ubuntu: `sudo apt-get install bubblewrap`."
            );
        }
        if report.apparmor_restriction_active && !report.bwrap_probe_passed {
            println!("\nAppArmor is restricting unprivileged user namespaces.");
            println!(
                "If an old Astrid-wide AppArmor userns profile is attached, have an administrator remove it and restart the daemon."
            );
            if Path::new(UBUNTU_BWRAP_PROFILE).is_file() || ubuntu_family() {
                if Path::new(UBUNTU_BWRAP_PROFILE).is_file() {
                    println!(
                        "Ubuntu supplies a Bubblewrap-specific profile at {UBUNTU_BWRAP_PROFILE}."
                    );
                } else {
                    println!(
                        "On Ubuntu, `sudo apt-get install apparmor-profiles` supplies a Bubblewrap-specific profile."
                    );
                }
                println!("Ask an administrator to review the distro profile and load it:");
                for line in ubuntu_profile_commands() {
                    println!("  {line}");
                }
            } else {
                println!(
                    "Ask an administrator for this distribution's protected Bubblewrap user-namespace policy; do not grant userns to Astrid."
                );
            }
            println!(
                "This grants user namespaces to Bubblewrap, not Astrid or arbitrary child programs."
            );
        }
        if args.apply {
            println!(
                "\n`--apply` no longer installs an Astrid-wide policy; use the reviewed administrator commands above."
            );
        }
    }
    ExitCode::FAILURE
}

fn ubuntu_profile_commands() -> [&'static str; 4] {
    [
        "sudo apt-get install bubblewrap apparmor-profiles",
        "sudo install -m 0644 /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/bwrap-userns-restrict",
        "sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict",
        "astrid setup",
    ]
}

fn ubuntu_family() -> bool {
    let Ok(release) = std::fs::read_to_string("/etc/os-release") else {
        return false;
    };
    ubuntu_family_release(&release)
}

fn ubuntu_family_release(release: &str) -> bool {
    release.lines().any(|line| {
        line.strip_prefix("ID=")
            .is_some_and(|id| id.trim_matches('"') == "ubuntu")
            || line.strip_prefix("ID_LIKE=").is_some_and(|ids| {
                ids.trim_matches('"')
                    .split_whitespace()
                    .any(|id| id == "ubuntu")
            })
    })
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "one result per independent probe"
)]
struct Report {
    os: &'static str,
    bwrap_installed: bool,
    bwrap_probe_passed: bool,
    bwrap_bind_fd_supported: bool,
    fuse_helper_available: bool,
    fuse_device_accessible: bool,
    apparmor_restriction_active: bool,
}

impl Report {
    fn ready(&self) -> bool {
        self.os != "linux"
            || (self.bwrap_installed
                && self.bwrap_probe_passed
                && self.bwrap_bind_fd_supported
                && self.fuse_helper_available
                && self.fuse_device_accessible)
    }

    fn print(&self) {
        println!("  OS:                                {}", self.os);
        if self.os != "linux" {
            println!("  Linux-specific sandbox checks skipped (macOS uses Seatbelt).");
            return;
        }
        check_line("bwrap binary installed", self.bwrap_installed);
        check_line(
            "bwrap descriptor-bind support",
            self.bwrap_bind_fd_supported,
        );
        check_line("CLI and daemon sandbox probes", self.bwrap_probe_passed);
        check_line("FUSE mount helper executable", self.fuse_helper_available);
        check_line("/dev/fuse read/write access", self.fuse_device_accessible);
        println!(
            "  AppArmor userns restriction:      {}",
            if self.apparmor_restriction_active {
                "active"
            } else {
                "inactive or unavailable"
            }
        );
        if self.apparmor_restriction_active && self.bwrap_probe_passed {
            println!("  Bubblewrap policy:                 effective in both execution contexts");
        }
    }
}

fn check_line(label: &str, ok: bool) {
    let marker = if ok { "✓".green() } else { "✗".red() };
    println!("  {marker} {label}");
}

fn fuse_guidance(report: &Report) -> Vec<&'static str> {
    let mut lines = vec!["Native tools need a FUSE helper and /dev/fuse access."];
    if !report.fuse_helper_available {
        lines.push("Install a FUSE helper: Debian/Ubuntu `sudo apt-get install fuse3`; Alpine `sudo apk add fuse3`.");
    }
    if !report.fuse_device_accessible {
        lines.push("Ask an administrator to inspect `ls -l /dev/fuse` and grant this user read/write access through the host's device policy.");
        lines.push("If /dev/fuse is absent, load the FUSE kernel module (`sudo modprobe fuse`); in a container, expose /dev/fuse and allow FUSE mounts in its policy.");
    }
    lines.push("Rerun `astrid setup` as the AOS user after the host is repaired.");
    lines
}

fn diagnose() -> Report {
    let os = std::env::consts::OS;
    let bwrap_installed = astrid_workspace::sandbox::packaged_bwrap_path().is_some();
    Report {
        os,
        bwrap_installed,
        bwrap_probe_passed: bwrap_installed && bwrap_probe_succeeds(),
        bwrap_bind_fd_supported: bwrap_installed && bwrap_bind_fd_supported(),
        fuse_helper_available: os == "linux" && fuse_helper_available(),
        fuse_device_accessible: os == "linux" && fuse_device_accessible(),
        apparmor_restriction_active: read_apparmor_sysctl() == Some(1),
    }
}

fn fuse_helper_available() -> bool {
    // Ordinary-user native tools require a helper even if this process could
    // mount directly with elevated privilege. Match fuser 0.18's Linux
    // fusermount candidates, including its explicit override.
    if let Some(path) = std::env::var_os("FUSERMOUNT_PATH") {
        if path.to_str().is_none() {
            return false;
        }
        return helper_spawns(&path);
    }
    [
        "fusermount3",
        "fusermount",
        "/sbin/fusermount3",
        "/sbin/fusermount",
        "/bin/fusermount3",
        "/bin/fusermount",
    ]
    .iter()
    .any(helper_spawns)
}

fn helper_spawns(path: impl AsRef<std::ffi::OsStr>) -> bool {
    Command::new(path)
        .arg("-h")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn fuse_device_accessible() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
        .is_ok()
}

fn bwrap_probe_succeeds() -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    if !probe_cli_sandbox(&executable) {
        return false;
    }
    let Ok(daemon) = crate::bootstrap::find_companion_binary("astrid-daemon") else {
        return false;
    };
    probe_daemon_sandbox(&daemon)
}

fn probe_cli_sandbox(executable: &Path) -> bool {
    Command::new(executable)
        .args(["setup", "--probe-sandbox-context"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn probe_daemon_sandbox(daemon: &Path) -> bool {
    Command::new(daemon)
        .arg("--setup-sandbox-probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn bwrap_bind_fd_supported() -> bool {
    let Some(path) = astrid_workspace::sandbox::packaged_bwrap_path() else {
        return false;
    };
    Command::new(path)
        .arg("--help")
        .output()
        .is_ok_and(|output| output.status.success() && has_bind_fd_flags(&output.stdout))
}

fn has_bind_fd_flags(help: &[u8]) -> bool {
    let help = String::from_utf8_lossy(help);
    ["--bind-fd ", "--ro-bind-fd "]
        .iter()
        .all(|flag| help.lines().any(|line| line.trim_start().starts_with(flag)))
}

fn read_apparmor_sysctl() -> Option<u8> {
    let raw =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok()?;
    raw.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_requires_both_descriptor_bind_flags() {
        assert!(has_bind_fd_flags(
            b"    --bind-fd FD DEST\n    --ro-bind-fd FD DEST\n"
        ));
        assert!(!has_bind_fd_flags(b"    --bind-fd FD DEST\n"));
    }

    #[test]
    fn active_apparmor_is_not_a_failure_when_real_probes_pass() {
        let mut report = Report {
            os: "linux",
            bwrap_installed: true,
            bwrap_probe_passed: true,
            bwrap_bind_fd_supported: true,
            fuse_helper_available: true,
            fuse_device_accessible: true,
            apparmor_restriction_active: true,
        };
        assert!(report.ready());
        report.bwrap_probe_passed = false;
        assert!(!report.ready());
    }

    #[test]
    fn linux_fuse_prerequisites_gate_setup_exit() {
        let args = SetupArgs {
            probe_sandbox_context: false,
            install_apparmor_root: false,
            print_apparmor: false,
            print_apparmor_current: false,
            apply: false,
        };
        let mut report = Report {
            os: "linux",
            bwrap_installed: true,
            bwrap_probe_passed: true,
            bwrap_bind_fd_supported: true,
            fuse_helper_available: false,
            fuse_device_accessible: true,
            apparmor_restriction_active: false,
        };
        assert_eq!(run_report(&args, &report), ExitCode::FAILURE);
        report.fuse_helper_available = true;
        assert_eq!(run_report(&args, &report), ExitCode::SUCCESS);
        report.fuse_device_accessible = false;
        assert_eq!(run_report(&args, &report), ExitCode::FAILURE);
        let device_guidance = fuse_guidance(&report).join("\n");
        assert!(device_guidance.contains("grant this user read/write access"));
        assert!(device_guidance.contains("expose /dev/fuse"));
        assert!(!device_guidance.contains("apt-get install fuse3"));
        report.os = "macos";
        assert_eq!(run_report(&args, &report), ExitCode::SUCCESS);
    }

    #[test]
    fn setup_does_not_offer_an_astrid_wide_profile() {
        let commands = ubuntu_profile_commands().join("\n");
        assert!(commands.contains("bwrap-userns-restrict"));
        assert!(!commands.contains("/etc/apparmor.d/astrid"));
        assert!(!commands.contains("apparmor_restrict_unprivileged_userns=0"));
    }

    #[test]
    fn ubuntu_recipe_is_only_for_ubuntu_family() {
        assert!(ubuntu_family_release("ID=ubuntu\n"));
        assert!(ubuntu_family_release("ID=\"ubuntu\"\n"));
        assert!(ubuntu_family_release("ID=pop\nID_LIKE=\"ubuntu debian\"\n"));
        assert!(!ubuntu_family_release("ID=debian\nID_LIKE=debian\n"));
    }

    #[cfg(unix)]
    #[test]
    fn failed_daemon_probe_cannot_claim_setup_readiness() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let daemon = directory.path().join("astrid-daemon");
        std::fs::write(&daemon, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!probe_daemon_sandbox(&daemon));
        std::fs::write(&daemon, "#!/bin/sh\n[ \"$1\" = '--setup-sandbox-probe' ]\n").unwrap();
        assert!(probe_daemon_sandbox(&daemon));
    }
}
