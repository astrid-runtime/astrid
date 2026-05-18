//! `astrid setup` — privileged one-time host configuration.
//!
//! Detects the OS-level sandbox prerequisites Astrid needs (the only
//! non-trivial one today: Linux unprivileged user namespaces, which
//! Ubuntu 23.10+ blocks by default — see issue #655) and prints the
//! exact commands the operator should run via `sudo` to satisfy them.
//!
//! The subcommand deliberately does **not** auto-elevate. Installing
//! an `AppArmor` profile is a privileged, host-wide change; we make it
//! easy to do, but never surprising. The operator either copy-pastes
//! the printed commands or runs `astrid setup --apply`, which re-execs
//! itself via `sudo` after confirming.

use std::process::{Command, ExitCode};

use anyhow::Result;
use clap::Args;
use colored::Colorize;

/// The packaged `AppArmor` profile, bundled into the binary at build
/// time so `astrid setup` can write a path-correct copy to /tmp for
/// the operator to install.
const APPARMOR_PROFILE_TEMPLATE: &str = include_str!("../../../../dist/apparmor/astrid");

#[derive(Args, Debug, Clone)]
pub(crate) struct SetupArgs {
    /// Print the `AppArmor` profile to stdout and exit (skip detection).
    /// Useful for distro packagers who want the profile content for
    /// inclusion in a .deb / .rpm / etc.
    #[arg(long)]
    pub print_apparmor: bool,

    /// Actually run the privileged install steps via `sudo`. Without
    /// this flag, the subcommand prints the commands it would run and
    /// exits — operators stay in control of when privilege escalation
    /// happens.
    #[arg(long)]
    pub apply: bool,
}

pub(crate) fn run(args: &SetupArgs) -> Result<ExitCode> {
    if args.print_apparmor {
        println!("{APPARMOR_PROFILE_TEMPLATE}");
        return Ok(ExitCode::SUCCESS);
    }

    println!("{}", "Astrid host setup".bold());
    println!();

    let report = diagnose();
    report.print();

    if !report.needs_apparmor_profile {
        println!();
        println!("{}", "All checks pass. No host setup required.".green());
        return Ok(ExitCode::SUCCESS);
    }

    println!();
    println!("{}", "Recommended commands:".bold());
    let cmds = install_commands();
    for line in &cmds {
        println!("  {line}");
    }

    if !args.apply {
        println!();
        println!("Run `astrid setup --apply` to execute these via sudo,");
        println!("or copy/paste them yourself.");
        return Ok(ExitCode::SUCCESS);
    }

    println!();
    println!("{}", "Applying via sudo...".bold());
    apply_install(&cmds)
}

// ── Diagnosis ──────────────────────────────────────────────────────

#[allow(
    clippy::struct_excessive_bools,
    reason = "report struct — one bool per probe is the clearest shape"
)]
struct Report {
    os: &'static str,
    bwrap_installed: bool,
    bwrap_probe_passed: bool,
    apparmor_restriction_active: bool,
    apparmor_profile_loaded: bool,
    needs_apparmor_profile: bool,
}

impl Report {
    fn print(&self) {
        println!("  OS:                                {}", self.os);
        if self.os != "linux" {
            println!(
                "  {}",
                "Linux-specific sandbox checks skipped (macOS uses Seatbelt).".dimmed()
            );
            return;
        }
        check_line(
            "bwrap binary installed",
            self.bwrap_installed,
            if self.bwrap_installed {
                "found"
            } else {
                "missing — install the `bubblewrap` package"
            },
        );
        check_line(
            "bwrap user-namespace probe",
            self.bwrap_probe_passed,
            if self.bwrap_probe_passed {
                "passes"
            } else if !self.bwrap_installed {
                "skipped (bwrap missing)"
            } else {
                "FAILS — sandbox cannot be applied"
            },
        );
        check_line(
            "AppArmor restriction on unprivileged userns",
            !self.apparmor_restriction_active,
            if self.apparmor_restriction_active {
                "active (sysctl=1) — Astrid needs an AppArmor profile"
            } else {
                "inactive (sysctl=0 or AppArmor not present)"
            },
        );
        check_line(
            "Astrid AppArmor profile loaded",
            self.apparmor_profile_loaded || !self.apparmor_restriction_active,
            if self.apparmor_profile_loaded {
                "loaded"
            } else if self.apparmor_restriction_active {
                "missing — needs install"
            } else {
                "not required (restriction inactive)"
            },
        );
    }
}

fn check_line(label: &str, ok: bool, detail: &str) {
    let marker = if ok { "✓".green() } else { "✗".red() };
    println!("  {marker} {label:<48} {detail}");
}

fn diagnose() -> Report {
    let os = std::env::consts::OS;
    let bwrap_installed = which("bwrap").is_some();
    let bwrap_probe_passed = bwrap_installed && bwrap_probe_succeeds();
    let apparmor_restriction_active = read_apparmor_sysctl().is_some_and(|v| v == 1);
    let apparmor_profile_loaded = is_astrid_profile_loaded();
    let needs_apparmor_profile = os == "linux"
        && bwrap_installed
        && !bwrap_probe_passed
        && apparmor_restriction_active
        && !apparmor_profile_loaded;
    Report {
        os,
        bwrap_installed,
        bwrap_probe_passed,
        apparmor_restriction_active,
        apparmor_profile_loaded,
        needs_apparmor_profile,
    }
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn bwrap_probe_succeeds() -> bool {
    Command::new("bwrap")
        .args(["--unshare-user", "--ro-bind", "/", "/", "--", "/bin/true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn read_apparmor_sysctl() -> Option<u8> {
    let raw =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok()?;
    raw.trim().parse().ok()
}

fn is_astrid_profile_loaded() -> bool {
    // aa-status output lists profile names one per line. Match on the
    // profile name we generate.
    Command::new("aa-status")
        .arg("--profiled")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("astrid"))
        .unwrap_or(false)
}

// ── Install commands ───────────────────────────────────────────────

fn install_commands() -> Vec<String> {
    let tmp_path = "/tmp/astrid-apparmor-profile";
    vec![
        format!("# 1. Write the profile to a temp location:"),
        format!("astrid setup --print-apparmor > {tmp_path}"),
        format!("# 2. Install it system-wide and load it (sudo required):"),
        format!("sudo install -m 644 {tmp_path} /etc/apparmor.d/astrid"),
        format!("sudo apparmor_parser -r /etc/apparmor.d/astrid"),
        format!("# 3. Verify:"),
        format!("sudo aa-status | grep astrid"),
    ]
}

fn apply_install(_cmds: &[String]) -> Result<ExitCode> {
    // Auto-apply runs the three privileged steps via sudo, prompting
    // once for the password. We re-spawn the relevant commands rather
    // than re-execing astrid itself, so the operator can see exactly
    // what's being run.
    let tmp_path = "/tmp/astrid-apparmor-profile";
    std::fs::write(tmp_path, APPARMOR_PROFILE_TEMPLATE)?;

    let install = Command::new("sudo")
        .args(["install", "-m", "644", tmp_path, "/etc/apparmor.d/astrid"])
        .status()?;
    if !install.success() {
        eprintln!("{}", "sudo install failed".red());
        return Ok(ExitCode::FAILURE);
    }

    let load = Command::new("sudo")
        .args(["apparmor_parser", "-r", "/etc/apparmor.d/astrid"])
        .status()?;
    if !load.success() {
        eprintln!("{}", "apparmor_parser failed".red());
        return Ok(ExitCode::FAILURE);
    }

    println!("{}", "Profile installed and loaded.".green());
    println!("Re-run `astrid setup` to verify the bwrap probe now passes.");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profile_has_required_userns_grant() {
        // If a future edit accidentally drops the `userns,` line, the
        // profile compiles but Astrid silently regresses to the #655
        // failure mode. Pin the contract here.
        assert!(
            APPARMOR_PROFILE_TEMPLATE.contains("userns,"),
            "AppArmor profile must grant the `userns,` capability"
        );
        assert!(
            APPARMOR_PROFILE_TEMPLATE.contains("profile astrid"),
            "AppArmor profile must declare a profile named `astrid`"
        );
        assert!(
            APPARMOR_PROFILE_TEMPLATE.contains("flags=(unconfined)"),
            "AppArmor profile must keep Astrid otherwise unconfined; \
             tighter confinement belongs in bwrap, not this profile"
        );
    }

    #[test]
    fn install_commands_reference_aa_status_for_verification() {
        // The verify step is the only feedback an operator has that the
        // profile is actually loaded; regressing it leaves them blind.
        let cmds = install_commands();
        assert!(cmds.iter().any(|c| c.contains("aa-status")));
        assert!(cmds.iter().any(|c| c.contains("apparmor_parser -r")));
    }
}
