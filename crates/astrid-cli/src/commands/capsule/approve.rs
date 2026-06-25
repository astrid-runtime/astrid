//! `astrid capsule approve <id>` and the install-time approval prompt (#995).
//!
//! A capsule's manifest-declared capabilities are INERT until an operator
//! approves them for the install principal. This module owns the operator-facing
//! side of that gate:
//!
//! * [`record_install_approval`] runs at the end of every CLI install. In
//!   batch / non-interactive mode it auto-approves; interactively it shows the
//!   declared capability surface and asks the operator to approve.
//! * [`run`] is the standalone `astrid capsule approve <id>` verb for activating
//!   a capsule that was installed-but-declined (or seeded inert).
//!
//! The trust record itself lives in
//! [`astrid_capsule::security::approval`]; this module only renders and prompts.

use anyhow::{Context, bail};
use astrid_capsule::manifest::CapsuleManifest;
use astrid_capsule::security::approval;
use astrid_core::dirs::AstridHome;

/// Record the operator's install-time approval decision for `capsule_id`.
///
/// `batch` is `true` for distro/offline/non-interactive installs (`astrid init`,
/// `install_offline_capsule`): those auto-approve, because the distro IS the
/// operator's chosen baseline. Interactively, the declared capability surface is
/// shown and the operator is prompted; a decline leaves the capsule inert and
/// prints how to approve it later.
///
/// # Errors
///
/// Propagates a failure to write the approval record (a denied prompt is NOT an
/// error — it is a deliberate operator choice).
pub(crate) fn record_install_approval(
    home: &AstridHome,
    capsule_id: &str,
    manifest: &CapsuleManifest,
    batch: bool,
) -> anyhow::Result<()> {
    let principal = astrid_capsule_install::install_principal();
    let fingerprint = approval::capability_fingerprint(manifest);

    if batch {
        approval::approve(home, &principal, &manifest.package.name, fingerprint)
            .with_context(|| format!("recording auto-approval for '{capsule_id}'"))?;
        return Ok(());
    }

    // Nothing to gate: a capsule that declares no capabilities and no IPC
    // patterns is inert by nature. Still record an approval so its (empty)
    // fingerprint is pinned and `capsule list` shows it as approved.
    let declared = describe_declared_capabilities(manifest);
    if declared.is_empty() {
        approval::approve(home, &principal, &manifest.package.name, fingerprint)
            .with_context(|| format!("recording approval for '{capsule_id}'"))?;
        return Ok(());
    }

    eprintln!();
    eprintln!("'{capsule_id}' requests these capabilities:");
    for line in &declared {
        eprintln!("  - {line}");
    }
    eprintln!();

    if prompt_yes_no(&format!("Approve and activate '{capsule_id}'?")) {
        approval::approve(home, &principal, &manifest.package.name, fingerprint)
            .with_context(|| format!("recording approval for '{capsule_id}'"))?;
        eprintln!("Approved. '{capsule_id}' will be active when the daemon loads it.");
    } else {
        eprintln!(
            "Declined. '{capsule_id}' is installed but INERT (no capabilities).\n  \
             Run `astrid capsule approve {capsule_id}` to activate it later."
        );
    }
    Ok(())
}

/// `astrid capsule approve <name>`: approve an installed-but-inert capsule for
/// the install principal at its current capability fingerprint, then nudge a
/// running daemon to reload it.
///
/// # Errors
///
/// Returns an error if the capsule is not installed, its manifest cannot be
/// read, or the approval record cannot be written.
pub(crate) async fn run(name: &str, workspace: bool) -> anyhow::Result<()> {
    ensure_valid_capsule_name(name)?;
    let home = AstridHome::resolve()?;
    let target_dir = super::install::resolve_target_dir(&home, name, workspace)?;
    let manifest_path = target_dir.join("Capsule.toml");
    if !manifest_path.exists() {
        bail!(
            "capsule '{name}' is not installed (no {})",
            manifest_path.display()
        );
    }
    let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
        .with_context(|| format!("reading manifest for '{name}'"))?;

    let principal = astrid_capsule_install::install_principal();
    let fingerprint = approval::capability_fingerprint(&manifest);

    let declared = describe_declared_capabilities(&manifest);
    if declared.is_empty() {
        eprintln!("'{name}' declares no capabilities — approving (it is inert by nature).");
    } else {
        eprintln!("'{name}' requests these capabilities:");
        for line in &declared {
            eprintln!("  - {line}");
        }
    }

    approval::approve(&home, &principal, &manifest.package.name, fingerprint)
        .with_context(|| format!("recording approval for '{name}'"))?;
    eprintln!("Approved '{name}'.");

    // Best-effort: if a daemon is running, hot-reload so the now-approved
    // capabilities take effect without a restart. Silent when no daemon is up.
    let reload = [name.to_string()];
    super::live_load::nudge_daemon_reload(&reload).await;
    Ok(())
}

/// Human-readable lines describing the SECURITY-RELEVANT declared capabilities
/// (fs / net / `host_process` / identity / uplink / ipc). Empty when the capsule
/// declares none — the signal that there is nothing to gate.
fn describe_declared_capabilities(manifest: &CapsuleManifest) -> Vec<String> {
    let caps = &manifest.capabilities;
    let mut lines = Vec::new();

    if !caps.net.is_empty() {
        lines.push(format!("network egress: {}", caps.net.join(", ")));
    }
    if !caps.net_connect.is_empty() {
        lines.push(format!("outbound TCP: {}", caps.net_connect.join(", ")));
    }
    if !caps.net_bind.is_empty() {
        lines.push(format!("socket bind: {}", caps.net_bind.join(", ")));
    }
    if !caps.fs_read.is_empty() {
        lines.push(format!("filesystem read: {}", caps.fs_read.join(", ")));
    }
    if !caps.fs_write.is_empty() {
        lines.push(format!("filesystem write: {}", caps.fs_write.join(", ")));
    }
    if !caps.host_process.is_empty() {
        let persist = if caps.allow_persistent {
            " (incl. persistent)"
        } else {
            ""
        };
        lines.push(format!(
            "host process exec{persist}: {}",
            caps.host_process.join(", ")
        ));
    }
    if !caps.identity.is_empty() {
        lines.push(format!("identity ops: {}", caps.identity.join(", ")));
    }
    if !caps.kv.is_empty() {
        lines.push(format!("KV store scopes: {}", caps.kv.join(", ")));
    }
    if caps.uplink {
        lines.push("uplink (binds a socket, may publish as other principals)".to_string());
    }
    if caps.allow_prompt_injection {
        lines.push("system-prompt injection".to_string());
    }

    let mut publish = manifest.effective_ipc_publish_patterns();
    publish.sort_unstable();
    if !publish.is_empty() {
        lines.push(format!("IPC publish: {}", publish.join(", ")));
    }
    let mut subscribe = manifest.effective_ipc_subscribe_patterns();
    subscribe.sort_unstable();
    if !subscribe.is_empty() {
        lines.push(format!("IPC subscribe: {}", subscribe.join(", ")));
    }

    lines
}

/// Prompt the operator with a yes/no question on stderr. Defaults to NO (the
/// fail-secure direction) on an empty entry or read error.
fn prompt_yes_no(question: &str) -> bool {
    eprint!("{question} [y/N]: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Reject a malformed capsule name before it is used as a path component in the
/// capsule directory or the approval store (#995).
///
/// Enforces the same identifier rules as install ([`astrid_capsule::capsule::CapsuleId`]):
/// lowercase alphanumeric and hyphens only. Without this, an operator typo like
/// `astrid capsule approve ../../evil` would write an approval record outside the
/// approvals directory.
fn ensure_valid_capsule_name(name: &str) -> anyhow::Result<()> {
    astrid_capsule::capsule::CapsuleId::new(name)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("invalid capsule name '{name}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_capsule_names_accepted() {
        assert!(ensure_valid_capsule_name("react").is_ok());
        assert!(ensure_valid_capsule_name("openai-compat").is_ok());
        assert!(ensure_valid_capsule_name("a1").is_ok());
    }

    #[test]
    fn path_traversal_names_rejected() {
        // The security-critical cases: a name that would escape the approvals dir.
        assert!(ensure_valid_capsule_name("../../evil").is_err());
        assert!(ensure_valid_capsule_name("foo/bar").is_err());
        assert!(ensure_valid_capsule_name("..").is_err());
        assert!(ensure_valid_capsule_name("a/../../b").is_err());
        assert!(ensure_valid_capsule_name("").is_err());
    }
}
