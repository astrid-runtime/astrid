//! Host-side native consent UI when the connected MCP **client** advertised
//! no elicitation capability at `initialize`.
//!
//! ## Runtime posture
//!
//! The kernel/CLI does not know or care which product launched the client.
//! The only signal is MCP: did `supported_elicitation_modes()` include a
//! usable mode? If yes → wire `elicitation/create` only (this module is
//! never called). If no → optional **local** system dialog so form-shaped
//! consent can still complete for a local `astrid mcp serve` process.
//!
//! Product hosts (IDEs, coding agents, chat CLIs, …) are out of scope here;
//! they are packaging and docs concerns for distributions built *on* Astrid.
//!
//! ## What we show (minimal system rectangles)
//!
//! | Kind | UI | Maps to form shape |
//! |------|----|--------------------|
//! | Binary | Deny / Allow buttons | `boolean` |
//! | Enum | Choose-from-list | `string` enum |
//! | Text | Dialog + text field | `string` |
//! | Secret | Dialog + secure field | `string` (local process only) |
//!
//! On macOS: stock `osascript` → AppKit `display dialog` / `choose from
//! list`. On Linux: zenity when present.
//!
//! ## Security boundary (local process vs remote server)
//!
//! `astrid mcp serve` is typically a **local** stdio child of the MCP client.
//! A host system dialog runs in that process, outside the LLM context: the
//! model never sees the UI, only the server-side decision.
//!
//! That is a different threat model from a **remotely hosted** MCP server,
//! where a dialog on the server machine is not the operator’s UI and secrets
//! must stay on a user-facing page (MCP URL-mode elicitation).
//!
//! Wire form mode still must not request secrets from a client that supports
//! elicitation (MCP client elicitation spec). For a local no-elicitation
//! client, a secure system field on the same machine as the shim keeps the
//! value out of the client/LLM; only this process sees it.
//!
//! ## Kill switch
//!
//! `ASTRID_MCP_HOST_FORM_DIALOG=0` (or `false` / `no` / `off`) → fail-secure
//! deny / `None` with no UI (CI / headless).

use std::process::Stdio;
use std::time::Duration;

use tracing::{debug, warn};

/// Default wall-clock wait for the operator to answer.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Whether the host native-dialog fallback is enabled.
///
/// Default **on** for interactive local serve. Explicit opt-out for
/// headless / CI.
pub(super) fn host_form_dialog_enabled() -> bool {
    match std::env::var("ASTRID_MCP_HOST_FORM_DIALOG") {
        Ok(v) => {
            let v = v.trim();
            !(v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("no")
                || v.eq_ignore_ascii_case("off"))
        },
        Err(_) => true,
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Binary consent: two system buttons (Deny / Allow, Grant, …).
///
/// Fail-secure: disabled env, cancel, timeout, or error → `false`.
pub(super) async fn binary_form_consent(
    title: &str,
    message: &str,
    accept_label: &str,
    deny_label: &str,
) -> bool {
    if !host_form_dialog_enabled() {
        debug!("MCP shim: host dialog disabled; denying binary consent");
        return false;
    }

    let title = title.to_owned();
    let message = message.to_owned();
    let accept_label = accept_label.to_owned();
    let deny_label = deny_label.to_owned();

    match tokio::task::spawn_blocking(move || {
        run_binary(&title, &message, &accept_label, &deny_label, DEFAULT_TIMEOUT)
    })
    .await
    {
        Ok(Ok(v)) => {
            debug!(accepted = v, "MCP shim: host binary consent resolved");
            v
        },
        Ok(Err(e)) => {
            warn!(error = %e, "MCP shim: host binary dialog failed; denying");
            false
        },
        Err(e) => {
            warn!(error = %e, "MCP shim: host binary dialog task failed; denying");
            false
        },
    }
}

/// Multi-choice consent: native list of labels. `options` are `(value, label)`.
///
/// Fail-secure: cancel / error → `None`.
pub(super) async fn enum_form_consent(
    title: &str,
    message: &str,
    options: &[(&str, &str)],
    default_value: &str,
) -> Option<String> {
    if !host_form_dialog_enabled() {
        debug!("MCP shim: host dialog disabled; denying enum consent");
        return None;
    }
    if options.is_empty() {
        return None;
    }

    let title = title.to_owned();
    let message = message.to_owned();
    let options: Vec<(String, String)> = options
        .iter()
        .map(|(v, l)| ((*v).to_owned(), (*l).to_owned()))
        .collect();
    let default_value = default_value.to_owned();

    match tokio::task::spawn_blocking(move || {
        run_enum(&title, &message, &options, &default_value, DEFAULT_TIMEOUT)
    })
    .await
    {
        Ok(Ok(v)) => {
            debug!(?v, "MCP shim: host enum consent resolved");
            v
        },
        Ok(Err(e)) => {
            warn!(error = %e, "MCP shim: host enum dialog failed; denying");
            None
        },
        Err(e) => {
            warn!(error = %e, "MCP shim: host enum dialog task failed; denying");
            None
        },
    }
}

/// Plain text field (non-secret). Cancel / empty-required → `None`.
///
/// Ready for future form-shaped string fields. Not used by ingress/grant today.
#[allow(dead_code)] // public surface for upcoming form-string shims
pub(super) async fn text_form_prompt(
    title: &str,
    message: &str,
    default: &str,
) -> Option<String> {
    text_like_prompt(title, message, default, false).await
}

/// Secure text field (bullets). Same local-host boundary as binary consent.
///
/// For **local** `mcp serve` only. Do not use this pattern as a substitute
/// for URL-mode when the MCP server is remotely hosted.
#[allow(dead_code)] // public surface for local secret collect when needed
pub(super) async fn secret_form_prompt(title: &str, message: &str) -> Option<String> {
    text_like_prompt(title, message, "", true).await
}

async fn text_like_prompt(
    title: &str,
    message: &str,
    default: &str,
    secret: bool,
) -> Option<String> {
    if !host_form_dialog_enabled() {
        debug!(secret, "MCP shim: host dialog disabled; denying text prompt");
        return None;
    }

    let title = title.to_owned();
    let message = message.to_owned();
    let default = default.to_owned();

    match tokio::task::spawn_blocking(move || {
        run_text(&title, &message, &default, secret, DEFAULT_TIMEOUT)
    })
    .await
    {
        Ok(Ok(v)) => {
            debug!(
                secret,
                has_value = v.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
                "MCP shim: host text prompt resolved"
            );
            v
        },
        Ok(Err(e)) => {
            warn!(error = %e, secret, "MCP shim: host text dialog failed; denying");
            None
        },
        Err(e) => {
            warn!(error = %e, secret, "MCP shim: host text dialog task failed; denying");
            None
        },
    }
}

// ── Platform dispatch ───────────────────────────────────────────────────────

fn run_binary(
    title: &str,
    message: &str,
    accept_label: &str,
    deny_label: &str,
    timeout: Duration,
) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        return macos_binary(title, message, accept_label, deny_label, timeout);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_binary(title, message, accept_label, deny_label, timeout);
    }
    #[cfg(not(unix))]
    {
        let _ = (title, message, accept_label, deny_label, timeout);
        Err("host dialog is not supported on this platform".into())
    }
}

fn run_enum(
    title: &str,
    message: &str,
    options: &[(String, String)],
    default_value: &str,
    timeout: Duration,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        return macos_enum(title, message, options, default_value, timeout);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_enum(title, message, options, default_value, timeout);
    }
    #[cfg(not(unix))]
    {
        let _ = (title, message, options, default_value, timeout);
        Err("host dialog is not supported on this platform".into())
    }
}

fn run_text(
    title: &str,
    message: &str,
    default: &str,
    secret: bool,
    timeout: Duration,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        return macos_text(title, message, default, secret, timeout);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return linux_text(title, message, default, secret, timeout);
    }
    #[cfg(not(unix))]
    {
        let _ = (title, message, default, secret, timeout);
        Err("host dialog is not supported on this platform".into())
    }
}

/// Escape a string for a double-quoted AppleScript literal.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ── macOS: stock AppKit dialogs via osascript ───────────────────────────────

#[cfg(target_os = "macos")]
fn macos_binary(
    title: &str,
    message: &str,
    accept_label: &str,
    deny_label: &str,
    timeout: Duration,
) -> Result<bool, String> {
    let secs = timeout.as_secs().max(1);
    // note: no custom icon art — system caution glyph only (native look)
    let script = format!(
        r#"display dialog "{msg}" with title "{title}" with icon caution buttons {{"{deny}", "{accept}"}} default button "{accept}" cancel button "{deny}" giving up after {secs}"#,
        msg = escape_applescript(message),
        title = escape_applescript(title),
        deny = escape_applescript(deny_label),
        accept = escape_applescript(accept_label),
        secs = secs,
    );
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to spawn osascript: {e}"))?;

    if !output.status.success() {
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("gave up:true") {
        return Ok(false);
    }
    Ok(stdout.contains(&format!("button returned:{accept_label}")))
}

#[cfg(target_os = "macos")]
fn macos_enum(
    title: &str,
    message: &str,
    options: &[(String, String)],
    default_value: &str,
    _timeout: Duration,
) -> Result<Option<String>, String> {
    let labels: Vec<String> = options
        .iter()
        .map(|(_, l)| format!("\"{}\"", escape_applescript(l)))
        .collect();
    let list = labels.join(", ");
    let default_label = options
        .iter()
        .find(|(v, _)| v == default_value)
        .map(|(_, l)| l.as_str())
        .unwrap_or(options[0].1.as_str());

    let script = format!(
        r#"
set theList to {{{list}}}
set theDefault to {{"{default}"}}
set theChoice to choose from list theList with prompt "{msg}" with title "{title}" default items theDefault
if theChoice is false then
  return "CANCEL"
end if
return item 1 of theChoice
"#,
        list = list,
        default = escape_applescript(default_label),
        msg = escape_applescript(message),
        title = escape_applescript(title),
    );
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to spawn osascript: {e}"))?;

    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() || stdout == "CANCEL" {
        return Ok(None);
    }
    for (value, label) in options {
        if label == &stdout {
            return Ok(Some(value.clone()));
        }
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn macos_text(
    title: &str,
    message: &str,
    default: &str,
    secret: bool,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let secs = timeout.as_secs().max(1);
    let hidden = if secret { " with hidden answer" } else { "" };
    let script = format!(
        r#"display dialog "{msg}" with title "{title}" default answer "{def}"{hidden} buttons {{"Cancel", "OK"}} default button "OK" cancel button "Cancel" giving up after {secs}"#,
        msg = escape_applescript(message),
        title = escape_applescript(title),
        def = escape_applescript(default),
        hidden = hidden,
        secs = secs,
    );
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to spawn osascript: {e}"))?;

    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("gave up:true") {
        return Ok(None);
    }
    // "button returned:OK, text returned:…"
    const MARKER: &str = "text returned:";
    if let Some(pos) = stdout.find(MARKER) {
        let mut text = stdout[pos + MARKER.len()..].to_owned();
        // Strip trailing ", gave up:false" if present.
        if let Some(cut) = text.find(", gave up:") {
            text.truncate(cut);
        }
        return Ok(Some(text.trim_end_matches('\n').to_owned()));
    }
    Ok(None)
}

// ── Linux: zenity when present (best-effort native-ish) ─────────────────────

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_binary(
    title: &str,
    message: &str,
    accept_label: &str,
    deny_label: &str,
    timeout: Duration,
) -> Result<bool, String> {
    let secs = timeout.as_secs().max(1).to_string();
    let output = std::process::Command::new("zenity")
        .args([
            "--question",
            "--title",
            title,
            "--text",
            message,
            "--ok-label",
            accept_label,
            "--cancel-label",
            deny_label,
            "--timeout",
            &secs,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("zenity unavailable: {e}"))?;
    Ok(output.status.success())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_enum(
    title: &str,
    message: &str,
    options: &[(String, String)],
    default_value: &str,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let secs = timeout.as_secs().max(1).to_string();
    let mut args = vec![
        "--list".into(),
        "--title".into(),
        title.to_owned(),
        "--text".into(),
        message.to_owned(),
        "--column".into(),
        "Choice".into(),
        "--hide-header".into(),
        "--timeout".into(),
        secs,
    ];
    for (_, label) in options {
        args.push(label.clone());
    }
    let _ = default_value;
    let output = std::process::Command::new("zenity")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("zenity unavailable: {e}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() {
        return Ok(None);
    }
    for (value, label) in options {
        if label == &stdout {
            return Ok(Some(value.clone()));
        }
    }
    Ok(None)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_text(
    title: &str,
    message: &str,
    default: &str,
    secret: bool,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let secs = timeout.as_secs().max(1).to_string();
    let mut cmd = std::process::Command::new("zenity");
    cmd.arg("--entry")
        .arg("--title")
        .arg(title)
        .arg("--text")
        .arg(message)
        .arg("--entry-text")
        .arg(default)
        .arg("--timeout")
        .arg(&secs);
    if secret {
        cmd.arg("--hide-text");
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("zenity unavailable: {e}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_owned();
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applescript_escape_quotes_and_backslashes() {
        assert_eq!(escape_applescript(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn host_dialog_env_parse_table() {
        for (raw, want) in [
            ("0", false),
            ("false", false),
            ("FALSE", false),
            ("no", false),
            ("off", false),
            ("1", true),
            ("true", true),
            ("yes", true),
        ] {
            let enabled = {
                let v = raw.trim();
                !(v == "0"
                    || v.eq_ignore_ascii_case("false")
                    || v.eq_ignore_ascii_case("no")
                    || v.eq_ignore_ascii_case("off"))
            };
            assert_eq!(enabled, want, "raw={raw}");
        }
    }

    #[test]
    fn module_documents_local_vs_hosted_and_native_surface() {
        let src = include_str!("host_dialog.rs");
        assert!(src.contains("local"));
        assert!(src.contains("hosted") || src.contains("remotely"));
        assert!(src.contains("osascript") || src.contains("AppKit"));
        assert!(src.contains("binary_form_consent"));
        assert!(src.contains("enum_form_consent"));
        assert!(src.contains("text_form_prompt"));
        assert!(src.contains("secret_form_prompt"));
    }
}
