//! CLI guided pre-bless for capsule local-egress (issue #1028, feature B).
//!
//! When onboarding / `astrid capsule config` collects a provider endpoint
//! (`base_url`) that points at a loopback/private/link-local address, the SSRF
//! airlock would block the capsule from reaching it at runtime. Rather than make
//! the operator hand-edit `etc/config.toml`, this module detects the local
//! endpoint at config time and offers to write the
//! `[security.capsule_local_egress]` exemption keyed by capsule id.
//!
//! # Why this is safe (and is NOT the runtime elicitation)
//!
//! The operator is unambiguously local *by construction*: this code runs in the
//! `astrid` CLI process the operator invoked. No remote user can be at this
//! prompt. So a plain stdin `[y/N]` is sufficient — there is no transport-origin
//! ambiguity to resolve (that is what feature A's runtime elicitation handles
//! for the daemon path). This is "guided pre-bless," producing the exact same
//! operator config a hand-edit would.
//!
//! # Scope
//!
//! Detection is **literal**: an IP literal in a local range, or the `localhost`
//! hostname family. A free-text / non-resolving / public host is treated as
//! remote and skipped (no DNS resolution is performed in the CLI — matching the
//! airlock, which only blocks IP literals at pre-flight and `localhost` at the
//! resolver).

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

/// True if `host` (a URL host component, no port) denotes a loopback, private,
/// link-local, or CGNAT address that the SSRF airlock blocks — i.e. an endpoint
/// a capsule can only reach via a `[security.capsule_local_egress]` exemption.
///
/// Accepts:
/// - `IPv4` literals: loopback (`127.0.0.0/8`), unspecified (`0.0.0.0`), RFC
///   1918 private (`10/8`, `172.16/12`, `192.168/16`), link-local
///   (`169.254/16`), CGNAT (`100.64/10`).
/// - `IPv6` literals (bracketed `[::1]` or bare): loopback (`::1`), unspecified
///   (`::`), ULA (`fc00::/7`), link-local (`fe80::/10`), deprecated site-local
///   (`fec0::/10`), and transition addresses (NAT64 `64:ff9b::/96`, 6to4
///   `2002::/16`, Teredo `2001:0::/32`) embedding a local `IPv4`; `IPv4`-mapped
///   forms are normalised and re-checked.
/// - The `localhost` hostname family (`localhost`, `*.localhost`).
///
/// Everything else — a public IP, a real DNS name — returns `false` (treated as
/// remote, no prompt).
#[must_use]
pub(crate) fn is_local_address(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() {
        return false;
    }

    // `localhost` and the reserved `.localhost` TLD always resolve to loopback.
    let lower = h.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }

    // IP literal? (strip IPv6 brackets first.)
    let bare = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h);
    match bare.parse::<IpAddr>() {
        Ok(ip) => ip_is_local(ip),
        // Any non-literal, non-localhost host is treated as remote: the CLI does
        // not resolve names (a public name that happens to resolve to a private
        // IP is out of scope here, exactly as for the airlock's pre-flight).
        Err(_) => false,
    }
}

/// True if a parsed IP is in the host airlock's block set — loopback, private,
/// link-local, CGNAT, deprecated site-local (`fec0::/10`), or a transition
/// address (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001:0::/32`)
/// embedding such an `IPv4`.
///
/// This delegates to the SAME predicate the runtime airlock uses
/// ([`astrid_core::net::ip_is_blocked`]; consumed by `astrid-capsule`
/// `http::is_safe_ip`), so the CLI offers a pre-bless for exactly the endpoints
/// the runtime would otherwise block — no drift between the two block sets.
fn ip_is_local(ip: IpAddr) -> bool {
    astrid_core::net::ip_is_blocked(ip)
}

/// Parse a provider endpoint string (`base_url`) into the `host:port` an
/// allowlist entry uses. Returns `None` for anything that is not a parseable URL
/// with a host (free-text values are skipped).
///
/// The port falls back to the URL scheme's default (`http` → 80, `https` →
/// 443) when absent, so the allowlist entry is always port-specific.
#[must_use]
pub(crate) fn endpoint_host_port(base_url: &str) -> Option<(String, u16)> {
    let url = url::Url::parse(base_url.trim()).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    Some((host, port))
}

/// Build the `host:port` allowlist entry for an endpoint, if it is local.
///
/// Returns `None` (skip — no prompt) when the endpoint does not parse as a URL
/// with a host, or the host is not a local address.
#[must_use]
pub(crate) fn local_egress_entry(base_url: &str) -> Option<String> {
    let (host, port) = endpoint_host_port(base_url)?;
    if is_local_address(&host) {
        Some(format!("{host}:{port}"))
    } else {
        None
    }
}

/// Append `entry` to `capsule_id`'s `[security.capsule_local_egress]` list in
/// the operator config at `config_path`, creating the file/section/key as
/// needed. Idempotent: an entry already present is left untouched.
///
/// Uses `toml_edit` so existing operator config (comments, formatting, other
/// keys) is preserved. Writes 0o600 on Unix — the operator config may carry
/// security-sensitive settings.
///
/// # Errors
///
/// Returns an error if the existing file is unreadable / malformed TOML, or the
/// write fails.
pub(crate) fn record_local_egress(config_path: &Path, capsule_id: &str, entry: &str) -> Result<()> {
    let mut doc = if config_path.exists() {
        let existing = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        existing
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("{} is not valid TOML", config_path.display()))?
    } else {
        toml_edit::DocumentMut::new()
    };

    // Navigate / create `[security.capsule_local_egress]`.
    let security = doc["security"].or_insert(toml_edit::table());
    if let Some(t) = security.as_table_mut() {
        // Keep the nested table from being rendered inline.
        t.set_implicit(true);
    }
    let egress = doc["security"]["capsule_local_egress"].or_insert(toml_edit::table());
    if let Some(t) = egress.as_table_mut() {
        t.set_implicit(true);
    }

    let list = doc["security"]["capsule_local_egress"][capsule_id].or_insert(
        toml_edit::Item::Value(toml_edit::Value::Array(toml_edit::Array::new())),
    );
    let Some(arr) = list.as_array_mut() else {
        anyhow::bail!("existing [security.capsule_local_egress].{capsule_id} is not an array");
    };

    // Idempotent: skip if already present (case-insensitive host match handled
    // by the host enforcement; here exact-string is enough for the operator
    // file's own dedup).
    let already = arr
        .iter()
        .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(entry)));
    if !already {
        arr.push(entry);
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    write_atomic(config_path, doc.to_string().as_bytes())
        .with_context(|| format!("write {}", config_path.display()))
}

/// Atomically write `data` to `path`: a same-directory temp sibling is written,
/// fsync'd, then `rename`d over `path`. An interrupted write therefore never
/// leaves a half-written / truncated operator config that the daemon would fail
/// to load — the rename either fully succeeds or `path` keeps its prior
/// contents.
///
/// On Unix the temp file is created mode `0o600` (the operator config may carry
/// security-sensitive settings) and the perms ride through the rename, so there
/// is no world-readable window.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        // Per-process monotonic counter disambiguating concurrent tmp filenames.
        // PID alone is not enough — two same-process writers to the same config
        // (e.g. a `--set` collecting several local endpoints) would race on the
        // same tmp path and stomp each other. Mirrors the profile io_impl.
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        // Same-filesystem temp sibling so `rename` is atomic. PID + monotonic
        // counter → unique per call across threads within a process and across
        // processes sharing the directory.
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = path.with_extension(format!("toml.tmp.{}.{seq}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);

        if let Err(e) = std::fs::rename(&tmp_path, path) {
            // Don't leave a config-adjacent temp file behind on failure.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        Ok(())
    }

    // Non-Unix fallback: no atomic rename, no explicit permissions. Astrid's
    // supported platforms are Unix; this exists only to keep the crate
    // buildable on Windows.
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// If `value` (the value just entered for a capsule env field) is a local
/// endpoint, prompt the operator on stdin to add the SSRF-airlock exemption and,
/// on yes, write it to the operator config.
///
/// **Non-interactive guard:** when stdin is NOT a terminal (a scripted
/// `astrid capsule config --set ...`, a piped install, CI), the prompt is
/// skipped entirely — no stdin is read (so we never block waiting for input or
/// consume the caller's piped data) and no exemption is written. The operator
/// can add the `[security.capsule_local_egress]` entry explicitly.
///
/// A no / EOF / non-local / unparseable value is also a silent skip — the
/// capsule install is never blocked on this. Best-effort: a config write
/// failure is reported to stderr but does not fail the install (the operator can
/// still hand-edit).
pub(crate) fn maybe_prompt_local_egress(capsule_id: &str, value: &str, config_path: &Path) {
    use std::io::IsTerminal;

    // Only a TTY is a real operator at a prompt. A non-interactive stdin
    // (script / pipe / CI) must not be read — reading would block waiting for
    // input or steal the caller's piped data — and must not auto-write the
    // exemption. Decline before touching stdin or the config.
    if !std::io::stdin().is_terminal() {
        return;
    }

    prompt_and_record(capsule_id, value, config_path, || {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok()?;
        Some(input)
    });
}

/// Testable core of [`maybe_prompt_local_egress`], with stdin abstracted behind
/// `read_answer` (called only when an answer is actually needed). The non-local
/// early-return means `read_answer` is never invoked for a non-local value.
fn prompt_and_record(
    capsule_id: &str,
    value: &str,
    config_path: &Path,
    read_answer: impl FnOnce() -> Option<String>,
) {
    let Some(entry) = local_egress_entry(value) else {
        return;
    };

    eprintln!();
    eprintln!("  '{value}' is a local/private address. Capsules cannot reach local");
    eprintln!("  endpoints unless you add an SSRF-airlock exemption.");
    eprint!("  Allow '{capsule_id}' to reach {entry}? [y/N]: ");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let Some(input) = read_answer() else {
        return;
    };
    let answer = input.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        eprintln!("  Skipped. The capsule will be blocked from {entry} until you add it.");
        return;
    }

    match record_local_egress(config_path, capsule_id, &entry) {
        Ok(()) => {
            eprintln!("  Added {entry} to [security.capsule_local_egress].{capsule_id}.");
            eprintln!("  Restart the daemon for the change to take effect.");
            // Revocation caveat: the operator allowlist is read into a load-time
            // snapshot (HostState::local_egress), so REMOVING this entry later
            // does NOT take effect until the daemon restarts. Surface it now so
            // an operator who edits the config to revoke is not falsely
            // reassured the exemption is gone.
            eprintln!(
                "  Note: removing this exemption later also requires a daemon restart \
                 — editing the config alone does not revoke an in-flight grant."
            );
        },
        Err(e) => {
            eprintln!("  Could not update operator config ({e}).");
            eprintln!(
                "  Add this to {} manually:\n    [security.capsule_local_egress]\n    {capsule_id} = [\"{entry}\"]",
                config_path.display()
            );
        },
    }
}

#[cfg(test)]
#[path = "local_egress_tests.rs"]
mod tests;
