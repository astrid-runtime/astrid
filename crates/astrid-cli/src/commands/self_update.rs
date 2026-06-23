//! Self-update command — download and install newer versions of the Astrid CLI.
//!
//! Checks GitHub releases for the `unicity-astrid/astrid` repo, compares
//! against the running binary's version, downloads the appropriate platform
//! binary, and swaps it in place.
//!
//! Also provides PATH setup helpers for `astrid init`.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::theme::Theme;

/// GitHub org/repo for the core Astrid release.
const GITHUB_ORG: &str = "unicity-astrid";
const GITHUB_REPO: &str = "astrid";

/// Current binary version (set at compile time).
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// TTL for cached update checks (24 hours).
const CHECK_TTL_SECS: u64 = 86_400;

/// The `~/.astrid/bin` directory where self-managed binaries live.
fn astrid_bin_dir() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    Ok(home.root().join("bin"))
}

/// Map the current platform to the GitHub release asset target triple.
fn platform_target() -> anyhow::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        (os, arch) => bail!("Unsupported platform: {os}/{arch}"),
    }
}

/// Cached update check result.
#[derive(serde::Serialize, serde::Deserialize)]
struct UpdateCache {
    checked_at: u64,
    latest_version: String,
}

fn cache_path() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    Ok(home.var_dir().join("update-check.json"))
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Check for a newer version (cached, background-safe).
///
/// Returns `Some(version)` if an update is available, `None` if up-to-date
/// or check failed/cached.
pub(crate) async fn check_for_update_cached() -> Option<String> {
    let path = cache_path().ok()?;

    // Check cache first
    if let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(cache) = serde_json::from_str::<UpdateCache>(&data)
        && now_epoch().saturating_sub(cache.checked_at) < CHECK_TTL_SECS
    {
        let current = semver::Version::parse(CURRENT_VERSION).ok()?;
        let latest = semver::Version::parse(&cache.latest_version).ok()?;
        return if latest > current {
            Some(cache.latest_version)
        } else {
            None
        };
    }

    // Cache miss or stale — do a live check
    let client = match reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Update check: failed to build HTTP client: {e}");
            return None;
        },
    };

    let url = format!("https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/releases/latest");
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("Update check: GitHub API request failed: {e}");
            return None;
        },
    };
    if !response.status().is_success() {
        tracing::debug!("Update check: GitHub API returned {}", response.status());
        return None;
    }

    let json: serde_json::Value = match response.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::debug!("Update check: failed to parse response: {e}");
            return None;
        },
    };
    let tag = json.get("tag_name")?.as_str()?;
    let version_str = tag.strip_prefix('v').unwrap_or(tag);

    // Update cache
    let cache = UpdateCache {
        checked_at: now_epoch(),
        latest_version: version_str.to_owned(),
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(&path, json);
    }

    let current = semver::Version::parse(CURRENT_VERSION).ok()?;
    let latest = semver::Version::parse(version_str).ok()?;
    if latest > current {
        Some(version_str.to_string())
    } else {
        None
    }
}

/// Print an update banner if a newer version is available.
pub(crate) async fn print_update_banner() {
    if let Some(latest) = check_for_update_cached().await {
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "Update available: v{CURRENT_VERSION} → v{latest}. Run `astrid self-update` to upgrade (includes distro + capsule sync)."
            ))
        );
    }
}

/// Fetch the latest release metadata from GitHub.
async fn fetch_latest_release(
    client: &reqwest::Client,
) -> anyhow::Result<(String, serde_json::Value)> {
    let url = format!("https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/releases/latest");
    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to reach GitHub API")?;
    if !response.status().is_success() {
        bail!("GitHub API returned {}", response.status());
    }
    let json: serde_json::Value = response
        .json()
        .await
        .context("failed to parse API response")?;
    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("release has no tag_name"))?;
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();
    Ok((version, json))
}

/// Download and extract the release archive to a temp directory.
/// Returns the path to the extracted directory.
async fn download_and_extract(
    client: &reqwest::Client,
    release: &serde_json::Value,
    version: &str,
    target: &str,
) -> anyhow::Result<tempfile::TempDir> {
    let asset_name = format!("astrid-{version}-{target}.tar.gz");
    let assets = release
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| anyhow::anyhow!("release has no assets"))?;

    let download_url = assets
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(&asset_name))
        .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
        .ok_or_else(|| {
            anyhow::anyhow!("no release asset '{asset_name}' — pre-built binaries may not be available for this platform")
        })?;

    let tmp_dir = tempfile::tempdir()?;
    let archive_path = tmp_dir.path().join(&asset_name);
    // Stream with 100 MB limit.
    let mut response = client.get(download_url).send().await?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(
            bytes.len() <= 100 * 1024 * 1024,
            "release archive exceeds 100 MB limit",
        );
    }
    std::fs::write(&archive_path, &bytes)?;

    let tar_gz = std::fs::File::open(&archive_path)?;
    let decoder = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(tmp_dir.path())?;

    Ok(tmp_dir)
}

/// Install binaries from an extracted release directory to `~/.astrid/bin/`.
fn install_binaries(from: &Path, install_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(install_dir)?;

    for name in ["astrid", "astrid-daemon"] {
        let src = from.join(name);
        if src.exists() {
            let dest = install_dir.join(name);
            std::fs::copy(&src, &dest).with_context(|| format!("failed to install {name}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
            }
        }
    }
    Ok(())
}

/// Run the self-update command — download and install the latest version,
/// then sync distro and capsule updates.
pub(crate) async fn run_self_update() -> anyhow::Result<()> {
    let target = platform_target()?;

    println!(
        "{}",
        Theme::info(&format!(
            "Checking for updates (current: v{CURRENT_VERSION}, platform: {target})..."
        ))
    );

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let (version_str, release) = fetch_latest_release(&client).await?;

    let current = semver::Version::parse(CURRENT_VERSION)?;
    let latest = semver::Version::parse(&version_str)?;

    if latest <= current {
        println!(
            "{}",
            Theme::success(&format!("Already up to date (v{CURRENT_VERSION})"))
        );
    } else {
        println!(
            "{}",
            Theme::info(&format!("Downloading v{version_str} for {target}..."))
        );

        let tmp_dir = download_and_extract(&client, &release, &version_str, target).await?;
        let extract_dir = tmp_dir
            .path()
            .join(format!("astrid-{version_str}-{target}"));

        let install_dir = astrid_bin_dir()?;
        install_binaries(&extract_dir, &install_dir)?;

        println!(
            "{}",
            Theme::success(&format!(
                "Updated to v{version_str} — installed to {}",
                install_dir.display()
            ))
        );

        if !is_in_path(&install_dir) {
            println!(
                "{}",
                Theme::warning(&format!(
                    "Note: {} is not in your PATH. Run `astrid init` to set it up.",
                    install_dir.display()
                ))
            );
        }
    }

    // Update cache
    let cache = UpdateCache {
        checked_at: now_epoch(),
        latest_version: version_str.clone(),
    };
    if let Ok(path) = cache_path()
        && let Ok(json) = serde_json::to_string(&cache)
    {
        let _ = std::fs::write(path, json);
    }

    // Sync distro + capsules after binary update.
    sync_distro_and_capsules().await?;

    Ok(())
}

/// Re-fetch the distro manifest and sync capsules.
///
/// Compares the remote Distro.toml against the local Distro.lock. If the
/// distro version changed, re-runs init to install new/updated capsules.
/// Then runs `capsule update` for any capsules with newer GitHub releases.
async fn sync_distro_and_capsules() -> anyhow::Result<()> {
    println!();
    println!("{}", Theme::info("Checking distro and capsule updates..."));

    let home = astrid_core::dirs::AstridHome::resolve()?;
    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    // Load existing lock to get the distro ID.
    let lock = super::distro::lock::load_lock(&lock_path)?;
    let distro_id = lock.as_ref().map_or("astralis", |l| l.distro.id.as_str());

    // Re-run init which handles: fetch manifest, diff lock, install new capsules.
    // init is idempotent — if lock is fresh it returns immediately. This runs
    // in a background sync with no human present, so use headless defaults.
    let sync_opts = super::init::InitOpts {
        yes: true,
        ..Default::default()
    };
    if let Err(e) = super::init::run_init(distro_id, &sync_opts).await {
        println!("{}", Theme::warning(&format!("Distro sync: {e}")));
    }

    // Update individual capsules (checks GitHub releases for newer versions).
    if let Err(e) = super::capsule::install::update_capsule(None, false).await {
        println!("{}", Theme::warning(&format!("Capsule update: {e}")));
    }

    Ok(())
}

// ── PATH setup helpers ──────────────────────────────────────────────────

/// Check if a directory is already in the current PATH.
fn is_in_path(dir: &Path) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|entry| entry == dir))
}

/// Detect the user's shell RC file.
fn detect_shell_rc() -> Option<PathBuf> {
    let home = directories::BaseDirs::new()?.home_dir().to_path_buf();
    let shell = std::env::var("SHELL").unwrap_or_default();

    if shell.ends_with("zsh") {
        Some(home.join(".zshrc"))
    } else if shell.ends_with("bash") {
        // Prefer .bashrc on Linux, .bash_profile on macOS
        let bashrc = home.join(".bashrc");
        let profile = home.join(".bash_profile");
        if cfg!(target_os = "macos") && profile.exists() {
            Some(profile)
        } else if bashrc.exists() {
            Some(bashrc)
        } else {
            Some(home.join(".bashrc"))
        }
    } else if shell.ends_with("fish") {
        Some(home.join(".config/fish/config.fish"))
    } else {
        // Fallback: try zshrc (macOS default), then bashrc
        let zshrc = home.join(".zshrc");
        if zshrc.exists() {
            Some(zshrc)
        } else {
            Some(home.join(".bashrc"))
        }
    }
}

/// Ensure `~/.astrid/bin` is in PATH. Prompts user if interactive.
///
/// Called by `astrid init` after capsule installation.
pub(crate) fn ensure_path_setup() -> anyhow::Result<()> {
    let bin_dir = astrid_bin_dir()?;
    std::fs::create_dir_all(&bin_dir)?;

    if is_in_path(&bin_dir) {
        return Ok(());
    }

    let bin_str = bin_dir.to_string_lossy();
    let Some(rc_file) = detect_shell_rc() else {
        println!(
            "{}",
            Theme::warning(&format!("Add {bin_str} to your PATH manually."))
        );
        return Ok(());
    };

    let export_line = if rc_file.to_string_lossy().contains("fish") {
        format!("fish_add_path {bin_str}")
    } else {
        format!("export PATH=\"{bin_str}:$PATH\"")
    };

    // Check if already in the RC file
    if let Ok(contents) = std::fs::read_to_string(&rc_file)
        && contents.contains(&*bin_str)
    {
        return Ok(()); // Already configured, just not sourced yet
    }

    // Prompt if interactive
    if std::io::stdin().is_terminal() {
        eprint!(
            "\n{bin_str} is not in your PATH. Add it to {}? [Y/n] ",
            rc_file.display()
        );
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() && !input.eq_ignore_ascii_case("y") {
            println!(
                "{}",
                Theme::dimmed(&format!("Skipped. Add manually: {export_line}"))
            );
            return Ok(());
        }
    }

    // Append to RC file
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_file)?;
    std::io::Write::write_all(
        &mut file,
        format!("\n# Astrid OS\n{export_line}\n").as_bytes(),
    )?;

    println!(
        "{}",
        Theme::success(&format!("Added to {}", rc_file.display()))
    );
    println!(
        "  Run: {} (or restart your terminal)",
        Theme::dimmed(&format!("source {}", rc_file.display()))
    );

    Ok(())
}
