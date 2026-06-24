//! Self-update command — download and install newer versions of the Astrid CLI.
//!
//! Discovers the latest GitHub release for `unicity-astrid/astrid`, compares it
//! to the running binary, and — for self-managed installs — verifies, stages,
//! and atomically swaps the new binary IN PLACE with a backup for rollback.
//! Homebrew installs are deferred to `brew upgrade` (we never shadow them with a
//! second copy). The release source can be overridden (`--source owner/repo` /
//! `ASTRID_UPDATE_REPO` / `ASTRID_UPDATE_API`) so the whole flow can be
//! rehearsed against a fork, pre-release, or local mock.
//!
//! Also provides PATH setup helpers for `astrid init`.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::cli::UpdateArgs;
use crate::theme::Theme;

/// Default GitHub org/repo for the core Astrid release. Overridable for
/// staging/testing — see [`resolve_repo`].
const DEFAULT_ORG: &str = "unicity-astrid";
const DEFAULT_REPO: &str = "astrid";

/// Current binary version (set at compile time).
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// TTL for cached update checks (24 hours).
const CHECK_TTL_SECS: u64 = 86_400;

/// Max size of a downloaded release archive.
const MAX_ARCHIVE_BYTES: usize = 100 * 1024 * 1024;

/// Binaries managed by an in-place update.
const MANAGED_BINARIES: &[&str] = &["astrid", "astrid-daemon"];

/// GitHub API base URL. `ASTRID_UPDATE_API` overrides it so the flow can be
/// rehearsed against a local/staging mock server.
fn api_base() -> String {
    std::env::var("ASTRID_UPDATE_API").unwrap_or_else(|_| "https://api.github.com".to_string())
}

/// Resolve the release source repo as `(owner, repo)`. Precedence: the explicit
/// `--source owner/repo`, then `ASTRID_UPDATE_REPO`, then the built-in default.
/// Lets the update flow be pointed at a fork or pre-release for staging/testing.
fn resolve_repo(source: Option<&str>) -> anyhow::Result<(String, String)> {
    let spec = source
        .map(str::to_owned)
        .or_else(|| std::env::var("ASTRID_UPDATE_REPO").ok());
    match spec {
        Some(s) => {
            let (owner, repo) = s
                .split_once('/')
                .filter(|(o, r)| !o.is_empty() && !r.is_empty())
                .ok_or_else(|| anyhow::anyhow!("update source must be 'owner/repo', got '{s}'"))?;
            Ok((owner.to_string(), repo.to_string()))
        },
        None => Ok((DEFAULT_ORG.to_string(), DEFAULT_REPO.to_string())),
    }
}

/// The `~/.astrid/bin` directory where `astrid init` puts self-managed binaries.
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

/// Resolved path of the currently-running `astrid` binary (symlinks followed) —
/// what self-update replaces in place.
fn running_binary() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine current executable path")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

/// Whether `exe` is a Homebrew-managed binary. Homebrew symlinks `bin/astrid`
/// into `…/Cellar/astrid/<version>/bin/astrid`, so the resolved path always
/// contains a `Cellar` component. Such installs update via `brew upgrade`, not
/// self-update — we must not shadow them with a second copy.
fn is_homebrew_managed(exe: &Path) -> bool {
    exe.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("Cellar"))
    })
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

fn write_cache(version: &str) {
    let cache = UpdateCache {
        checked_at: now_epoch(),
        latest_version: version.to_owned(),
    };
    if let Ok(path) = cache_path()
        && let Ok(json) = serde_json::to_string(&cache)
    {
        let _ = std::fs::write(path, json);
    }
}

/// Check for a newer version (cached, background-safe). Returns `Some(version)`
/// if an update is available, `None` if up-to-date or the check failed.
pub(crate) async fn check_for_update_cached() -> Option<String> {
    let path = cache_path().ok()?;

    if let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(cache) = serde_json::from_str::<UpdateCache>(&data)
        && now_epoch().saturating_sub(cache.checked_at) < CHECK_TTL_SECS
    {
        let current = semver::Version::parse(CURRENT_VERSION).ok()?;
        let latest = semver::Version::parse(&cache.latest_version).ok()?;
        return (latest > current).then_some(cache.latest_version);
    }

    let (owner, repo) = resolve_repo(None).ok()?;
    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let url = format!("{}/repos/{owner}/{repo}/releases/latest", api_base());
    let response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let json: serde_json::Value = response.json().await.ok()?;
    let tag = json.get("tag_name")?.as_str()?;
    let version_str = tag.strip_prefix('v').unwrap_or(tag);
    write_cache(version_str);

    let current = semver::Version::parse(CURRENT_VERSION).ok()?;
    let latest = semver::Version::parse(version_str).ok()?;
    (latest > current).then(|| version_str.to_string())
}

/// Print an install-aware update banner if a newer version is available.
/// Homebrew installs are told to `brew upgrade`; everyone else `astrid update`.
pub(crate) async fn print_update_banner() {
    let Some(latest) = check_for_update_cached().await else {
        return;
    };
    let how = match running_binary() {
        Ok(exe) if is_homebrew_managed(&exe) => "brew upgrade astrid",
        _ => "astrid update",
    };
    eprintln!(
        "{}",
        Theme::warning(&format!(
            "Update available: v{CURRENT_VERSION} → v{latest}. Run `{how}` to upgrade."
        ))
    );
}

/// Fetch the latest release metadata `(version, json)` from the resolved repo.
async fn fetch_latest_release(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
) -> anyhow::Result<(String, serde_json::Value)> {
    let url = format!("{}/repos/{owner}/{repo}/releases/latest", api_base());
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

/// Find a release asset's browser download URL by exact name.
fn asset_url<'a>(release: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    release
        .get("assets")?
        .as_array()?
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
        .and_then(|a| a.get("browser_download_url").and_then(|u| u.as_str()))
}

/// Stream a URL into memory under the size cap.
async fn download(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("download failed: HTTP {}", response.status());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(
            bytes.len() <= MAX_ARCHIVE_BYTES,
            "release archive exceeds {MAX_ARCHIVE_BYTES} byte limit"
        );
    }
    Ok(bytes)
}

/// Hex-encode bytes (no extra dep).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Verify `archive` against the sha256 recorded for `asset_name` in a
/// `SHA256SUMS.txt` body (`<hex>  <name>` per line). This is INTEGRITY only —
/// it catches a corrupt/truncated/MITM-altered download whose checksum no longer
/// matches the release's recorded sum. It is NOT authenticity (an attacker who
/// controls the release controls both the artifact and the sum); a publisher
/// signature is tracked separately.
fn verify_sha256(archive: &[u8], sums_body: &str, asset_name: &str) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    let expected = sums_body
        .lines()
        .find_map(|line| {
            let mut it = line.split_whitespace();
            let hex = it.next()?;
            let name = it.next()?;
            // `sha256sum` marks binary entries with a leading '*'.
            (name.trim_start_matches('*') == asset_name).then_some(hex)
        })
        .ok_or_else(|| anyhow::anyhow!("no checksum for '{asset_name}' in SHA256SUMS"))?;
    let actual = to_hex(&Sha256::digest(archive));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("checksum mismatch for '{asset_name}': expected {expected}, got {actual}");
    }
    Ok(())
}

/// Back up and atomically swap the named binaries from `extract_dir` into
/// `install_dir`.
///
/// Each existing binary is copied to `<name>.bak` first; new binaries are staged
/// as temp files in `install_dir` (same filesystem) and `rename`d into place —
/// atomic on Unix, and safe over a running binary (the live process keeps its
/// old inode). If any rename fails, every binary is restored from its backup so
/// the install is never left half-swapped. The `.bak` copies are left in place
/// for manual rollback after a successful update.
fn backup_and_swap(install_dir: &Path, extract_dir: &Path, names: &[&str]) -> anyhow::Result<()> {
    // 0. The expected binaries are a SET. A release missing one would otherwise
    //    leave a version-mismatched pair (new `astrid`, old `astrid-daemon`)
    //    while still reporting success — require them all before touching disk.
    for name in names {
        anyhow::ensure!(
            extract_dir.join(name).exists(),
            "release archive is missing '{name}'"
        );
    }

    // 1. Back up existing live binaries.
    let mut backups: Vec<(PathBuf, PathBuf)> = Vec::new(); // (live, bak)
    for name in names {
        let live = install_dir.join(name);
        if live.exists() {
            let bak = install_dir.join(format!("{name}.bak"));
            std::fs::copy(&live, &bak)
                .with_context(|| format!("failed to back up {}", live.display()))?;
            backups.push((live, bak));
        }
    }

    // 2. Stage new binaries as temp files in the install dir (same fs as the
    //    target, so the rename below is atomic).
    let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new(); // (tmp, live)
    for name in names {
        let tmp = install_dir.join(format!(".{name}.new"));
        std::fs::copy(extract_dir.join(name), &tmp)
            .with_context(|| format!("failed to stage {name}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        staged.push((tmp, install_dir.join(name)));
    }

    // 3. Atomically rename each staged binary into place. On the first failure,
    //    roll every binary back from its backup and clean up the remaining temps.
    //    Rollback uses `rename` (not `copy`): copying over a binary that is
    //    currently executing fails with ETXTBSY, whereas renaming swaps the
    //    directory entry without touching the running inode. A rollback failure
    //    is surfaced rather than swallowed.
    for (idx, (tmp, live)) in staged.iter().enumerate() {
        if let Err(e) = std::fs::rename(tmp, live) {
            let mut rollback_errs = Vec::new();
            for (blive, bak) in &backups {
                if let Err(re) = std::fs::rename(bak, blive) {
                    rollback_errs.push(format!("{}: {re}", blive.display()));
                }
            }
            for (t, _) in &staged[idx..] {
                let _ = std::fs::remove_file(t);
            }
            let base = format!("failed to install {}", live.display());
            let msg = if rollback_errs.is_empty() {
                base
            } else {
                format!(
                    "{base}; ROLLBACK ALSO FAILED ({}) — restore *.bak manually",
                    rollback_errs.join("; ")
                )
            };
            return Err(e).context(msg);
        }
    }
    Ok(())
}

/// Best-effort writability check for a directory: create and drop a uniquely
/// named temp file in it. A fixed probe name could collide with (and clobber) a
/// real file or another concurrent updater; `tempfile` picks a random suffix and
/// removes the file on drop.
fn is_writable_dir(dir: &Path) -> bool {
    tempfile::Builder::new()
        .prefix(".astrid-write-probe")
        .tempfile_in(dir)
        .is_ok()
}

/// Confirm an action. True if `assume_yes`, if stdin is not a TTY (scripted —
/// the user ran the command intentionally), or on a yes/empty answer (default
/// yes). False only on an explicit "no".
fn confirm(prompt: &str, assume_yes: bool) -> anyhow::Result<bool> {
    if assume_yes || !std::io::stdin().is_terminal() {
        return Ok(true);
    }
    eprint!("{prompt} [Y/n] ");
    std::io::Write::flush(&mut std::io::stderr())?;
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input)? == 0 {
        // EOF (Ctrl-D) before any answer — treat as "no" rather than defaulting
        // to yes; a closed stdin is not consent to overwrite the binary.
        return Ok(false);
    }
    let input = input.trim();
    Ok(input.is_empty() || input.eq_ignore_ascii_case("y") || input.eq_ignore_ascii_case("yes"))
}

/// Run the self-update command — flag → stage → finish:
/// check the latest release, (for self-managed installs) verify + atomically
/// swap the binary in place with rollback, restart the daemon, then sync distro
/// and capsules. Homebrew installs are deferred to `brew upgrade`.
pub(crate) async fn run_self_update(args: UpdateArgs) -> anyhow::Result<()> {
    let target = platform_target()?;
    let (owner, repo) = resolve_repo(args.source.as_deref())?;

    // Homebrew installs update via brew — never shadow them with a second copy.
    let exe = running_binary()?;
    if is_homebrew_managed(&exe) {
        println!(
            "{}",
            Theme::info(
                "Astrid was installed via Homebrew. Update it with:\n  brew upgrade astrid"
            )
        );
        return Ok(());
    }

    println!(
        "{}",
        Theme::info(&format!(
            "Checking for updates (current: v{CURRENT_VERSION}, platform: {target}, source: {owner}/{repo})..."
        ))
    );

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let (version_str, release) = fetch_latest_release(&client, &owner, &repo).await?;
    let current = semver::Version::parse(CURRENT_VERSION)?;
    let latest = semver::Version::parse(&version_str)?;
    write_cache(&version_str);

    if latest <= current {
        println!(
            "{}",
            Theme::success(&format!("Already up to date (v{CURRENT_VERSION})."))
        );
        return Ok(());
    }

    if args.check {
        println!(
            "{}",
            Theme::info(&format!(
                "Update available: v{CURRENT_VERSION} → v{version_str}. Run `astrid update` to install."
            ))
        );
        return Ok(());
    }

    // Update IN PLACE at the directory of the running binary, so there is exactly
    // one `astrid` and `which astrid` never diverges from the updated version.
    let install_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve install directory for {}", exe.display()))?
        .to_path_buf();
    if !is_writable_dir(&install_dir) {
        bail!(
            "{} is not writable — re-run with elevated permissions, or reinstall via Homebrew/cargo.",
            install_dir.display()
        );
    }

    if !confirm(
        &format!(
            "Update Astrid v{CURRENT_VERSION} → v{version_str} in {}?",
            install_dir.display()
        ),
        args.yes,
    )? {
        println!("{}", Theme::dimmed("Update cancelled."));
        return Ok(());
    }

    // Stage: download → verify checksum → extract.
    let (_tmp_dir, extract_dir) =
        download_verify_extract(&client, &release, &version_str, target).await?;

    // Finish: back up + atomically swap (rolls back on any failure).
    backup_and_swap(&install_dir, &extract_dir, MANAGED_BINARIES)?;
    println!(
        "{}",
        Theme::success(&format!(
            "Updated to v{version_str} (previous binaries kept as *.bak in {})",
            install_dir.display()
        ))
    );

    finish_update(&install_dir).await
}

/// Download the release archive for `version`/`target`, verify its checksum, and
/// extract it. Returns the temp dir (kept alive by the caller for the lifetime
/// of `extract_dir`) and the extracted `astrid-<version>-<target>/` directory.
async fn download_verify_extract(
    client: &reqwest::Client,
    release: &serde_json::Value,
    version: &str,
    target: &str,
) -> anyhow::Result<(tempfile::TempDir, PathBuf)> {
    println!(
        "{}",
        Theme::info(&format!("Downloading v{version} for {target}..."))
    );
    let asset_name = format!("astrid-{version}-{target}.tar.gz");
    let url = asset_url(release, &asset_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no release asset '{asset_name}' — no pre-built binary for this platform"
            )
        })?
        .to_string();
    let archive = download(client, &url).await?;

    // Fail closed: a release with no SHA256SUMS.txt is unverifiable, so we refuse
    // to install it rather than swap in an unchecked binary. (SHA256SUMS is
    // integrity, not authenticity — but skipping it entirely would defeat even
    // the on-the-wire / corrupted-download check.)
    let sums_url = asset_url(release, "SHA256SUMS.txt")
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "release has no SHA256SUMS.txt — refusing to install an unverifiable binary"
            )
        })?;
    let sums = download(client, &sums_url).await?;
    let sums_body = String::from_utf8(sums).context("SHA256SUMS.txt is not UTF-8")?;
    verify_sha256(&archive, &sums_body, &asset_name)?;
    println!("{}", Theme::dimmed("Checksum verified."));

    let tmp_dir = tempfile::tempdir()?;
    let archive_path = tmp_dir.path().join(&asset_name);
    std::fs::write(&archive_path, &archive)?;
    {
        let tar_gz = std::fs::File::open(&archive_path)?;
        let decoder = flate2::read::GzDecoder::new(tar_gz);
        let mut tar = tar::Archive::new(decoder);
        tar.unpack(tmp_dir.path())?;
    }
    let extract_dir = tmp_dir.path().join(format!("astrid-{version}-{target}"));
    Ok((tmp_dir, extract_dir))
}

/// After the binary swap: restart a running daemon so the new code takes effect,
/// sync distro + capsules, and warn if the install dir isn't on PATH.
async fn finish_update(install_dir: &Path) -> anyhow::Result<()> {
    if crate::socket_client::proxy_socket_path().exists() {
        println!(
            "{}",
            Theme::info("Stopping the running daemon so the new version loads on next use...")
        );
        if let Err(e) = super::daemon::handle_stop().await {
            println!(
                "{}",
                Theme::warning(&format!(
                    "Could not stop the daemon ({e}); restart it with `astrid restart`."
                ))
            );
        }
    }

    sync_distro_and_capsules().await?;

    if !is_in_path(install_dir) {
        println!(
            "{}",
            Theme::warning(&format!(
                "Note: {} is not on your PATH; run `astrid init` to set it up.",
                install_dir.display()
            ))
        );
    }
    Ok(())
}

/// Re-fetch the distro manifest and sync capsules.
///
/// Compares the remote Distro.toml against the local Distro.lock. If the distro
/// version changed, re-runs init to install new/updated capsules. Then runs
/// `capsule update` for any capsules with newer GitHub releases.
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
    // init is idempotent — if lock is fresh it returns immediately.
    if let Err(e) = super::init::run_init(distro_id).await {
        println!("{}", Theme::warning(&post_update_sync_message(&e)));
    }

    // Update individual capsules (checks GitHub releases for newer versions).
    if let Err(e) = super::capsule::install::update_capsule(None, false).await {
        println!("{}", Theme::warning(&format!("Capsule update: {e}")));
    }

    Ok(())
}

/// Choose the warning text for a failed post-update distro sync.
///
/// The post-swap sync re-runs `init` inside the **still-running old process**
/// (old `CARGO_PKG_VERSION`) after the new binary is already on disk. If the
/// freshly-fetched `Distro.toml` raised its `[distro].astrid-version` floor to
/// the new release, the version gate fires — but here it is *expected and benign*:
/// the on-disk binary is already correct, only the in-flight process is stale, so
/// the raw "Run `astrid update`" text would be confusing right after a successful
/// update. We look for the typed [`AstridVersionTooOld`] and substitute an
/// accurate "takes effect next run" message; every other failure keeps the
/// generic "Distro sync: {e}" warning.
///
/// The match walks the **whole error chain** (`err.chain()`), not just the root,
/// so the softening still fires if a caller has wrapped the gate error with
/// `.context(...)` — a `downcast_ref` on the root alone would silently miss a
/// context-wrapped gate and resurface the confusing raw "Run `astrid update`"
/// text right after a successful update.
///
/// Pure over the error so the decision is unit-testable without running a real
/// update.
fn post_update_sync_message(err: &anyhow::Error) -> String {
    let is_version_gate = err.chain().any(|e| {
        e.downcast_ref::<super::distro::validate::AstridVersionTooOld>()
            .is_some()
    });
    if is_version_gate {
        "The updated distro manifest requires the new astrid; it will take effect \
         on your next run — restart astrid (or re-run `astrid distro apply`)."
            .to_string()
    } else {
        format!("Distro sync: {err}")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homebrew_path_is_detected() {
        assert!(is_homebrew_managed(Path::new(
            "/opt/homebrew/Cellar/astrid/0.8.0/bin/astrid"
        )));
        assert!(is_homebrew_managed(Path::new(
            "/usr/local/Cellar/astrid/0.8.0/bin/astrid"
        )));
        assert!(!is_homebrew_managed(Path::new(
            "/Users/jb/.astrid/bin/astrid"
        )));
        assert!(!is_homebrew_managed(Path::new("/usr/local/bin/astrid")));
        assert!(!is_homebrew_managed(Path::new(
            "/home/jb/.cargo/bin/astrid"
        )));
    }

    #[test]
    fn resolve_repo_precedence_and_validation() {
        // An explicit `--source` wins over env/default and parses owner/repo.
        // (The `None` path falls through to ASTRID_UPDATE_REPO then the default
        // — not asserted here, since the env var can't be isolated under the
        // clippy ban on set_var/remove_var.)
        assert_eq!(
            resolve_repo(Some("acme/astrid")).unwrap(),
            ("acme".to_string(), "astrid".to_string())
        );
        assert!(resolve_repo(Some("no-slash")).is_err());
        assert!(resolve_repo(Some("owner/")).is_err());
        assert!(resolve_repo(Some("/repo")).is_err());
    }

    #[test]
    fn sha256_verification_matches_and_rejects() {
        use sha2::Digest;
        let archive = b"hello astrid";
        let good = to_hex(&sha2::Sha256::digest(archive));
        let body = format!("{good}  astrid-1.0.0-x.tar.gz\n");
        verify_sha256(archive, &body, "astrid-1.0.0-x.tar.gz").expect("matching sum verifies");

        // Wrong sum -> error.
        let bad_body = format!("{}  astrid-1.0.0-x.tar.gz\n", "0".repeat(64));
        assert!(verify_sha256(archive, &bad_body, "astrid-1.0.0-x.tar.gz").is_err());
        // Missing entry -> error.
        assert!(
            verify_sha256(archive, "deadbeef  other.tar.gz\n", "astrid-1.0.0-x.tar.gz").is_err()
        );
    }

    #[test]
    fn backup_and_swap_replaces_and_keeps_backup() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("bin");
        let extract = dir.path().join("new");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&extract).unwrap();

        std::fs::write(install.join("astrid"), b"OLD").unwrap();
        std::fs::write(install.join("astrid-daemon"), b"OLD-D").unwrap();
        std::fs::write(extract.join("astrid"), b"NEW").unwrap();
        std::fs::write(extract.join("astrid-daemon"), b"NEW-D").unwrap();

        backup_and_swap(&install, &extract, MANAGED_BINARIES).unwrap();

        assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"NEW");
        assert_eq!(
            std::fs::read(install.join("astrid-daemon")).unwrap(),
            b"NEW-D"
        );
        // Previous binaries preserved for manual rollback.
        assert_eq!(std::fs::read(install.join("astrid.bak")).unwrap(), b"OLD");
        assert_eq!(
            std::fs::read(install.join("astrid-daemon.bak")).unwrap(),
            b"OLD-D"
        );
        // No staging temps left behind.
        assert!(!install.join(".astrid.new").exists());
    }

    #[test]
    fn backup_and_swap_bails_when_archive_missing_a_binary() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("bin");
        let extract = dir.path().join("new");
        std::fs::create_dir_all(&install).unwrap();
        std::fs::create_dir_all(&extract).unwrap();

        std::fs::write(install.join("astrid"), b"OLD").unwrap();
        std::fs::write(install.join("astrid-daemon"), b"OLD-D").unwrap();
        // Archive only ships `astrid`; `astrid-daemon` is absent.
        std::fs::write(extract.join("astrid"), b"NEW").unwrap();

        assert!(backup_and_swap(&install, &extract, MANAGED_BINARIES).is_err());

        // The completeness check runs before anything is touched: live binaries
        // are unchanged and no backups or staging temps were created.
        assert_eq!(std::fs::read(install.join("astrid")).unwrap(), b"OLD");
        assert_eq!(
            std::fs::read(install.join("astrid-daemon")).unwrap(),
            b"OLD-D"
        );
        assert!(!install.join("astrid.bak").exists());
        assert!(!install.join(".astrid.new").exists());
    }

    #[test]
    fn post_update_sync_message_softens_version_gate() {
        use super::super::distro::validate::AstridVersionTooOld;
        use anyhow::Context as _;

        // The version-floor gate fired during the post-swap sync (old in-flight
        // process, new binary already on disk) — the user must see the benign
        // "takes effect next run" message, NOT the raw "Run `astrid update`" text.
        let gate: anyhow::Error = AstridVersionTooOld {
            req: ">=0.8.0".to_string(),
            running: "0.7.0".to_string(),
        }
        .into();
        let msg = post_update_sync_message(&gate);
        assert!(
            msg.contains("take effect")
                && msg.contains("next run")
                && !msg.contains("Run `astrid update`"),
            "version-gate failure must yield the benign restart message, got: {msg}"
        );

        // FIX F: a CONTEXT-WRAPPED gate error must still be softened. The
        // typed gate is buried under two `.context(...)` layers; the displayed
        // (outermost) message is now the context string, so a match that only
        // looked at the surface text would miss it. `post_update_sync_message`
        // walks `err.chain()` to find `AstridVersionTooOld` underneath.
        let wrapped: anyhow::Error = Err::<(), _>(anyhow::Error::from(AstridVersionTooOld {
            req: ">=0.8.0".to_string(),
            running: "0.7.0".to_string(),
        }))
        .context("re-running init after update")
        .context("syncing distro")
        .unwrap_err();
        // Guard: the outermost display text is the context, not the gate's own
        // message — so the softening must come from a chain walk, not from
        // inspecting the surface error.
        assert_eq!(wrapped.to_string(), "syncing distro");
        assert!(
            wrapped.chain().any(<dyn std::error::Error + 'static>::is::<AstridVersionTooOld>),
            "guard: the typed gate must be reachable by walking the chain"
        );
        let msg = post_update_sync_message(&wrapped);
        assert!(
            msg.contains("take effect")
                && msg.contains("next run")
                && !msg.contains("Run `astrid update`"),
            "context-wrapped version-gate failure must still be softened, got: {msg}"
        );

        // Any OTHER sync failure keeps the generic warn path verbatim.
        let other = anyhow::anyhow!("network unreachable while fetching Distro.toml");
        let msg = post_update_sync_message(&other);
        assert!(
            msg.starts_with("Distro sync:") && msg.contains("network unreachable"),
            "non-gate failure must use the generic warn path, got: {msg}"
        );
    }
}
