//! Signed-channel self-update and PATH setup for `astrid init`.
//!
//! Stable is the default; dev/nightly are explicit. Self-managed installs swap
//! authenticated binaries in place with rollback backups. Homebrew and Cargo
//! remain package-manager owned. Discovery can use a mirror or mock, but the
//! accepted Astrid workflow identities and issuer cannot be overridden.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::cli::UpdateArgs;
use crate::theme::Theme;

use super::UpdateChannel;
use super::update_auth::{
    UpdateStageError, authenticate_archive, extract_verified_archive,
    integrity_manifest_download_error, publisher_bundle_download_error, verify_integrity,
};
use super::update_channel;

#[path = "self_update_notice.rs"]
mod notice;
pub(crate) use notice::print_update_banner;
use notice::{handle_managed_channel, write_cache};

/// Default Astrid release repository. Discovery overrides never widen the
/// authenticated publisher identity.
const DEFAULT_ORG: &str = "astrid-runtime";
const DEFAULT_REPO: &str = "astrid";

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_TTL_SECS: u64 = 86_400;
const MAX_ARCHIVE_BYTES: usize = 100 * 1024 * 1024;
const MAX_RELEASE_ASSETS: usize = 1_024;
const MAX_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;

const MANAGED_BINARIES: &[&str] = &["astrid", "astrid-daemon"];

/// GitHub API base URL. `ASTRID_UPDATE_API` overrides it so the flow can be
/// rehearsed against a local/staging mock server.
pub(super) fn api_base() -> String {
    std::env::var("ASTRID_UPDATE_API").unwrap_or_else(|_| "https://api.github.com".to_string())
}

/// Resolve release discovery: explicit `--source`, environment, then default.
/// Mirrors and mocks must still serve archives signed by Astrid's exact identity.
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

/// The cargo install-bin directories to test a binary against: `$CARGO_HOME/bin`
/// (if set) and the default `~/.cargo/bin`, each canonicalized where possible so
/// a symlinked cargo home still matches the canonicalized running-binary path.
fn cargo_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut push = |base: PathBuf| {
        let bin = base.join("bin");
        // Canonicalize so a symlinked cargo home resolves to the same real path
        // `running_binary()` produced; fall back to the raw join if it can't.
        dirs.push(bin.canonicalize().unwrap_or(bin));
    };
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        push(PathBuf::from(home));
    }
    if let Some(base) = directories::BaseDirs::new() {
        push(base.home_dir().join(".cargo"));
    }
    dirs
}

/// Whether `exe` is a `cargo install`-managed binary. Cargo installs land in
/// `$CARGO_HOME/bin` (default `~/.cargo/bin`). Such installs update via
/// `cargo install`, not an in-place binary swap. Detection tries the resolved
/// cargo-bin directories first (honouring a custom `CARGO_HOME` and resolving
/// symlinks), then falls back to a structural check — a `.cargo` path component
/// immediately followed by `bin`, compared as `OsStr` so a non-UTF-8 component
/// neither drops out nor misaligns the pair. A cargo install we still fail to
/// recognise simply classifies as `SelfManaged` and updates in place, which
/// works (it swaps the binary wherever it lives) — only the shown upgrade hint
/// differs.
fn is_cargo_managed(exe: &Path) -> bool {
    use std::ffi::OsStr;
    if cargo_bin_dirs().iter().any(|dir| exe.starts_with(dir)) {
        return true;
    }
    let comps: Vec<&OsStr> = exe
        .components()
        .map(std::path::Component::as_os_str)
        .collect();
    comps
        .windows(2)
        .any(|w| w[0] == OsStr::new(".cargo") && w[1] == OsStr::new("bin"))
}

/// How the running `astrid` binary is managed. Determines how an update is
/// APPLIED (and the instruction shown); the version CHECK itself is
/// install-method-independent — always the GitHub release, on macOS and Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMethod {
    /// Homebrew (`…/Cellar/astrid/…`) — updates via `brew upgrade`.
    Homebrew,
    /// `cargo install` (`…/.cargo/bin/astrid`) — updates via `cargo install`.
    Cargo,
    /// A self-managed binary (`~/.astrid/bin`, a direct download, …) — updated
    /// in place by downloading the release and atomically swapping the binary.
    SelfManaged,
}

impl InstallMethod {
    /// Classify the running binary from its resolved path.
    fn detect(exe: &Path) -> Self {
        if is_homebrew_managed(exe) {
            Self::Homebrew
        } else if is_cargo_managed(exe) {
            Self::Cargo
        } else {
            Self::SelfManaged
        }
    }

    /// The command a user runs to upgrade this install.
    fn upgrade_command(self, channel: UpdateChannel) -> &'static str {
        match self {
            Self::Homebrew => "brew upgrade astrid",
            Self::Cargo => "cargo install astrid --force",
            Self::SelfManaged => match channel {
                UpdateChannel::Stable => "astrid update",
                UpdateChannel::Dev => "astrid update --channel dev",
                UpdateChannel::Nightly => "astrid update --channel nightly",
            },
        }
    }

    /// Human-readable name of the manager, for the "installed via …" message.
    fn label(self) -> &'static str {
        match self {
            Self::Homebrew => "Homebrew",
            Self::Cargo => "cargo",
            Self::SelfManaged => "a self-managed install",
        }
    }

    /// Whether an external package manager owns the binary, so `astrid update`
    /// must defer to it rather than swapping the binary in place (which would
    /// leave the manager's metadata pointing at a version it no longer controls).
    fn manages_own_binary(self) -> bool {
        matches!(self, Self::Homebrew | Self::Cargo)
    }
}

/// What `astrid update` / `astrid update --check` should do, decided purely from
/// the install method and version comparison. Factored out so the guarantee that
/// a `--check` reports availability for EVERY install method (#1121 — the
/// session-start nudge relies on it) is unit-testable without a network round
/// trip. Before this, the Homebrew branch returned before the check ran, so the
/// nudge never fired for brew installs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdatePlan {
    /// Running version is already >= latest.
    UpToDate,
    /// An update exists; report it and how to get it (any method; `--check`).
    Available { how: &'static str },
    /// An update exists but an external manager owns the binary — defer to it.
    DeferToManager {
        manager: &'static str,
        how: &'static str,
    },
    /// An update exists and we manage the binary — download and swap in place.
    ApplyInPlace,
}

/// Decide the update plan. Pure over its inputs.
fn plan_update(
    method: InstallMethod,
    current: &semver::Version,
    latest: &semver::Version,
    is_check: bool,
    channel: UpdateChannel,
) -> UpdatePlan {
    // A channel is authoritative in either direction. A deliberate rollback is
    // published as a higher signed generation pointing at an older immutable
    // release, so only exact version equality means no action.
    if latest == current {
        return UpdatePlan::UpToDate;
    }
    // A `--check` always REPORTS, regardless of install method — the version
    // check is method-independent, and only reporting (not applying) is asked.
    if is_check {
        return UpdatePlan::Available {
            how: method.upgrade_command(channel),
        };
    }
    if method.manages_own_binary() {
        return UpdatePlan::DeferToManager {
            manager: method.label(),
            how: method.upgrade_command(channel),
        };
    }
    UpdatePlan::ApplyInPlace
}

/// Find exactly one release asset and return its browser download URL.
pub(super) fn exact_asset_url<'a>(
    release: &'a serde_json::Value,
    name: &str,
) -> anyhow::Result<&'a str> {
    let assets = release
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("release has no asset list"))?;
    anyhow::ensure!(
        assets.len() <= MAX_RELEASE_ASSETS,
        "release contains too many assets"
    );
    let mut matches = assets
        .iter()
        .filter(|asset| asset.get("name").and_then(|value| value.as_str()) == Some(name));
    let asset = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("release has no asset '{name}'"))?;
    anyhow::ensure!(
        matches.next().is_none(),
        "release contains duplicate asset '{name}'"
    );
    asset
        .get("browser_download_url")
        .and_then(|value| value.as_str())
        .filter(|url| !url.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release asset '{name}' has no download URL"))
}

fn publisher_bundle_url<'a>(
    release: &'a serde_json::Value,
    archive_name: &str,
) -> Result<&'a str, UpdateStageError> {
    let bundle_name = format!("{archive_name}.sigstore.json");
    exact_asset_url(release, &bundle_name)
        .map_err(|error| UpdateStageError::publisher(error.to_string()))
}

fn integrity_manifest_url(release: &serde_json::Value) -> Result<&str, UpdateStageError> {
    exact_asset_url(release, "BLAKE3SUMS.txt")
        .map_err(|error| UpdateStageError::integrity(error.to_string()))
}

/// Stream a URL into memory under the size cap.
pub(super) async fn download_bounded(
    client: &reqwest::Client,
    url: &str,
    limit: usize,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("{label} download failed"))?;
    if !response.status().is_success() {
        bail!("{label} download failed: HTTP {}", response.status());
    }
    if let Some(length) = response.content_length() {
        let length = usize::try_from(length)
            .map_err(|_| anyhow::anyhow!("{label} exceeds {limit} byte limit"))?;
        anyhow::ensure!(length <= limit, "{label} exceeds {limit} byte limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("{label} download failed"))?
    {
        anyhow::ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "{label} exceeds {limit} byte limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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
/// resolve the signed channel, (for self-managed installs) verify + atomically
/// swap the binary in place with rollback, restart the daemon, then update
/// capsules. Distro refresh requires explicit recorded source provenance and is
/// deliberately skipped by this path. Homebrew installs are deferred to `brew upgrade`.
pub(crate) async fn run_self_update(args: UpdateArgs) -> anyhow::Result<()> {
    let target = platform_target()?;
    let (owner, repo) = resolve_repo(args.source.as_deref())?;
    let exe = running_binary()?;
    let method = InstallMethod::detect(&exe);

    println!(
        "{}",
        Theme::info(&format!(
            "Checking the signed {} channel (current: v{CURRENT_VERSION}, platform: {target}, source: {owner}/{repo})...",
            args.channel
        ))
    );

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resolved =
        update_channel::resolve_signed_channel(&client, &owner, &repo, args.channel, target)
            .await?;
    let version_str = resolved.version;
    let release = resolved.release;
    let current = semver::Version::parse(CURRENT_VERSION)?;
    let latest = semver::Version::parse(&version_str)?;
    write_cache(args.channel, &version_str);

    if handle_managed_channel(method, args.channel, &current, &latest, &version_str)? {
        return Ok(());
    }

    match plan_update(method, &current, &latest, args.check, args.channel) {
        UpdatePlan::UpToDate => {
            println!(
                "{}",
                Theme::success(&format!("Already up to date (v{CURRENT_VERSION})."))
            );
            return Ok(());
        },
        UpdatePlan::Available { how } => {
            println!(
                "{}",
                Theme::info(&format!(
                    "Update available: v{CURRENT_VERSION} → v{version_str}. Run `{how}` to upgrade."
                ))
            );
            return Ok(());
        },
        UpdatePlan::DeferToManager { manager, how } => {
            println!(
                "{}",
                Theme::info(&format!(
                    "Astrid was installed via {manager}. Update it with:\n  {how}"
                ))
            );
            return Ok(());
        },
        UpdatePlan::ApplyInPlace => {},
    }

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

    let (_tmp_dir, extract_dir) = download_verify_extract(
        &client,
        &release,
        &version_str,
        target,
        &resolved.target_blake3,
    )
    .await
    .map_err(anyhow::Error::new)?;

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

/// Authenticate, content-check, and extract one platform archive.
async fn download_verify_extract(
    client: &reqwest::Client,
    release: &serde_json::Value,
    version: &str,
    target: &str,
    expected_blake3: &str,
) -> Result<(tempfile::TempDir, PathBuf), UpdateStageError> {
    println!(
        "{}",
        Theme::info(&format!("Downloading v{version} for {target}..."))
    );
    let asset_name = format!("astrid-{version}-{target}.tar.gz");
    let archive_url = exact_asset_url(release, &asset_name)
        .with_context(|| format!("no pre-built binary for platform {target}"))
        .map_err(UpdateStageError::Preparation)?
        .to_owned();
    let archive = download_bounded(client, &archive_url, MAX_ARCHIVE_BYTES, "release archive")
        .await
        .map_err(UpdateStageError::Preparation)?;

    let bundle_url = publisher_bundle_url(release, &asset_name)?.to_owned();
    let bundle = download_bounded(
        client,
        &bundle_url,
        MAX_BUNDLE_BYTES,
        "publisher-authentication bundle",
    )
    .await
    .map_err(|error| publisher_bundle_download_error(&error))?;
    let authenticated = authenticate_archive(archive, &bundle, version).await?;
    println!("{}", Theme::dimmed("Publisher authenticated."));

    // This remains a separate integrity signal. It neither replaces nor is
    // presented as publisher authentication.
    let sums_url = integrity_manifest_url(release)?.to_owned();
    let sums = download_bounded(
        client,
        &sums_url,
        MAX_MANIFEST_BYTES,
        "BLAKE3 integrity manifest",
    )
    .await
    .map_err(|error| integrity_manifest_download_error(&error))?;
    let sums_body = String::from_utf8(sums)
        .map_err(|_| UpdateStageError::integrity("BLAKE3SUMS.txt is not UTF-8"))?;
    let archive = verify_integrity(
        authenticated,
        &sums_body,
        &asset_name,
        Some(expected_blake3),
    )?;
    println!("{}", Theme::dimmed("Integrity verified."));

    // The mutating boundary accepts only the fully verified archive type.
    extract_verified_archive(archive, &asset_name, &format!("astrid-{version}-{target}"))
        .map_err(UpdateStageError::Preparation)
}

/// After the binary swap: restart a running daemon so the new code takes effect,
/// update capsules, and warn if the install dir isn't on PATH.
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

/// Update capsules after a binary update without inventing distro provenance.
///
/// A lock records only a distro identity, not its source. Re-fetching from that
/// identity would silently choose a product source, so distro refresh is skipped
/// until the operator supplies an explicit source to `astrid init --distro`.
/// Capsule update remains independent and checks installed capsules for releases.
async fn sync_distro_and_capsules() -> anyhow::Result<()> {
    println!();
    println!("{}", Theme::info("Checking distro and capsule updates..."));

    let home = astrid_core::dirs::AstridHome::resolve()?;
    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    // A lock records the installed distro identity, not its canonical source.
    // Do not turn that identity into an organization-qualified network fetch:
    // the runtime has no product source default and must not invent provenance.
    let lock = super::distro::lock::load_lock(&lock_path)?;
    match distro_refresh_action(lock.is_some()) {
        DistroRefreshAction::SkipNoProvenance => {
            println!(
                "{}",
                Theme::warning(
                    "Distro refresh skipped because the installed lock does not record an explicit source. Re-run `astrid init --distro <@owner/repo|URL|path|.shuttle>` to refresh it.",
                )
            );
        },
        DistroRefreshAction::NoInstalledDistro => {},
    }

    // Update individual capsules (checks GitHub releases for newer versions).
    if let Err(e) = super::capsule::install::update_capsule(None, false, false).await {
        println!("{}", Theme::warning(&format!("Capsule update: {e}")));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DistroRefreshAction {
    SkipNoProvenance,
    NoInstalledDistro,
}

const fn distro_refresh_action(has_lock: bool) -> DistroRefreshAction {
    if has_lock {
        DistroRefreshAction::SkipNoProvenance
    } else {
        DistroRefreshAction::NoInstalledDistro
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

/// True if the match starting at byte `start` sits on a `#`-commented
/// (inert) rc line — a `#` appears between the line start and the match.
///
/// A commented line is a no-op in the shell, so treating a match inside one
/// as "already configured" would silently skip the real PATH setup. Both
/// match paths in [`rc_configures_path`] consult this so a commented block or
/// token never counts.
fn match_is_commented(rc: &str, start: usize) -> bool {
    let line_start = rc[..start].rfind('\n').map_or(0, |nl| nl.saturating_add(1));
    rc[line_start..start].contains('#')
}

/// Whether `rc_contents` already puts the bin dir on PATH, so a second run
/// must not append a duplicate block.
///
/// Returns "already configured" (skip the append) only when EITHER the exact
/// block we emit (`export_line`) is present — the reliable idempotency signal,
/// since we always write it verbatim — OR `bin_str` appears as a WHOLE path
/// component: bounded on both sides by a shell PATH-list separator. A bare
/// substring match must NOT count: an rc containing `.astrid/bin_backup` or
/// `.astrid/bin/sub` would otherwise make the guard skip the real
/// `.astrid/bin` setup and silently leave astrid off PATH. A match on a
/// `#`-commented (inert) line is likewise NOT a match, on both paths. When
/// unsure we err toward ADDING the block — a duplicate PATH entry is harmless;
/// a silent skip is not. Pure over its inputs so the guarantee is
/// unit-testable without a real shell rc.
fn rc_configures_path(rc_contents: &str, bin_str: &str, export_line: &str) -> bool {
    // Our exact block is the authoritative "already done" marker — unless it
    // is commented out, in which case it is inert and we must add a live one.
    if let Some(start) = rc_contents.find(export_line)
        && !match_is_commented(rc_contents, start)
    {
        return true;
    }
    if bin_str.is_empty() {
        return false;
    }

    // A PATH entry is bounded by these separators in a shell rc line. The
    // leading set admits assignment/grouping openers (`=`, `(`); the trailing
    // set admits a grouping close (`)`). A following `/`, alphanumeric, `_`,
    // or `-` means `bin_str` is only a prefix of a longer path — NOT a match.
    let is_lead = |c: char| matches!(c, ':' | '"' | '\'' | '=' | '(' | ' ' | '\t' | '\n' | '\r');
    let is_trail = |c: char| matches!(c, ':' | '"' | '\'' | ')' | ' ' | '\t' | '\n' | '\r');

    let mut from = 0;
    while let Some(rel) = rc_contents[from..].find(bin_str) {
        let start = from.saturating_add(rel);
        let end = start.saturating_add(bin_str.len());

        // Skip a match inside a commented-out line, e.g.
        // `# export PATH="…/.astrid/bin:$PATH"`, and keep scanning.
        if match_is_commented(rc_contents, start) {
            from = end;
            continue;
        }

        let lead_ok = start == 0
            || rc_contents[..start]
                .chars()
                .next_back()
                .is_some_and(is_lead);
        let trail_ok =
            end == rc_contents.len() || rc_contents[end..].chars().next().is_some_and(is_trail);
        if lead_ok && trail_ok {
            return true;
        }
        from = end;
    }
    false
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

    // Idempotency: if the rc file already wires the bin dir onto PATH, do
    // NOT append a second block. `astrid init` (and the first-run auto-init)
    // calls this on every run, so an unguarded append would accumulate a
    // duplicate `# Astrid OS` block per invocation.
    if let Ok(contents) = std::fs::read_to_string(&rc_file)
        && rc_configures_path(&contents, &bin_str, &export_line)
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
#[path = "self_update_tests.rs"]
mod tests;
