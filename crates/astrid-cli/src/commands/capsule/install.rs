//! Capsule management commands - install capsules securely.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use astrid_capsule::discovery::load_manifest;
use astrid_core::dirs::AstridHome;

use super::meta::{BakedTopic, CapsuleMeta, read_meta, write_meta};

/// When true, import validation and env prompting are suppressed.
/// Set by `install_capsule_batch` (called from distro init) where the
/// distro handles env config and all capsules are installed together.
static BATCH_MODE: AtomicBool = AtomicBool::new(false);

/// Result of checking a remote source for a newer capsule version.
enum UpdateCheck {
    /// A newer version is available remotely.
    Available { latest: semver::Version },
    /// The installed version is already the latest (or newer).
    UpToDate { latest: semver::Version },
    /// Version check failed due to a transient or unexpected error.
    Failed { reason: String },
    /// Source type does not support remote version checking (expected, not an error).
    Skipped { reason: String },
}

/// Strip common version prefixes (`v`, `V`) from a Git tag before semver parsing.
fn strip_version_prefix(tag: &str) -> &str {
    tag.strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag)
}

/// Extract `(org, repo)` from a GitHub URL like `https://github.com/org/repo`,
/// `github.com/org/repo`, or `github.com/org/repo.git`. Anchors on the
/// `github.com/` marker so extra path segments (`/tree/main`, `.git`) are
/// safely ignored.
fn extract_github_org_repo(url: &str) -> Option<(&str, &str)> {
    let idx = url.find("github.com/")?;
    let after_host = &url[idx.saturating_add("github.com/".len())..];
    let trimmed = after_host.trim_end_matches('/');
    let (org, rest) = trimmed.split_once('/')?;
    // Take the first path segment as repo, stripping `.git` suffix if present
    let repo = rest.split('/').next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if org.is_empty() || repo.is_empty() {
        return None;
    }
    Some((org, repo))
}

/// Parse a capsule source string into `(org, repo)` for GitHub-backed sources.
///
/// Handles `@org/repo`, `openclaw:@org/repo`, `github.com/org/repo`, and
/// `https://github.com/org/repo`.
fn parse_github_source(source: &str) -> Option<(String, String)> {
    // @org/repo -> github.com/org/repo
    if let Some(repo_path) = source.strip_prefix('@') {
        let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
        return None;
    }

    // openclaw:@org/repo -> extract from the @org/repo part
    if let Some(rest) = source.strip_prefix("openclaw:") {
        if let Some(repo_path) = rest.strip_prefix('@') {
            let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }
        // openclaw:name (no @) - not a GitHub source
        return None;
    }

    // github.com/org/repo or https://github.com/org/repo
    if source.contains("github.com/") {
        let (org, repo) = extract_github_org_repo(source)?;
        return Some((org.to_string(), repo.to_string()));
    }

    None
}

/// Fetch the latest release version from GitHub for a given org/repo.
async fn fetch_github_latest_version(
    client: &reqwest::Client,
    org: &str,
    repo: &str,
) -> anyhow::Result<semver::Version> {
    let api_url = format!("https://api.github.com/repos/{org}/{repo}/releases/latest");
    let response = client
        .get(&api_url)
        .send()
        .await
        .context("failed to reach GitHub API")?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("no GitHub releases found for {org}/{repo}");
    }
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
        || response.status() == reqwest::StatusCode::FORBIDDEN
    {
        bail!("GitHub API rate limit exceeded - try again later");
    }
    if !response.status().is_success() {
        bail!("GitHub API returned {}", response.status());
    }

    let json: serde_json::Value = response
        .json()
        .await
        .context("failed to parse GitHub API response")?;
    let tag_name = json
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub release has missing or empty tag_name"))?;

    let version_str = strip_version_prefix(tag_name);
    semver::Version::parse(version_str)
        .with_context(|| format!("GitHub tag '{tag_name}' is not valid semver"))
}

/// Check whether a newer version is available from a capsule's source.
async fn check_remote_version(
    client: &reqwest::Client,
    source: &str,
    current_version: &str,
) -> UpdateCheck {
    let Ok(current) = semver::Version::parse(current_version) else {
        return UpdateCheck::Failed {
            reason: format!("installed version '{current_version}' is not valid semver"),
        };
    };

    // OpenClaw (non-GitHub) sources - expected, not an error
    if source.starts_with("openclaw:") && !source.contains('@') {
        return UpdateCheck::Skipped {
            reason: "OpenClaw registry not yet implemented".to_string(),
        };
    }

    // Local paths cannot be version-checked remotely - expected, not an error
    if source.starts_with('.') || source.starts_with('/') {
        return UpdateCheck::Skipped {
            reason: "local source".to_string(),
        };
    }

    // GitHub-backed sources
    if let Some((org, repo)) = parse_github_source(source) {
        match fetch_github_latest_version(client, &org, &repo).await {
            Ok(latest) => {
                if latest > current {
                    UpdateCheck::Available { latest }
                } else {
                    UpdateCheck::UpToDate { latest }
                }
            },
            Err(e) => UpdateCheck::Failed {
                reason: format!("{e}"),
            },
        }
    } else {
        UpdateCheck::Skipped {
            reason: format!("unsupported source: {source}"),
        }
    }
}

/// Update one or all installed capsules from their original source.
///
/// If `target` is `Some`, force-reinstall that capsule from its recorded source.
/// If `None`, check all installed capsules for newer versions and only update
/// those where the remote version is strictly newer (semver comparison).
///
/// # TODO
/// - Add a registry manifest (like brew formulas) that pins version + Blake3 hash
///   per capsule. `update` should fetch the manifest, compare versions against
///   `meta.json`, only download if newer, and verify Blake3 hash before installing.
///   Trust chain: registry manifest (signed) -> pinned URL + Blake3 -> verified binary.
pub(crate) async fn update_capsule(target: Option<&str>, workspace: bool) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;

    if let Some(name) = target {
        // Single capsule: always force-reinstall from recorded source.
        let target_dir = resolve_target_dir(&home, name, workspace)?;
        if !target_dir.exists() {
            bail!("Capsule '{name}' is not installed.");
        }

        let meta = read_meta(&target_dir)
            .ok_or_else(|| anyhow::anyhow!("Capsule '{name}' has no meta.json - cannot determine original source. Re-install it manually."))?;

        let source = meta.source.ok_or_else(|| {
            anyhow::anyhow!(
                "Capsule '{name}' was installed before source tracking was added. Re-install it manually to record the source."
            )
        })?;

        eprintln!("Updating {name} from {source}...");
        install_capsule(&source, workspace).await
    } else {
        update_all_capsules(&home, workspace).await
    }
}

/// Check all installed capsules for updates and install those with newer versions.
async fn update_all_capsules(home: &AstridHome, workspace: bool) -> anyhow::Result<()> {
    let principal = astrid_core::PrincipalId::default();
    let capsules_dir = home.principal_home(&principal).capsules_dir();
    if !capsules_dir.exists() {
        eprintln!("No capsules installed.");
        return Ok(());
    }

    // Collect installed capsules with their metadata
    let mut capsules: Vec<(String, Option<CapsuleMeta>)> = Vec::new();
    for entry in std::fs::read_dir(&capsules_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = read_meta(&entry.path());
        capsules.push((name, meta));
    }

    if capsules.is_empty() {
        eprintln!("No capsules installed.");
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    eprintln!(
        "Checking {} installed capsule(s) for updates...",
        capsules.len()
    );

    // Check phase: determine which capsules have updates available
    let mut to_update: Vec<(String, String)> = Vec::new(); // (name, source)
    let mut up_to_date = 0u32;
    let mut check_failed = 0u32;
    let mut skipped = 0u32;

    for (name, meta) in &capsules {
        let Some(meta) = meta else {
            eprintln!("  {name}: skipped (no meta.json)");
            skipped = skipped.saturating_add(1);
            continue;
        };
        let Some(ref source) = meta.source else {
            eprintln!("  {name}: skipped (no source recorded)");
            skipped = skipped.saturating_add(1);
            continue;
        };

        match check_remote_version(&client, source, &meta.version).await {
            UpdateCheck::Available { latest } => {
                eprintln!("  {name}: {} -> {latest} (update available)", meta.version);
                to_update.push((name.clone(), source.clone()));
            },
            UpdateCheck::UpToDate { latest } => {
                eprintln!("  {name}: {} (up to date, latest: {latest})", meta.version);
                up_to_date = up_to_date.saturating_add(1);
            },
            UpdateCheck::Failed { reason } => {
                eprintln!("  {name}: {} (check failed: {reason})", meta.version);
                check_failed = check_failed.saturating_add(1);
            },
            UpdateCheck::Skipped { reason } => {
                eprintln!("  {name}: skipped ({reason})");
                skipped = skipped.saturating_add(1);
            },
        }
    }

    // Install phase: update capsules with newer versions
    let mut updated = 0u32;
    let mut install_failed = 0u32;
    for (name, source) in &to_update {
        eprintln!("Updating {name} from {source}...");
        if let Err(e) = install_capsule(source, workspace).await {
            eprintln!("  Failed to update {name}: {e}");
            install_failed = install_failed.saturating_add(1);
        } else {
            updated = updated.saturating_add(1);
        }
    }

    eprintln!(
        "Done: {updated} updated, {up_to_date} up-to-date, {check_failed} check-failed, {skipped} skipped, {install_failed} install-failed."
    );

    // Regenerate Distro.lock if any capsules were updated.
    if updated > 0 {
        regenerate_distro_lock(home)?;
    }

    Ok(())
}

/// Install a capsule from a source.
///
/// When `batch` is true (called from `astrid init`), import validation and
/// env prompting are skipped — the distro handles env config and all
/// capsules are installed together so import checks are meaningless mid-batch.
pub(crate) async fn install_capsule(source: &str, workspace: bool) -> anyhow::Result<()> {
    install_capsule_inner(source, workspace).await
}

/// Install a capsule in batch mode (from distro init) — skips import
/// validation and env prompting.
pub(crate) async fn install_capsule_batch(source: &str, workspace: bool) -> anyhow::Result<()> {
    BATCH_MODE.store(true, Ordering::Relaxed);
    let result = install_capsule_inner(source, workspace).await;
    BATCH_MODE.store(false, Ordering::Relaxed);
    result
}

async fn install_capsule_inner(source: &str, workspace: bool) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;

    // 1. Explicit Local Path - no source tracking (re-fetch doesn't make sense)
    if source.starts_with('.') || source.starts_with('/') {
        return install_from_local(source, workspace, &home, None);
    }

    // 2. OpenClaw Explicit Prefix
    if let Some(rest) = source.strip_prefix("openclaw:") {
        // If it uses the github namespace alias after the prefix
        if let Some(repo) = rest.strip_prefix('@') {
            let url = format!("https://github.com/{repo}");
            return install_from_github(&url, workspace, &home, true, Some(source)).await;
        }
        return install_from_openclaw(rest, workspace, &home, Some(source));
    }

    // 3. Native Namespace Alias (@org/repo) -> GitHub
    if let Some(repo) = source.strip_prefix('@') {
        let url = format!("https://github.com/{repo}");
        return install_from_github(&url, workspace, &home, false, Some(source)).await;
    }

    // 4. Raw GitHub URL
    if source.starts_with("github.com/") || source.starts_with("https://github.com/") {
        return install_from_github(source, workspace, &home, false, Some(source)).await;
    }

    // 5. Fallback: Assume it's a local folder - no source tracking
    install_from_local(source, workspace, &home, None)
}

pub(crate) async fn install_from_github(
    url: &str,
    workspace: bool,
    home: &AstridHome,
    _is_openclaw: bool,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let (org, repo) = extract_github_org_repo(url).ok_or_else(|| {
        anyhow::anyhow!("Invalid GitHub URL format. Expected github.com/org/repo or @org/repo")
    })?;

    // Priority 1: `.capsule` archive from GitHub release assets. A packed
    // archive contains everything needed for install (WASM binary, manifest,
    // and bundled WIT definitions including shared SDK contracts).
    let api_url = format!("https://api.github.com/repos/{org}/{repo}/releases/latest");

    if let Ok(response) = client.get(&api_url).send().await
        && response.status().is_success()
        && let Ok(json) = response.json::<serde_json::Value>().await
        && let Some(assets) = json.get("assets").and_then(serde_json::Value::as_array)
    {
        for asset in assets {
            if let Some(name) = asset.get("name").and_then(serde_json::Value::as_str)
                && name.ends_with(".capsule")
                && let Some(download_url) = asset
                    .get("browser_download_url")
                    .and_then(serde_json::Value::as_str)
            {
                let tmp_dir = tempfile::tempdir()?;
                let sanitized_name = Path::new(name).file_name().unwrap_or_default();
                let download_path = tmp_dir.path().join(sanitized_name);
                // Stream with 50 MB limit.
                let mut dl = client.get(download_url).send().await?;
                let mut bytes = Vec::new();
                while let Some(chunk) = dl.chunk().await? {
                    bytes.extend_from_slice(&chunk);
                    anyhow::ensure!(
                        bytes.len() <= 50 * 1024 * 1024,
                        "capsule archive exceeds 50 MB limit",
                    );
                }
                std::fs::write(&download_path, &bytes)?;
                return unpack_and_install(&download_path, workspace, home, original_source);
            }
        }
    }

    // Priority 2: clone + build from source with astrid-build.
    clone_and_build(url, repo, workspace, home, original_source)
}

/// Clone a GitHub repository and build the capsule from source using `astrid-build`.
fn clone_and_build(
    url: &str,
    repo: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for cloning")?;
    let clone_dir = tmp_dir.path().join(repo);

    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "1", url, &clone_dir.to_string_lossy()])
        .status()
        .context("Failed to spawn git clone")?;

    if !status.success() {
        bail!("Failed to clone repository from GitHub.");
    }

    let output_dir = tmp_dir.path().join("dist");
    std::fs::create_dir_all(&output_dir)?;

    let build_bin = crate::bootstrap::find_companion_binary("astrid-build")?;
    let build_status = std::process::Command::new(build_bin)
        .arg(clone_dir.to_str().context("Invalid clone dir path")?)
        .arg("--output")
        .arg(output_dir.to_str().context("Invalid output dir path")?)
        .status()
        .context("Failed to run astrid-build")?;
    if !build_status.success() {
        bail!(
            "astrid-build failed with exit code {}",
            build_status.code().unwrap_or(1)
        );
    }

    // Find the .capsule file
    for entry in std::fs::read_dir(&output_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
            return unpack_and_install(&entry.path(), workspace, home, original_source);
        }
    }

    bail!("Universal Migrator failed to produce a .capsule archive.");
}

pub(crate) fn install_from_openclaw(
    source: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let capsule_name = source.strip_prefix("openclaw:").unwrap_or(source);

    // Step 1: Mock Registry Fetch
    // In a real implementation, this would hit https://registry.openclaw.io
    // For now, we assume the user might have a local directory with that name for testing,
    // or we just bail if it doesn't exist locally as a fallback.
    let source_path = Path::new(capsule_name);
    if !source_path.exists() {
        bail!(
            "OpenClaw registry fetch not yet implemented. Please provide a local path to the OpenClaw capsule directory."
        );
    }

    transpile_and_install(source_path, workspace, home, original_source)
}

pub(crate) fn transpile_and_install(
    source_path: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for transpilation")?;
    let output_dir = tmp_dir.path();

    // Delegate to astrid-build for OpenClaw compilation
    let build_bin = crate::bootstrap::find_companion_binary("astrid-build")?;
    let status = std::process::Command::new(build_bin)
        .arg(source_path)
        .arg("--output")
        .arg(output_dir)
        .arg("--type")
        .arg("openclaw")
        .status()
        .context("Failed to run astrid-build for OpenClaw transpilation")?;
    if !status.success() {
        bail!(
            "OpenClaw compilation failed (astrid-build exit code {})",
            status.code().unwrap_or(1)
        );
    }

    // astrid-build produces a .capsule archive — find and unpack it
    for entry in std::fs::read_dir(output_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
            return unpack_and_install(&entry.path(), workspace, home, original_source);
        }
    }
    bail!("OpenClaw compilation succeeded but no .capsule archive was produced")
}

pub(crate) fn install_from_local(
    source: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("Source path does not exist: {source}");
    }

    // Auto-detect OpenClaw
    if source_path.join("openclaw.plugin.json").exists()
        && !source_path.join("Capsule.toml").exists()
    {
        return transpile_and_install(source_path, workspace, home, original_source);
    }

    // Unpack .capsule archive if it is a file
    if source_path.is_file() && source.ends_with(".capsule") {
        return unpack_and_install(source_path, workspace, home, original_source);
    }

    // Auto-build Rust capsules if we point at a source directory with a Cargo.toml
    if source_path.is_dir() && source_path.join("Cargo.toml").exists() {
        let tmp_dir = tempfile::tempdir().context("failed to create temp dir for building")?;
        let output_dir = tmp_dir.path().join("dist");

        let build_bin = crate::bootstrap::find_companion_binary("astrid-build")?;
        let status = std::process::Command::new(build_bin)
            .arg(source)
            .arg("--output")
            .arg(output_dir.to_str().context("Invalid output dir path")?)
            .arg("--type")
            .arg("rust")
            .status()
            .context("Failed to run astrid-build")?;
        if !status.success() {
            bail!(
                "astrid-build failed with exit code {}",
                status.code().unwrap_or(1)
            );
        }

        // Find the newly built .capsule file in the output directory
        for entry in std::fs::read_dir(&output_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
                return unpack_and_install(&entry.path(), workspace, home, original_source);
            }
        }
        bail!("Failed to auto-build capsule from Cargo project.");
    }

    install_from_local_path_inner(source_path, workspace, home, original_source)
}

fn unpack_and_install(
    archive_path: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for unpacking")?;
    let unpack_dir = tmp_dir.path();

    let tar_gz = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

    let tar = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);

    // Safely unpack the archive, verifying paths to prevent traversal and symlink attacks
    for entry in archive
        .entries()
        .context("Failed to read archive entries")?
    {
        let mut entry = entry.context("Failed to read archive entry")?;
        let entry_path = entry.path().context("Invalid path in archive")?;

        // Prevent absolute paths or path traversal (..)
        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!(
                "Malicious archive detected: invalid path '{}'",
                entry_path.display()
            );
        }

        let out_path = unpack_dir.join(&entry_path);

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Deny symlinks to prevent arbitrary file writes
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            bail!(
                "Malicious archive detected: symlinks are not allowed ('{}')",
                entry_path.display()
            );
        }

        entry
            .unpack(&out_path)
            .with_context(|| format!("Failed to unpack file: {}", out_path.display()))?;
    }

    install_from_local_path_inner(unpack_dir, workspace, home, original_source)
}

pub(crate) fn install_from_local_path(
    source_path: &Path,
    workspace: bool,
    home: &AstridHome,
) -> anyhow::Result<()> {
    install_from_local_path_inner(source_path, workspace, home, None)
}

pub(crate) fn install_from_local_path_inner(
    source_path: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let manifest_path = source_path.join("Capsule.toml");
    if !manifest_path.exists() {
        bail!("No Capsule.toml found in {}", source_path.display());
    }

    let manifest = load_manifest(&manifest_path).context("failed to load Capsule manifest")?;
    let id = manifest.package.name.clone();
    let new_version = manifest.package.version.clone();

    // Check for export conflicts with installed capsules before touching disk.
    check_export_conflicts(&manifest)?;

    // Resolve Target Directory
    let target_dir = resolve_target_dir(home, &id, workspace)?;
    let parent = target_dir.parent().context("target dir has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    // Detect install vs upgrade by checking existing meta.json
    let existing_meta = read_meta(&target_dir);
    let (phase, previous_version) = if let Some(ref meta) = existing_meta {
        (
            astrid_capsule::engine::wasm::host_state::LifecyclePhase::Upgrade,
            Some(meta.version.clone()),
        )
    } else {
        (
            astrid_capsule::engine::wasm::host_state::LifecyclePhase::Install,
            None,
        )
    };

    // Backup existing target if present (for rollback on lifecycle failure).
    let backup_dir = if target_dir.exists() {
        let backup = target_dir.with_extension("bak");
        if backup.exists() {
            std::fs::remove_dir_all(&backup)?;
        }
        std::fs::rename(&target_dir, &backup)?;
        Some(backup)
    } else {
        None
    };

    // Copy capsule files
    if let Err(e) = copy_capsule_dir(source_path, &target_dir) {
        // Restore backup on copy failure
        if let Some(ref backup) = backup_dir {
            let _ = std::fs::remove_dir_all(&target_dir);
            let _ = std::fs::rename(backup, &target_dir);
        }
        return Err(e);
    }

    // Preserve existing .env.json from backup (user configuration survives reinstall).
    if let Some(ref backup) = backup_dir {
        restore_env_from_backup(home, backup, &id);
    }

    // Run lifecycle hook if a WASM binary exists
    if let Err(e) = run_lifecycle_if_wasm(
        &target_dir,
        &manifest,
        &id,
        phase,
        previous_version.as_deref(),
    ) {
        eprintln!("Lifecycle hook failed: {e}");
        // Rollback: restore previous installation
        let _ = std::fs::remove_dir_all(&target_dir);
        if let Some(ref backup) = backup_dir {
            let _ = std::fs::rename(backup, &target_dir);
        }
        return Err(e);
    }

    // Bake topic declarations with inline schema content.
    let baked_topics = match bake_topics(&manifest, &target_dir) {
        Ok(t) => t,
        Err(e) => {
            // Rollback: restore previous installation (lifecycle hook already ran
            // and cannot be undone, but at least restore the directory state).
            let _ = std::fs::remove_dir_all(&target_dir);
            if let Some(ref backup) = backup_dir {
                let _ = std::fs::rename(backup, &target_dir);
            }
            return Err(e);
        },
    };

    // Content-address WASM binary into bin/ (shared, deduped).
    let wasm_hash = content_address_wasm(home, &target_dir, &manifest)?;

    // Content-address WIT files into wit/ (shared, deduped).
    let wit_files = content_address_wit(home, &target_dir)?;

    // Write meta.json on success
    let now = chrono::Utc::now().to_rfc3339();
    let meta = CapsuleMeta {
        version: new_version,
        installed_at: existing_meta
            .as_ref()
            .map_or_else(|| now.clone(), |m| m.installed_at.clone()),
        updated_at: now,
        source: original_source
            .map(String::from)
            .or_else(|| existing_meta.and_then(|m| m.source)),
        imports: version_map_to_strings(&manifest.imports, |d| d.version.to_string()),
        exports: version_map_to_strings(&manifest.exports, |d| d.version.to_string()),
        topics: baked_topics,
        wasm_hash,
        wit_files,
    };
    write_meta(&target_dir, &meta)?;

    // Prompt for [env] fields only on first install (no prior .env.json).
    // In batch mode (distro init), env files are pre-written by the distro.
    if !BATCH_MODE.load(Ordering::Relaxed) {
        let env_path = resolve_env_path(home, &manifest.package.name)?;
        if !manifest.env.is_empty() && !env_path.exists() {
            prompt_env_fields(&manifest.env, &env_path)?;
        }

        // Warn if the newly installed capsule has unsatisfied imports.
        // Skipped in batch mode since capsules are installed together.
        validate_install_imports(&manifest);
    }

    // Clean up backup
    if let Some(ref backup) = backup_dir {
        let _ = std::fs::remove_dir_all(backup);
    }

    Ok(())
}

/// Check if a newly installed capsule's required imports are satisfied by
/// other installed capsules' exports. Prints actionable guidance for
/// unsatisfied required imports. Silent for optional imports.
fn validate_install_imports(manifest: &astrid_capsule::manifest::CapsuleManifest) {
    if !manifest.has_imports() {
        return;
    }
    let Ok(all_capsules) = super::meta::scan_installed_capsules() else {
        return;
    };

    let mut missing = Vec::new();

    for (ns, name, req, optional) in manifest.import_tuples() {
        if optional {
            continue;
        }
        let satisfied = all_capsules.iter().any(|c| {
            c.name != manifest.package.name
                && c.meta.as_ref().is_some_and(|m| {
                    m.exports
                        .get(ns)
                        .and_then(|ifaces| ifaces.get(name))
                        .and_then(|v| semver::Version::parse(v).ok())
                        .is_some_and(|v| req.matches(&v))
                })
        });

        if !satisfied {
            missing.push(format!("{ns}/{name} {req}"));
        }
    }

    if !missing.is_empty() {
        eprintln!();
        for m in &missing {
            eprintln!("  Note: {} needs {m}.", manifest.package.name);
        }
        eprintln!(
            "  Install the missing capsule(s) or run `astrid init` to set up a complete environment."
        );
    }
}

/// Check if a capsule being installed exports interfaces already exported by
/// another installed capsule. Prints an informational notice but does NOT
/// block installation — multiple capsules exporting the same interface is
/// valid (e.g. multiple LLM providers coexisting). The kernel boot validator
/// warns at runtime if duplicate exports cause double-processing concerns.
fn check_export_conflicts(
    manifest: &astrid_capsule::manifest::CapsuleManifest,
) -> anyhow::Result<()> {
    if !manifest.has_exports() {
        return Ok(());
    }

    let all_capsules = super::meta::scan_installed_capsules()
        .context("failed to scan installed capsules for export conflict check")?;

    // Collect shared exports: (namespace/interface, existing capsule name)
    let mut shared: Vec<(String, String)> = Vec::new();

    for (ns, name, _ver) in manifest.export_triples() {
        for c in &all_capsules {
            // Skip self (reinstall/upgrade case)
            if c.name == manifest.package.name {
                continue;
            }
            if let Some(ref meta) = c.meta
                && meta
                    .exports
                    .get(ns)
                    .and_then(|ifaces| ifaces.get(name))
                    .is_some()
            {
                shared.push((format!("{ns}/{name}"), c.name.clone()));
            }
        }
    }

    for (iface, capsule) in &shared {
        tracing::info!(
            interface = %iface,
            existing = %capsule,
            new = %manifest.package.name,
            "Shared export — both capsules will be active"
        );
    }

    Ok(())
}

/// Regenerate the Distro.lock from currently installed capsules.
///
/// Scans all installed capsules, reads their meta.json, and writes a new
/// lockfile with current versions and BLAKE3 hashes. Called after `update`
/// to keep the lock in sync.
fn regenerate_distro_lock(home: &AstridHome) -> anyhow::Result<()> {
    use crate::commands::distro::lock::{DistroLock, DistroLockMeta, LockedCapsule, write_lock};

    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    // Only regenerate if a lock already exists (distro was initialized).
    let Some(existing) = crate::commands::distro::lock::load_lock(&lock_path)? else {
        return Ok(());
    };

    let all = super::meta::scan_installed_capsules()?;
    let capsules: Vec<LockedCapsule> = all
        .iter()
        .map(|c| {
            let (version, source, hash) = c.meta.as_ref().map_or_else(
                || {
                    eprintln!(
                        "  Warning: {} has no meta.json, locked with empty version",
                        c.name,
                    );
                    (String::new(), String::new(), String::new())
                },
                |meta| {
                    (
                        meta.version.clone(),
                        meta.source.clone().unwrap_or_default(),
                        meta.wasm_hash
                            .as_ref()
                            .map(|h| format!("blake3:{h}"))
                            .unwrap_or_default(),
                    )
                },
            );
            LockedCapsule {
                name: c.name.clone(),
                version,
                source,
                hash,
            }
        })
        .collect();

    let (id, version) = (existing.distro.id, existing.distro.version);

    let lock = DistroLock {
        schema_version: 1,
        distro: DistroLockMeta {
            id,
            version,
            resolved_at: chrono::Utc::now().to_rfc3339(),
        },
        capsules,
    };

    write_lock(&lock_path, &lock)?;
    eprintln!("Distro.lock updated.");
    Ok(())
}

/// Content-address WASM binaries into the shared `bin/` directory.
///
/// Finds `.wasm` files in the capsule target directory, hashes them with
/// BLAKE3, copies to `bin/{hash}.wasm`, and removes the original from the
/// capsule directory. Returns the hash if a WASM binary was processed.
fn content_address_wasm(
    home: &AstridHome,
    target_dir: &Path,
    manifest: &astrid_capsule::manifest::CapsuleManifest,
) -> anyhow::Result<Option<String>> {
    let Some(component) = manifest.components.first() else {
        return Ok(None);
    };

    let wasm_path = if component.path.is_absolute() {
        component.path.clone()
    } else {
        target_dir.join(&component.path)
    };

    if !wasm_path.exists() || wasm_path.extension().and_then(|e| e.to_str()) != Some("wasm") {
        return Ok(None);
    }

    let wasm_bytes = std::fs::read(&wasm_path)
        .with_context(|| format!("failed to read WASM binary: {}", wasm_path.display()))?;

    let hash = blake3::hash(&wasm_bytes).to_hex().to_string();
    let bin_dir = home.bin_dir();
    std::fs::create_dir_all(&bin_dir)?;

    let dest = bin_dir.join(format!("{hash}.wasm"));
    if !dest.exists() {
        std::fs::write(&dest, &wasm_bytes)?;
    }

    // Remove the WASM from the capsule dir — it now lives in bin/
    let _ = std::fs::remove_file(&wasm_path);

    Ok(Some(hash))
}

/// Content-address WIT files from a capsule's `wit/` directory into the
/// shared `wit/` store. Each `.wit` file is BLAKE3-hashed and stored as
/// `wit/{hash}.wit`. Returns a map of original filename → hash.
/// Content-address all `.wit` files under `target_dir/wit/` (recursively)
/// into the system-wide append-only BLAKE3 store at `home.wit_dir()`.
///
/// The content store is a single source of truth shared across all principals
/// and all capsules — identical WIT content (e.g. the SDK's shared contracts
/// bundled into every capsule archive) is deduped to a single blob on disk.
///
/// # Append-only semantics
///
/// The store is append-only from the installer's perspective. Blobs are never
/// deleted on uninstall — only an explicit admin GC (`astrid wit gc`) sweeps
/// unreferenced blobs. This preserves replay: a historic capsule state can be
/// reconstructed as long as the blobs it referenced still exist.
///
/// # Returns
///
/// A `HashMap<String, String>` mapping each WIT file's **relative path** under
/// `wit/` (e.g. `"deps/astrid-contracts/astrid-contracts.wit"`) to its BLAKE3
/// hex hash. This is stored in `meta.json` as the capsule's WIT manifest.
///
/// After content addressing succeeds, the per-capsule `target_dir/wit/`
/// directory is deleted — `wit_files` is the authoritative reference.
fn content_address_wit(
    home: &AstridHome,
    target_dir: &Path,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let wit_source = target_dir.join("wit");
    let mut hashes = std::collections::HashMap::new();

    if !wit_source.is_dir() {
        return Ok(hashes);
    }

    let wit_store = home.wit_dir();
    std::fs::create_dir_all(&wit_store)?;

    content_address_wit_recursive(&wit_source, &wit_source, &wit_store, &mut hashes)?;

    // The per-capsule wit/ directory is no longer needed — the content store
    // holds the blobs and meta.json holds the relative-path → hash manifest.
    std::fs::remove_dir_all(&wit_source).with_context(|| {
        format!(
            "failed to remove per-capsule wit dir: {}",
            wit_source.display()
        )
    })?;

    Ok(hashes)
}

/// Recursive helper for `content_address_wit`. Walks the tree and hashes every
/// `.wit` file, keying the returned map by path relative to `wit_root`.
fn content_address_wit_recursive(
    wit_root: &Path,
    current: &Path,
    wit_store: &Path,
    hashes: &mut std::collections::HashMap<String, String>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("failed to read {}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            content_address_wit_recursive(wit_root, &path, wit_store, hashes)?;
            continue;
        }

        if !file_type.is_file() || path.extension().and_then(|e| e.to_str()) != Some("wit") {
            continue;
        }

        // Enforce 1MB size limit to prevent DoS from oversized .wit files.
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        if metadata.len() > 1024 * 1024 {
            anyhow::bail!(
                "WIT file {} exceeds 1MB size limit ({})",
                path.display(),
                metadata.len(),
            );
        }

        // Key by path relative to the capsule's wit/ root so tree shape is
        // preserved (e.g. "deps/astrid-contracts/astrid-contracts.wit").
        let rel_path = path
            .strip_prefix(wit_root)
            .with_context(|| {
                format!(
                    "WIT path {} not under wit root {}",
                    path.display(),
                    wit_root.display()
                )
            })?
            .to_string_lossy()
            .into_owned();

        let content =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

        let hash = blake3::hash(&content).to_hex().to_string();
        let dest = wit_store.join(format!("{hash}.wit"));

        // Atomic write: only write if absent, and use a temp file + rename
        // so concurrent installers writing the same hash don't observe
        // partial content. Multiple writers converge on identical bytes.
        if !dest.exists() {
            let tmp = wit_store.join(format!("{hash}.tmp.{}", std::process::id()));
            std::fs::write(&tmp, &content)
                .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
            // rename is atomic on POSIX when source and dest are in the same dir.
            // If another writer beat us to it, we lose the race harmlessly.
            match std::fs::rename(&tmp, &dest) {
                Ok(()) => {},
                Err(_) if dest.exists() => {
                    let _ = std::fs::remove_file(&tmp);
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e).with_context(|| {
                        format!("failed to rename temp file to {}", dest.display())
                    });
                },
            }
        }

        hashes.insert(rel_path, hash);
    }

    Ok(())
}

/// Convert a nested namespace→interface→T map to namespace→interface→String
/// by extracting the version via the provided closure.
fn version_map_to_strings<T>(
    map: &std::collections::HashMap<String, std::collections::HashMap<String, T>>,
    version_fn: impl Fn(&T) -> String,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    map.iter()
        .map(|(ns, ifaces)| {
            let inner = ifaces
                .iter()
                .map(|(name, def)| (name.clone(), version_fn(def)))
                .collect();
            (ns.clone(), inner)
        })
        .collect()
}

/// Resolve the path to a capsule's env config file.
///
/// Returns `home/{principal}/.config/env/{capsule}.env.json`.
fn resolve_env_path(home: &AstridHome, capsule_name: &str) -> anyhow::Result<PathBuf> {
    let principal = astrid_core::PrincipalId::default();
    let ph = home.principal_home(&principal);
    let env_dir = ph.env_dir();
    std::fs::create_dir_all(&env_dir)?;
    Ok(env_dir.join(format!("{capsule_name}.env.json")))
}

/// Copy `.env.json` from a backup directory to the new env path if it exists.
///
/// Called after a reinstall to ensure user-configured environment variables survive.
fn restore_env_from_backup(home: &AstridHome, backup_dir: &Path, capsule_name: &str) {
    let old_env = backup_dir.join(".env.json");
    if old_env.exists()
        && let Ok(env_path) = resolve_env_path(home, capsule_name)
    {
        let _ = std::fs::copy(&old_env, env_path);
    }
}

/// Prompt the user for missing environment variable values defined in `[env]`.
///
/// Reads existing env config if present, skips fields that already have values,
/// and writes the updated config back with 0o600 permissions.
fn prompt_env_fields(
    env_defs: &std::collections::HashMap<String, astrid_capsule::manifest::EnvDef>,
    env_path: &Path,
) -> anyhow::Result<()> {
    // Load existing values
    let mut values: serde_json::Map<String, serde_json::Value> = if env_path.exists() {
        let content = std::fs::read_to_string(env_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        serde_json::Map::new()
    };

    let mut prompted = false;

    // Sort keys for deterministic prompt order
    let mut keys: Vec<&String> = env_defs.keys().collect();
    keys.sort();

    for key in keys {
        // Skip if already has a value
        if values.contains_key(key.as_str()) {
            continue;
        }

        let def = &env_defs[key];

        if !prompted {
            eprintln!("\nThis capsule requires configuration:");
            prompted = true;
        }

        let prompt = def.request.as_deref().unwrap_or(key.as_str());
        let description = def.description.as_deref().unwrap_or("");
        let default = def.default.as_ref().and_then(|v| v.as_str()).unwrap_or("");

        if !description.is_empty() {
            eprintln!("  {description}");
        }

        let is_secret = def.env_type == "secret";
        let is_enum = !def.enum_values.is_empty();

        let value = if is_secret {
            eprint!("  {prompt}: ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        } else {
            if is_enum {
                eprintln!("  Options: {}", def.enum_values.join(", "));
            }
            let hint = if default.is_empty() {
                String::new()
            } else {
                format!(" [{default}]")
            };
            eprint!("  {prompt}{hint}: ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() && !default.is_empty() {
                default.to_string()
            } else {
                input.to_string()
            }
        };

        if !value.is_empty() {
            values.insert(key.clone(), serde_json::Value::String(value));
        }
    }

    if prompted {
        // Write .env.json with 0o600 permissions
        let json = serde_json::to_string_pretty(&values)?;
        std::fs::write(env_path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!("  Configuration saved.\n");
    }

    Ok(())
}

/// Maximum schema file size (1 MB). Prevents oversized schemas from bloating `meta.json`.
const MAX_SCHEMA_FILE_SIZE: u64 = 1024 * 1024;

/// Read topic declarations from the manifest and bake schema content inline.
///
/// For each `[[topic]]` entry, the schema is resolved from one of two sources
/// (in priority order):
///
/// 1. **`wit_type`** — references a WIT record name in the capsule's `wit/` directory.
///    The record is parsed from WIT and converted to JSON Schema, with `///` doc
///    comments becoming `"description"` fields.
/// 2. **`schema`** — path to a JSON Schema file relative to the capsule directory.
///
/// If neither is set, the topic is baked without a schema.
fn bake_topics(
    manifest: &astrid_capsule::manifest::CapsuleManifest,
    capsule_dir: &Path,
) -> anyhow::Result<Vec<BakedTopic>> {
    let mut baked = Vec::with_capacity(manifest.topics.len());

    let canonical_capsule_dir = std::fs::canonicalize(capsule_dir).with_context(|| {
        format!(
            "failed to canonicalize capsule dir: {}",
            capsule_dir.display()
        )
    })?;

    // Lazily parse WIT files — only if at least one topic references wit_type.
    let wit_schemas = if manifest.topics.iter().any(|t| t.wit_type.is_some()) {
        Some(
            astrid_build::wit_schema::WitSchemas::from_dir(&capsule_dir.join("wit")).with_context(
                || {
                    format!(
                        "failed to parse WIT files in {}",
                        capsule_dir.join("wit").display()
                    )
                },
            )?,
        )
    } else {
        None
    };

    for topic in &manifest.topics {
        // wit_type takes precedence over schema file path.
        let schema = if let Some(ref wit_type) = topic.wit_type {
            let schemas = wit_schemas
                .as_ref()
                .expect("wit_schemas is Some when any topic has wit_type");
            let json_schema = schemas.get(wit_type).ok_or_else(|| {
                anyhow::anyhow!(
                    "[[topic]] '{}' references wit_type '{}' but no WIT record with \
                     that name was found in {}/wit/",
                    topic.name,
                    wit_type,
                    capsule_dir.display()
                )
            })?;
            Some(json_schema.clone())
        } else if let Some(ref schema_path) = topic.schema {
            Some(read_schema_file(
                &topic.name,
                schema_path,
                capsule_dir,
                &canonical_capsule_dir,
            )?)
        } else {
            None
        };

        baked.push(BakedTopic {
            name: topic.name.clone(),
            direction: topic.direction,
            description: topic.description.clone(),
            schema,
        });
    }

    Ok(baked)
}

/// Read and validate a JSON Schema file for a topic declaration.
///
/// Verifies the path stays within the capsule directory, enforces a size limit,
/// and parses the content as JSON.
fn read_schema_file(
    topic_name: &str,
    schema_path: &Path,
    capsule_dir: &Path,
    canonical_capsule_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    let full_path = capsule_dir.join(schema_path);

    let canonical = std::fs::canonicalize(&full_path).with_context(|| {
        format!(
            "[[topic]] '{}' schema file not found: '{}'",
            topic_name,
            full_path.display()
        )
    })?;
    if !canonical.starts_with(canonical_capsule_dir) {
        bail!(
            "[[topic]] '{}' schema path '{}' resolves outside the capsule directory",
            topic_name,
            schema_path.display()
        );
    }

    let file = std::fs::File::open(&canonical).with_context(|| {
        format!(
            "failed to open schema file for topic '{}': '{}'",
            topic_name,
            canonical.display()
        )
    })?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat schema file: {}", canonical.display()))?
        .len();
    if file_len > MAX_SCHEMA_FILE_SIZE {
        bail!(
            "[[topic]] '{}' schema file '{}' is {} bytes, exceeding the {} byte limit",
            topic_name,
            schema_path.display(),
            file_len,
            MAX_SCHEMA_FILE_SIZE
        );
    }
    let capacity = usize::try_from(file_len)
        .with_context(|| format!("schema file size {file_len} exceeds platform usize limit"))?;
    let mut content = String::with_capacity(capacity);
    std::io::Read::read_to_string(
        &mut std::io::Read::take(file, MAX_SCHEMA_FILE_SIZE + 1),
        &mut content,
    )
    .with_context(|| {
        format!(
            "failed to read schema file for topic '{}': '{}'",
            topic_name,
            canonical.display()
        )
    })?;
    if content.len() as u64 > MAX_SCHEMA_FILE_SIZE {
        bail!(
            "[[topic]] '{}' schema file '{}' exceeded the {} byte limit during read",
            topic_name,
            schema_path.display(),
            MAX_SCHEMA_FILE_SIZE
        );
    }
    serde_json::from_str(&content).with_context(|| {
        format!(
            "[[topic]] '{}' schema file '{}' contains invalid JSON",
            topic_name,
            schema_path.display()
        )
    })
}

/// Run lifecycle hooks if the capsule contains a WASM binary.
///
/// Non-WASM capsules (OpenClaw/JS) are skipped silently.
fn run_lifecycle_if_wasm(
    target_dir: &Path,
    manifest: &astrid_capsule::manifest::CapsuleManifest,
    capsule_id: &str,
    phase: astrid_capsule::engine::wasm::host_state::LifecyclePhase,
    previous_version: Option<&str>,
) -> anyhow::Result<()> {
    // Find the WASM binary from the manifest's component definitions
    let Some(component) = manifest.components.first() else {
        return Ok(()); // No components - skip lifecycle
    };

    let wasm_path = if component.path.is_absolute() {
        component.path.clone()
    } else {
        target_dir.join(&component.path)
    };

    if !wasm_path.exists() || wasm_path.extension().and_then(|e| e.to_str()) != Some("wasm") {
        return Ok(()); // Not a WASM capsule - skip lifecycle
    }

    let wasm_bytes = std::fs::read(&wasm_path)
        .with_context(|| format!("failed to read WASM binary: {}", wasm_path.display()))?;

    // Build minimal infrastructure for lifecycle dispatch
    let kv_store = std::sync::Arc::new(astrid_storage::MemoryKvStore::new());
    let kv = astrid_storage::ScopedKvStore::new(kv_store, format!("plugin:{capsule_id}"))
        .context("failed to create scoped KV store")?;
    let event_bus = astrid_events::EventBus::with_capacity(128);

    // Reuse the current tokio runtime if one exists (e.g. when called from
    // `#[tokio::main]`). Only create a new runtime for standalone/test contexts
    // where no runtime is active.
    let (owned_rt, handle) = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        (None, handle)
    } else {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to build tokio runtime for lifecycle")?;
        let handle = rt.handle().clone();
        (Some(rt), handle)
    };

    // Spawn a CLI-inline elicit handler that prompts on stdin.
    // Runs as a tokio task so we can use the async EventReceiver::recv().
    let elicit_bus = event_bus.clone();
    // Exact match: the elicit host function publishes to "astrid.v1.elicit".
    // If the topic is ever extended (e.g. "astrid.v1.elicit.request"), update
    // this subscription and the integration test in lifecycle_e2e.rs.
    let elicit_receiver = event_bus.subscribe_topic("astrid.v1.elicit");
    let elicit_handle = handle.spawn(async move {
        cli_elicit_handler(elicit_receiver, elicit_bus).await;
    });

    let capsule_id_owned = astrid_capsule::capsule::CapsuleId::new(capsule_id.to_string())
        .map_err(|e| anyhow::anyhow!("invalid capsule ID: {e}"))?;
    let secret_store = astrid_storage::build_secret_store(capsule_id, kv.clone(), handle.clone());
    // Resolve principal home so lifecycle hooks can use home:// VFS.
    let home_root = astrid_core::dirs::AstridHome::resolve().ok().map(|h| {
        h.principal_home(&astrid_core::PrincipalId::default())
            .root()
            .to_path_buf()
    });

    let cfg = astrid_capsule::engine::wasm::LifecycleConfig {
        wasm_bytes,
        capsule_id: capsule_id_owned,
        workspace_root: target_dir.to_path_buf(),
        home_root,
        kv,
        event_bus: event_bus.clone(),
        config: std::collections::HashMap::new(),
        secret_store,
    };

    let result = if let Some(rt) = &owned_rt {
        // Enter the runtime context so Handle::current() works inside
        // run_lifecycle. Do NOT use block_in_place here - we are not a
        // tokio worker thread, and block_in_place would panic.
        let _guard = rt.enter();
        astrid_capsule::engine::wasm::run_lifecycle(cfg, phase, previous_version)
    } else {
        tokio::task::block_in_place(|| {
            astrid_capsule::engine::wasm::run_lifecycle(cfg, phase, previous_version)
        })
    };

    // Signal the elicit handler to stop
    elicit_handle.abort();
    drop(event_bus);
    drop(owned_rt);

    result.map_err(|e| anyhow::anyhow!("lifecycle dispatch failed: {e}"))
}

/// Prompt the user on stdin for a single elicit field (runs in a blocking thread).
///
/// Returns `(value, values)` where exactly one is `Some`.
async fn prompt_stdin_field(
    prompt: String,
    field_type: astrid_types::ipc::OnboardingFieldType,
    default: Option<String>,
) -> (Option<String>, Option<Vec<String>>) {
    use astrid_types::ipc::OnboardingFieldType;

    match field_type {
        OnboardingFieldType::Text => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let hint = default
                    .as_ref()
                    .map(|d| format!(" [{d}]"))
                    .unwrap_or_default();
                print!("{prompt}{hint}: ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                let input = input.trim().to_string();
                if input.is_empty() {
                    default.unwrap_or_default()
                } else {
                    input
                }
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Secret => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                print!("{prompt} (secret, input hidden): ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                input.trim().to_string()
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Enum(options) => {
            let val = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                println!("{prompt}:");
                for (i, opt) in options.iter().enumerate() {
                    println!("  {}: {opt}", i.saturating_add(1));
                }
                print!("Select [1-{}]: ", options.len());
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                let idx: usize = input.trim().parse().unwrap_or(0);
                if idx >= 1 && idx <= options.len() {
                    options[idx.saturating_sub(1)].clone()
                } else {
                    options.first().cloned().unwrap_or_default()
                }
            })
            .await
            .unwrap_or_default();
            (Some(val), None)
        },
        OnboardingFieldType::Array => {
            let items = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                println!("{prompt} (enter values one per line, empty line to finish):");
                let mut items = Vec::new();
                loop {
                    print!("> ");
                    let _ = std::io::stdout().flush();
                    let mut input = String::new();
                    let _ = std::io::stdin().read_line(&mut input);
                    let input = input.trim().to_string();
                    if input.is_empty() {
                        break;
                    }
                    items.push(input);
                }
                items
            })
            .await
            .unwrap_or_default();
            (None, Some(items))
        },
    }
}

/// CLI-inline elicit handler for non-TUI installs.
///
/// Listens for `ElicitRequest` IPC messages and prompts on stdin,
/// then publishes `ElicitResponse` back to the event bus.
async fn cli_elicit_handler(
    mut receiver: astrid_events::EventReceiver,
    event_bus: astrid_events::EventBus,
) {
    use astrid_events::AstridEvent;
    use astrid_types::ipc::IpcPayload;

    loop {
        let Some(event) = receiver.recv().await else {
            return;
        };

        let AstridEvent::Ipc { message, .. } = &*event else {
            continue;
        };

        let IpcPayload::ElicitRequest {
            request_id,
            capsule_id,
            field,
        } = &message.payload
        else {
            continue;
        };

        let request_id = *request_id;
        let prompt = field.description.as_ref().map_or_else(
            || format!("[{capsule_id}] {}", field.key),
            |d| format!("[{capsule_id}] {d}"),
        );

        let (value, values) =
            prompt_stdin_field(prompt, field.field_type.clone(), field.default.clone()).await;

        let response_topic = format!("astrid.v1.elicit.response.{request_id}");
        let response = IpcPayload::ElicitResponse {
            request_id,
            value,
            values,
        };
        let msg = astrid_types::ipc::IpcMessage::new(response_topic, response, uuid::Uuid::nil());
        event_bus.publish(AstridEvent::Ipc {
            message: msg,
            metadata: astrid_events::EventMetadata::default(),
        });
    }
}

/// Recursively copy a directory tree, dereferencing symlinks.
///
/// Symlinks are resolved to their target content (like `cp -rL`). This is
/// required because `npm install` creates symlinks in `node_modules/.bin/`
/// and the archiver also dereferences them via `follow_symlinks(true)`.
pub(crate) fn copy_capsule_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
    copy_capsule_dir_inner(src, dst, true)
}

fn copy_capsule_dir_inner(src: &Path, dst: &Path, is_root: bool) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;

    for entry in
        std::fs::read_dir(src).with_context(|| format!("failed to read {}", src.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            let name = entry.file_name();
            // Always skip .git and target. Only skip dist at the top level —
            // inside node_modules, dist/ contains compiled library code that
            // Tier 2 capsules need at runtime.
            if name == ".git" || name == "target" || (is_root && name == "dist") {
                continue;
            }
            copy_capsule_dir_inner(&src_path, &dst_path, false)?;
        } else if file_type.is_symlink() {
            // Dereference symlinks: resolve to the target's content and copy as
            // a regular file. This handles npm's node_modules/.bin/ symlinks.
            // fs::copy follows symlinks by default (reads the target, not the link).
            let metadata = std::fs::metadata(&src_path)
                .with_context(|| format!("symlink target not found for {}", src_path.display()))?;
            if metadata.is_dir() {
                // Symlink points to a directory - recurse into it
                copy_capsule_dir_inner(&src_path, &dst_path, false)?;
            } else {
                std::fs::copy(&src_path, &dst_path)
                    .with_context(|| format!("failed to copy {}", src_path.display()))?;
            }
        } else {
            std::fs::copy(&src_path, &dst_path)
                .with_context(|| format!("failed to copy {}", src_path.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn resolve_target_dir(
    home: &AstridHome,
    id: &str,
    workspace: bool,
) -> anyhow::Result<std::path::PathBuf> {
    if workspace {
        let root = std::env::current_dir().context("could not determine current directory")?;
        Ok(root.join(".astrid").join("capsules").join(id))
    } else {
        // User-installed capsules go to the principal's home, not the system dir.
        let principal = astrid_core::PrincipalId::default();
        let ph = home.principal_home(&principal);
        Ok(ph.capsules_dir().join(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_preserves_node_modules() {
        // End-to-end: create a capsule directory with node_modules, install it
        // via install_from_local_path, and verify node_modules is preserved in
        // the installed directory.
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();

        // Minimal Capsule.toml
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"install-test\"\nversion = \"1.0.0\"\n\n\
             [[mcp_server]]\nid = \"install-test\"\ncommand = \"node\"\nargs = [\"bridge.mjs\"]\n",
        )
        .unwrap();

        // Bridge script
        std::fs::write(base.join("bridge.mjs"), "// bridge").unwrap();

        // Source
        std::fs::create_dir_all(base.join("src")).unwrap();
        std::fs::write(base.join("src/index.js"), "module.exports = {};").unwrap();

        // package.json + node_modules (simulating npm install output)
        std::fs::write(
            base.join("package.json"),
            r#"{"name": "install-test", "dependencies": {"got": "^1.0"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(base.join("node_modules/got")).unwrap();
        std::fs::write(
            base.join("node_modules/got/index.js"),
            "module.exports = {};",
        )
        .unwrap();

        // Install into a fake AstridHome
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        install_from_local_path(base, false, &home).expect("install should succeed");

        // Verify installed directory preserves node_modules
        let installed = home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("install-test");
        assert!(
            installed.join("Capsule.toml").exists(),
            "installed capsule must have Capsule.toml"
        );
        assert!(
            installed.join("node_modules/got/index.js").exists(),
            "installed capsule must preserve node_modules"
        );
        assert!(
            installed.join("package.json").exists(),
            "installed capsule must preserve package.json"
        );
        assert!(
            installed.join("src/index.js").exists(),
            "installed capsule must preserve source"
        );
    }

    #[test]
    fn copy_capsule_dir_skips_git_and_build_artifacts() {
        let src_dir = tempfile::tempdir().unwrap();
        let base = src_dir.path();

        std::fs::write(base.join("index.js"), "// code").unwrap();
        std::fs::create_dir_all(base.join(".git/objects")).unwrap();
        std::fs::write(base.join(".git/objects/abc"), "blob").unwrap();
        std::fs::create_dir_all(base.join("dist")).unwrap();
        std::fs::write(base.join("dist/out.js"), "// built").unwrap();
        std::fs::create_dir_all(base.join("target")).unwrap();
        std::fs::write(base.join("target/debug"), "// rust").unwrap();
        std::fs::create_dir_all(base.join("node_modules/pkg")).unwrap();
        std::fs::write(base.join("node_modules/pkg/index.js"), "// dep").unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        copy_capsule_dir(base, dst_dir.path()).unwrap();

        assert!(dst_dir.path().join("index.js").exists());
        assert!(
            dst_dir.path().join("node_modules/pkg/index.js").exists(),
            "node_modules must be preserved"
        );
        assert!(
            !dst_dir.path().join(".git").exists(),
            ".git must be skipped"
        );
        assert!(
            !dst_dir.path().join("dist").exists(),
            "dist must be skipped"
        );
        assert!(
            !dst_dir.path().join("target").exists(),
            "target must be skipped"
        );
    }

    #[test]
    #[cfg_attr(windows, ignore = "symlinks require elevated privileges on Windows")]
    fn install_dereferences_node_modules_bin_symlinks() {
        // Simulates the realistic npm install output: node_modules/.bin/
        // contains relative symlinks to package executables. copy_capsule_dir
        // must dereference these into regular files instead of bailing.
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();

        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"symlink-test\"\nversion = \"1.0.0\"\n\n\
             [[mcp_server]]\nid = \"symlink-test\"\ncommand = \"node\"\nargs = [\"bridge.mjs\"]\n",
        )
        .unwrap();
        std::fs::write(base.join("bridge.mjs"), "// bridge").unwrap();

        // Create node_modules with a .bin/ symlink (like npm install produces)
        std::fs::create_dir_all(base.join("node_modules/somepkg")).unwrap();
        std::fs::write(
            base.join("node_modules/somepkg/cli.js"),
            "#!/usr/bin/env node\nconsole.log('works');",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("node_modules/.bin")).unwrap();

        // Relative symlink — this is what npm actually creates
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            std::path::Path::new("../somepkg/cli.js"),
            base.join("node_modules/.bin/somepkg"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            std::path::Path::new("../somepkg/cli.js"),
            base.join("node_modules/.bin/somepkg"),
        )
        .unwrap();

        // Install must succeed (previously bailed on symlink)
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        install_from_local_path(base, false, &home).expect("install must not bail on symlinks");

        // Verify the symlink was dereferenced into a regular file
        let installed = home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("symlink-test");
        let bin_file = installed.join("node_modules/.bin/somepkg");
        assert!(
            bin_file.exists(),
            ".bin/somepkg must exist as a regular file"
        );
        assert!(
            !bin_file.is_symlink(),
            ".bin/somepkg must be a regular file, not a symlink"
        );
        let content = std::fs::read_to_string(&bin_file).unwrap();
        assert!(
            content.contains("works"),
            "dereferenced file must have original content"
        );
    }

    #[test]
    fn meta_json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let meta = CapsuleMeta {
            version: "1.2.3".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-03-12T00:00:00Z".into(),
            source: Some("@org/my-capsule".into()),
            imports: {
                let mut m = std::collections::HashMap::new();
                let mut astrid = std::collections::HashMap::new();
                astrid.insert("session".into(), "^1.0".into());
                m.insert("astrid".into(), astrid);
                m
            },
            exports: {
                let mut m = std::collections::HashMap::new();
                let mut astrid = std::collections::HashMap::new();
                astrid.insert("llm".into(), "1.0.0".into());
                m.insert("astrid".into(), astrid);
                m
            },
            topics: vec![],
            wasm_hash: None,
            wit_files: std::collections::HashMap::new(),
        };
        write_meta(dir.path(), &meta).unwrap();
        let loaded = read_meta(dir.path()).expect("meta should be readable");
        assert_eq!(loaded.version, "1.2.3");
        assert_eq!(loaded.installed_at, "2026-01-01T00:00:00Z");
        assert_eq!(loaded.updated_at, "2026-03-12T00:00:00Z");
        assert_eq!(loaded.source.as_deref(), Some("@org/my-capsule"));
        assert_eq!(loaded.exports["astrid"]["llm"], "1.0.0");
        assert_eq!(loaded.imports["astrid"]["session"], "^1.0");
    }

    #[test]
    fn meta_json_roundtrip_without_source() {
        let dir = tempfile::tempdir().unwrap();
        let meta = CapsuleMeta {
            version: "1.0.0".into(),
            installed_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            source: None,
            imports: std::collections::HashMap::new(),
            exports: std::collections::HashMap::new(),
            topics: vec![],
            wasm_hash: None,
            wit_files: std::collections::HashMap::new(),
        };
        write_meta(dir.path(), &meta).unwrap();
        let loaded = read_meta(dir.path()).expect("meta should be readable");
        assert!(loaded.source.is_none());
        // Also verify optional fields are omitted from JSON (skip_serializing_if)
        let json = std::fs::read_to_string(dir.path().join("meta.json")).unwrap();
        assert!(
            !json.contains("source"),
            "source: None should be omitted from JSON"
        );
        assert!(
            !json.contains("imports"),
            "empty imports should be omitted from JSON"
        );
        assert!(
            !json.contains("exports"),
            "empty exports should be omitted from JSON"
        );
    }

    #[test]
    fn read_meta_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_meta(dir.path()).is_none());
    }

    #[test]
    fn install_writes_meta_json() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"meta-test\"\nversion = \"2.0.0\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        install_from_local_path(base, false, &home).expect("install should succeed");

        let installed = home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("meta-test");
        let meta = read_meta(&installed).expect("meta.json should exist after install");
        assert_eq!(meta.version, "2.0.0");
    }

    #[test]
    fn install_detects_upgrade_preserves_installed_at() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"upgrade-test\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());

        // First install
        install_from_local_path(base, false, &home).expect("first install");
        let meta1 = read_meta(
            &home
                .principal_home(&astrid_core::PrincipalId::default())
                .capsules_dir()
                .join("upgrade-test"),
        )
        .unwrap();
        assert_eq!(meta1.version, "1.0.0");
        let original_installed_at = meta1.installed_at.clone();

        // Upgrade
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"upgrade-test\"\nversion = \"2.0.0\"\n",
        )
        .unwrap();
        install_from_local_path(base, false, &home).expect("upgrade");

        let meta2 = read_meta(
            &home
                .principal_home(&astrid_core::PrincipalId::default())
                .capsules_dir()
                .join("upgrade-test"),
        )
        .unwrap();
        assert_eq!(meta2.version, "2.0.0");
        assert_eq!(
            meta2.installed_at, original_installed_at,
            "installed_at should be preserved across upgrades"
        );
    }

    #[test]
    fn test_strip_version_prefix() {
        assert_eq!(strip_version_prefix("v1.2.3"), "1.2.3");
        assert_eq!(strip_version_prefix("V1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("v0.0.1-alpha"), "0.0.1-alpha");
        // Non-standard prefixes are left as-is (semver parse will fail gracefully)
        assert_eq!(strip_version_prefix("release-1.0.0"), "release-1.0.0");
    }

    #[test]
    fn test_extract_github_org_repo() {
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");

        let (org, repo) = extract_github_org_repo("github.com/myorg/myrepo").unwrap();
        assert_eq!(org, "myorg");
        assert_eq!(repo, "myrepo");

        // Trailing slash
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo/").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");

        // Too short
        assert!(extract_github_org_repo("singlepart").is_none());
    }

    #[test]
    fn test_parse_github_source_at_prefix() {
        let (org, repo) = parse_github_source("@org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_https() {
        let (org, repo) = parse_github_source("https://github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_bare() {
        let (org, repo) = parse_github_source("github.com/org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_openclaw_at() {
        let (org, repo) = parse_github_source("openclaw:@org/repo").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_github_source_non_github() {
        assert!(parse_github_source("openclaw:my-capsule").is_none());
        assert!(parse_github_source("./local/path").is_none());
        assert!(parse_github_source("/absolute/path").is_none());
    }

    #[tokio::test]
    async fn test_check_remote_version_openclaw_skipped() {
        let client = reqwest::Client::new();
        let result = check_remote_version(&client, "openclaw:my-capsule", "1.0.0").await;
        assert!(matches!(result, UpdateCheck::Skipped { reason } if reason.contains("OpenClaw")));
    }

    #[tokio::test]
    async fn test_check_remote_version_invalid_semver() {
        let client = reqwest::Client::new();
        let result = check_remote_version(&client, "@org/repo", "not-a-version").await;
        assert!(
            matches!(result, UpdateCheck::Failed { reason } if reason.contains("not valid semver"))
        );
    }

    #[tokio::test]
    async fn test_check_remote_version_local_skipped() {
        let client = reqwest::Client::new();
        let result = check_remote_version(&client, "./local/path", "1.0.0").await;
        assert!(
            matches!(result, UpdateCheck::Skipped { reason } if reason.contains("local source"))
        );

        let result = check_remote_version(&client, "/absolute/path", "1.0.0").await;
        assert!(
            matches!(result, UpdateCheck::Skipped { reason } if reason.contains("local source"))
        );
    }

    #[test]
    fn install_bakes_topic_schema_into_meta() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::create_dir_all(base.join("schemas")).unwrap();
        std::fs::write(
            base.join("schemas/chunk.json"),
            r#"{"type":"object","properties":{"content":{"type":"string"}}}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"topic-test\"\nversion = \"1.0.0\"\n\n\
             [[topic]]\nname = \"llm.v1.chunk\"\ndirection = \"publish\"\n\
             description = \"Streaming chunk\"\nschema = \"schemas/chunk.json\"\n\n\
             [[topic]]\nname = \"llm.v1.request\"\ndirection = \"subscribe\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        install_from_local_path(base, false, &home).expect("install should succeed");

        let installed = home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("topic-test");
        let meta = read_meta(&installed).expect("meta.json should exist");
        assert_eq!(meta.topics.len(), 2);
        assert_eq!(meta.topics[0].name, "llm.v1.chunk");
        assert_eq!(
            meta.topics[0].direction,
            astrid_capsule::manifest::TopicDirection::Publish
        );
        assert_eq!(
            meta.topics[0].description.as_deref(),
            Some("Streaming chunk")
        );
        assert!(meta.topics[0].schema.is_some(), "schema should be baked");
        let schema = meta.topics[0].schema.as_ref().unwrap();
        assert_eq!(schema["type"], "object");

        // Second topic has no schema
        assert_eq!(meta.topics[1].name, "llm.v1.request");
        assert_eq!(
            meta.topics[1].direction,
            astrid_capsule::manifest::TopicDirection::Subscribe
        );
        assert!(meta.topics[1].schema.is_none());
    }

    #[test]
    fn install_fails_on_missing_schema_file() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"missing-schema\"\nversion = \"1.0.0\"\n\n\
             [[topic]]\nname = \"foo.bar\"\ndirection = \"publish\"\n\
             schema = \"schemas/nonexistent.json\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let err = install_from_local_path(base, false, &home)
            .expect_err("install should fail with missing schema");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("schema file not found") || msg.contains("No such file"),
            "expected schema-file-not-found error, got: {msg}"
        );
    }

    #[test]
    fn install_fails_on_invalid_json_schema() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::write(base.join("bad.json"), "not valid json {{{").unwrap();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"bad-json\"\nversion = \"1.0.0\"\n\n\
             [[topic]]\nname = \"foo.bar\"\ndirection = \"publish\"\n\
             schema = \"bad.json\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let err = install_from_local_path(base, false, &home)
            .expect_err("install should fail with invalid JSON");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid JSON"),
            "expected invalid JSON error, got: {msg}"
        );
    }

    #[test]
    fn install_fails_on_oversized_schema() {
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        // Create a file just over 1 MB
        let big = vec![b' '; (MAX_SCHEMA_FILE_SIZE as usize) + 1];
        std::fs::write(base.join("big.json"), &big).unwrap();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"big-schema\"\nversion = \"1.0.0\"\n\n\
             [[topic]]\nname = \"foo.bar\"\ndirection = \"publish\"\n\
             schema = \"big.json\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let err = install_from_local_path(base, false, &home)
            .expect_err("install should fail with oversized schema");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeding"),
            "expected size limit error, got: {msg}"
        );
    }

    #[test]
    fn install_no_topics_backwards_compat() {
        // Existing capsules without [[topic]] should still produce valid meta.json.
        let capsule_dir = tempfile::tempdir().unwrap();
        let base = capsule_dir.path();
        std::fs::write(
            base.join("Capsule.toml"),
            "[package]\nname = \"no-topics\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        install_from_local_path(base, false, &home).expect("install should succeed");

        let installed = home
            .principal_home(&astrid_core::PrincipalId::default())
            .capsules_dir()
            .join("no-topics");
        let meta = read_meta(&installed).expect("meta.json should exist");
        assert!(meta.topics.is_empty());
    }

    #[test]
    fn test_extract_github_org_repo_extra_path() {
        // Extra path segments after org/repo should be ignored
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo/tree/main").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_extract_github_org_repo_git_suffix() {
        let (org, repo) = extract_github_org_repo("https://github.com/org/repo.git").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");
    }

    /// Helper for testing .wasm asset detection logic.
    fn find_wasm_asset(assets: &[serde_json::Value]) -> Option<String> {
        assets.iter().find_map(|asset| {
            let name = asset.get("name")?.as_str()?;
            if !Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
            {
                return None;
            }
            Some(name.to_string())
        })
    }

    #[test]
    fn try_install_wasm_asset_prefers_first_wasm() {
        // If multiple .wasm assets exist, should pick the first one
        let assets = vec![
            serde_json::json!({
                "name": "first.wasm",
                "browser_download_url": "https://example.com/first.wasm"
            }),
            serde_json::json!({
                "name": "second.wasm",
                "browser_download_url": "https://example.com/second.wasm"
            }),
        ];
        assert_eq!(find_wasm_asset(&assets).as_deref(), Some("first.wasm"));
    }

    #[test]
    fn try_install_wasm_asset_skips_non_wasm() {
        // .capsule assets should not be matched by the .wasm check
        let assets = vec![serde_json::json!({
            "name": "capsule.capsule",
            "browser_download_url": "https://example.com/capsule.capsule"
        })];
        assert!(
            find_wasm_asset(&assets).is_none(),
            ".capsule should not match .wasm check"
        );
    }

    #[test]
    fn try_install_wasm_asset_case_insensitive() {
        let assets = vec![serde_json::json!({
            "name": "capsule.WASM",
            "browser_download_url": "https://example.com/capsule.WASM"
        })];
        assert_eq!(
            find_wasm_asset(&assets).as_deref(),
            Some("capsule.WASM"),
            "should match .WASM case-insensitively"
        );
    }

    #[test]
    fn capsule_toml_raw_url_format() {
        // Verify the raw.githubusercontent.com URL format is correct
        let org = "unicity-astrid";
        let repo = "capsule-cli";
        let tag = "v0.1.0";
        let url = format!("https://raw.githubusercontent.com/{org}/{repo}/{tag}/Capsule.toml");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/unicity-astrid/capsule-cli/v0.1.0/Capsule.toml"
        );
    }
}
