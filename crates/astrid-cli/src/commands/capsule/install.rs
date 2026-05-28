//! `astrid capsule install` — source resolution, then hand off to the install lib.
//!
//! This file owns the **source-resolution** side of installing a capsule:
//! GitHub release-asset download with clone-and-build fallback, `OpenClaw`
//! transpile via `astrid-build`, archive (`*.capsule`) detection, local
//! Cargo-source auto-build, and the dispatcher that routes `@org/repo`,
//! `openclaw:…`, `github.com/…`, and `./local` shapes to the right
//! pathway.
//!
//! The **post-resolution** install machinery (file layout, content
//! addressing of WASM/WIT into `bin/<hash>.wasm` / `wit/<hash>.wit`,
//! lifecycle hooks, topic baking, `meta.json` writes) lives in the
//! [`astrid_capsule_install`] crate so the kernel-side admin install
//! handler reaches disk through the same code path the CLI does.
//!
//! ## What the lib changed (versus the previous CLI-inline version)
//!
//! The previous install copied the entire capsule tree into the target
//! directory, then read the `.wasm` back out, BLAKE3-hashed it, wrote
//! `bin/<hash>.wasm`, and deleted the per-capsule copy. Same dance for
//! `wit/`. The new lib hashes from the **source** directly, writes to
//! the content store once, and the per-capsule directory copy excludes
//! `*.wasm` and the top-level `wit/` by construction — no transient
//! staging copy. The runtime contract is unchanged (loader still reads
//! by hash via `resolve_content_addressed_wasm`); only the install
//! path is cleaner.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use astrid_capsule_install::{InstallOptions, InstallOutput};
use astrid_core::dirs::AstridHome;
use astrid_events::EventBus;

use super::install_prompts::{cli_elicit_handler, prompt_env_fields};

/// Re-exported so sibling CLI modules (`init.rs`, `remove.rs`) keep the
/// `super::install::resolve_target_dir` import path.
pub(crate) use astrid_capsule_install::resolve_target_dir;

/// Re-exported so the `update` subcommand in [`super::install_update`]
/// can drive a refresh through the same dispatcher as a fresh install.
pub(crate) use super::install_update::update_capsule;

/// When true, import validation and env prompting are suppressed.
/// Set by `install_capsule_batch` (called from distro init) where the
/// distro handles env config and all capsules are installed together.
static BATCH_MODE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// GitHub source-resolution helpers — shared with `install_update`.
// ---------------------------------------------------------------------------

/// Strip common version prefixes (`v`, `V`) from a Git tag before semver parsing.
pub(super) fn strip_version_prefix(tag: &str) -> &str {
    tag.strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag)
}

/// Extract `(org, repo)` from a GitHub URL. Anchors on the
/// `github.com/` marker so extra path segments (`/tree/main`, `.git`)
/// are safely ignored.
fn extract_github_org_repo(url: &str) -> Option<(&str, &str)> {
    let idx = url.find("github.com/")?;
    let after_host = &url[idx.saturating_add("github.com/".len())..];
    let trimmed = after_host.trim_end_matches('/');
    let (org, rest) = trimmed.split_once('/')?;
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
pub(super) fn parse_github_source(source: &str) -> Option<(String, String)> {
    if let Some(repo_path) = source.strip_prefix('@') {
        let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
        return None;
    }

    if let Some(rest) = source.strip_prefix("openclaw:") {
        if let Some(repo_path) = rest.strip_prefix('@') {
            let parts: Vec<&str> = repo_path.splitn(2, '/').collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }
        return None;
    }

    if source.contains("github.com/") {
        let (org, repo) = extract_github_org_repo(source)?;
        return Some((org.to_string(), repo.to_string()));
    }

    None
}

// ---------------------------------------------------------------------------
// Top-level install dispatch
// ---------------------------------------------------------------------------

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

    // 1. Explicit local path — no source tracking (re-fetch doesn't make sense).
    if source.starts_with('.') || source.starts_with('/') {
        return install_from_local(source, workspace, &home, None);
    }

    // 2. OpenClaw prefix.
    if let Some(rest) = source.strip_prefix("openclaw:") {
        if let Some(repo) = rest.strip_prefix('@') {
            let url = format!("https://github.com/{repo}");
            return install_from_github(&url, workspace, &home, true, Some(source)).await;
        }
        return install_from_openclaw(rest, workspace, &home, Some(source));
    }

    // 3. Namespace alias @org/repo → GitHub.
    if let Some(repo) = source.strip_prefix('@') {
        let url = format!("https://github.com/{repo}");
        return install_from_github(&url, workspace, &home, false, Some(source)).await;
    }

    // 4. Raw GitHub URL.
    if source.starts_with("github.com/") || source.starts_with("https://github.com/") {
        return install_from_github(source, workspace, &home, false, Some(source)).await;
    }

    // 5. Fallback: assume local folder.
    install_from_local(source, workspace, &home, None)
}

// ---------------------------------------------------------------------------
// GitHub installs — release-artifact download with clone-and-build fallback.
// ---------------------------------------------------------------------------

async fn install_from_github(
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

    // Priority 1: download a packed `.capsule` archive from the
    // latest release. The archive contains everything an install
    // needs (WASM, manifest, bundled WIT definitions).
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
                return unpack_via_lib(&download_path, workspace, home, original_source);
            }
        }
    }

    // Priority 2: clone + build from source via astrid-build.
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

    for entry in std::fs::read_dir(&output_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
            return unpack_via_lib(&entry.path(), workspace, home, original_source);
        }
    }

    bail!("Universal Migrator failed to produce a .capsule archive.");
}

// ---------------------------------------------------------------------------
// OpenClaw flow — local transpile via astrid-build.
// ---------------------------------------------------------------------------

fn install_from_openclaw(
    source: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let capsule_name = source.strip_prefix("openclaw:").unwrap_or(source);

    let source_path = Path::new(capsule_name);
    if !source_path.exists() {
        bail!(
            "OpenClaw registry fetch not yet implemented. Please provide a local path to the \
             OpenClaw capsule directory."
        );
    }

    transpile_and_install(source_path, workspace, home, original_source)
}

fn transpile_and_install(
    source_path: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for transpilation")?;
    let output_dir = tmp_dir.path();

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

    for entry in std::fs::read_dir(output_dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
            return unpack_via_lib(&entry.path(), workspace, home, original_source);
        }
    }
    bail!("OpenClaw compilation succeeded but no .capsule archive was produced")
}

// ---------------------------------------------------------------------------
// Local-source dispatcher — archive vs directory vs Rust-source autobuild.
// ---------------------------------------------------------------------------

fn install_from_local(
    source: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("Source path does not exist: {source}");
    }

    // Auto-detect OpenClaw (no Capsule.toml, has openclaw.plugin.json).
    if source_path.join("openclaw.plugin.json").exists()
        && !source_path.join("Capsule.toml").exists()
    {
        return transpile_and_install(source_path, workspace, home, original_source);
    }

    // Unpack `.capsule` archive when source is a file.
    if source_path.is_file() && source.ends_with(".capsule") {
        return unpack_via_lib(source_path, workspace, home, original_source);
    }

    // Auto-build Rust capsules when source is a directory with a Cargo.toml.
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

        for entry in std::fs::read_dir(&output_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("capsule") {
                return unpack_via_lib(&entry.path(), workspace, home, original_source);
            }
        }
        bail!("Failed to auto-build capsule from Cargo project.");
    }

    install_from_local_path(source_path, workspace, home, original_source)
}

// ---------------------------------------------------------------------------
// CLI wrappers around the install lib.
// ---------------------------------------------------------------------------

/// Install a capsule from a directory containing `Capsule.toml`.
///
/// CLI-facing wrapper that wires up an in-process event bus with a
/// stdin elicit handler subscribed (so capsules can prompt for
/// `[env]` values during their install lifecycle hook), runs the
/// install via the shared lib, then renders post-install diagnostics
/// and prompts for any unset `[env]` fields.
pub(crate) fn install_from_local_path(
    source_dir: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(Ordering::Relaxed),
        lifecycle_bus: None,
    };
    let output = run_with_elicit(opts, |opts, bus| {
        astrid_capsule_install::install_from_local_path(
            source_dir,
            home,
            InstallOptions {
                lifecycle_bus: Some(bus),
                ..opts
            },
        )
    })?;
    finish_install(&output, home)
}

/// Unpack a `.capsule` archive and install from it.
fn unpack_via_lib(
    archive: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
) -> anyhow::Result<()> {
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(Ordering::Relaxed),
        lifecycle_bus: None,
    };
    let output = run_with_elicit(opts, |opts, bus| {
        astrid_capsule_install::unpack_and_install(
            archive,
            home,
            InstallOptions {
                lifecycle_bus: Some(bus),
                ..opts
            },
        )
    })?;
    finish_install(&output, home)
}

/// Run a lib-install closure with a fresh event bus and a stdin
/// elicit handler subscribed. Tears the handler down before
/// returning either Ok or Err.
fn run_with_elicit<F>(opts: InstallOptions, f: F) -> anyhow::Result<InstallOutput>
where
    F: FnOnce(InstallOptions, EventBus) -> anyhow::Result<InstallOutput>,
{
    let event_bus = EventBus::with_capacity(128);
    let receiver = event_bus.subscribe_topic("astrid.v1.elicit");
    let bus_for_handler = event_bus.clone();
    let elicit_task = tokio::runtime::Handle::try_current().ok().map(|h| {
        h.spawn(async move {
            cli_elicit_handler(receiver, bus_for_handler).await;
        })
    });
    let result = f(opts, event_bus.clone());
    if let Some(task) = elicit_task {
        task.abort();
    }
    drop(event_bus);
    result
}

/// Render post-install diagnostics and prompt for unset env fields.
fn finish_install(output: &InstallOutput, _home: &AstridHome) -> anyhow::Result<()> {
    let batch = BATCH_MODE.load(Ordering::Relaxed);

    if !batch && output.env_needs_prompt {
        // Load manifest from the target (always present post-install).
        let manifest_path = output.target_dir.join("Capsule.toml");
        let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
            .context("re-reading manifest for env prompts")?;
        prompt_env_fields(&manifest.env, &output.env_path)?;
    }

    if !batch && !output.missing_imports.is_empty() {
        let importer = output.target_dir.file_name().map_or_else(
            || "capsule".to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        eprintln!();
        for missing in &output.missing_imports {
            eprintln!(
                "  Note: {importer} needs {}/{} {}.",
                missing.namespace, missing.interface, missing.requirement
            );
        }
        eprintln!(
            "  Install the missing capsule(s) or run `astrid init` to set up a complete environment."
        );
    }

    for c in &output.export_conflicts {
        tracing::info!(
            interface = %c.interface,
            existing = %c.existing_capsule,
            "Shared export — both capsules will be active"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — source-resolution helpers only. Install-machinery tests live
// in `astrid-capsule-install`; `update`/`check_remote_version` tests
// live in `install_update`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_version_prefix() {
        assert_eq!(strip_version_prefix("v1.2.3"), "1.2.3");
        assert_eq!(strip_version_prefix("V1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix("v0.0.1-alpha"), "0.0.1-alpha");
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

        let (org, repo) = extract_github_org_repo("https://github.com/org/repo/").unwrap();
        assert_eq!(org, "org");
        assert_eq!(repo, "repo");

        assert!(extract_github_org_repo("singlepart").is_none());
    }

    #[test]
    fn test_extract_github_org_repo_extra_path() {
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
