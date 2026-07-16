//! `astrid capsule install` — source resolution, then hand off to the install lib.
//!
//! This file owns the **source-resolution** side of installing a capsule:
//! GitHub release-asset download with clone-and-build fallback, archive
//! (`*.capsule`) detection, local Cargo-source auto-build, and the
//! dispatcher that routes `@org/repo`, `github.com/…`, and `./local`
//! shapes to the right pathway.
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

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule_install::github_source::{
    capsule_assets, extract_github_org_repo, parse_github_source, pick_capsule,
};
use astrid_capsule_install::{InstallOptions, InstallOutput, resolve_target_dir_for_with_layout};
use astrid_core::dirs::AstridHome;
use astrid_events::EventBus;

use super::install_prompts::{
    cli_elicit_handler, headless_elicit_handler, prompt_env_fields, write_headless_env_fields,
};

pub(crate) use super::install_batch::{
    BatchInstallOutcome, InstalledCapsuleOutcome, RefSpec, install_capsule_batch,
};
use super::install_github::{github_api_client, release_tag_url, resolve_github_ref};

#[derive(Clone, Copy)]
struct ExpectedCapsule<'a> {
    id: &'a CapsuleId,
    version: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct InstallContext<'a> {
    workspace: bool,
    home: &'a AstridHome,
    original_source: Option<&'a str>,
    principal: &'a astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'a>>,
    prompt: &'a ManualInstallOptions,
}

/// Operator input policy for a manual capsule install.
#[derive(Debug, Clone, Default)]
pub(super) struct ManualInstallOptions {
    yes: bool,
    vars: HashMap<String, String>,
}

impl ManualInstallOptions {
    fn from_cli(yes: bool, items: &[String]) -> anyhow::Result<Self> {
        let mut vars = HashMap::new();
        for item in items {
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--var must be KEY=VALUE (got {item:?})"))?;
            if key.is_empty() {
                bail!("--var has an empty key (got {item:?})");
            }
            if vars.insert(key.to_string(), value.to_string()).is_some() {
                bail!("--var '{key}' was supplied more than once");
            }
        }
        Ok(Self { yes, vars })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OfflineCapsuleProvenance<'a> {
    pub(crate) original_source: &'a str,
    pub(crate) resolved_ref: Option<&'a str>,
    pub(crate) signer: Option<&'a str>,
    pub(crate) signature: Option<&'a str>,
}

/// Re-exported so sibling CLI modules (`init.rs`, `shuttle_install.rs`)
/// keep the `super::install::resolve_target_dir_for` import path. The
/// `_for` variant scopes the target to a specific principal — the
/// init/distro path uses it to read back a capsule it installed under a
/// non-`default` principal's home.
pub(crate) use astrid_capsule_install::resolve_target_dir_for;

/// Re-exported so the `update` subcommand in [`super::install_update`]
/// can drive a refresh through the same dispatcher as a fresh install.
pub(crate) use super::install_update::update_capsule;

/// When true, import validation and env prompting are suppressed.
/// Set by `install_capsule_batch` (called from distro init) where the
/// distro handles env config and all capsules are installed together.
pub(super) static BATCH_MODE: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Top-level install dispatch
// ---------------------------------------------------------------------------

/// Split a trailing `@version` suffix off a `@org/repo@version` source.
///
/// Returns `(base_source, Some(version))` when a version pin is present,
/// `(source, None)` otherwise. The pin is the substring after the
/// **second** `@` (the first introduces the `@org/repo` alias). Only
/// the `@org/...` alias form carries a version suffix — plain
/// `github.com/...` URLs and local paths are returned untouched, since
/// a bare `@` is meaningful in neither.
pub(super) fn split_version_suffix(source: &str) -> (&str, Option<&str>) {
    let Some(rest) = source.strip_prefix('@') else {
        return (source, None);
    };
    // `rest` is `org/repo` or `org/repo@version`. Split on the next `@`.
    match rest.split_once('@') {
        Some((base, version)) if !version.is_empty() => {
            // Re-attach the leading `@` we stripped from `base`.
            let base_len = base.len().saturating_add(1); // +1 for '@'
            (&source[..base_len], Some(version))
        },
        _ => (source, None),
    }
}

/// Install a capsule from `source` (the manual `astrid capsule install` path).
///
/// `capsule` is the optional `--capsule <name>` selector. When `Some`, a
/// multi-capsule release installs only `<name>.capsule`; when `None` (the
/// default), a release ships every `.capsule` asset and all of them are
/// installed. A single-asset release installs that one either way.
pub(crate) async fn install_capsule(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
) -> anyhow::Result<()> {
    install_capsule_with_options(source, capsule, workspace, false, &[]).await
}

/// Manual install with explicit non-interactive configuration inputs.
pub(crate) async fn install_capsule_with_options(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
    yes: bool,
    vars: &[String],
) -> anyhow::Result<()> {
    let principal = crate::principal::current();
    let prompt = ManualInstallOptions::from_cli(yes, vars)?;
    let (installed, _resolved) = install_capsule_inner(
        source,
        capsule,
        workspace,
        &RefSpec::default(),
        &principal,
        None,
        &prompt,
    )
    .await?;
    let installed_ids: Vec<String> = installed
        .iter()
        .map(|capsule| capsule.id.as_str().to_string())
        .collect();
    // Live-load: if a daemon is running, hot-load (or upgrade) each just-installed
    // capsule so it's usable without a restart. Best-effort and non-fatal — the
    // on-disk install above already succeeded standalone. The `update` and TUI
    // install paths route through here too, so they inherit live hot-swap.
    super::live_load::nudge_daemon_reload(&installed_ids).await;
    Ok(())
}

/// Install dispatch shared by the CLI and distro-batch paths.
///
/// `name_hint` is the `--capsule <name>` / distro capsule `name` selector
/// used to pick the right archive when a release ships several. Returns
/// `(installed_capsule_ids, resolved_ref)`: the ids of every capsule
/// installed, and the resolved git ref for GitHub-backed sources (`Some`),
/// or `None` for local-path sources, which have no remote ref to resolve.
pub(super) async fn install_capsule_inner(
    source: &str,
    name_hint: Option<&str>,
    workspace: bool,
    refspec: &RefSpec,
    principal: &astrid_core::PrincipalId,
    expected: Option<&CapsuleId>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    let home = AstridHome::resolve()?;

    // Recover any `@org/repo@version` CLI suffix and fold it into the
    // ref spec (an explicit RefSpec from a distro manifest wins).
    let (base, suffix_version) = split_version_suffix(source);
    let version = refspec
        .version
        .clone()
        .or_else(|| suffix_version.map(str::to_string));
    let tag = refspec.tag.clone();
    let expected = expected.map(|id| ExpectedCapsule {
        id,
        version: version.as_deref(),
    });

    // 1. Explicit local path — record the path as the source so a
    //    later `astrid distro update` can re-resolve from it (it's the
    //    canonical reference for a locally-sourced capsule). No remote
    //    ref to resolve.
    if base.starts_with('.') || base.starts_with('/') {
        let ids = install_from_local(
            base,
            workspace,
            &home,
            Some(base),
            principal,
            expected,
            prompt,
        )?;
        return Ok((ids, None));
    }

    // 2. Namespace alias @org/repo → GitHub.
    if let Some(repo) = base.strip_prefix('@') {
        let url = format!("https://github.com/{repo}");
        return install_from_github(
            &url,
            name_hint,
            version.as_deref(),
            tag.as_deref(),
            InstallContext {
                workspace,
                home: &home,
                original_source: Some(base),
                principal,
                expected,
                prompt,
            },
        )
        .await;
    }

    // 3. Raw GitHub URL.
    if base.starts_with("github.com/") || base.starts_with("https://github.com/") {
        return install_from_github(
            base,
            name_hint,
            version.as_deref(),
            tag.as_deref(),
            InstallContext {
                workspace,
                home: &home,
                original_source: Some(base),
                principal,
                expected,
                prompt,
            },
        )
        .await;
    }

    // 4. Fallback: assume local folder. No remote ref to resolve.
    let ids = install_from_local(
        base,
        workspace,
        &home,
        Some(base),
        principal,
        expected,
        prompt,
    )?;
    Ok((ids, None))
}

// ---------------------------------------------------------------------------
// GitHub installs — release-artifact download with clone-and-build fallback.
// ---------------------------------------------------------------------------

/// Stream a `.capsule` asset to `dest`, enforcing a 50 MB ceiling.
async fn download_capsule_asset(
    client: &reqwest::Client,
    download_url: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    let mut dl = client
        .get(download_url)
        .send()
        .await
        .context("failed to start capsule download")?;
    let mut bytes = Vec::new();
    while let Some(chunk) = dl.chunk().await? {
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(
            bytes.len() <= 50 * 1024 * 1024,
            "capsule archive exceeds 50 MB limit",
        );
    }
    std::fs::write(dest, &bytes).with_context(|| format!("failed to write {}", dest.display()))?;
    Ok(())
}

/// Install from a GitHub source, returning the concrete ref that was
/// actually resolved and fetched (`Some` on the release-asset path). The
/// clone-and-build fallback returns `None` — there is no single release
/// tag it resolved (it builds from whatever `--depth 1` HEAD it cloned).
async fn install_from_github(
    url: &str,
    name_hint: Option<&str>,
    version: Option<&str>,
    tag: Option<&str>,
    context: InstallContext<'_>,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    // Authenticated when a token is present so release resolution isn't
    // throttled at the anonymous 60/hr limit mid-distro (see
    // `github_api_client`).
    let client = github_api_client()?;

    let (org, repo) = extract_github_org_repo(url).ok_or_else(|| {
        anyhow::anyhow!("Invalid GitHub URL format. Expected github.com/org/repo or @org/repo")
    })?;

    // Whether the caller pinned a concrete release. A pin is a hard
    // contract: if it cannot be honored we fail loudly rather than build
    // HEAD, which would install something other than what was pinned and
    // break the reproducibility the pin exists to guarantee.
    let pinned = version.is_some() || tag.is_some();

    // Priority 1: download packed `.capsule` archive(s) from the release
    // resolved by version/tag (or latest when unpinned). Each archive
    // contains everything an install needs (WASM, manifest, bundled WIT
    // definitions). The ref resolved here is the *actually resolved* tag —
    // the single source of truth threaded into the lock; we never silently
    // fall back to `releases/latest` when a version/tag is pinned.
    match resolve_github_ref(&client, org, repo, version, tag).await {
        Ok(resolved_ref) => {
            // Fetch the resolved release's assets. Build the URL via
            // `release_tag_url` so a tag containing `/` is percent-encoded as
            // one segment.
            let api_url = release_tag_url(org, repo, &resolved_ref)?;
            let candidates = if let Ok(response) = client.get(&api_url).send().await
                && response.status().is_success()
                && let Ok(json) = response.json::<serde_json::Value>().await
                && let Some(assets) = json.get("assets").and_then(serde_json::Value::as_array)
            {
                capsule_assets(assets)
            } else {
                Vec::new()
            };

            if !candidates.is_empty() {
                let ids = match name_hint {
                    // Distro path, or manual `--capsule <name>`: install exactly
                    // `<name>.capsule` (a single-asset release installs that one
                    // regardless of the hint, via `pick_capsule`).
                    Some(hint) => {
                        let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
                        let idx = pick_capsule(&names, Some(hint))?
                            .expect("non-empty candidates always select an index");
                        let (name, download_url) = &candidates[idx];
                        let id = download_and_unpack(&client, name, download_url, context).await?;
                        vec![id]
                    },
                    // Manual install with no `--capsule`: install EVERY capsule
                    // the release ships. Best-effort — report which assets fail
                    // but keep going, then fail if any did.
                    None => install_all_capsules(&client, &candidates, context).await?,
                };
                return Ok((ids, Some(resolved_ref)));
            }

            // The ref resolved, but the release ships no `.capsule` asset. A
            // pin must NOT silently fall through to building HEAD — fail with
            // the real, actionable cause. Unpinned, fall through to
            // clone-and-build.
            if pinned {
                bail!("release {resolved_ref} of {org}/{repo} ships no .capsule asset");
            }
        },
        // A pinned ref that could not be resolved is a hard error: surface
        // the real cause (a bad version/tag, a network failure) and never
        // build HEAD for a pin.
        Err(e) if pinned => {
            return Err(e).context(format!(
                "failed to resolve pinned version/tag for {org}/{repo}"
            ));
        },
        // Unpinned resolution failure (e.g. no `latest` release): fall
        // through to clone-and-build.
        Err(_) => {},
    }

    // Priority 2: clone + build from source via astrid-build — reached only
    // when nothing was pinned (a pin would have bailed above).
    let id = clone_and_build(url, repo, name_hint, context)?;
    Ok((vec![id], None))
}

/// Download a `.capsule` file to `dest_path` WITHOUT installing it,
/// returning the concrete git ref that was actually resolved.
///
/// This is the seal pipeline's source-resolution primitive: it mirrors
/// the release-asset download half of [`install_from_github`] but stops
/// before handing off to the install lib. Clone-and-build is *not* a
/// fallback here — a sealable distro must ship pre-built `.capsule`
/// release assets, so a missing asset is a hard error the maintainer
/// must resolve.
///
/// `name_hint` is the distro capsule `name`, used to pick the right
/// archive when one source ships several (a monorepo builds/releases one
/// `.capsule` per capsule crate) — the same `capsule_assets`/`pick_capsule`
/// selection [`install_from_github`] uses. A single-asset release installs
/// that one regardless of the hint.
///
/// The returned ref is the single source of truth the seal records in
/// the lock's `resolved_ref`: it is whatever GitHub reported as the
/// release `tag_name`, never an optimistic guess from the manifest.
pub(crate) async fn resolve_capsule_to_file(
    source: &str,
    version: Option<&str>,
    tag: Option<&str>,
    name_hint: Option<&str>,
    dest_path: &Path,
) -> anyhow::Result<String> {
    let (org, repo) = parse_github_source(source).ok_or_else(|| {
        anyhow::anyhow!(
            "seal can only resolve GitHub-backed capsule sources (@org/repo); got {source:?}"
        )
    })?;

    // Authenticated when a token is present (see `github_api_client`).
    let client = github_api_client()?;

    let resolved_ref = resolve_github_ref(&client, &org, &repo, version, tag).await?;

    // Fetch the resolved release's assets and pick the right `<name>.capsule`
    // (the same selection the install path uses), so a release shipping
    // several capsules downloads the one the seal asked for rather than the
    // first. A missing `.capsule` asset is a hard error — seal requires
    // pre-built release artifacts.
    let api_url = release_tag_url(&org, &repo, &resolved_ref)?;
    let response = client
        .get(&api_url)
        .send()
        .await
        .context("failed to fetch release metadata")?;
    if !response.status().is_success() {
        bail!(
            "GitHub API returned {} fetching release {resolved_ref} of {org}/{repo}",
            response.status()
        );
    }
    let json: serde_json::Value = response.json().await.context("invalid release metadata")?;
    let assets = json
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let candidates = capsule_assets(assets);
    let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
    let Some(idx) = pick_capsule(&names, name_hint)? else {
        bail!(
            "release {resolved_ref} of {org}/{repo} ships no .capsule asset — \
             seal requires pre-built release artifacts"
        );
    };
    let (_, download_url) = &candidates[idx];

    download_capsule_asset(&client, download_url, dest_path).await?;
    Ok(resolved_ref)
}

/// Download a single `.capsule` asset (streamed, 50 MB cap) and install it.
/// Returns the installed capsule id.
async fn download_and_unpack(
    client: &reqwest::Client,
    name: &str,
    download_url: &str,
    context: InstallContext<'_>,
) -> anyhow::Result<InstalledCapsuleOutcome> {
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
    unpack_via_lib(
        &download_path,
        context.workspace,
        context.home,
        context.original_source,
        context.principal,
        context.expected,
        context.prompt,
    )
}

/// Install every `.capsule` asset in a release (the manual-install default).
///
/// Best-effort: each failure is reported with the asset name, but the loop
/// continues so one bad archive doesn't block the rest. Returns an error if
/// **any** asset failed, naming all that did — failures are surfaced, never
/// silently swallowed.
async fn install_all_capsules(
    client: &reqwest::Client,
    candidates: &[(String, String)],
    context: InstallContext<'_>,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    eprintln!("Release ships {} capsule(s):", candidates.len());
    let mut installed: Vec<InstalledCapsuleOutcome> = Vec::new();
    let mut failed: Vec<(&str, String)> = Vec::new();
    for (name, download_url) in candidates {
        eprintln!("Installing {name}...");
        match download_and_unpack(client, name, download_url, context).await {
            Ok(id) => installed.push(id),
            Err(e) => {
                eprintln!("  Failed to install {name}: {e}");
                failed.push((name, e.to_string()));
            },
        }
    }

    eprintln!(
        "Done: {} installed, {} failed.",
        installed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        let names = failed
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(", ");
        bail!("failed to install {} capsule(s): {names}", failed.len());
    }
    Ok(installed)
}

/// Clone a GitHub repository and build the capsule from source using
/// `astrid-build`. Returns the installed capsule id.
fn clone_and_build(
    url: &str,
    repo: &str,
    name_hint: Option<&str>,
    context: InstallContext<'_>,
) -> anyhow::Result<InstalledCapsuleOutcome> {
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

    // Surface (not swallow) a per-entry read error rather than silently
    // dropping a file with `filter_map(Result::ok)` — a transient I/O or
    // permissions error on one entry should be reported, not hide a capsule
    // the operator expects to be installed.
    let mut produced: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&output_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                eprintln!("warning: skipping unreadable build-output entry: {err}");
                continue;
            },
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("capsule") {
            produced.push(path);
        }
    }
    let names: Vec<&str> = produced
        .iter()
        .map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or(""))
        .collect();
    if let Some(idx) = pick_capsule(&names, name_hint)? {
        return unpack_via_lib(
            &produced[idx],
            context.workspace,
            context.home,
            context.original_source,
            context.principal,
            context.expected,
            context.prompt,
        );
    }

    bail!("astrid-build produced no .capsule archive.");
}

// ---------------------------------------------------------------------------
// Local-source dispatcher — archive vs directory vs Rust-source autobuild.
// ---------------------------------------------------------------------------

fn install_from_local(
    source: &str,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    principal: &astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'_>>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("Source path does not exist: {source}");
    }

    // Unpack `.capsule` archive when source is a file.
    if source_path.is_file() && source.ends_with(".capsule") {
        return unpack_via_lib(
            source_path,
            workspace,
            home,
            original_source,
            principal,
            expected,
            prompt,
        )
        .map(|installed| vec![installed]);
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
                return unpack_via_lib(
                    &entry.path(),
                    workspace,
                    home,
                    original_source,
                    principal,
                    expected,
                    prompt,
                )
                .map(|installed| vec![installed]);
            }
        }
        bail!("Failed to auto-build capsule from Cargo project.");
    }

    install_from_local_path_for_principal(
        source_path,
        workspace,
        home,
        original_source,
        principal,
        expected,
        prompt,
    )
    .map(|installed| vec![installed])
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
) -> anyhow::Result<String> {
    let principal = crate::principal::current();
    let prompt = ManualInstallOptions::default();
    install_from_local_path_for_principal(
        source_dir,
        workspace,
        home,
        original_source,
        &principal,
        None,
        &prompt,
    )
    .map(|installed| installed.id.as_str().to_string())
}

fn install_from_local_path_for_principal(
    source_dir: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    principal: &astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'_>>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(Ordering::Relaxed),
        lifecycle_bus: None,
    };
    let output = run_with_elicit(opts, prompt, |opts, bus| {
        let opts = InstallOptions {
            lifecycle_bus: Some(bus),
            ..opts
        };
        match expected {
            Some(expected) => {
                astrid_capsule_install::install_from_local_path_checked_for_principal_with_layout(
                    source_dir,
                    home,
                    opts,
                    principal,
                    expected.id,
                    expected.version,
                    crate::workspace_layout::current(),
                )
            },
            None => astrid_capsule_install::install_from_local_path_for_principal_with_layout(
                source_dir,
                home,
                opts,
                principal,
                crate::workspace_layout::current(),
            ),
        }
    })?;
    finish_install(&output, home, principal, prompt)
}

/// Install a capsule from a local `.capsule` file in batch (offline)
/// mode, recording `original_source` and signing provenance in
/// `meta.json`.
///
/// Used by the `.shuttle` offline-install path: the file already lives
/// in the verified mirror, so no network is touched. `original_source`
/// is the distro's canonical `@org/repo` (NOT the mirror path) so a
/// later online `update` can re-resolve. Provenance fields are
/// descriptive — trust was established by the distro signature check
/// before this is called, not re-derived here.
pub(crate) fn install_offline_capsule(
    archive: &Path,
    home: &AstridHome,
    expected: &CapsuleId,
    expected_version: Option<&str>,
    provenance: OfflineCapsuleProvenance<'_>,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    BATCH_MODE.store(true, Ordering::Relaxed);
    let prompt = ManualInstallOptions::default();
    let result = (|| {
        let installed = unpack_via_lib(
            archive,
            false,
            home,
            Some(provenance.original_source),
            principal,
            Some(ExpectedCapsule {
                id: expected,
                version: expected_version,
            }),
            &prompt,
        )?;
        // Post-stamp provenance into the freshly-written meta.json. The
        // unpack above installs under the explicit target principal and
        // selected workspace layout, so read metadata through the same path.
        let target_dir = resolve_target_dir_for_with_layout(
            home,
            principal,
            expected.as_str(),
            false,
            crate::workspace_layout::current(),
        )?;
        if let Some(mut meta) = super::meta::read_meta(&target_dir) {
            meta.resolved_ref = provenance.resolved_ref.map(String::from);
            meta.signer = provenance.signer.map(String::from);
            meta.signature = provenance.signature.map(String::from);
            super::meta::write_meta(&target_dir, &meta)?;
        }
        Ok(installed)
    })();
    BATCH_MODE.store(false, Ordering::Relaxed);
    result
}

/// Unpack a `.capsule` archive and install from it. Returns the installed
/// capsule id.
fn unpack_via_lib(
    archive: &Path,
    workspace: bool,
    home: &AstridHome,
    original_source: Option<&str>,
    principal: &astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'_>>,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let opts = InstallOptions {
        workspace,
        original_source: original_source.map(String::from),
        skip_import_check: BATCH_MODE.load(Ordering::Relaxed),
        lifecycle_bus: None,
    };
    let output = run_with_elicit(opts, prompt, |opts, bus| {
        let opts = InstallOptions {
            lifecycle_bus: Some(bus),
            ..opts
        };
        match expected {
            Some(expected) => {
                astrid_capsule_install::unpack_and_install_checked_for_principal_with_layout(
                    archive,
                    home,
                    opts,
                    principal,
                    expected.id,
                    expected.version,
                    crate::workspace_layout::current(),
                )
            },
            None => astrid_capsule_install::unpack_and_install_for_principal_with_layout(
                archive,
                home,
                opts,
                principal,
                crate::workspace_layout::current(),
            ),
        }
    })?;
    finish_install(&output, home, principal, prompt)
}

/// Run a lib-install closure with a fresh event bus and a stdin
/// elicit handler subscribed. Tears the handler down before
/// returning either Ok or Err.
fn run_with_elicit<F>(
    opts: InstallOptions,
    prompt: &ManualInstallOptions,
    f: F,
) -> anyhow::Result<InstallOutput>
where
    F: FnOnce(InstallOptions, EventBus) -> anyhow::Result<InstallOutput>,
{
    let event_bus = EventBus::with_capacity(128);
    let receiver = event_bus.subscribe_topic("astrid.v1.elicit");
    let bus_for_handler = event_bus.clone();
    let headless_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let elicit_task = tokio::runtime::Handle::try_current().ok().map(|h| {
        if prompt.yes {
            let vars = prompt.vars.clone();
            let errors = std::sync::Arc::clone(&headless_errors);
            h.spawn(async move {
                headless_elicit_handler(receiver, bus_for_handler, vars, errors).await;
            })
        } else {
            h.spawn(async move {
                cli_elicit_handler(receiver, bus_for_handler).await;
            })
        }
    });
    let result = f(opts, event_bus.clone());
    if let Some(task) = elicit_task {
        task.abort();
    }
    drop(event_bus);
    let errors = headless_errors
        .lock()
        .map_err(|_| anyhow::anyhow!("headless configuration error state was poisoned"))?;
    if !errors.is_empty() {
        bail!(
            "non-interactive capsule configuration failed: {}",
            errors.join("; ")
        );
    }
    result
}

/// Render post-install diagnostics and prompt for unset env fields. Returns the
/// installed capsule id (its directory name), so the manual-install path can
/// nudge a running daemon to hot-load exactly that capsule.
fn finish_install(
    output: &InstallOutput,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let batch = BATCH_MODE.load(Ordering::Relaxed);

    // Load the manifest once (always present post-install) — used both for
    // env prompting and for surfacing the CLI commands this capsule adds.
    let manifest_path = output.target_dir.join("Capsule.toml");
    let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
        .context("re-reading manifest for post-install diagnostics")?;

    // Visibility (no approval gate in this phase): if the capsule declares
    // any `kind = "cli"` commands, list the new top-level `astrid capsule
    // <verb>` verbs it adds so the operator knows what just became
    // invocable. Printed adjacent to the other manifest-derived notices.
    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let meta = super::meta::read_meta(&output.target_dir)
        .context("installed capsule has no readable meta.json")?;
    if manifest.package.version != meta.version || output.installed_version != meta.version {
        bail!(
            "installed capsule '{}' version disagreement: manifest={}, meta={}, installer={}",
            capsule_id,
            manifest.package.version,
            meta.version,
            output.installed_version
        );
    }
    if output.wasm_hash != meta.wasm_hash {
        bail!(
            "installed capsule '{}' hash disagreement: installer={:?}, meta={:?}",
            capsule_id,
            output.wasm_hash,
            meta.wasm_hash
        );
    }
    let cli_commands: Vec<&astrid_capsule::manifest::CommandDef> = manifest
        .commands
        .iter()
        .filter(|c| c.kind == astrid_core::kernel_api::CommandKind::Cli)
        .collect();
    if !cli_commands.is_empty() {
        eprintln!();
        eprintln!("This capsule adds CLI commands:");
        for c in cli_commands {
            let desc = c.description.as_deref().unwrap_or("(no description)");
            eprintln!("  {} — {desc} (provider: {capsule_id})", c.name);
        }
    }

    if !batch {
        if prompt.yes {
            write_headless_env_fields(
                &manifest.env,
                &output.env_path,
                capsule_id.as_str(),
                home,
                principal,
                &prompt.vars,
            )?;
        } else if output.env_needs_prompt {
            prompt_env_fields(
                &manifest.env,
                &output.env_path,
                capsule_id.as_str(),
                &home.config_path(),
                home,
                principal,
            )?;
        }
    }

    if !batch && !output.missing_imports.is_empty() {
        let importer = capsule_id.as_str();
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

    // Contracts skew — warn-only. Side-loading an ahead-of-daemon dev
    // build is legitimate, so a differing `astrid-contracts.wit` pin is
    // surfaced, never blocked. Classified from the just-written meta.json
    // (the canonical was seeded during install), so it reflects the same
    // pins `capsule show` / `list` read. Silent for aligned pins and for
    // a fresh home with no canonical to compare against.
    if !batch {
        let skew = super::show::contracts_skew_at(&output.target_dir, home);
        super::show::print_install_skew_notice(capsule_id.as_str(), &skew);
    }

    Ok(InstalledCapsuleOutcome {
        id: capsule_id,
        version: meta.version,
        wasm_hash: meta.wasm_hash,
    })
}

// ---------------------------------------------------------------------------
// Tests — source-resolution helpers only. Install-machinery tests live
// in `astrid-capsule-install`; `update`/`check_remote_version` tests
// live in `install_update`.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
