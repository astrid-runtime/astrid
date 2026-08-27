//! `astrid capsule install` source resolution and daemon hand-off.
//!
//! Shared post-resolution layout and lifecycle work lives in
//! [`astrid_capsule_install`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
#[cfg(test)]
use astrid_capsule_install::AuthorityDecision;
use astrid_capsule_install::github_source::{
    capsule_assets, extract_github_org_repo, parse_github_source, pick_capsule,
};
use astrid_core::dirs::AstridHome;

use super::{station, station_rollback};

pub(crate) use super::install_batch::{
    BatchInstallOutcome, InstalledCapsuleOutcome, RefSpec, install_capsule_batch,
};
use super::install_github::{github_api_client, release_tag_url, resolve_github_ref};

mod authority;
#[path = "install_local.rs"]
mod install_local;
#[path = "station_install.rs"]
mod station_install;

#[cfg(test)]
use astrid_capsule_install::inspect_directory_for_principal_with_layout;
#[cfg(test)]
use authority::authority_decision;
use authority::daemon_install_authority;

use install_local::{install_from_local, unpack_via_lib};

pub(crate) use station_install::StationInstallRequest;
pub(crate) use station_install::install_capsule_with_options_and_station_lock;
#[cfg(test)]
pub(crate) use station_install::install_capsule_with_options_and_station_lock_in_home;
#[cfg(test)]
pub(crate) use station_install::test_daemon_install_call;
#[cfg(test)]
pub(crate) use station_install::test_local_install_backend;
#[cfg(test)]
pub(crate) use station_rollback::{combine_install_and_restore_errors, restore_station_lock};

#[derive(Clone, Copy)]
struct ExpectedCapsule<'a> {
    id: &'a CapsuleId,
    version: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct InstallContext<'a> {
    workspace: bool,
    /// Route non-workspace installs through the authenticated daemon writer.
    daemon: bool,
    home: &'a AstridHome,
    original_source: Option<&'a str>,
    principal: &'a astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'a>>,
    prompt: &'a ManualInstallOptions,
}

/// Inputs shared by manual, persisted-source, and distro-batch dispatch.
/// Keeping the source request typed avoids a long positional argument list at
/// the source boundary, where Station and GitHub authority diverge.
pub(super) struct InstallRequest<'a> {
    pub(super) source: &'a str,
    pub(super) name_hint: Option<&'a str>,
    pub(super) workspace: bool,
    pub(super) refspec: &'a RefSpec,
    pub(super) principal: &'a astrid_core::PrincipalId,
    pub(super) expected: Option<&'a CapsuleId>,
    pub(super) prompt: &'a ManualInstallOptions,
    pub(super) allow_station: bool,
}

struct SourceInstallContext<'a> {
    base: &'a str,
    name_hint: Option<&'a str>,
    version: Option<&'a str>,
    tag: Option<&'a str>,
    workspace: bool,
    home: &'a AstridHome,
    principal: &'a astrid_core::PrincipalId,
    expected: Option<ExpectedCapsule<'a>>,
    prompt: &'a ManualInstallOptions,
    allow_station: bool,
}

/// Operator input policy for a manual capsule install.
#[derive(Debug, Clone, Default)]
pub(super) struct ManualInstallOptions {
    pub(super) yes: bool,
    pub(super) approve_untrusted: bool,
    pub(super) vars: HashMap<String, String>,
}

impl ManualInstallOptions {
    fn from_cli(yes: bool, approve_untrusted: bool, items: &[String]) -> anyhow::Result<Self> {
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
        Ok(Self {
            yes,
            approve_untrusted,
            vars,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OfflineCapsuleProvenance<'a> {
    pub(crate) original_source: &'a str,
    pub(crate) resolved_ref: Option<&'a str>,
    pub(crate) signer: Option<&'a str>,
    pub(crate) signature: Option<&'a str>,
}

/// Resolve a principal capsule's installed materialization directory for
/// lockfile verification.
pub(crate) use astrid_capsule_install::resolve_target_dir_for;

/// Re-exported so the `update` subcommand in [`super::install_update`]
/// can drive a refresh through the same dispatcher as a fresh install.
pub(crate) use super::install_update::update_capsule;

/// When true, import validation and env prompting are suppressed.
/// Set by `install_capsule_batch` (called from distro init) where the
/// distro handles env config and all capsules are installed together.
pub(super) static BATCH_MODE: AtomicBool = AtomicBool::new(false);

/// Split a trailing `@version` suffix off a `@org/repo@version` source.
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
/// `capsule` is the optional `--capsule <name>` selector. When `Some`, a
/// multi-capsule release installs only `<name>.capsule`; when `None` (the
/// default), a release ships every `.capsule` asset and all of them are
/// installed. A single-asset release installs that one either way.
pub(crate) async fn install_capsule(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
) -> anyhow::Result<()> {
    install_capsule_with_options(source, capsule, workspace, false, false, &[]).await
}

/// Manual install with explicit non-interactive configuration inputs.
pub(crate) async fn install_capsule_with_options(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
    yes: bool,
    approve_untrusted: bool,
    vars: &[String],
) -> anyhow::Result<()> {
    station_install::install_capsule_with_options_and_station_lock(
        &station_install::StationInstallRequest {
            source,
            capsule,
            workspace,
            yes,
            approve_untrusted,
            station_lock: None,
            station_lock_sha256: None,
            vars,
        },
    )
    .await
}

/// Reinstall a previously persisted source without allowing a newly
/// configured Station source to reinterpret its provenance.
pub(crate) async fn install_existing_source_with_options(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    let principal = crate::principal::current();
    install_existing_source_in_home_with_options(
        source,
        capsule,
        workspace,
        approve_untrusted,
        &home,
        &principal,
    )
    .await
}

pub(super) async fn install_existing_source_in_home_with_options(
    source: &str,
    capsule: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<()> {
    let prompt = ManualInstallOptions {
        approve_untrusted,
        ..Default::default()
    };
    let (installed, _resolved) = install_capsule_inner_at(
        InstallRequest {
            source,
            name_hint: capsule,
            workspace,
            refspec: &RefSpec::default(),
            principal,
            expected: None,
            prompt: &prompt,
            allow_station: false,
        },
        home,
    )
    .await?;
    let installed_ids: Vec<String> = installed
        .iter()
        .map(|capsule| capsule.id.as_str().to_string())
        .collect();
    super::live_load::nudge_daemon_reload(&installed_ids).await;
    Ok(())
}

/// Install dispatch shared by the CLI and distro-batch paths.
/// Returns `(installed_capsule_ids, resolved_ref)`: the ids of every capsule
/// installed, and the resolved git ref for GitHub-backed sources (`Some`), or
/// `None` for local-path sources, which have no remote ref to resolve.
pub(super) async fn install_capsule_inner(
    request: InstallRequest<'_>,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    let home = AstridHome::resolve()?;
    install_capsule_inner_at(request, &home).await
}

pub(super) async fn install_capsule_inner_at(
    request: InstallRequest<'_>,
    home: &AstridHome,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    // Recover any `@org/repo@version` CLI suffix and fold it into the
    // ref spec (an explicit RefSpec from a distro manifest wins).
    let (base, suffix_version) = split_version_suffix(request.source);
    let version = request
        .refspec
        .version
        .clone()
        .or_else(|| suffix_version.map(str::to_string));
    let tag = request.refspec.tag.clone();
    let expected = request.expected.map(|id| ExpectedCapsule {
        id,
        version: version.as_deref(),
    });

    dispatch_source(SourceInstallContext {
        base,
        name_hint: request.name_hint,
        version: version.as_deref(),
        tag: tag.as_deref(),
        workspace: request.workspace,
        home,
        principal: request.principal,
        expected,
        prompt: request.prompt,
        allow_station: request.allow_station,
    })
    .await
}

#[cfg(test)]
pub(super) async fn test_install_station_source(
    source: &str,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    test_install_station_source_with_workspace(source, home, principal, prompt, true).await
}

#[cfg(test)]
pub(super) async fn test_install_station_source_with_workspace(
    source: &str,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
    workspace: bool,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    let coordinate = source
        .strip_prefix('@')
        .ok_or_else(|| anyhow::anyhow!("test Station source must be a coordinate"))?;
    let context = SourceInstallContext {
        base: source,
        name_hint: None,
        version: None,
        tag: None,
        workspace,
        home,
        principal,
        expected: None,
        prompt,
        allow_station: true,
    };
    let (installed, _) = install_station_source(&context, coordinate).await?;
    Ok(installed)
}

#[cfg(test)]
pub(super) async fn test_install_local_source(
    source: &str,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    let context = SourceInstallContext {
        base: source,
        name_hint: None,
        version: None,
        tag: None,
        workspace: true,
        home,
        principal,
        expected: None,
        prompt,
        allow_station: false,
    };
    let (installed, _) = install_local_source(&context).await?;
    Ok(installed)
}

async fn dispatch_source(
    context: SourceInstallContext<'_>,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    // Explicit paths and unknown source forms are local installs. A
    // configured interactive @namespace/name may instead cross the Station
    // trust boundary; every other @ form remains GitHub-backed.
    if context.base.starts_with('.') || context.base.starts_with('/') {
        return install_local_source(&context).await;
    }
    if context.allow_station
        && !BATCH_MODE.load(Ordering::Relaxed)
        && let Some(coordinate) = context.base.strip_prefix('@')
        && coordinate.matches('/').count() == 1
    {
        let station_configured = station::is_configured()?;
        if station_dispatch(context.base, true, context.workspace, station_configured)? {
            return install_station_source(&context, coordinate).await;
        }
    }
    if let Some(repo) = context.base.strip_prefix('@') {
        let url = format!("https://github.com/{repo}");
        return install_github_source(&context, &url).await;
    }
    if context.base.starts_with("github.com/") || context.base.starts_with("https://github.com/") {
        return install_github_source(&context, context.base).await;
    }
    install_local_source(&context).await
}

async fn install_local_source(
    context: &SourceInstallContext<'_>,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    let ids = install_from_local(
        context.base,
        context.workspace,
        context.home,
        Some(context.base),
        context.principal,
        context.expected,
        context.prompt,
    )
    .await?;
    clear_replaced_station_locks(context.workspace, context.principal, &ids).await?;
    Ok((ids, None))
}

async fn install_station_source(
    context: &SourceInstallContext<'_>,
    coordinate: &str,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    let coordinate = format!("@{coordinate}");
    let staged = station::resolve_and_fetch(&coordinate, context.version, None)?;
    let staged_path = staged
        .path
        .to_str()
        .context("Station handoff path is not UTF-8")?;
    let station_id = CapsuleId::new(staged.lock.coordinate.name.clone())?;
    if let Some(expected) = context.expected {
        anyhow::ensure!(
            expected.id == &station_id,
            "Station lock coordinate does not match the requested capsule"
        );
    }
    let name = staged.lock.coordinate.name.as_str();
    let previous = station::load_lock(context.principal, name).await?;
    let previous_for_failure = previous.clone();
    station::store_lock(context.principal, name, staged.lock.clone()).await?;
    let ids = match install_from_local(
        staged_path,
        context.workspace,
        context.home,
        None,
        context.principal,
        Some(ExpectedCapsule {
            id: &station_id,
            version: Some(staged.lock.version.as_str()),
        }),
        context.prompt,
    )
    .await
    {
        Ok(ids) => ids,
        Err(error) => {
            return Err(station_rollback::combine_install_and_restore_errors(
                error,
                station_rollback::restore_station_lock(
                    context.principal,
                    name,
                    previous_for_failure.as_ref(),
                    &staged.lock,
                )
                .await,
            ));
        },
    };
    if ids.iter().any(|installed| installed.id.as_str() != name) {
        station_rollback::restore_station_lock(
            context.principal,
            name,
            previous.as_ref(),
            &staged.lock,
        )
        .await?;
        bail!("Station lock coordinate does not match installed capsule");
    }
    Ok((ids, None))
}

async fn install_github_source(
    context: &SourceInstallContext<'_>,
    url: &str,
) -> anyhow::Result<(Vec<InstalledCapsuleOutcome>, Option<String>)> {
    let result = install_from_github(
        url,
        context.name_hint,
        context.version,
        context.tag,
        InstallContext {
            workspace: context.workspace,
            daemon: !context.workspace,
            home: context.home,
            original_source: Some(context.base),
            principal: context.principal,
            expected: context.expected,
            prompt: context.prompt,
        },
    )
    .await?;
    clear_replaced_station_locks(context.workspace, context.principal, &result.0).await?;
    Ok(result)
}

/// Station locks are persisted through daemon control state. Workspace mode
/// has no authenticated owner-scoped writer, so configured Station aliases
/// must fail before resolution and handoff.
pub(super) fn station_workspace_guard(
    workspace: bool,
    station_configured: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(workspace && station_configured),
        "Station coordinate installs require daemon/control state; use a daemon install"
    );
    Ok(())
}

/// Decide whether one interactive alias is a Station coordinate. Explicit
/// GitHub URLs, unconfigured aliases, and provenance-preserving callers pass
/// through to the existing GitHub/local dispatcher.
pub(super) fn station_dispatch(
    base: &str,
    allow_station: bool,
    workspace: bool,
    station_configured: bool,
) -> anyhow::Result<bool> {
    let Some(coordinate) = base.strip_prefix('@') else {
        return Ok(false);
    };
    if coordinate.matches('/').count() != 1 || !allow_station {
        return Ok(false);
    }
    station_workspace_guard(workspace, station_configured)?;
    Ok(station_configured)
}

async fn clear_replaced_station_locks(
    workspace: bool,
    principal: &astrid_core::PrincipalId,
    installed: &[InstalledCapsuleOutcome],
) -> anyhow::Result<()> {
    if workspace && !station_rollback::station_lock_clear_ready() {
        return Ok(());
    }
    for capsule in installed {
        station::clear_lock(principal, capsule.id.as_str())
            .await
            .with_context(|| {
                format!(
                    "clear stale Station lock after installing {}",
                    capsule.id.as_str()
                )
            })?;
    }
    Ok(())
}

/// Re-resolve and install an existing Station lock through the normal local
/// archive installer. The Station lock, never GitHub/latest, chooses bytes.
pub(super) async fn install_from_station_lock(
    name: &str,
    lock: &astrid_core::kernel_api::StationLock,
    workspace: bool,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    approve_untrusted: bool,
) -> anyhow::Result<Vec<InstalledCapsuleOutcome>> {
    let staged = station::resolve_and_fetch("", None, Some(lock))?;
    anyhow::ensure!(
        staged.lock.coordinate.name == name,
        "Station lock coordinate does not match installed capsule"
    );
    let staged_path = staged
        .path
        .to_str()
        .context("Station handoff path is not UTF-8")?;
    let expected_id = CapsuleId::new(name.to_owned())?;
    let prompt = ManualInstallOptions {
        approve_untrusted,
        ..Default::default()
    };
    let previous = if workspace {
        None
    } else {
        station::load_lock(principal, name).await?
    };
    let previous_for_failure = previous.clone();
    if !workspace {
        station::store_lock(principal, name, staged.lock.clone()).await?;
    }
    let ids = install_from_local(
        staged_path,
        workspace,
        home,
        None,
        principal,
        Some(ExpectedCapsule {
            id: &expected_id,
            version: Some(staged.lock.version.as_str()),
        }),
        &prompt,
    )
    .await;
    let ids = match ids {
        Ok(ids) => ids,
        Err(error) => {
            if !workspace {
                return Err(station_rollback::combine_install_and_restore_errors(
                    error,
                    station_rollback::restore_station_lock(
                        principal,
                        name,
                        previous_for_failure.as_ref(),
                        &staged.lock,
                    )
                    .await,
                ));
            }
            return Err(error);
        },
    };
    if !workspace && ids.iter().any(|installed| installed.id != expected_id) {
        station_rollback::restore_station_lock(principal, name, previous.as_ref(), &staged.lock)
            .await?;
        bail!("Station installed an unexpected capsule");
    }
    Ok(ids)
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
    let id = clone_and_build(url, repo, name_hint, context).await?;
    Ok((vec![id], None))
}

/// Download a `.capsule` file to `dest_path` WITHOUT installing it,
/// returning the concrete git ref that was actually resolved.
/// This is the seal pipeline's source-resolution primitive: it mirrors
/// the release-asset download half of [`install_from_github`] but stops
/// before handing off to the install lib. Clone-and-build is *not* a
/// fallback here — a sealable distro must ship pre-built `.capsule`
/// release assets, so a missing asset is a hard error the maintainer
/// must resolve.
/// `name_hint` is the distro capsule `name`, used to pick the right
/// archive when one source ships several (a monorepo builds/releases one
/// `.capsule` per capsule crate) — the same `capsule_assets`/`pick_capsule`
/// selection [`install_from_github`] uses. A single-asset release installs
/// that one regardless of the hint.
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
    if context.daemon {
        return super::install_daemon::install_local_via_daemon_outcome(
            download_path
                .to_str()
                .context("invalid downloaded archive path")?,
            context.prompt,
            daemon_install_authority(
                download_path
                    .to_str()
                    .context("invalid downloaded archive path")?,
                context.principal,
                context.prompt,
            )?,
        )
        .await;
    }
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
async fn clone_and_build(
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
        if context.daemon {
            return super::install_daemon::install_local_via_daemon_outcome(
                produced[idx]
                    .to_str()
                    .context("invalid built archive path")?,
                context.prompt,
                daemon_install_authority(
                    produced[idx]
                        .to_str()
                        .context("invalid built archive path")?,
                    context.principal,
                    context.prompt,
                )?,
            )
            .await;
        }
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

// Source-resolution tests live here; install machinery is tested in
// `astrid-capsule-install` and `install_update`.
#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
