//! `astrid capsule update` and post-update Distro.lock regeneration.
//!
//! Update flow: read every installed capsule's recorded `source`,
//! ask the source's host (GitHub releases today) for the latest
//! tagged version, compare against the installed semver, force a
//! reinstall when strictly newer. Local-path sources are reported as
//! "skipped" rather than treated as errors.
//!
//! `regenerate_distro_lock` re-emits `Distro.lock` from the current
//! on-disk state after a successful update batch so the lockfile
//! never drifts from reality.

use anyhow::{Context, bail};
use astrid_capsule_install::github_source::{parse_github_source, strip_version_prefix};
use astrid_capsule_install::{
    CapsuleLocation, InstalledCapsule, scan_installed_capsules_in_home_for_with_layout,
};
use astrid_core::dirs::AstridHome;

use super::install::{ManualInstallOptions, install_capsule_with_options};
use super::install_index::{
    IndexClient, ProductionIndexClient, install_from_index_with_home,
    validate_existing_index_provenance,
};
use super::meta::{CapsuleMeta, read_meta};
use crate::commands::index::{IndexSource, IndexStore};

/// Result of checking a remote source for a newer capsule version.
pub(super) enum UpdateCheck {
    Available { latest: semver::Version },
    UpToDate { latest: semver::Version },
    Failed { reason: String },
    Skipped { reason: String },
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
pub(super) async fn check_remote_version(
    client: &reqwest::Client,
    source: &str,
    current_version: &str,
) -> UpdateCheck {
    let Ok(current) = semver::Version::parse(current_version) else {
        return UpdateCheck::Failed {
            reason: format!("installed version '{current_version}' is not valid semver"),
        };
    };

    if source.starts_with('.') || source.starts_with('/') {
        return UpdateCheck::Skipped {
            reason: "local source".to_string(),
        };
    }

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
/// If `target` is `Some`, force-reinstall that capsule from its
/// recorded source. If `None`, check all installed capsules for newer
/// versions and only update those where the remote version is
/// strictly newer (semver comparison).
pub(crate) async fn update_capsule(
    target: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    let client = ProductionIndexClient::for_home(home.root())?;
    update_capsule_with_index(target, workspace, approve_untrusted, None, &client).await
}

/// Update capsules with an optional explicit Capsule Index client.
///
/// Capsules carrying [`CapsuleMeta::index_provenance`] are always refreshed
/// through that exact configured Index identity. They are never passed to the
/// GitHub resolver, even when the recorded source happens to look like a
/// GitHub coordinate. An explicit `index_id` is likewise fail-closed when the
/// selected capsule has no matching provenance.
pub(crate) async fn update_capsule_with_index<C: IndexClient + ?Sized>(
    target: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
    index_id: Option<&str>,
    client: &C,
) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    let principal = crate::principal::current();

    if let Some(name) = target {
        let target_dir = astrid_capsule_install::resolve_target_dir_for_with_layout(
            &home,
            &principal,
            name,
            workspace,
            crate::workspace_layout::current(),
        )?;
        if !target_dir.exists() {
            bail!("Capsule '{name}' is not installed.");
        }
        let meta = read_meta(&target_dir).ok_or_else(|| {
            anyhow::anyhow!(
                "Capsule '{name}' has no meta.json - cannot determine original source. \
                 Re-install it manually."
            )
        })?;

        if let Some(provenance) = meta.index_provenance.as_ref() {
            let selected = index_id.unwrap_or_else(|| provenance.lock.index_id().as_str());
            anyhow::ensure!(
                selected == provenance.lock.index_id().as_str(),
                "Capsule '{name}' is bound to Index '{}', not '{}'; refusing a different Index",
                provenance.lock.index_id(),
                selected
            );
            let index = configured_index(&home, selected)?;
            validate_existing_index_provenance(&index, provenance)?;
            eprintln!(
                "Updating {name} from Index {} ({})...",
                provenance.lock.index_id(),
                index.base_url
            );
            let prompt = ManualInstallOptions {
                approve_untrusted,
                ..Default::default()
            };
            let coordinate = provenance.lock.coordinate().to_string();
            let installed = install_from_index_with_home(
                &coordinate,
                selected,
                workspace,
                &home,
                &principal,
                &prompt,
                client,
            )
            .await?;
            super::live_load::nudge_daemon_reload(&[installed.id.as_str().to_string()]).await;
            regenerate_distro_lock(&home, &principal)?;
            return Ok(());
        }

        if let Some(selected) = index_id {
            bail!(
                "Capsule '{name}' has no Index provenance; refusing explicit Index '{selected}' update"
            );
        }

        // Legacy GitHub/local update path remains unchanged for metadata that
        // predates Index provenance.
        return update_capsule_legacy(Some(name), workspace, approve_untrusted).await;
    }

    if index_id.is_some() {
        let updated = update_index_capsules(
            &home,
            &principal,
            workspace,
            approve_untrusted,
            index_id,
            client,
        )
        .await?;
        if updated > 0 {
            regenerate_distro_lock(&home, &principal)?;
        }
        return Ok(());
    }

    // Refresh Index-provenanced capsules first, then let the legacy scanner
    // handle only non-Index installations. `update_all_capsules` explicitly
    // skips Index provenance so no GitHub request can be made for them.
    let _ = update_index_capsules(
        &home,
        &principal,
        workspace,
        approve_untrusted,
        None,
        client,
    )
    .await?;
    update_capsule_legacy(None, workspace, approve_untrusted).await
}

/// The pre-Index update implementation, retained for backward-compatible
/// GitHub and local-path installations.
async fn update_capsule_legacy(
    target: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    let principal = crate::principal::current();

    if let Some(name) = target {
        let target_dir = astrid_capsule_install::resolve_target_dir_for_with_layout(
            &home,
            &principal,
            name,
            workspace,
            crate::workspace_layout::current(),
        )?;
        if !target_dir.exists() {
            bail!("Capsule '{name}' is not installed.");
        }

        let meta = read_meta(&target_dir).ok_or_else(|| {
            anyhow::anyhow!(
                "Capsule '{name}' has no meta.json - cannot determine original source. \
                 Re-install it manually."
            )
        })?;

        let source = meta.source.ok_or_else(|| {
            anyhow::anyhow!(
                "Capsule '{name}' was installed before source tracking was added. \
                 Re-install it manually to record the source."
            )
        })?;

        eprintln!("Updating {name} from {source}...");
        // Re-install exactly the capsule being updated. When `source` is a
        // monorepo release that ships several `.capsule` assets, pass `name`
        // as the selector so update refreshes only that one — not every
        // capsule the release contains.
        install_capsule_with_options(
            &source,
            Some(name),
            workspace,
            false,
            approve_untrusted,
            &[],
        )
        .await
    } else {
        update_all_capsules(&home, &principal, workspace, approve_untrusted).await
    }
}

fn configured_index(home: &AstridHome, index_id: &str) -> anyhow::Result<IndexSource> {
    let index = IndexStore::from_home(home.root(), None)
        .load()?
        .into_iter()
        .find(|index| index.id == index_id)
        .ok_or_else(|| anyhow::anyhow!("Index source not found: {index_id}"))?;
    anyhow::ensure!(
        index.enabled,
        "Index source '{}' is disabled; enable it before resolution",
        index.id
    );
    Ok(index)
}

/// Refresh all installed capsules carrying Index provenance through their
/// bound source. Returns the number of successful installs. When `index_id`
/// is supplied, capsules bound to other sources are ignored and a missing
/// match is an error rather than a silent GitHub fallback.
async fn update_index_capsules<C: IndexClient + ?Sized>(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    workspace: bool,
    approve_untrusted: bool,
    index_id: Option<&str>,
    client: &C,
) -> anyhow::Result<usize> {
    let capsules = filter_update_scope(
        scan_installed_capsules_in_home_for_with_layout(
            home,
            principal,
            crate::workspace_layout::current(),
        )?,
        workspace,
    );
    let mut matched = 0usize;
    let mut updated = 0usize;
    for capsule in capsules {
        let Some(meta) = capsule.meta else {
            continue;
        };
        let Some(provenance) = meta.index_provenance else {
            continue;
        };
        let bound_id = provenance.lock.index_id().as_str();
        if let Some(selected) = index_id
            && selected != bound_id
        {
            continue;
        }
        matched = matched.saturating_add(1);
        let index = configured_index(home, bound_id)?;
        validate_existing_index_provenance(&index, &provenance)?;
        let coordinate = provenance.lock.coordinate().to_string();
        eprintln!(
            "Updating {} from Index {} ({})...",
            capsule.name, bound_id, index.base_url
        );
        let prompt = ManualInstallOptions {
            approve_untrusted,
            ..Default::default()
        };
        let installed = install_from_index_with_home(
            &coordinate,
            bound_id,
            workspace,
            home,
            principal,
            &prompt,
            client,
        )
        .await
        .with_context(|| format!("update Index capsule {}", capsule.name))?;
        super::live_load::nudge_daemon_reload(&[installed.id.as_str().to_string()]).await;
        updated = updated.saturating_add(1);
    }
    if index_id.is_some() && matched == 0 {
        bail!(
            "No installed capsules are bound to Index '{}'",
            index_id.unwrap_or_default()
        );
    }
    Ok(updated)
}

/// Check all installed capsules for updates and install those with newer versions.
async fn update_all_capsules(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    workspace: bool,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    let capsules: Vec<(String, Option<CapsuleMeta>)> = filter_update_scope(
        scan_installed_capsules_in_home_for_with_layout(
            home,
            principal,
            crate::workspace_layout::current(),
        )?,
        workspace,
    )
    .into_iter()
    .map(|capsule| (capsule.name, capsule.meta))
    .collect();

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

    let mut to_update: Vec<(String, String)> = Vec::new();
    let mut up_to_date = 0u32;
    let mut check_failed = 0u32;
    let mut skipped = 0u32;

    for (name, meta) in &capsules {
        let Some(meta) = meta else {
            eprintln!("  {name}: skipped (no meta.json)");
            skipped = skipped.saturating_add(1);
            continue;
        };
        if meta.index_provenance.is_some() {
            // Index provenance is handled by `update_index_capsules`; never
            // send its recorded source through the GitHub API path.
            eprintln!("  {name}: skipped (Capsule Index source)");
            skipped = skipped.saturating_add(1);
            continue;
        }
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

    let mut updated = 0u32;
    let mut install_failed = 0u32;
    for (name, source) in &to_update {
        eprintln!("Updating {name} from {source}...");
        // Selector = the capsule being updated, so a monorepo source refreshes
        // only this one (see the single-target update above).
        if let Err(e) = install_capsule_with_options(
            source,
            Some(name),
            workspace,
            false,
            approve_untrusted,
            &[],
        )
        .await
        {
            eprintln!("  Failed to update {name}: {e}");
            install_failed = install_failed.saturating_add(1);
        } else {
            updated = updated.saturating_add(1);
        }
    }

    eprintln!(
        "Done: {updated} updated, {up_to_date} up-to-date, {check_failed} check-failed, \
         {skipped} skipped, {install_failed} install-failed."
    );

    if updated > 0 {
        regenerate_distro_lock(home, principal)?;
    }

    Ok(())
}

fn filter_update_scope(capsules: Vec<InstalledCapsule>, workspace: bool) -> Vec<InstalledCapsule> {
    let selected = if workspace {
        CapsuleLocation::Workspace
    } else {
        CapsuleLocation::User
    };
    capsules
        .into_iter()
        .filter(|capsule| capsule.location == selected)
        .collect()
}

/// Regenerate the Distro.lock from currently installed capsules.
///
/// Scans all installed capsules, reads their `meta.json`, and writes
/// a new lockfile with current versions and BLAKE3 hashes. Called
/// after `update` to keep the lock in sync.
fn regenerate_distro_lock(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<()> {
    use crate::commands::distro::lock::{DistroLock, DistroLockMeta, LockedCapsule, write_lock};

    let lock_path = home
        .principal_home(principal)
        .config_dir()
        .join("distro.lock");

    let Some(existing) = crate::commands::distro::lock::load_lock(&lock_path)? else {
        return Ok(());
    };

    let all = scan_installed_capsules_in_home_for_with_layout(
        home,
        principal,
        crate::workspace_layout::current(),
    )?;
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
                resolved_ref: c.meta.as_ref().and_then(|m| m.resolved_ref.clone()),
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
        // Preserve the manifest hash from the prior lock — a capsule
        // update doesn't change the manifest the lock was sealed from.
        manifest_hash: existing.manifest_hash,
    };

    write_lock(&lock_path, &lock)?;
    eprintln!("Distro.lock updated.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(name: &str, location: CapsuleLocation) -> InstalledCapsule {
        InstalledCapsule {
            name: name.to_string(),
            meta: None,
            location,
        }
    }

    #[test]
    fn update_scope_does_not_move_capsules_between_locations() {
        let user = filter_update_scope(
            vec![
                installed("user-only", CapsuleLocation::User),
                installed("workspace-only", CapsuleLocation::Workspace),
            ],
            false,
        );
        assert_eq!(user.len(), 1);
        assert_eq!(user[0].name, "user-only");

        let workspace = filter_update_scope(
            vec![
                installed("user-only", CapsuleLocation::User),
                installed("workspace-only", CapsuleLocation::Workspace),
            ],
            true,
        );
        assert_eq!(workspace.len(), 1);
        assert_eq!(workspace[0].name, "workspace-only");
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
}
