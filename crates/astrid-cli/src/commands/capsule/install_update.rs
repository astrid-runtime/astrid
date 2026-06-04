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
use astrid_capsule_install::scan_installed_capsules;
use astrid_core::dirs::AstridHome;

use super::install::{install_capsule, parse_github_source, strip_version_prefix};
use super::meta::{CapsuleMeta, read_meta};

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
pub(crate) async fn update_capsule(target: Option<&str>, workspace: bool) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;

    if let Some(name) = target {
        let target_dir = astrid_capsule_install::resolve_target_dir(&home, name, workspace)?;
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
        if let Err(e) = install_capsule(source, workspace).await {
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
        regenerate_distro_lock(home)?;
    }

    Ok(())
}

/// Regenerate the Distro.lock from currently installed capsules.
///
/// Scans all installed capsules, reads their `meta.json`, and writes
/// a new lockfile with current versions and BLAKE3 hashes. Called
/// after `update` to keep the lock in sync.
fn regenerate_distro_lock(home: &AstridHome) -> anyhow::Result<()> {
    use crate::commands::distro::lock::{DistroLock, DistroLockMeta, LockedCapsule, write_lock};

    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    let Some(existing) = crate::commands::distro::lock::load_lock(&lock_path)? else {
        return Ok(());
    };

    let all = scan_installed_capsules()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
