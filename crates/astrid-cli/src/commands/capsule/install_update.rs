//! `astrid capsule update` and post-update daemon distro-provenance refresh.
//!
//! Update flow: read every installed capsule's recorded `source`,
//! ask the source's host (GitHub releases today) for the latest
//! tagged version, compare against the installed semver, force a
//! reinstall when strictly newer. Local-path sources are reported as
//! "skipped" rather than treated as errors.
//!
//! `regenerate_distro_lock` re-emits the authenticated daemon-owned distro
//! record from the current installed state after a successful update batch so
//! provenance never drifts from reality.

use anyhow::{Context, bail};
use astrid_capsule_install::github_source::{parse_github_source, strip_version_prefix};
use astrid_capsule_install::{
    CapsuleLocation, InstalledCapsule, scan_installed_capsules_in_home_for_with_layout,
};
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{CapsuleMetadataEntry, KernelRequest, KernelResponse, StationLock};

use super::install::{
    install_existing_source_in_home_with_options, install_existing_source_with_options,
    install_from_station_lock,
};
use super::meta::{CapsuleMeta, read_meta};
use super::station;

/// Result of checking a remote source for a newer capsule version.
pub(super) enum UpdateCheck {
    Available { latest: semver::Version },
    UpToDate { latest: semver::Version },
    Failed { reason: String },
    Skipped { reason: String },
}

pub(crate) enum DaemonUpdateSource {
    Durable(String),
    Station(Box<StationLock>),
    None,
}

struct DaemonUpdatePlan {
    to_update: Vec<(String, String)>,
    station_to_update: Vec<(String, Box<StationLock>)>,
    up_to_date: u32,
    check_failed: u32,
    skipped: u32,
}

pub(crate) fn daemon_update_source(
    entry: &CapsuleMetadataEntry,
    station_lock: Option<StationLock>,
) -> DaemonUpdateSource {
    if let Some(source) = &entry.update_source {
        // Durable package provenance is authoritative even when a stale
        // Station control record is still present for the same name.
        DaemonUpdateSource::Durable(source.clone())
    } else if let Some(lock) = station_lock {
        DaemonUpdateSource::Station(Box::new(lock))
    } else {
        DaemonUpdateSource::None
    }
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
    let principal = crate::principal::current();
    update_capsule_in_home(target, workspace, approve_untrusted, &home, &principal).await
}

async fn update_capsule_in_home(
    target: Option<&str>,
    workspace: bool,
    approve_untrusted: bool,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
) -> anyhow::Result<()> {
    if !workspace {
        return update_daemon_capsules(target, principal, approve_untrusted).await;
    }

    if let Some(name) = target {
        let target_dir = astrid_capsule_install::resolve_target_dir_for_with_layout(
            home,
            principal,
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
        install_existing_source_in_home_with_options(
            &source,
            Some(name),
            workspace,
            approve_untrusted,
            home,
            principal,
        )
        .await
    } else {
        update_all_capsules(home, principal, workspace, approve_untrusted).await
    }
}

#[cfg(test)]
pub(super) async fn test_update_workspace_capsule_in_home(
    name: &str,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    update_capsule_in_home(Some(name), true, approve_untrusted, home, principal).await
}

async fn daemon_capsule_metadata() -> anyhow::Result<Vec<CapsuleMetadataEntry>> {
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    match client.request(KernelRequest::GetCapsuleMetadata).await? {
        KernelResponse::CapsuleMetadata(entries) => Ok(entries),
        KernelResponse::Error(message) => {
            bail!("daemon rejected capsule metadata request: {message}")
        },
        other => bail!("unexpected daemon response: {other:?}"),
    }
}

async fn update_daemon_capsules(
    target: Option<&str>,
    principal: &astrid_core::PrincipalId,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    let entries = daemon_capsule_metadata().await?;
    if let Some(name) = target {
        let entry = entries
            .into_iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| anyhow::anyhow!("Capsule '{name}' is not installed."))?;
        let station_lock = if entry.update_source.is_none() {
            station::load_lock(principal, name).await?
        } else {
            None
        };
        match daemon_update_source(&entry, station_lock) {
            DaemonUpdateSource::Durable(source) => {
                eprintln!("Updating {name} from {source}...");
                install_existing_source_with_options(&source, Some(name), false, approve_untrusted)
                    .await?;
                return regenerate_distro_lock(principal).await;
            },
            DaemonUpdateSource::Station(lock) => {
                eprintln!("Updating {name} from Station {}...", lock.coordinate.name);
                let home = AstridHome::resolve()?;
                let ids = install_from_station_lock(
                    name,
                    &lock,
                    false,
                    &home,
                    principal,
                    approve_untrusted,
                )
                .await?;
                let installed_ids = ids
                    .iter()
                    .map(|capsule| capsule.id.as_str().to_owned())
                    .collect::<Vec<_>>();
                super::live_load::nudge_daemon_reload(&installed_ids).await;
                return Ok(());
            },
            DaemonUpdateSource::None => eprintln!(
                "Capsule '{name}' has no remotely updateable source; its durable package is unchanged."
            ),
        }
        Ok(())
    } else {
        update_all_daemon_capsules(entries, principal, approve_untrusted).await
    }
}

async fn update_all_daemon_capsules(
    entries: Vec<CapsuleMetadataEntry>,
    principal: &astrid_core::PrincipalId,
    approve_untrusted: bool,
) -> anyhow::Result<()> {
    if entries.is_empty() {
        eprintln!("No capsules installed.");
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    eprintln!(
        "Checking {} installed capsule(s) for updates...",
        entries.len()
    );

    let plan = plan_daemon_updates(entries, principal, &client).await?;
    let DaemonUpdatePlan {
        to_update,
        station_to_update,
        up_to_date,
        check_failed,
        skipped,
    } = plan;

    let mut updated = 0u32;
    let mut install_failed = 0u32;
    for (name, lock) in &station_to_update {
        eprintln!("Updating {name} from Station {}...", lock.coordinate.name);
        let home = AstridHome::resolve()?;
        match install_from_station_lock(name, lock, false, &home, principal, approve_untrusted)
            .await
        {
            Ok(ids) => {
                let installed_ids = ids
                    .iter()
                    .map(|capsule| capsule.id.as_str().to_owned())
                    .collect::<Vec<_>>();
                super::live_load::nudge_daemon_reload(&installed_ids).await;
                updated = updated.saturating_add(1);
            },
            Err(error) => {
                eprintln!("  Failed to update {name}: {error}");
                install_failed = install_failed.saturating_add(1);
            },
        }
    }
    for (name, source) in &to_update {
        eprintln!("Updating {name} from {source}...");
        if let Err(error) =
            install_existing_source_with_options(source, Some(name), false, approve_untrusted).await
        {
            eprintln!("  Failed to update {name}: {error}");
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
        regenerate_distro_lock(principal).await?;
    }
    Ok(())
}

async fn plan_daemon_updates(
    entries: Vec<CapsuleMetadataEntry>,
    principal: &astrid_core::PrincipalId,
    client: &reqwest::Client,
) -> anyhow::Result<DaemonUpdatePlan> {
    let mut plan = DaemonUpdatePlan {
        to_update: Vec::new(),
        station_to_update: Vec::new(),
        up_to_date: 0,
        check_failed: 0,
        skipped: 0,
    };
    for entry in entries {
        let station_lock = if entry.update_source.is_none() {
            station::load_lock(principal, &entry.name).await?
        } else {
            None
        };
        let source = match daemon_update_source(&entry, station_lock) {
            DaemonUpdateSource::Durable(source) => source,
            DaemonUpdateSource::Station(lock) => {
                eprintln!("  {}: Station lock re-resolve required", entry.name);
                plan.station_to_update.push((entry.name, lock));
                continue;
            },
            DaemonUpdateSource::None => {
                eprintln!("  {}: skipped (no remote source recorded)", entry.name);
                plan.skipped = plan.skipped.saturating_add(1);
                continue;
            },
        };
        match check_remote_version(client, &source, &entry.version).await {
            UpdateCheck::Available { latest } => {
                eprintln!(
                    "  {}: {} -> {latest} (update available)",
                    entry.name, entry.version
                );
                plan.to_update.push((entry.name, source));
            },
            UpdateCheck::UpToDate { latest } => {
                eprintln!(
                    "  {}: {} (up to date, latest: {latest})",
                    entry.name, entry.version
                );
                plan.up_to_date = plan.up_to_date.saturating_add(1);
            },
            UpdateCheck::Failed { reason } => {
                eprintln!(
                    "  {}: {} (check failed: {reason})",
                    entry.name, entry.version
                );
                plan.check_failed = plan.check_failed.saturating_add(1);
            },
            UpdateCheck::Skipped { reason } => {
                eprintln!("  {}: skipped ({reason})", entry.name);
                plan.skipped = plan.skipped.saturating_add(1);
            },
        }
    }
    Ok(plan)
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
        if let Err(e) =
            install_existing_source_with_options(source, Some(name), workspace, approve_untrusted)
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
        regenerate_distro_lock(principal).await?;
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

/// Regenerate the daemon-owned distro provenance from currently installed capsules.
///
/// Reads the authenticated daemon registry and writes a new record with
/// current versions and BLAKE3 hashes. Native install paths never participate.
async fn regenerate_distro_lock(principal: &astrid_core::PrincipalId) -> anyhow::Result<()> {
    use crate::commands::distro::lock::{
        DistroLock, DistroLockMeta, LockedCapsule, load_lock_from_daemon, write_lock_to_daemon,
    };

    let Some(existing) = load_lock_from_daemon(principal).await? else {
        return Ok(());
    };

    let prior_refs: std::collections::HashMap<_, _> = existing
        .capsules
        .iter()
        .map(|capsule| (capsule.name.clone(), capsule.resolved_ref.clone()))
        .collect();
    let capsules: Vec<LockedCapsule> = daemon_capsule_metadata()
        .await?
        .into_iter()
        .map(|entry| LockedCapsule {
            resolved_ref: prior_refs.get(&entry.name).cloned().flatten(),
            name: entry.name,
            version: entry.version,
            source: entry.update_source.unwrap_or_default(),
            hash: entry
                .wasm_hash
                .map(|hash| format!("blake3:{hash}"))
                .unwrap_or_default(),
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

    write_lock_to_daemon(principal, &lock).await?;
    eprintln!("Distro provenance updated in the daemon.");
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

    #[test]
    fn durable_github_source_wins_over_stale_station_lock() {
        let entry = CapsuleMetadataEntry {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            description: None,
            interceptor_events: Vec::new(),
            imports: std::collections::HashMap::new(),
            exports: std::collections::HashMap::new(),
            capabilities: serde_json::Value::Null,
            env: std::collections::HashMap::new(),
            wit_hashes: Vec::new(),
            wasm_hash: None,
            update_source: Some("@example/demo".to_owned()),
            source_id: None,
            owner_uid: None,
            registry_source: None,
        };
        let selected = daemon_update_source(&entry, Some(station_lock_fixture()));
        assert!(
            matches!(selected, DaemonUpdateSource::Durable(source) if source == "@example/demo")
        );
    }

    fn station_lock_fixture() -> StationLock {
        let digest = |prefix: &str, byte: u8| format!("{prefix}{}", hex::encode([byte; 32]));
        StationLock {
            schema: "station-lock-v2".to_owned(),
            station_id: "official".to_owned(),
            trust_root: digest("sha256:", 1),
            coordinate: astrid_core::kernel_api::StationCoordinate {
                namespace: "official".to_owned(),
                name: "demo".to_owned(),
            },
            version: "1.0.0".to_owned(),
            publication_digest: digest("blake3:", 2),
            artifact_size: 0,
            artifact_media_type: "application/vnd.astrid.capsule".to_owned(),
            artifact_sha256: digest("sha256:", 3),
            artifact_blake3: digest("blake3:", 4),
            manifest_digest: digest("blake3:", 5),
            capsule_content_digest: digest("blake3:", 6),
            package_digest: digest("blake3:", 7),
            component_count: 0,
            component_digest: digest("blake3:", 8),
            wit_digest: digest("blake3:", 9),
            capability_digest: digest("blake3:", 10),
            ipc_digest: digest("blake3:", 11),
            runtime_abi_digest: digest("blake3:", 12),
            dependency_digest: digest("blake3:", 13),
            provenance_digest: digest("blake3:", 14),
            source_digest: digest("blake3:", 15),
        }
    }
}
