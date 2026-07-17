//! Cached stable-channel notices and package-manager handoff.

use std::path::PathBuf;

use anyhow::bail;

use crate::theme::Theme;

use super::{
    CHECK_TTL_SECS, CURRENT_VERSION, InstallMethod, UpdateChannel, platform_target, resolve_repo,
    running_binary, update_channel,
};

#[derive(serde::Serialize, serde::Deserialize)]
struct UpdateCache {
    checked_at: u64,
    latest_version: String,
    channel: String,
}

fn cache_path() -> anyhow::Result<PathBuf> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    Ok(home.var_dir().join("update-check.json"))
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(super) fn write_cache(channel: UpdateChannel, version: &str) {
    let cache = UpdateCache {
        checked_at: now_epoch(),
        latest_version: version.to_owned(),
        channel: channel.as_str().to_owned(),
    };
    if let Ok(path) = cache_path()
        && let Ok(json) = serde_json::to_string(&cache)
    {
        let _ = std::fs::write(path, json);
    }
}

pub(crate) async fn check_for_update_cached() -> Option<String> {
    let path = cache_path().ok()?;
    if let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(cache) = serde_json::from_str::<UpdateCache>(&data)
        && now_epoch().saturating_sub(cache.checked_at) < CHECK_TTL_SECS
        && cache.channel == UpdateChannel::Stable.as_str()
    {
        let current = semver::Version::parse(CURRENT_VERSION).ok()?;
        let selected = semver::Version::parse(&cache.latest_version).ok()?;
        return (selected != current).then_some(cache.latest_version);
    }

    let target = platform_target().ok()?;
    let (owner, repo) = resolve_repo(None).ok()?;
    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let resolved = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        update_channel::resolve_signed_channel(
            &client,
            &owner,
            &repo,
            UpdateChannel::Stable,
            target,
        ),
    )
    .await
    .ok()?
    .ok()?;
    let version = resolved.version;
    write_cache(UpdateChannel::Stable, &version);
    let current = semver::Version::parse(CURRENT_VERSION).ok()?;
    let selected = semver::Version::parse(&version).ok()?;
    (selected != current).then_some(version)
}

pub(crate) async fn print_update_banner() {
    let Some(latest) = check_for_update_cached().await else {
        return;
    };
    let current = semver::Version::parse(CURRENT_VERSION).ok();
    let selected = semver::Version::parse(&latest).ok();
    let how = running_binary()
        .ok()
        .map(|executable| InstallMethod::detect(&executable))
        .and_then(|method| {
            managed_update_command(method, current.as_ref()?, selected.as_ref()?, &latest)
                .or_else(|| Some(method.upgrade_command(UpdateChannel::Stable).to_owned()))
        })
        .unwrap_or_else(|| "astrid update".to_owned());
    eprintln!(
        "{}",
        Theme::warning(&format!(
            "Update available: v{CURRENT_VERSION} → v{latest}. Run `{how}` to upgrade."
        ))
    );
}

pub(super) fn managed_update_command(
    method: InstallMethod,
    current: &semver::Version,
    selected: &semver::Version,
    selected_version: &str,
) -> Option<String> {
    if !method.manages_own_binary() {
        return None;
    }
    Some(match method {
        InstallMethod::Homebrew if selected < current => {
            "brew reinstall astrid-runtime/tap/astrid".to_owned()
        },
        InstallMethod::Homebrew => "brew upgrade astrid-runtime/tap/astrid".to_owned(),
        InstallMethod::Cargo => {
            format!("cargo install astrid --version ={selected_version} --force")
        },
        InstallMethod::SelfManaged => unreachable!("self-managed installs update in place"),
    })
}

pub(super) fn handle_managed_channel(
    method: InstallMethod,
    channel: UpdateChannel,
    current: &semver::Version,
    selected: &semver::Version,
    selected_version: &str,
) -> anyhow::Result<bool> {
    if !method.manages_own_binary() {
        return Ok(false);
    }
    if channel != UpdateChannel::Stable {
        bail!(
            "{}-managed installs follow only stable; use a self-managed Astrid install for '{}'.",
            method.label(),
            channel
        );
    }
    if selected == current {
        return Ok(false);
    }
    let how = managed_update_command(method, current, selected, selected_version)
        .expect("package-managed method has an update command");
    let message = if selected < current {
        format!(
            "The signed stable channel rolled back v{CURRENT_VERSION} → v{selected_version}. Apply the package-managed rollback with:\n  {how}"
        )
    } else {
        format!(
            "Astrid was installed via {}. Update to signed stable v{selected_version} with:\n  {how}",
            method.label()
        )
    };
    println!(
        "{}",
        if selected < current {
            Theme::warning(&message)
        } else {
            Theme::info(&message)
        }
    );
    Ok(true)
}
