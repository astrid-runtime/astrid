//! Read-only, authenticated-owner update discovery. Publisher release metadata
//! is not an install-authority grant, nor proof that the archive was verified.
use anyhow::{Context, bail};
use astrid_capsule_install::github_source::{parse_github_source, strip_version_prefix};
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use serde::Serialize;
use std::collections::HashMap;
use std::process::ExitCode;

#[derive(Serialize)]
struct Inventory {
    schema_version: u32,
    principal: String,
    items: Vec<Item>,
}

#[derive(Serialize)]
struct Item {
    name: String,
    installed_version: String,
    wasm_hash: Option<String>,
    candidate_version: Option<String>,
    source: Option<String>,
    availability: Availability,
    verification: &'static str,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Available,
    Current,
    Ahead,
    Unsupported,
    Failed,
}

impl Availability {
    const fn label(&self) -> &'static str {
        match self {
            Self::Available => "update available",
            Self::Current => "up to date",
            Self::Ahead => "ahead of release",
            Self::Unsupported => "manual review",
            Self::Failed => "check failed",
        }
    }
}

async fn bounded_metadata(
    request: impl std::future::Future<Output = anyhow::Result<KernelResponse>>,
) -> anyhow::Result<KernelResponse> {
    // Bound the complete authenticated connection, including both workspace
    // checks: readiness can disappear between the initial probe and handshake.
    tokio::time::timeout(std::time::Duration::from_secs(5), request)
        .await
        .context("Runtime discovery timed out; start the runtime and retry")?
}

fn text_item(item: &Item) -> String {
    let candidate = item.candidate_version.as_deref().unwrap_or("unknown");
    format!(
        "{} {}: {} (candidate {}) — {}",
        item.name,
        item.installed_version,
        item.availability.label(),
        candidate,
        item.message
    )
}

fn repository(source: &str) -> Option<(String, String)> {
    let (base, _) = super::install::split_version_suffix(source);
    let (org, repo) = parse_github_source(base)?;
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && s != "."
            && s != ".."
    };
    (valid(&org) && valid(&repo)).then_some((org, repo))
}

async fn release(
    client: &reqwest::Client,
    org: &str,
    repo: &str,
) -> Result<serde_json::Value, String> {
    let mut response = client
        .get(format!(
            "https://api.github.com/repos/{org}/{repo}/releases/latest"
        ))
        .send()
        .await
        .map_err(|_| "GitHub is unreachable".to_owned())?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub returned HTTP {}; this is not an up-to-date result",
            response.status()
        ));
    }
    // Release metadata is a bounded control response, not an artifact download.
    // One MiB accommodates large release inventories without accepting a stream.
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "GitHub response was interrupted".to_owned())?
    {
        if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
            return Err("GitHub release metadata exceeds one MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "GitHub returned malformed release metadata".into())
}

fn classify(
    name: &str,
    installed: &str,
    document: &serde_json::Value,
) -> Result<(Availability, String), String> {
    let tag = document
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or("Release has no tag")?;
    let candidate = semver::Version::parse(strip_version_prefix(tag))
        .map_err(|_| "Custom release tags need publisher-specific update metadata".to_owned())?;
    let installed = semver::Version::parse(installed)
        .map_err(|_| "Installed package has no semantic version".to_owned())?;
    // Do not infer a monorepo's package from the first .capsule asset. Only a
    // conventional exact package asset is advertised by this generic adapter.
    let expected = format!("{name}.capsule");
    let count = document
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(&expected))
        .count();
    if count != 1 {
        return Err("Release does not identify exactly one matching capsule asset; review its publisher instructions".into());
    }
    let availability = match candidate.cmp(&installed) {
        std::cmp::Ordering::Greater => Availability::Available,
        std::cmp::Ordering::Equal => Availability::Current,
        std::cmp::Ordering::Less => Availability::Ahead,
    };
    Ok((availability, candidate.to_string()))
}

pub(crate) async fn check(target: Option<&str>, json: bool) -> anyhow::Result<ExitCode> {
    // This connects only to the existing authenticated workspace; unlike
    // install it never calls ensure_persistent_daemon.
    require_ready_metadata(&crate::socket_client::readiness_path())?;
    let response = bounded_metadata(async {
        let mut kernel = crate::socket_client::connect_kernel_for_workspace(None).await?;
        Ok(kernel.request(KernelRequest::GetCapsuleMetadata).await?)
    })
    .await?;
    let entries = match response {
        KernelResponse::CapsuleMetadata(entries) => entries,
        KernelResponse::Error(message) => {
            bail!("Runtime refused capsule metadata discovery: {message}")
        },
        _ => bail!("Unexpected runtime response to capsule metadata discovery"),
    };
    if target.is_some_and(|name| !entries.iter().any(|entry| entry.name == name)) {
        bail!("Requested capsule is not installed in this principal");
    }
    let client = super::install_github::github_api_client()?;
    let mut releases = HashMap::new();
    let mut items = Vec::new();
    for entry in entries
        .into_iter()
        .filter(|entry| target.is_none_or(|name| entry.name == name))
    {
        let mut item = Item { name: entry.name, installed_version: entry.version, wasm_hash: entry.wasm_hash, candidate_version: None, source: None, availability: Availability::Unsupported, verification: "unverified", message: "No supported remote source recorded; update through the managing distribution or local source".into() };
        if let Some((org, repo)) = entry.update_source.as_deref().and_then(repository) {
            item.source = Some(format!("@{org}/{repo}"));
            let key = (org, repo);
            if !releases.contains_key(&key) {
                releases.insert(key.clone(), release(&client, &key.0, &key.1).await);
            }
            match &releases[&key] {
                Ok(document) => match classify(&item.name, &item.installed_version, document) {
                    Ok((availability, version)) => {
                        item.availability = availability;
                        item.candidate_version = Some(version);
                        item.message = "Publisher release metadata only. Review the archive identity, compatibility and new capabilities before installation; distribution-managed capsules must use their distribution updater.".into();
                    },
                    Err(message) => item.message = message,
                },
                Err(message) => {
                    item.availability = Availability::Failed;
                    item.message.clone_from(message);
                },
            }
        }
        items.push(item);
    }
    let failed = items
        .iter()
        .any(|item| matches!(item.availability, Availability::Failed));
    let inventory = Inventory {
        schema_version: 1,
        principal: crate::principal::current().to_string(),
        items,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string(&inventory).context("encode update inventory")?
        );
    } else {
        for item in inventory.items {
            println!("{}", text_item(&item));
        }
    }
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn require_ready_metadata(path: &std::path::Path) -> anyhow::Result<()> {
    // The ordinary connection helper waits for a daemon that is starting.
    // Discovery must not spend that startup window waiting for a stopped
    // runtime. This is only an availability probe: the connection still
    // authenticates and checks the selected workspace before querying it.
    let metadata = std::fs::metadata(path)
        .context("Runtime is not ready; start it explicitly before checking capsule updates")?;
    if !metadata.is_file() {
        bail!("Runtime readiness metadata is not a regular file");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn readiness_disappearing_during_connect_cannot_wait_for_startup() {
        let result = bounded_metadata(std::future::pending()).await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn plain_output_names_status_and_candidate() {
        let mut item = Item {
            name: "alpha".into(),
            installed_version: "1.0.0".into(),
            candidate_version: Some("2.0.0".into()),
            wasm_hash: None,
            source: None,
            availability: Availability::Available,
            verification: "unverified",
            message: "Review before installation".into(),
        };
        assert!(text_item(&item).contains("update available (candidate 2.0.0)"));
        item.availability = Availability::Current;
        assert!(text_item(&item).contains("up to date"));
        item.availability = Availability::Ahead;
        assert!(text_item(&item).contains("ahead of release"));
    }
    #[test]
    fn stopped_runtime_is_reported_without_startup_wait() {
        let path =
            std::env::temp_dir().join(format!("astrid-update-stopped-{}", uuid::Uuid::new_v4()));
        assert!(require_ready_metadata(&path).is_err());
        assert!(!path.exists());
    }
    #[test]
    fn never_guesses_an_asset_or_custom_tag() {
        assert!(
            classify(
                "alpha",
                "1.0.0",
                &serde_json::json!({"tag_name":"v2.0.0","assets":[{"name":"beta.capsule"}]})
            )
            .is_err()
        );
        assert!(
            classify(
                "alpha",
                "1.0.0",
                &serde_json::json!({"tag_name":"alpha-2.0","assets":[{"name":"alpha.capsule"}]})
            )
            .is_err()
        );
    }
    #[test]
    fn source_validation_does_not_turn_paths_into_network_requests() {
        assert!(repository("/tmp/github.com/org/repo").is_none());
        assert!(repository("@../repo").is_none());
        assert_eq!(
            repository("@org/repo@1.0.0"),
            Some(("org".into(), "repo".into()))
        );
    }
    #[test]
    fn ahead_is_not_an_upgrade() {
        let result = classify(
            "alpha",
            "3.0.0",
            &serde_json::json!({"tag_name":"v2.0.0","assets":[{"name":"alpha.capsule"}]}),
        )
        .unwrap();
        assert!(matches!(result.0, Availability::Ahead));
    }
}
