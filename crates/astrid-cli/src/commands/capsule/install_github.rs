//! GitHub API client and concrete release-ref resolution for capsule installs.

use anyhow::{Context, bail};

fn github_token() -> Option<String> {
    ["GH_TOKEN", "GITHUB_TOKEN"].into_iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn github_api_client() -> anyhow::Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = github_token() {
        match reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(mut value) => {
                value.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, value);
            },
            Err(_) => eprintln!(
                "warning: ignoring malformed GH_TOKEN/GITHUB_TOKEN \
                 (not a valid HTTP header value); proceeding with anonymous GitHub API access"
            ),
        }
    }
    reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .default_headers(headers)
        .build()
        .context("failed to build GitHub HTTP client")
}

pub(super) fn release_tag_url(org: &str, repo: &str, tag: &str) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(&format!(
        "https://api.github.com/repos/{org}/{repo}/releases"
    ))
    .context("failed to build GitHub releases URL")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("GitHub releases URL cannot be a base"))?
        .push("tags")
        .push(tag);
    Ok(url.to_string())
}

pub(super) async fn resolve_github_ref(
    client: &reqwest::Client,
    org: &str,
    repo: &str,
    version: Option<&str>,
    tag: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(tag) = tag {
        return Ok(tag.to_string());
    }
    if let Some(version) = version {
        for candidate in [format!("v{version}"), version.to_string()] {
            let tag_url = release_tag_url(org, repo, &candidate)?;
            let response = client.get(&tag_url).send().await.with_context(|| {
                format!("failed to query release tag {candidate} for {org}/{repo}")
            })?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                continue;
            }
            if !response.status().is_success() {
                bail!(
                    "GitHub API error querying release tag {candidate} for {org}/{repo}: HTTP {}",
                    response.status()
                );
            }
            let json = response
                .json::<serde_json::Value>()
                .await
                .with_context(|| format!("invalid GitHub API response for tag {candidate}"))?;
            return Ok(json
                .get("tag_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&candidate)
                .to_string());
        }
        bail!("no GitHub release found for version {version} in {org}/{repo}");
    }

    tracing::debug!(%org, %repo, "no version/tag pin — resolving latest release");
    let api_url = format!("https://api.github.com/repos/{org}/{repo}/releases/latest");
    let response = client
        .get(&api_url)
        .send()
        .await
        .context("failed to reach GitHub API for latest release")?;
    if !response.status().is_success() {
        bail!(
            "GitHub API returned {} for {org}/{repo} latest release",
            response.status()
        );
    }
    let json: serde_json::Value = response
        .json()
        .await
        .context("invalid GitHub API response")?;
    Ok(json
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("latest")
        .to_string())
}
