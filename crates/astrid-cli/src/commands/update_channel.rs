//! Strict signed-channel metadata validation and rollback state.

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, bail, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::cli::UpdateChannel;

use super::self_update::{api_base, download_bounded, exact_asset_url};
use super::update_auth::MetadataAuthenticator;

const PRODUCT: &str = "astrid-runtime";
const REPOSITORY: &str = "astrid-runtime/astrid";
const CONTRACTS_REPOSITORY: &str = "astrid-runtime/wit";
const TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
];
const MAX_RELEASE_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;

pub(super) struct ResolvedChannelRelease {
    pub(super) version: String,
    pub(super) release: serde_json::Value,
    pub(super) target_blake3: String,
}

async fn fetch_release_by_tag(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    tag: &str,
) -> anyhow::Result<serde_json::Value> {
    let encoded_tag: String = url::form_urlencoded::byte_serialize(tag.as_bytes()).collect();
    let url = format!(
        "{}/repos/{owner}/{repo}/releases/tags/{encoded_tag}",
        api_base()
    );
    let body =
        download_bounded(client, &url, MAX_RELEASE_METADATA_BYTES, "release metadata").await?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).context("failed to parse release metadata")?;
    let actual_tag = json
        .get("tag_name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("release has no tag_name"))?;
    ensure!(
        actual_tag == tag,
        "release endpoint returned tag '{actual_tag}', expected '{tag}'"
    );
    Ok(json)
}

pub(super) async fn resolve_signed_channel(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    channel: UpdateChannel,
    target: &str,
) -> anyhow::Result<ResolvedChannelRelease> {
    // One process owns channel acceptance through the final atomic pointer
    // commit. Without this lock, concurrent generations could interleave and
    // leave the lower pointer as the accepted rollback floor.
    let _lock = acquire_channel_lock(channel)?;
    let channel_release = fetch_release_by_tag(
        client,
        owner,
        repo,
        &format!("channel-{}", channel.as_str()),
    )
    .await?;
    let pointer_url = exact_asset_url(&channel_release, "channel.toml")?.to_owned();
    let pointer_bundle_url =
        exact_asset_url(&channel_release, "channel.toml.sigstore.json")?.to_owned();
    let pointer =
        download_bounded(client, &pointer_url, MAX_MANIFEST_BYTES, "channel metadata").await?;
    let pointer_bundle = download_bounded(
        client,
        &pointer_bundle_url,
        MAX_BUNDLE_BYTES,
        "channel metadata authentication bundle",
    )
    .await?;

    let authenticator = MetadataAuthenticator::production()
        .await
        .map_err(anyhow::Error::new)?;
    let pointer = authenticator
        .authenticate_channel_pointer(pointer, &pointer_bundle)
        .map_err(anyhow::Error::new)?
        .into_bytes();
    let parsed = parse_channel(&pointer, channel, Utc::now())?;
    enforce_continuity(channel, &parsed, &pointer)?;

    let release = fetch_release_by_tag(client, owner, repo, parsed.tag()).await?;
    let manifest_url = exact_asset_url(&release, parsed.metadata_asset())?.to_owned();
    let manifest_bundle_name = format!("{}.sigstore.json", parsed.metadata_asset());
    let manifest_bundle_url = exact_asset_url(&release, &manifest_bundle_name)?.to_owned();
    let manifest = download_bounded(
        client,
        &manifest_url,
        MAX_MANIFEST_BYTES,
        "immutable release manifest",
    )
    .await?;
    let manifest_bundle = download_bounded(
        client,
        &manifest_bundle_url,
        MAX_BUNDLE_BYTES,
        "release manifest authentication bundle",
    )
    .await?;
    let manifest = authenticator
        .authenticate_release_manifest(manifest, &manifest_bundle, parsed.version())
        .map_err(anyhow::Error::new)?
        .into_bytes();
    verify_release_manifest(&manifest, &parsed)?;
    let target_blake3 = parsed.target(target)?.blake3.clone();

    // Accept only a pointer whose immutable release manifest independently
    // authenticates and matches every content-bound field.
    persist_accepted(channel, &pointer, &pointer_bundle)?;
    Ok(ResolvedChannelRelease {
        version: parsed.version().to_owned(),
        release,
        target_blake3,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct TargetMetadata {
    pub(super) triple: String,
    pub(super) asset: String,
    pub(super) size: i64,
    pub(super) blake3: String,
    pub(super) sha256: String,
    pub(super) sigstore_bundle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ChannelRelease {
    version: String,
    tag: String,
    source_commit: String,
    metadata_asset: String,
    metadata_blake3: String,
    release_workflow_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct ChannelPointer {
    schema_version: i64,
    kind: String,
    product: String,
    repository: String,
    channel: String,
    generation: i64,
    published_at: String,
    expires_at: String,
    release: ChannelRelease,
    targets: Vec<TargetMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ContractsMetadata {
    repository: String,
    commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: i64,
    kind: String,
    product: String,
    repository: String,
    version: String,
    tag: String,
    source_commit: String,
    release_workflow_identity: String,
    contracts: ContractsMetadata,
    targets: Vec<TargetMetadata>,
}

impl ChannelPointer {
    pub(super) fn version(&self) -> &str {
        &self.release.version
    }

    pub(super) fn tag(&self) -> &str {
        &self.release.tag
    }

    pub(super) fn metadata_asset(&self) -> &str {
        &self.release.metadata_asset
    }

    pub(super) fn target(&self, triple: &str) -> anyhow::Result<&TargetMetadata> {
        self.targets
            .iter()
            .find(|target| target.triple == triple)
            .ok_or_else(|| anyhow::anyhow!("signed channel has no target '{triple}'"))
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_version(value: &str) -> anyhow::Result<semver::Version> {
    let parsed = semver::Version::parse(value)
        .with_context(|| format!("signed channel version '{value}' is not valid semver"))?;
    ensure!(
        parsed.to_string() == value,
        "signed channel version '{value}' is not canonical semver"
    );
    Ok(parsed)
}

fn canonical_time(value: &str, label: &str) -> anyhow::Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("signed channel {label} is not RFC3339"))?
        .with_timezone(&Utc);
    ensure!(
        parsed.to_rfc3339_opts(SecondsFormat::Secs, true) == value,
        "signed channel {label} is not canonical UTC RFC3339 seconds"
    );
    Ok(parsed)
}

fn validate_targets(targets: &[TargetMetadata], version: &str) -> anyhow::Result<()> {
    ensure!(
        targets.len() == TARGETS.len(),
        "signed metadata must contain exactly four targets"
    );
    let mut seen = HashSet::new();
    for target in targets {
        ensure!(
            TARGETS.contains(&target.triple.as_str()) && seen.insert(target.triple.as_str()),
            "signed metadata target set is invalid"
        );
        let expected_asset = format!("astrid-{version}-{}.tar.gz", target.triple);
        ensure!(
            target.asset == expected_asset
                && target.sigstore_bundle == format!("{expected_asset}.sigstore.json"),
            "signed metadata asset identity is invalid for {}",
            target.triple
        );
        ensure!(
            target.size > 0,
            "signed metadata target size must be positive"
        );
        ensure!(
            is_lower_hex_64(&target.blake3) && is_lower_hex_64(&target.sha256),
            "signed metadata target digest is invalid"
        );
    }
    ensure!(
        seen.len() == TARGETS.len(),
        "signed metadata target set is incomplete"
    );
    Ok(())
}

pub(super) fn parse_channel(
    bytes: &[u8],
    expected_channel: UpdateChannel,
    now: DateTime<Utc>,
) -> anyhow::Result<ChannelPointer> {
    let text = std::str::from_utf8(bytes).context("signed channel metadata is not UTF-8")?;
    let pointer: ChannelPointer =
        toml::from_str(text).context("signed channel metadata is invalid TOML")?;
    validate_pointer(&pointer, expected_channel, Some(now))?;
    Ok(pointer)
}

fn validate_pointer(
    pointer: &ChannelPointer,
    expected_channel: UpdateChannel,
    now: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    ensure!(
        pointer.schema_version == 1
            && pointer.kind == "astrid-channel"
            && pointer.product == PRODUCT
            && pointer.repository == REPOSITORY,
        "signed channel identity is invalid"
    );
    ensure!(
        pointer.channel == expected_channel.as_str(),
        "signed channel names '{}', expected '{}'",
        pointer.channel,
        expected_channel.as_str()
    );
    ensure!(
        pointer.generation > 0,
        "signed channel generation must be positive"
    );
    let published = canonical_time(&pointer.published_at, "published-at")?;
    let expires = canonical_time(&pointer.expires_at, "expires-at")?;
    ensure!(expires > published, "signed channel lifetime is invalid");
    if let Some(now) = now {
        ensure!(now <= expires, "signed channel metadata has expired");
        let latest_reasonable_publication = now
            .checked_add_signed(chrono::Duration::seconds(MAX_FUTURE_SKEW_SECS))
            .context("channel publication skew overflowed the clock")?;
        ensure!(
            published <= latest_reasonable_publication,
            "signed channel published-at is unreasonably far in the future"
        );
    }
    let max_lifetime = match expected_channel {
        UpdateChannel::Stable => chrono::Duration::days(30),
        UpdateChannel::Dev => chrono::Duration::days(7),
        UpdateChannel::Nightly => chrono::Duration::days(2),
    };
    ensure!(
        expires.signed_duration_since(published) <= max_lifetime,
        "signed channel lifetime exceeds the maximum for its channel"
    );
    let version = canonical_version(&pointer.release.version)?;
    if expected_channel == UpdateChannel::Stable {
        ensure!(
            version.pre.is_empty(),
            "stable channel cannot point to a prerelease"
        );
    }
    ensure!(
        pointer.release.tag == format!("v{version}"),
        "signed channel release tag does not match its version"
    );
    ensure!(
        is_commit(&pointer.release.source_commit),
        "signed channel source commit is invalid"
    );
    ensure!(
        pointer.release.metadata_asset == format!("astrid-{version}-release.toml"),
        "signed channel release metadata asset is invalid"
    );
    ensure!(
        is_lower_hex_64(&pointer.release.metadata_blake3),
        "signed channel release metadata BLAKE3 is invalid"
    );
    ensure!(
        pointer.release.release_workflow_identity
            == format!(
                "https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}"
            ),
        "signed channel release workflow identity is invalid"
    );
    validate_targets(&pointer.targets, &pointer.release.version)?;
    Ok(())
}

pub(super) fn verify_release_manifest(
    bytes: &[u8],
    pointer: &ChannelPointer,
) -> anyhow::Result<()> {
    ensure!(
        blake3::hash(bytes).to_hex().as_str() == pointer.release.metadata_blake3,
        "immutable release manifest does not match the channel BLAKE3 digest"
    );
    let text = std::str::from_utf8(bytes).context("release manifest is not UTF-8")?;
    let manifest: ReleaseManifest =
        toml::from_str(text).context("release manifest is invalid TOML")?;
    ensure!(
        manifest.schema_version == 1
            && manifest.kind == "astrid-release"
            && manifest.product == PRODUCT
            && manifest.repository == REPOSITORY,
        "release manifest identity is invalid"
    );
    ensure!(
        manifest.version == pointer.release.version
            && manifest.tag == pointer.release.tag
            && manifest.source_commit == pointer.release.source_commit
            && manifest.release_workflow_identity == pointer.release.release_workflow_identity,
        "release manifest does not match the signed channel pointer"
    );
    ensure!(
        manifest.contracts.repository == CONTRACTS_REPOSITORY
            && is_commit(&manifest.contracts.commit),
        "release manifest contracts identity is invalid"
    );
    validate_targets(&manifest.targets, &manifest.version)?;
    ensure!(
        manifest.targets == pointer.targets,
        "release manifest targets do not match the signed channel pointer"
    );
    Ok(())
}

fn state_paths(channel: UpdateChannel) -> anyhow::Result<(PathBuf, PathBuf)> {
    let home = astrid_core::dirs::AstridHome::resolve()?;
    let dir = home.var_dir().join("update").join("channels");
    Ok((
        dir.join(format!("{}.toml", channel.as_str())),
        dir.join(format!("{}.toml.sigstore.json", channel.as_str())),
    ))
}

struct ChannelLock(std::fs::File);

impl Drop for ChannelLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn acquire_channel_lock(channel: UpdateChannel) -> anyhow::Result<ChannelLock> {
    let (pointer_path, _) = state_paths(channel)?;
    let dir = pointer_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("channel state path has no parent"))?;
    std::fs::create_dir_all(dir).context("could not create channel state directory")?;
    let lock_path = dir.join(format!(".{}.lock", channel.as_str()));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .context("could not open channel update lock")?;
    lock.try_lock_exclusive()
        .context("another Astrid process is already resolving this channel")?;
    Ok(ChannelLock(lock))
}

pub(super) fn enforce_continuity(
    channel: UpdateChannel,
    candidate: &ChannelPointer,
    candidate_bytes: &[u8],
) -> anyhow::Result<()> {
    let (pointer_path, _) = state_paths(channel)?;
    let previous_bytes = match std::fs::read(&pointer_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("could not read accepted channel state"),
    };
    let text =
        std::str::from_utf8(&previous_bytes).context("accepted channel state is not UTF-8")?;
    let previous: ChannelPointer =
        toml::from_str(text).context("accepted channel state is invalid TOML")?;
    validate_pointer(&previous, channel, None)?;
    enforce_continuity_values(candidate, candidate_bytes, &previous, &previous_bytes)
}

fn enforce_continuity_values(
    candidate: &ChannelPointer,
    candidate_bytes: &[u8],
    previous: &ChannelPointer,
    previous_bytes: &[u8],
) -> anyhow::Result<()> {
    if candidate.generation < previous.generation {
        bail!("signed channel generation rollback rejected");
    }
    if candidate.generation == previous.generation && candidate_bytes != previous_bytes {
        bail!("signed channel same-generation equivocation rejected");
    }
    Ok(())
}

pub(super) fn persist_accepted(
    channel: UpdateChannel,
    pointer: &[u8],
    bundle: &[u8],
) -> anyhow::Result<()> {
    let (pointer_path, bundle_path) = state_paths(channel)?;
    let dir = pointer_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("channel state path has no parent"))?;
    std::fs::create_dir_all(dir).context("could not create channel state directory")?;
    // The pointer is the continuity commit marker and is replaced last. A
    // crash after the bundle write leaves the prior accepted generation in
    // force; the next locked resolution can safely repair the bundle.
    atomic_write(&bundle_path, bundle)?;
    atomic_write(&pointer_path, pointer)?;
    Ok(())
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("channel state path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(dir)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("could not persist {}", path.display()))?;
    std::fs::File::open(dir)?
        .sync_all()
        .with_context(|| format!("could not sync {}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
#[path = "update_channel_tests.rs"]
mod tests;
