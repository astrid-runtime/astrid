//! Authenticate selected Distro sources before `init` mutates runtime state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;

use super::super::distro::local_source::{
    normalize_authenticated_manifest_path, resolve_local_capsule_archive,
};
use super::super::distro::lock::{DistroLock, manifest_hash};
use super::super::distro::manifest::{DistroCapsule, DistroManifest, parse_manifest};
use super::super::distro::trust;
use super::InitOpts;

/// A selected signed source Distro after its authentication boundary.
#[derive(Debug)]
pub(super) struct SignedDistroBundle {
    pub(super) manifest: DistroManifest,
    pub(super) lock: DistroLock,
    /// Exact raw `Distro.toml` bytes represented by `manifest_hash`.
    pub(super) manifest_hash: String,
    /// Maintainer-resolved refs from the signed lock, keyed by capsule name.
    pub(super) pinned_refs: HashMap<String, String>,
    /// The local manifest whose parent authenticates relative members.
    pub(super) manifest_path: Option<PathBuf>,
}

/// A source after authentication and before runtime mutation.
#[derive(Debug)]
pub(super) enum PreparedDistro {
    Shuttle,
    Manifest {
        manifest: Box<DistroManifest>,
        manifest_hash: String,
    },
    Signed(Box<SignedDistroBundle>),
}

/// Split an authenticated source into its install inputs.
pub(super) fn unpack_prepared(
    prepared: PreparedDistro,
) -> (DistroManifest, String, Option<SignedDistroBundle>) {
    match prepared {
        PreparedDistro::Shuttle => unreachable!("shuttle installs return before this branch"),
        PreparedDistro::Manifest {
            manifest,
            manifest_hash,
        } => (*manifest, manifest_hash, None),
        PreparedDistro::Signed(bundle) => {
            let manifest = bundle.manifest.clone();
            (manifest, bundle.manifest_hash.clone(), Some(*bundle))
        },
    }
}

/// Authenticate a selected source before any runtime state is created.
pub(super) async fn prepare_distro_source(
    distro_source: &str,
    opts: &InitOpts,
    home: &AstridHome,
) -> anyhow::Result<PreparedDistro> {
    if distro_source.ends_with(".shuttle") {
        return Ok(PreparedDistro::Shuttle);
    }
    if opts.require_signed {
        return Ok(PreparedDistro::Signed(Box::new(
            fetch_signed_manifest(distro_source, opts.offline, opts.accept_new_key, home).await?,
        )));
    }
    let (manifest_bytes, manifest) = fetch_manifest_bytes(distro_source, opts.offline).await?;
    Ok(PreparedDistro::Manifest {
        manifest: Box::new(manifest),
        manifest_hash: manifest_hash(&manifest_bytes),
    })
}

/// Resolve each member to bytes and prove those bytes match the signed lock.
pub(super) async fn resolve_signed_capsules(
    selected: &[DistroCapsule],
    bundle: &SignedDistroBundle,
    staging: &Path,
) -> anyhow::Result<Vec<DistroCapsule>> {
    let signed_by_name: HashMap<&str, &super::super::distro::lock::LockedCapsule> = bundle
        .lock
        .capsules
        .iter()
        .map(|capsule| (capsule.name.as_str(), capsule))
        .collect();
    let mut resolved = Vec::with_capacity(selected.len());
    for capsule in selected {
        let signed = signed_by_name
            .get(capsule.name.as_str())
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!("selected capsule '{}' is not in signed lock", capsule.name)
            })?;
        let pinned_tag = signed.resolved_ref.as_deref().or(capsule.tag.as_deref());
        let archive_path = staging.join(format!("{}.capsule", capsule.name));
        if let Some(local_source) =
            resolve_local_capsule_archive(&capsule.source, bundle.manifest_path.as_deref())
                .with_context(|| format!("resolve signed capsule {}", capsule.name))?
        {
            std::fs::copy(&local_source, &archive_path).with_context(|| {
                format!(
                    "copy signed capsule {} from {}",
                    capsule.name,
                    local_source.display()
                )
            })?;
        } else {
            if capsule.source.starts_with('.') || capsule.source.starts_with('/') {
                bail!(
                    "signed Distro member '{}' must resolve to a prebuilt .capsule archive",
                    capsule.name
                );
            }
            let _ = Some(
                super::super::capsule::install::resolve_capsule_to_file(
                    &capsule.source,
                    (!capsule.version.is_empty()).then_some(capsule.version.as_str()),
                    pinned_tag,
                    Some(&capsule.name),
                    &archive_path,
                )
                .await?,
            );
        }
        let bytes = std::fs::read(&archive_path)
            .with_context(|| format!("read resolved capsule {}", capsule.name))?;
        let actual = manifest_hash(&bytes);
        if signed.hash != actual {
            std::fs::remove_file(&archive_path)
                .with_context(|| format!("discard hash-mismatched capsule {}", capsule.name))?;
            anyhow::bail!(
                "capsule '{}' hash mismatch: signed lock has {}, resolved artifact has {actual}",
                capsule.name,
                signed.hash
            );
        }
        let mut member = capsule.clone();
        member.source = archive_path.to_string_lossy().into_owned();
        resolved.push(member);
    }
    Ok(resolved)
}

/// Resolve a distro source to its exact bytes and parse those bytes once.
async fn fetch_manifest_bytes(
    source: &str,
    offline: bool,
) -> anyhow::Result<(Vec<u8>, DistroManifest)> {
    let path = Path::new(source);
    if path.exists() && path.is_file() {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        return parse_manifest_bytes(bytes);
    }

    if offline {
        bail!(
            "--offline: '{source}' is not a local file and network fetch is forbidden \
             (use a Distro.toml path or a .shuttle archive)"
        );
    }

    let url = super::resolve_distro_url(source)?;
    eprintln!("Fetching Distro.toml...");
    let bytes = fetch_url_bytes(&url, "Distro.toml", 1024 * 1024).await?;
    parse_manifest_bytes(bytes)
}

fn parse_manifest_bytes(bytes: Vec<u8>) -> anyhow::Result<(Vec<u8>, DistroManifest)> {
    anyhow::ensure!(bytes.len() <= 1024 * 1024, "Distro.toml exceeds 1 MB limit");
    let content = std::str::from_utf8(&bytes).context("Distro.toml is not valid UTF-8")?;
    let manifest = parse_manifest(content)?;
    Ok((bytes, manifest))
}

/// Fetch the signed TOML, its maintainer lock, and existing lock signature.
async fn fetch_signed_manifest(
    source: &str,
    offline: bool,
    accept_new_key: bool,
    home: &AstridHome,
) -> anyhow::Result<SignedDistroBundle> {
    let source_path = PathBuf::from(source);
    let local_manifest_path = source_path
        .is_file()
        .then(|| normalize_authenticated_manifest_path(&source_path))
        .transpose()?;
    let source = local_manifest_path
        .as_deref()
        .and_then(Path::to_str)
        .map_or_else(|| source.to_owned(), str::to_owned);
    let (manifest_bytes, manifest) = fetch_manifest_bytes(&source, offline).await?;
    let manifest_hash = manifest_hash(&manifest_bytes);
    let lock_bytes = fetch_signed_member(&source, offline, "Distro.lock").await?;
    anyhow::ensure!(
        lock_bytes.len() <= 1024 * 1024,
        "Distro.lock exceeds 1 MB limit"
    );
    let lock_text = std::str::from_utf8(&lock_bytes).context("Distro.lock is not valid UTF-8")?;
    let lock: DistroLock =
        toml::from_str(lock_text).context("failed to parse signed Distro.lock")?;
    let sig_bytes = fetch_signed_member(&source, offline, "Distro.sig").await?;
    anyhow::ensure!(
        sig_bytes.len() <= 64 * 1024,
        "Distro.sig exceeds size limit"
    );
    let sig_hex = std::str::from_utf8(&sig_bytes).context("Distro.sig is not valid UTF-8")?;
    let pinned_refs = verify_signed_manifest(
        home,
        &manifest,
        &manifest_hash,
        &lock,
        sig_hex,
        accept_new_key,
    )?;

    Ok(SignedDistroBundle {
        manifest,
        lock,
        manifest_hash,
        pinned_refs,
        manifest_path: local_manifest_path,
    })
}

/// Read a lock/sig sibling locally or at its matching remote path.
async fn fetch_signed_member(
    source: &str,
    offline: bool,
    file_name: &str,
) -> anyhow::Result<Vec<u8>> {
    let manifest_path = Path::new(source);
    if manifest_path.exists() && manifest_path.is_file() {
        let path = manifest_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Distro.toml has no parent directory"))?
            .join(file_name);
        return std::fs::read(&path)
            .with_context(|| format!("failed to read signed source member {}", path.display()));
    }

    if offline {
        bail!(
            "--offline: signed source member {file_name} is not local and network access is forbidden"
        );
    }

    let mut url = url::Url::parse(&super::resolve_distro_url(source)?)?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("signed source URL cannot contain path segments"))?
        .pop()
        .push(file_name);
    fetch_url_bytes(url.as_str(), file_name, 1024 * 1024).await
}

async fn fetch_url_bytes(url: &str, name: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch {name}"))?;
    if !response.status().is_success() {
        bail!(
            "failed to fetch {name} from {url} (HTTP {})",
            response.status()
        );
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(bytes.len() <= limit, "{name} exceeds size limit");
    }
    Ok(bytes)
}

/// Bind exact TOML bytes into the signed lock, then verify that lock.
fn verify_signed_manifest(
    home: &AstridHome,
    manifest: &DistroManifest,
    manifest_hash: &str,
    lock: &DistroLock,
    sig_hex: &str,
    accept_new_key: bool,
) -> anyhow::Result<HashMap<String, String>> {
    if lock.manifest_hash.as_deref() != Some(manifest_hash) {
        bail!(
            "signed Distro.toml does not match Distro.lock manifest_hash; refusing to resolve members"
        );
    }
    validate_signed_member_sets(manifest, lock)?;
    let signing = manifest.distro.signing.as_ref().ok_or_else(|| {
        anyhow::anyhow!("signed Distro.toml has no [distro.signing] configuration")
    })?;
    let outcome = trust::verify_and_pin(
        home,
        &manifest.distro.id,
        &signing.pubkey,
        sig_hex,
        lock,
        accept_new_key,
        trust::TrustPolicy::RequireExistingPin,
    )?;
    tracing::info!(
        distro = %manifest.distro.id,
        action = ?outcome.action,
        "authenticated source Distro"
    );

    Ok(lock
        .capsules
        .iter()
        .filter_map(|capsule| {
            capsule
                .resolved_ref
                .clone()
                .map(|resolved_ref| (capsule.name.clone(), resolved_ref))
        })
        .collect())
}

/// Require the signed lock to describe exactly the authenticated TOML members.
fn validate_signed_member_sets(manifest: &DistroManifest, lock: &DistroLock) -> anyhow::Result<()> {
    if lock.schema_version != manifest.schema_version
        || lock.distro.id != manifest.distro.id
        || lock.distro.version != manifest.distro.version
    {
        bail!("Distro.lock identity does not match the signed Distro.toml");
    }

    let declared: HashMap<&str, &DistroCapsule> = manifest
        .capsules
        .iter()
        .map(|capsule| (capsule.name.as_str(), capsule))
        .collect();
    anyhow::ensure!(
        declared.len() == manifest.capsules.len() && lock.capsules.len() == declared.len(),
        "signed Distro.lock members do not match Distro.toml declarations"
    );
    for capsule in &lock.capsules {
        let declared_capsule = declared
            .get(capsule.name.as_str())
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "signed Distro.lock contains undeclared capsule '{}'",
                    capsule.name
                )
            })?;
        if capsule.source != declared_capsule.source || capsule.version != declared_capsule.version
        {
            bail!(
                "signed Distro.lock entry '{}' does not match Distro.toml",
                capsule.name
            );
        }
        anyhow::ensure!(
            !capsule.hash.is_empty(),
            "signed Distro.lock entry '{}' has no capsule hash",
            capsule.name
        );
    }
    Ok(())
}
