//! Thin subprocess adapter for the standalone `astrid-station` CLI.
//!
//! Station remains a separate transport/trust domain. This module only asks
//! it to resolve and fetch a verified archive, then hands Astrid a private
//! local path. Station coordinates and URLs never enter Astrid installer
//! provenance.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, StationLock};
use serde_json::Value;

const DEFAULT_HOME: &str = ".astrid-station";
const LOCK_SCHEMA_V2: &str = "station-lock-v2";
const MANIFEST_DOMAIN: &[u8] = b"astrid:capsule-manifest:v1\0";

/// A private Station handoff ready for Astrid's existing local installer.
#[derive(Debug, Clone)]
pub(crate) struct StationArtifact {
    /// Archive staged below Station's `var/sources/<id>/handoff` directory.
    pub(crate) path: PathBuf,
    /// Exact typed source lock returned by Station.
    pub(crate) lock: StationLock,
}

/// Whether at least one enabled Station source is configured.
pub(crate) fn is_configured() -> anyhow::Result<bool> {
    is_configured_at(&station_bin(), &station_home())
}

fn is_configured_at(binary: &Path, home: &Path) -> anyhow::Result<bool> {
    let output = match run_command_at(binary, home, &["source", "list"]) {
        Ok(output) => output,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(false);
        },
        Err(error) => return Err(error),
    };
    let sources = source_values(&output)?;
    Ok(sources.iter().any(|source| {
        source
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }))
}

/// Resolve and fetch a Station coordinate into the private handoff area.
///
/// A new install first resolves and writes a strict typed lock. An update passes
/// the existing lock to Station, so no GitHub/latest path is consulted.
pub(crate) fn resolve_and_fetch(
    coordinate: &str,
    requirement: Option<&str>,
    existing: Option<&StationLock>,
) -> anyhow::Result<StationArtifact> {
    resolve_and_fetch_at(
        coordinate,
        requirement,
        existing,
        &station_bin(),
        &station_home(),
    )
}

fn resolve_and_fetch_at(
    coordinate: &str,
    requirement: Option<&str>,
    existing: Option<&StationLock>,
    binary: &Path,
    home: &Path,
) -> anyhow::Result<StationArtifact> {
    // Normalize the entire lock before Station can fetch or stage bytes. This
    // closes the boundary where a bare BLAKE3 returned by an older Station
    // client would otherwise survive until the daemon write after install.
    let existing = existing
        .map(|lock| {
            let mut lock = lock.clone();
            canonicalize_lock(&mut lock)?;
            validate_lock(&lock)?;
            Ok::<_, anyhow::Error>(lock)
        })
        .transpose()?;
    let sources = enabled_source_ids_at(binary, home)?;
    if sources.is_empty() {
        bail!("Station is not configured (no enabled source)");
    }
    if let Some(lock) = existing.as_ref() {
        let lock_coordinate = coordinate_string(lock)?;
        let mut last_error = None;
        for source in sources {
            match fetch_for_source_at(&source, &lock_coordinate, None, Some(lock), binary, home) {
                Ok(artifact) => return Ok(artifact),
                Err(error) => last_error = Some(error),
            }
        }
        return Err(
            last_error.unwrap_or_else(|| anyhow::anyhow!("Station lock could not be resolved"))
        );
    }
    let source = &sources[0];
    fetch_for_source_at(source, coordinate, requirement, None, binary, home)
}

/// Load a Station lock from the authenticated owner's control namespace.
pub(crate) async fn load_lock(
    principal: &PrincipalId,
    capsule: &str,
) -> anyhow::Result<Option<StationLock>> {
    #[cfg(test)]
    if test_lock_backend::active() {
        return Ok(test_lock_backend::get(principal, capsule));
    }
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let response = client
        .request(AdminRequestKind::StationLockGet {
            principal: principal.clone(),
            capsule: capsule.to_owned(),
        })
        .await?;
    match response {
        AdminResponseBody::StationLock(mut lock) => {
            if let Some(lock) = lock.as_mut() {
                canonicalize_lock(lock)?;
            }
            Ok(*lock)
        },
        AdminResponseBody::Error(error) => Err(anyhow::anyhow!(error)),
        other => bail!("unexpected Station lock response: {other:?}"),
    }
}

/// Persist a Station lock in the authenticated owner's control namespace.
pub(crate) async fn store_lock(
    principal: &PrincipalId,
    capsule: &str,
    mut lock: StationLock,
) -> anyhow::Result<()> {
    canonicalize_lock(&mut lock)?;
    #[cfg(test)]
    if test_lock_backend::active() {
        test_lock_backend::set(principal, capsule, lock);
        return Ok(());
    }
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let current = client
        .request(AdminRequestKind::StationLockGet {
            principal: principal.clone(),
            capsule: capsule.to_owned(),
        })
        .await?;
    let current = match current {
        AdminResponseBody::StationLock(lock) => *lock,
        AdminResponseBody::Error(error) => return Err(anyhow::anyhow!(error)),
        other => bail!("unexpected Station lock response: {other:?}"),
    };
    let expected_hash = current.as_ref().map(station_lock_digest).transpose()?;
    let response = client
        .request(AdminRequestKind::StationLockSet {
            principal: principal.clone(),
            capsule: capsule.to_owned(),
            lock: Box::new(lock),
            expected_hash,
        })
        .await?;
    match response {
        AdminResponseBody::Success(_) => Ok(()),
        AdminResponseBody::Error(error) => Err(anyhow::anyhow!(error)),
        other => bail!("unexpected Station lock response: {other:?}"),
    }
}

/// Clear a Station lock after a successful non-Station replacement or remove.
/// The daemon treats deletion as an idempotent typed control operation.
pub(crate) async fn clear_lock(principal: &PrincipalId, capsule: &str) -> anyhow::Result<()> {
    #[cfg(test)]
    if test_lock_backend::active() {
        test_lock_backend::delete(principal, capsule);
        return Ok(());
    }
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let response = client
        .request(AdminRequestKind::StationLockDelete {
            principal: principal.clone(),
            capsule: capsule.to_owned(),
            expected_hash: None,
        })
        .await?;
    match response {
        AdminResponseBody::Success(_) => Ok(()),
        AdminResponseBody::Error(error) => Err(anyhow::anyhow!(error)),
        other => bail!("unexpected Station lock delete response: {other:?}"),
    }
}

/// Verify the Station lock's manifest digest against Astrid's authority
/// domain over the exact archived Capsule.toml bytes.
pub(crate) fn verify_manifest_digest(archive: &Path, lock: &StationLock) -> anyhow::Result<()> {
    let manifest = astrid_build::artifact::read_archive_text(archive, "Capsule.toml")
        .with_context(|| format!("read Capsule.toml from {}", archive.display()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(manifest.as_bytes());
    let expected = hasher.finalize();
    let mut canonical_lock = lock.clone();
    canonicalize_lock(&mut canonical_lock)?;
    let supplied = decode_blake3(&canonical_lock.manifest_digest)?;
    anyhow::ensure!(
        expected.as_bytes() == supplied.as_slice(),
        "Station manifest_digest disagrees with Astrid authority digest"
    );
    Ok(())
}

fn fetch_for_source_at(
    source: &str,
    coordinate: &str,
    requirement: Option<&str>,
    existing: Option<&StationLock>,
    binary: &Path,
    home: &Path,
) -> anyhow::Result<StationArtifact> {
    let staging = stage_lock(source, coordinate, requirement, existing, binary, home)?;
    let lock_coordinate = coordinate_string(&staging.lock)?;
    let publication_hex = digest_hex(&staging.lock.publication_digest)?;
    let stage = prepare_handoff(home, source, &publication_hex)?;
    fetch_handoff(source, lock_coordinate, &stage, &staging, binary, home)?;
    verify_manifest_digest(&stage, &staging.lock)?;
    Ok(StationArtifact {
        path: stage,
        lock: staging.lock,
    })
}

struct LockStaging {
    _dir: tempfile::TempDir,
    path: PathBuf,
    lock: StationLock,
}

fn stage_lock(
    source: &str,
    coordinate: &str,
    requirement: Option<&str>,
    existing: Option<&StationLock>,
    binary: &Path,
    home: &Path,
) -> anyhow::Result<LockStaging> {
    validate_coordinate(coordinate)?;
    let existing = existing
        .map(|lock| {
            let mut lock = lock.clone();
            canonicalize_lock(&mut lock)?;
            validate_lock(&lock)?;
            Ok::<_, anyhow::Error>(lock)
        })
        .transpose()?;
    std::fs::create_dir_all(home)
        .with_context(|| format!("create Station home {}", home.display()))?;
    let lock_dir = tempfile::Builder::new()
        .prefix("astrid-station-")
        .tempdir_in(home)
        .context("create private Station lock staging")?;
    let lock_path = lock_dir.path().join("resolved.lock.json");
    if let Some(lock) = existing.as_ref() {
        let bytes = serde_json::to_vec_pretty(lock).context("encode Station lock")?;
        std::fs::write(&lock_path, bytes).context("write Station lock staging")?;
    }
    if existing.is_none() {
        let requirement = requirement.unwrap_or("*");
        let mut args = vec![
            "resolve".to_owned(),
            "--source".to_owned(),
            source.to_owned(),
            coordinate.to_owned(),
            "--requirement".to_owned(),
            requirement.to_owned(),
            "--write-lock".to_owned(),
            lock_path.display().to_string(),
        ];
        let output = run_command_owned_at(binary, home, &mut args)?;
        let output_lock = output
            .get("lock")
            .ok_or_else(|| anyhow::anyhow!("Station resolve response omitted lock"))?;
        let mut output_lock: StationLock =
            serde_json::from_value(output_lock.clone()).context("decode Station resolve lock")?;
        canonicalize_lock(&mut output_lock)?;
        if lock_path.exists() {
            let mut persisted: StationLock = serde_json::from_slice(
                &std::fs::read(&lock_path).context("read Station resolve lock")?,
            )
            .context("decode Station resolve lock file")?;
            canonicalize_lock(&mut persisted)?;
            anyhow::ensure!(
                persisted == output_lock,
                "Station resolve lock file disagrees with JSON lock"
            );
            write_lock_staging(&lock_path, &persisted)?;
        } else {
            write_lock_staging(&lock_path, &output_lock)?;
        }
    }
    let lock_bytes = std::fs::read(&lock_path).context("read Station lock staging")?;
    let mut lock: StationLock = serde_json::from_slice(&lock_bytes)
        .context("decode Station lock (expected station-lock-v2)")?;
    canonicalize_lock(&mut lock)?;
    write_lock_staging(&lock_path, &lock)?;
    validate_lock(&lock)?;
    let lock_coordinate = coordinate_string(&lock)?;
    anyhow::ensure!(
        existing.is_none() || lock_coordinate == coordinate,
        "Station lock coordinate differs from the installed capsule"
    );
    Ok(LockStaging {
        _dir: lock_dir,
        path: lock_path,
        lock,
    })
}

fn prepare_handoff(home: &Path, source: &str, publication_hex: &str) -> anyhow::Result<PathBuf> {
    let stage = home
        .join("var")
        .join("sources")
        .join(source)
        .join("handoff")
        .join(format!("{publication_hex}.capsule"));
    anyhow::ensure!(
        stage
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            == Some("handoff"),
        "Station handoff path is outside the private handoff directory"
    );
    if let Some(parent) = stage.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create Station handoff {}", parent.display()))?;
    }
    reject_symlink_ancestors(&stage, home)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&stage) {
        anyhow::ensure!(
            !metadata.file_type().is_symlink() && metadata.is_file(),
            "Station handoff path is not a regular archive"
        );
        std::fs::remove_file(&stage).context("remove stale Station handoff archive")?;
    }
    Ok(stage)
}

fn fetch_handoff(
    source: &str,
    lock_coordinate: String,
    stage: &Path,
    staging: &LockStaging,
    binary: &Path,
    home: &Path,
) -> anyhow::Result<()> {
    let mut args = vec![
        "fetch".to_owned(),
        "--source".to_owned(),
        source.to_owned(),
        lock_coordinate,
        "--output".to_owned(),
        stage.display().to_string(),
        "--lock".to_owned(),
        staging.path.display().to_string(),
        "--write-lock".to_owned(),
        staging.path.display().to_string(),
    ];
    let fetch_output = run_command_owned_at(binary, home, &mut args)?;
    let fetched_digest = fetch_output
        .get("publication_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Station fetch response omitted publication_digest"))?;
    anyhow::ensure!(
        canonical_blake3(fetched_digest)? == staging.lock.publication_digest,
        "Station fetch publication_digest disagrees with the source lock"
    );
    let fetched_output = fetch_output
        .get("output")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Station fetch response omitted output path"))?;
    anyhow::ensure!(
        Path::new(fetched_output) == stage,
        "Station fetch output path differs from the private handoff path"
    );
    if let Some(output_lock) = fetch_output.get("lock") {
        let mut output_lock: StationLock =
            serde_json::from_value(output_lock.clone()).context("decode Station fetch lock")?;
        canonicalize_lock(&mut output_lock)?;
        if output_lock != staging.lock {
            bail!("Station fetch JSON lock disagrees with the resolved lock");
        }
        write_lock_staging(&staging.path, &output_lock)?;
    }
    let stage_metadata =
        std::fs::symlink_metadata(stage).context("inspect Station handoff archive")?;
    anyhow::ensure!(
        !stage_metadata.file_type().is_symlink() && stage_metadata.is_file(),
        "Station fetch did not produce a regular private handoff archive"
    );
    anyhow::ensure!(
        stage.is_file(),
        "Station fetch did not produce a private handoff archive"
    );
    let mut final_lock: StationLock = serde_json::from_slice(
        &std::fs::read(&staging.path).context("read Station lock after fetch")?,
    )
    .context("decode Station lock after fetch")?;
    canonicalize_lock(&mut final_lock)?;
    anyhow::ensure!(
        final_lock == staging.lock,
        "Station fetch changed the source lock"
    );
    Ok(())
}

fn write_lock_staging(path: &Path, lock: &StationLock) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(lock).context("encode Station lock staging")?;
    std::fs::write(path, bytes)
        .with_context(|| format!("write Station lock {}", path.display()))?;
    Ok(())
}

fn source_values(value: &Value) -> anyhow::Result<Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values.clone()),
        Value::Object(object) => object
            .get("sources")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Station source list response omitted sources")),
        _ => bail!("Station source list response was not an array"),
    }
}

fn enabled_source_ids_at(binary: &Path, home: &Path) -> anyhow::Result<Vec<String>> {
    let output = run_command_at(binary, home, &["source", "list"])?;
    let mut sources = source_values(&output)?
        .into_iter()
        .filter(|source| {
            source
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|source| source.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    sources.retain(|source| validate_source_id(source).is_ok());
    Ok(sources)
}

fn run_command_at(binary: &Path, home: &Path, args: &[&str]) -> anyhow::Result<Value> {
    let mut owned = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    run_command_owned_at(binary, home, &mut owned)
}

fn run_command_owned_at(binary: &Path, home: &Path, args: &mut [String]) -> anyhow::Result<Value> {
    let mut command = Command::new(binary);
    command.arg("--json").arg("--home").arg(home);
    command.args(args.iter());
    let output = command.output().map_err(anyhow::Error::from)?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!(
            "astrid-station failed ({}): {}",
            output.status,
            detail.trim()
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse astrid-station JSON response (stdout={})",
            String::from_utf8_lossy(&output.stdout).trim()
        )
    })
}

fn station_bin() -> PathBuf {
    #[cfg(test)]
    if let Some((binary, _)) = TEST_STATION_PATHS.lock().unwrap().clone() {
        return binary;
    }
    std::env::var_os("ASTRID_STATION_BIN")
        .map_or_else(|| PathBuf::from("astrid-station"), PathBuf::from)
}

fn station_home() -> PathBuf {
    #[cfg(test)]
    if let Some((_, home)) = TEST_STATION_PATHS.lock().unwrap().clone() {
        return home;
    }
    std::env::var_os("ASTRID_STATION_HOME")
        .map_or_else(|| PathBuf::from(DEFAULT_HOME), PathBuf::from)
}

#[cfg(test)]
static TEST_STATION_PATHS: std::sync::Mutex<Option<(PathBuf, PathBuf)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) struct TestStationPathsGuard(Option<(PathBuf, PathBuf)>);

#[cfg(test)]
impl Drop for TestStationPathsGuard {
    fn drop(&mut self) {
        *TEST_STATION_PATHS.lock().unwrap() = self.0.take();
    }
}

#[cfg(test)]
pub(super) fn test_station_paths(binary: &Path, home: &Path) -> TestStationPathsGuard {
    let previous = TEST_STATION_PATHS
        .lock()
        .unwrap()
        .replace((binary.to_path_buf(), home.to_path_buf()));
    TestStationPathsGuard(previous)
}

fn reject_symlink_ancestors(path: &Path, root: &Path) -> anyhow::Result<()> {
    // Keep the handoff path lexical while walking it. Canonicalizing each
    // ancestor before inspection would resolve a symlink and make the link
    // itself invisible to `symlink_metadata`.
    let cwd = std::env::current_dir().context("resolve current directory for Station handoff")?;
    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        cwd.join(root)
    };
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    anyhow::ensure!(
        path.starts_with(&root),
        "Station handoff escaped Station home (path={}, root={})",
        path.display(),
        root.display()
    );
    let mut current = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Station handoff has no parent"))?
        .to_path_buf();
    loop {
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("inspect Station handoff {}", current.display()))?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Station handoff path contains a symlink: {}",
            current.display()
        );
        if current == root {
            return Ok(());
        }
        current = current
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Station handoff escaped Station home"))?
            .to_path_buf();
        anyhow::ensure!(
            current.starts_with(&root),
            "Station handoff escaped Station home (path={}, root={})",
            current.display(),
            root.display()
        );
    }
}

fn validate_source_id(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value == value.trim()
            && value != "."
            && value != ".."
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "invalid Station source id"
    );
    anyhow::ensure!(
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        }),
        "invalid Station source id"
    );
    Ok(())
}

fn validate_coordinate(value: &str) -> anyhow::Result<()> {
    let Some(rest) = value.strip_prefix('@') else {
        bail!("Station coordinate must use @namespace/name");
    };
    let Some((namespace, name)) = rest.split_once('/') else {
        bail!("Station coordinate must use @namespace/name");
    };
    anyhow::ensure!(
        !namespace.is_empty() && !name.is_empty(),
        "invalid Station coordinate"
    );
    anyhow::ensure!(
        validate_coordinate_part(namespace) && validate_coordinate_part(name),
        "invalid Station coordinate"
    );
    Ok(())
}

fn validate_coordinate_part(value: &str) -> bool {
    value.len() <= 63
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.as_bytes().last().is_some_and(|byte| *byte != b'-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn coordinate_string(lock: &StationLock) -> anyhow::Result<String> {
    validate_coordinate(&format!(
        "@{}/{}",
        lock.coordinate.namespace, lock.coordinate.name
    ))?;
    Ok(format!(
        "@{}/{}",
        lock.coordinate.namespace, lock.coordinate.name
    ))
}

fn validate_lock(lock: &StationLock) -> anyhow::Result<()> {
    anyhow::ensure!(
        lock.schema == LOCK_SCHEMA_V2,
        "Station lock schema must be station-lock-v2"
    );
    validate_source_id(&lock.station_id)?;
    anyhow::ensure!(
        decode_digest(&lock.trust_root, "sha256:").is_ok(),
        "invalid Station trust root"
    );
    coordinate_string(lock)?;
    anyhow::ensure!(
        !lock.version.is_empty() && lock.version.len() <= 128,
        "invalid Station version"
    );
    for value in [
        &lock.publication_digest,
        &lock.manifest_digest,
        &lock.capsule_content_digest,
        &lock.package_digest,
        &lock.component_digest,
        &lock.wit_digest,
        &lock.capability_digest,
        &lock.ipc_digest,
        &lock.runtime_abi_digest,
        &lock.dependency_digest,
        &lock.provenance_digest,
        &lock.source_digest,
    ] {
        decode_blake3(value)?;
    }
    decode_digest(&lock.artifact_sha256, "sha256:")?;
    decode_blake3(&lock.artifact_blake3)?;
    anyhow::ensure!(
        lock.artifact_size <= 64 * 1024 * 1024,
        "Station artifact exceeds size limit"
    );
    anyhow::ensure!(
        !lock.artifact_media_type.is_empty(),
        "Station artifact media type is empty"
    );
    Ok(())
}

fn digest_hex(value: &str) -> anyhow::Result<String> {
    let bytes = decode_blake3(value)?;
    Ok(hex::encode(bytes))
}

fn canonicalize_lock(lock: &mut StationLock) -> anyhow::Result<()> {
    for value in [
        &mut lock.publication_digest,
        &mut lock.manifest_digest,
        &mut lock.capsule_content_digest,
        &mut lock.package_digest,
        &mut lock.component_digest,
        &mut lock.wit_digest,
        &mut lock.capability_digest,
        &mut lock.ipc_digest,
        &mut lock.runtime_abi_digest,
        &mut lock.dependency_digest,
        &mut lock.provenance_digest,
        &mut lock.source_digest,
        &mut lock.artifact_blake3,
    ] {
        let canonical = canonical_blake3(value)?;
        *value = canonical;
    }
    Ok(())
}

fn canonical_blake3(value: &str) -> anyhow::Result<String> {
    let hex = value.strip_prefix("blake3:").unwrap_or(value);
    anyhow::ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid canonical blake3 digest"
    );
    Ok(format!("blake3:{hex}"))
}

fn decode_blake3(value: &str) -> anyhow::Result<Vec<u8>> {
    decode_digest(value, "blake3:")
}

fn decode_digest(value: &str, prefix: &str) -> anyhow::Result<Vec<u8>> {
    let hex = value
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("digest algorithm is not {prefix}"))?;
    anyhow::ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid digest"
    );
    hex::decode(hex).context("decode digest")
}

fn station_lock_digest(lock: &StationLock) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(lock).context("encode Station lock")?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

#[cfg(test)]
mod test_lock_backend {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    static BACKEND_LOCK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    static LOCKS: Mutex<Option<HashMap<String, StationLock>>> = Mutex::new(None);
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    pub(super) struct Guard {
        _permit: tokio::sync::SemaphorePermit<'static>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            *LOCKS.lock().unwrap() = None;
            ACTIVE.store(false, Ordering::Release);
        }
    }

    pub(super) async fn install() -> Guard {
        let permit = BACKEND_LOCK.acquire().await.unwrap();
        *LOCKS.lock().unwrap() = Some(HashMap::new());
        ACTIVE.store(true, Ordering::Release);
        Guard { _permit: permit }
    }

    pub(super) fn active() -> bool {
        ACTIVE.load(Ordering::Acquire)
    }

    fn key(principal: &PrincipalId, capsule: &str) -> String {
        format!("{principal}:{capsule}")
    }

    pub(super) fn get(principal: &PrincipalId, capsule: &str) -> Option<StationLock> {
        LOCKS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|locks| locks.get(&key(principal, capsule)).cloned())
    }

    pub(super) fn set(principal: &PrincipalId, capsule: &str, lock: StationLock) {
        LOCKS
            .lock()
            .unwrap()
            .as_mut()
            .expect("test Station lock backend")
            .insert(key(principal, capsule), lock);
    }

    pub(super) fn delete(principal: &PrincipalId, capsule: &str) {
        if let Some(locks) = LOCKS.lock().unwrap().as_mut() {
            locks.remove(&key(principal, capsule));
        }
    }
}

#[cfg(test)]
pub(super) fn test_lock_backend_active() -> bool {
    test_lock_backend::active()
}

#[cfg(all(test, unix))]
#[path = "station_regressions.rs"]
mod regressions;

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::fs::File;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tar::Builder;

    fn digest(prefix: &str, byte: u8) -> String {
        format!("{prefix}{}", hex::encode([byte; 32]))
    }

    fn sample_lock(manifest_digest: &str) -> StationLock {
        StationLock {
            schema: LOCK_SCHEMA_V2.to_owned(),
            station_id: "official".to_owned(),
            trust_root: digest("sha256:", 0x11),
            coordinate: astrid_core::kernel_api::StationCoordinate {
                namespace: "official".to_owned(),
                name: "demo".to_owned(),
            },
            version: "1.0.0".to_owned(),
            publication_digest: digest("blake3:", 0x22),
            artifact_size: 0,
            artifact_media_type: "application/vnd.astrid.capsule".to_owned(),
            artifact_sha256: digest("sha256:", 0x33),
            artifact_blake3: digest("blake3:", 0x44),
            manifest_digest: manifest_digest.to_owned(),
            capsule_content_digest: digest("blake3:", 0x55),
            package_digest: digest("blake3:", 0x66),
            component_count: 0,
            component_digest: digest("blake3:", 0x77),
            wit_digest: digest("blake3:", 0x88),
            capability_digest: digest("blake3:", 0x99),
            ipc_digest: digest("blake3:", 0xaa),
            runtime_abi_digest: digest("blake3:", 0xbb),
            dependency_digest: digest("blake3:", 0xcc),
            provenance_digest: digest("blake3:", 0xdd),
            source_digest: digest("blake3:", 0xee),
        }
    }

    fn capsule_archive(manifest: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.capsule");
        let file = File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut archive = Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "Capsule.toml", manifest)
            .unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
        (dir, path)
    }

    #[cfg(unix)]
    fn fake_station_script(dir: &Path, fixture: &Path, marker: &Path) -> PathBuf {
        let script = dir.join("astrid-station-fake");
        let body = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"{}\"\ncase \" $* \" in\n  *' source list '*) printf '%s\\n' '{{\"sources\":[{{\"id\":\"official\",\"enabled\":true}}]}}' ;;\n  *' fetch '*) prev=; out=; for arg in \"$@\"; do if [ \"$prev\" = '--output' ]; then out=\"$arg\"; cp \"{}\" \"$arg\"; fi; prev=\"$arg\"; done; printf '{{\"source\":\"official\",\"version\":\"1.0.0\",\"publication_digest\":\"{}\",\"output\":\"%s\"}}\\n' \"$out\" ;;\n  *) exit 97 ;;\nesac\n",
            marker.display(),
            fixture.display(),
            hex::encode([0x22_u8; 32]),
        );
        std::fs::write(&script, body).unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();
        script
    }

    #[test]
    fn manifest_digest_requires_canonical_station_form() {
        assert_eq!(
            decode_blake3(
                "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap()
            .len(),
            32
        );
        assert!(
            decode_blake3("0000000000000000000000000000000000000000000000000000000000000000")
                .is_err()
        );
        assert!(
            decode_blake3(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
    }

    #[test]
    fn bare_station_commitments_are_normalized_before_fetch() {
        let manifest = "0".repeat(64);
        let mut lock = sample_lock(&manifest);
        lock.publication_digest = "1".repeat(64);
        lock.artifact_blake3 = "2".repeat(64);
        canonicalize_lock(&mut lock).unwrap();
        assert!(lock.publication_digest.starts_with("blake3:"));
        assert!(lock.artifact_blake3.starts_with("blake3:"));
        validate_lock(&lock).unwrap();
    }

    #[test]
    fn station_stage_coordinate_is_strict() {
        assert!(validate_coordinate("@official/demo").is_ok());
        assert!(validate_coordinate("https://github.com/official/demo").is_err());
        assert!(validate_coordinate("@official/demo/extra").is_err());
    }

    #[test]
    fn wrong_lock_schema_fails_closed() {
        let mut lock = sample_lock(&digest("blake3:", 0x01));
        lock.schema = "station-lock-v1".to_owned();
        assert!(validate_lock(&lock).is_err());
    }

    #[test]
    fn manifest_digest_matches_exact_capsule_toml_bytes_and_normalizes_wire_form() {
        let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
        let (_dir, archive) = capsule_archive(manifest);
        let mut hasher = blake3::Hasher::new();
        hasher.update(MANIFEST_DOMAIN);
        hasher.update(manifest);
        let digest = hasher.finalize().to_hex().to_string();
        let mut lock = sample_lock(&format!("blake3:{digest}"));
        verify_manifest_digest(&archive, &lock).unwrap();
        lock.manifest_digest = digest.clone();
        verify_manifest_digest(&archive, &lock).unwrap();
        lock.manifest_digest = format!("sha256:{digest}");
        assert!(verify_manifest_digest(&archive, &lock).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn station_update_uses_existing_lock_and_private_handoff_not_astrid_cas() {
        let root = tempfile::tempdir().unwrap();
        let station_home = root.path().join("station");
        let astrid_home = root.path().join("astrid");
        std::fs::create_dir_all(&station_home).unwrap();
        std::fs::create_dir_all(&astrid_home).unwrap();
        let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
        let (_fixture_dir, fixture) = capsule_archive(manifest);
        let mut hasher = blake3::Hasher::new();
        hasher.update(MANIFEST_DOMAIN);
        hasher.update(manifest);
        let mut lock = sample_lock(&format!("blake3:{}", hasher.finalize().to_hex()));
        // Older Station clients emitted bare BLAKE3 commitments. The update
        // path must normalize those before fetch and handoff side effects.
        lock.publication_digest = hex::encode([0x22_u8; 32]);
        lock.artifact_blake3 = hex::encode([0x44_u8; 32]);
        let marker = root.path().join("station-calls");
        let script = fake_station_script(root.path(), &fixture, &marker);

        assert!(is_configured_at(&script, &station_home).unwrap());
        let artifact = resolve_and_fetch_at("", None, Some(&lock), &script, &station_home).unwrap();

        let calls = std::fs::read_to_string(&marker).unwrap();
        assert!(calls.contains("fetch"));
        assert!(calls.contains("--lock"));
        assert!(!calls.contains(" resolve "));
        let expected_parent = station_home.join("var/sources/official/handoff");
        assert!(artifact.path.starts_with(expected_parent));
        assert!(!artifact.path.starts_with(astrid_home.join("var")));
        assert!(artifact.path.is_file());
        assert_eq!(artifact.lock.publication_digest, digest("blake3:", 0x22));
        assert_eq!(artifact.lock.artifact_blake3, digest("blake3:", 0x44));
    }
}
