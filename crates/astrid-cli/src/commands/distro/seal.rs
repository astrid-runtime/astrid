//! `astrid distro seal` — build a signed, offline-installable `.shuttle`.
//!
//! The seal pipeline is maintainer-side and online: it reads a local
//! `Distro.toml`, downloads each capsule's pre-built `.capsule` release
//! asset (without installing), hashes everything, builds a resolved
//! [`DistroLock`], signs `blake3(canonical_json(lock))` with the
//! maintainer's ed25519 key, and packs the whole thing into a
//! deterministic `.shuttle` archive.
//!
//! Output layout (see [`super::shuttle`]):
//! `Distro.toml`, `Distro.lock`, `Distro.sig`, `capsules/<name>.capsule`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use super::lock::{DistroLock, DistroLockMeta, LockedCapsule, manifest_hash};
use super::manifest::{DistroManifest, parse_manifest};
use super::shuttle::{self, ShuttleEntry};
use super::sign;
use crate::commands::capsule::install::resolve_capsule_to_file;
use crate::theme::Theme;

/// Run `astrid distro seal`.
///
/// `distro` is a path to a local `Distro.toml` (or a directory
/// containing one). `output` is the `.shuttle` destination. `key` is a
/// file holding the 32 raw ed25519 secret-key bytes.
pub(crate) async fn run_seal(distro: &str, output: &Path, key: &Path) -> anyhow::Result<()> {
    // 1. Load the manifest, keeping the verbatim bytes for hashing.
    let manifest_path = resolve_manifest_path(distro)?;
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .context("Distro.toml is not valid UTF-8")?;
    let manifest: DistroManifest = parse_manifest(manifest_text)?;

    // 2. Load the signing key (32 raw bytes). Never logged.
    let keypair = load_signing_key(key)?;

    eprintln!(
        "{}",
        Theme::header(&format!(
            "Sealing {} {}",
            manifest.distro.id, manifest.distro.version
        ))
    );

    // 3. Resolve every capsule to a staged `.capsule` file (no install).
    let staging = tempfile::tempdir().context("failed to create staging dir")?;
    let capsules_stage = staging.path().join(shuttle::CAPSULES_DIR);
    std::fs::create_dir_all(&capsules_stage)?;

    let mut locked: Vec<LockedCapsule> = Vec::with_capacity(manifest.capsules.len());
    let mut capsule_entries: Vec<ShuttleEntry> = Vec::with_capacity(manifest.capsules.len());

    for cap in &manifest.capsules {
        eprintln!("  resolving {} ({})", cap.name, cap.source);
        let dest = capsules_stage.join(format!("{}.capsule", cap.name));
        resolve_capsule_to_file(
            &cap.source,
            (!cap.version.is_empty()).then_some(cap.version.as_str()),
            cap.tag.as_deref(),
            &dest,
        )
        .await
        .with_context(|| format!("failed to resolve capsule {}", cap.name))?;

        let bytes = std::fs::read(&dest)
            .with_context(|| format!("failed to read staged capsule {}", cap.name))?;
        let hash = format!("blake3:{}", blake3::hash(&bytes).to_hex());

        locked.push(LockedCapsule {
            name: cap.name.clone(),
            version: cap.version.clone(),
            source: cap.source.clone(),
            hash,
            resolved_ref: cap.resolved_ref(),
        });
        capsule_entries.push(ShuttleEntry {
            path: shuttle::capsule_member_path(&cap.name),
            bytes,
        });
    }

    // 4. Build the resolved lock with the manifest hash bound in.
    let lock = DistroLock {
        schema_version: manifest.schema_version,
        distro: DistroLockMeta {
            id: manifest.distro.id.clone(),
            version: manifest.distro.version.clone(),
            // Fixed timestamp keeps the seal deterministic. The real
            // install records its own resolved_at in the user's lock.
            resolved_at: "1970-01-01T00:00:00+00:00".to_string(),
        },
        capsules: locked,
        manifest_hash: Some(manifest_hash(&manifest_bytes)),
    };

    // 5. Sign blake3(canonical_json(lock)).
    let sig_hex = sign::sign_lock(&lock, &keypair)?;

    // 6. Serialize lock and assemble all archive members.
    let lock_toml = toml::to_string_pretty(&lock).context("failed to serialize Distro.lock")?;
    let mut entries = vec![
        ShuttleEntry {
            path: shuttle::MANIFEST_NAME.to_string(),
            bytes: manifest_bytes,
        },
        ShuttleEntry {
            path: shuttle::LOCK_NAME.to_string(),
            bytes: lock_toml.into_bytes(),
        },
        ShuttleEntry {
            path: shuttle::SIG_NAME.to_string(),
            bytes: sig_hex.into_bytes(),
        },
    ];
    entries.extend(capsule_entries);

    // 7. Pack deterministically.
    shuttle::pack(output, entries)?;

    eprintln!();
    eprintln!(
        "{}",
        Theme::success(&format!(
            "Sealed {} capsule(s) -> {}",
            manifest.capsules.len(),
            output.display()
        ))
    );
    eprintln!(
        "  signed by {}",
        sign::pubkey_to_wire(&keypair.export_public_key())
    );
    Ok(())
}

/// Resolve a seal `distro` argument to a `Distro.toml` path.
fn resolve_manifest_path(distro: &str) -> anyhow::Result<PathBuf> {
    let p = Path::new(distro);
    if p.is_dir() {
        let candidate = p.join("Distro.toml");
        if candidate.is_file() {
            return Ok(candidate);
        }
        bail!("{} contains no Distro.toml", p.display());
    }
    if p.is_file() {
        return Ok(p.to_path_buf());
    }
    bail!(
        "seal requires a local Distro.toml path or its directory; {distro:?} is not a file or directory"
    )
}

/// Load a 32-byte raw ed25519 secret key from `path`. Never logged.
fn load_signing_key(path: &Path) -> anyhow::Result<astrid_crypto::KeyPair> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read signing key {}", path.display()))?;
    if bytes.len() != 32 {
        bail!(
            "signing key {} must be exactly 32 raw bytes (got {})",
            path.display(),
            bytes.len()
        );
    }
    astrid_crypto::KeyPair::from_secret_key(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid ed25519 secret key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_signing_key_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("bad.key");
        std::fs::write(&key, [0u8; 16]).unwrap();
        let err = load_signing_key(&key).unwrap_err();
        assert!(err.to_string().contains("32 raw bytes"), "got: {err}");
    }

    #[test]
    fn resolve_manifest_path_finds_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Distro.toml"), "x").unwrap();
        let p = resolve_manifest_path(dir.path().to_str().unwrap()).unwrap();
        assert!(p.ends_with("Distro.toml"));
    }
}
