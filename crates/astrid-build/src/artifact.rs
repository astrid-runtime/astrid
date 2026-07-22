//! Capsule artifact signing and verification.
//!
//! A capsule signature binds the normalized path and bytes of every regular
//! file in the archive except this module's provenance envelope. Tar metadata
//! is intentionally excluded: modes and timestamps are packaging details, not
//! runtime authority. Duplicate paths, special entries, directory/external
//! symlinks, and unsafe paths fail closed. Internal file symlinks are
//! dereferenced exactly as the installer copies them.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;
use astrid_crypto::{KeyPair, PublicKey, Signature};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

/// Root archive entry containing the self-describing capsule signature.
pub const PROVENANCE_FILE: &str = "Capsule.provenance.json";

const SCHEMA_VERSION: u32 = 1;
const ALGORITHM: &str = "ed25519-blake3-tree-v1";
const CONTENT_DOMAIN: &[u8] = b"astrid:capsule-content:v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"astrid:capsule-provenance:v1\0";

#[derive(Debug)]
struct ContentRecord {
    path: String,
    size: u64,
    hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct ProvenanceEnvelope {
    schema_version: u32,
    algorithm: String,
    content_digest: String,
    signer: PublicKey,
    signature: Signature,
}

/// Verified provenance carried by a signed capsule artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProvenance {
    /// BLAKE3 digest of the canonical capsule content tree.
    pub content_digest: String,
    /// Runtime public key which signed the artifact.
    pub signer: PublicKey,
    /// Ed25519 signature over the domain-separated content digest.
    pub signature: Signature,
}

/// Result of inspecting a capsule tree or archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactVerification {
    /// Content is internally hashed but carries no capsule signature.
    Unsigned {
        /// BLAKE3 digest of the canonical capsule content tree.
        content_digest: String,
    },
    /// Content and the embedded Ed25519 signature both verified.
    Signed(VerifiedProvenance),
}

impl ArtifactVerification {
    /// The canonical content digest, available for signed and unsigned input.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        match self {
            Self::Unsigned { content_digest } => content_digest,
            Self::Signed(provenance) => &provenance.content_digest,
        }
    }
}

/// Sign a freshly-created capsule archive with the selected runtime key.
///
/// # Errors
///
/// Fails when the archive is malformed, already contains a provenance entry,
/// contains unsafe or duplicate entries, or cannot be replaced atomically.
pub fn sign_archive(archive_path: &Path, keypair: &KeyPair) -> anyhow::Result<VerifiedProvenance> {
    let (records, envelope) = read_archive(archive_path)?;
    if envelope.is_some() {
        bail!("capsule archive already contains {PROVENANCE_FILE}");
    }
    let content_digest = digest_records(records)?;
    let signature = keypair.sign(&signature_message(&content_digest));
    let provenance = VerifiedProvenance {
        content_digest: content_digest.clone(),
        signer: keypair.export_public_key(),
        signature,
    };
    let envelope = ProvenanceEnvelope {
        schema_version: SCHEMA_VERSION,
        algorithm: ALGORITHM.to_string(),
        content_digest,
        signer: provenance.signer,
        signature,
    };
    rewrite_with_provenance(archive_path, &serde_json::to_vec_pretty(&envelope)?)?;
    Ok(provenance)
}

/// Sign a capsule archive with the runtime identity selected by `ASTRID_HOME`.
/// Generates the same owner-only key the kernel will load if this is the first
/// Astrid operation on the installation.
///
/// # Errors
///
/// Fails when the Astrid home cannot be resolved, the runtime key cannot be
/// loaded or created, or [`sign_archive`] fails.
pub fn sign_archive_with_runtime_key(archive_path: &Path) -> anyhow::Result<VerifiedProvenance> {
    let home =
        AstridHome::resolve().context("failed to resolve Astrid home for capsule signing")?;
    let keypair = astrid_crypto::load_or_generate_keypair(&home.runtime_key_path())
        .context("failed to load the runtime capsule-signing key")?;
    sign_archive(archive_path, &keypair)
}

/// Verify an archive signature and canonical content digest.
///
/// Unsigned archives are reported as [`ArtifactVerification::Unsigned`]. A
/// present but malformed, mismatched, or invalid signature is always an error.
///
/// # Errors
///
/// Fails on malformed or unsafe archive entries and invalid provenance.
pub fn verify_archive(archive_path: &Path) -> anyhow::Result<ArtifactVerification> {
    let (records, envelope) = read_archive(archive_path)?;
    verify_records(records, envelope.as_deref())
}

/// Verify a staged directory using the same canonical tree algorithm as a
/// `.capsule` archive.
///
/// # Errors
///
/// Fails on unsafe links, unreadable files, invalid provenance, or digest
/// mismatch.
pub fn verify_directory(source_dir: &Path) -> anyhow::Result<ArtifactVerification> {
    let canonical_root = std::fs::canonicalize(source_dir).with_context(|| {
        format!(
            "failed to canonicalize capsule directory {}",
            source_dir.display()
        )
    })?;
    let mut records = Vec::new();
    let mut envelope = None;
    collect_directory_records(
        source_dir,
        &canonical_root,
        source_dir,
        &mut records,
        &mut envelope,
    )?;
    verify_records(records, envelope.as_deref())
}

/// Read one regular UTF-8 file from a capsule archive.
///
/// # Errors
///
/// Fails when the archive is malformed, contains duplicate matching entries,
/// or the requested entry is absent or not UTF-8.
pub fn read_archive_text(archive_path: &Path, requested: &str) -> anyhow::Result<String> {
    let file = File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut found = None;
    for entry in archive
        .entries()
        .context("failed to read capsule archive")?
    {
        let mut entry = entry.context("failed to read capsule archive entry")?;
        let path = normalized_entry_path(&entry)?;
        if path != requested {
            continue;
        }
        if found.is_some() {
            bail!("capsule archive contains duplicate entry '{requested}'");
        }
        if !entry.header().entry_type().is_file() {
            bail!("capsule archive entry '{requested}' is not a regular file");
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        found =
            Some(String::from_utf8(bytes).with_context(|| {
                format!("capsule archive entry '{requested}' is not valid UTF-8")
            })?);
    }
    found.with_context(|| format!("capsule archive is missing '{requested}'"))
}

fn read_archive(archive_path: &Path) -> anyhow::Result<(Vec<ContentRecord>, Option<Vec<u8>>)> {
    let file = File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut records = Vec::new();
    let mut envelope = None;
    let mut seen = HashSet::new();

    for entry in archive
        .entries()
        .context("failed to read capsule archive")?
    {
        let mut entry = entry.context("failed to read capsule archive entry")?;
        let path = normalized_entry_path(&entry)?;
        if !seen.insert(path.clone()) {
            bail!("capsule archive contains duplicate entry '{path}'");
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            bail!("capsule archive contains unsupported entry '{path}'");
        }
        if path == PROVENANCE_FILE {
            if entry.size() > 64 * 1024 {
                bail!("capsule provenance envelope exceeds 64 KiB");
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .context("failed to read capsule provenance")?;
            envelope = Some(bytes);
            continue;
        }
        records.push(hash_reader(path, entry.size(), &mut entry)?);
    }
    Ok((records, envelope))
}

fn normalized_entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> anyhow::Result<String> {
    let path = entry.path().context("invalid capsule archive path")?;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .context("capsule archive paths must be UTF-8")?
                    .to_string(),
            ),
            Component::CurDir => {},
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe capsule archive path '{}'", path.display());
            },
        }
    }
    if parts.is_empty() {
        bail!("capsule archive contains an empty path");
    }
    Ok(parts.join("/"))
}

fn hash_reader(path: String, size: u64, reader: &mut impl Read) -> anyhow::Result<ContentRecord> {
    let mut hasher = blake3::Hasher::new();
    let mut read = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        read = read.saturating_add(count as u64);
    }
    if read != size {
        bail!("capsule entry '{path}' size changed while hashing");
    }
    Ok(ContentRecord {
        path,
        size,
        hash: *hasher.finalize().as_bytes(),
    })
}

fn digest_records(mut records: Vec<ContentRecord>) -> anyhow::Result<String> {
    records.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    if records.windows(2).any(|pair| pair[0].path == pair[1].path) {
        bail!("capsule content tree contains duplicate paths");
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTENT_DOMAIN);
    for record in records {
        let path = record.path.as_bytes();
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update(&record.size.to_le_bytes());
        hasher.update(&record.hash);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn signature_message(content_digest: &str) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIGNATURE_DOMAIN.len().saturating_add(content_digest.len()));
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(content_digest.as_bytes());
    message
}

fn verify_records(
    records: Vec<ContentRecord>,
    envelope: Option<&[u8]>,
) -> anyhow::Result<ArtifactVerification> {
    let content_digest = digest_records(records)?;
    let Some(bytes) = envelope else {
        return Ok(ArtifactVerification::Unsigned { content_digest });
    };
    let envelope: ProvenanceEnvelope =
        serde_json::from_slice(bytes).context("invalid capsule provenance envelope")?;
    if envelope.schema_version != SCHEMA_VERSION || envelope.algorithm != ALGORITHM {
        bail!(
            "unsupported capsule provenance schema {} / algorithm '{}'",
            envelope.schema_version,
            envelope.algorithm
        );
    }
    if envelope.content_digest != content_digest {
        bail!("capsule content digest does not match its signed provenance");
    }
    envelope
        .signer
        .verify(
            &signature_message(&envelope.content_digest),
            &envelope.signature,
        )
        .context("capsule provenance signature verification failed")?;
    Ok(ArtifactVerification::Signed(VerifiedProvenance {
        content_digest,
        signer: envelope.signer,
        signature: envelope.signature,
    }))
}

fn rewrite_with_provenance(archive_path: &Path, envelope: &[u8]) -> anyhow::Result<()> {
    let parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .context("failed to stage signed capsule archive")?;
    {
        let input = File::open(archive_path)?;
        let mut source = tar::Archive::new(GzDecoder::new(input));
        let encoder = GzEncoder::new(staged.as_file_mut(), Compression::default());
        let mut target = tar::Builder::new(encoder);
        for entry in source
            .entries()
            .context("failed to read unsigned capsule")?
        {
            let mut entry = entry.context("failed to copy unsigned capsule entry")?;
            let path = normalized_entry_path(&entry)?;
            if path == PROVENANCE_FILE {
                bail!("capsule archive already contains {PROVENANCE_FILE}");
            }
            let header = entry.header().clone();
            target
                .append(&header, &mut entry)
                .with_context(|| format!("failed to copy capsule entry '{path}'"))?;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(envelope.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        target.append_data(&mut header, PROVENANCE_FILE, envelope)?;
        let encoder = target.into_inner()?;
        encoder.finish()?;
    }
    staged.as_file_mut().sync_all()?;
    staged
        .persist(archive_path)
        .map_err(|error| anyhow::anyhow!("failed to replace signed capsule archive: {error}"))?;
    Ok(())
}

fn collect_directory_records(
    root: &Path,
    canonical_root: &Path,
    current: &Path,
    records: &mut Vec<ContentRecord>,
    envelope: &mut Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed to read capsule directory {}", current.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            let resolved = std::fs::canonicalize(&path)
                .with_context(|| format!("failed to resolve capsule symlink {}", path.display()))?;
            if !resolved.starts_with(canonical_root) {
                bail!(
                    "capsule symlink resolves outside its source tree: {}",
                    path.display()
                );
            }
            let metadata = std::fs::metadata(&resolved)?;
            if !metadata.is_file() {
                bail!(
                    "capsule content cannot contain a directory symlink: {}",
                    path.display()
                );
            }
            let relative = path.strip_prefix(root)?;
            let normalized = normalize_relative_path(relative)?;
            let mut file = File::open(&resolved)?;
            records.push(hash_reader(normalized, metadata.len(), &mut file)?);
            continue;
        }
        if file_type.is_dir() {
            collect_directory_records(root, canonical_root, &path, records, envelope)?;
            continue;
        }
        if !file_type.is_file() {
            bail!(
                "capsule content contains a special file: {}",
                path.display()
            );
        }
        let relative = path.strip_prefix(root)?;
        let normalized = normalize_relative_path(relative)?;
        if normalized == PROVENANCE_FILE {
            if envelope.is_some() {
                bail!("capsule directory contains duplicate provenance");
            }
            *envelope = Some(std::fs::read(&path)?);
            continue;
        }
        let mut file = File::open(&path)?;
        let size = file.metadata()?.len();
        records.push(hash_reader(normalized, size, &mut file)?);
    }
    Ok(())
}

fn normalize_relative_path(path: &Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .context("capsule paths must be UTF-8")?
                    .to_string(),
            ),
            Component::CurDir => {},
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe capsule path '{}'", path.display());
            },
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_archive(path: &Path, manifest: &[u8], payload: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for (name, bytes) in [("Capsule.toml", manifest), ("capsule.wasm", payload)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
        }
        tar.finish().unwrap();
    }

    #[test]
    fn sign_and_verify_archive_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("test.capsule");
        unsigned_archive(
            &archive,
            b"[package]\nname='test'\nversion='1.0.0'\n",
            b"wasm",
        );
        let key = KeyPair::generate();
        let signed = sign_archive(&archive, &key).unwrap();
        assert_eq!(
            verify_archive(&archive).unwrap(),
            ArtifactVerification::Signed(signed)
        );
    }

    #[test]
    fn tampered_signed_archive_fails() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("test.capsule");
        unsigned_archive(
            &archive,
            b"[package]\nname='test'\nversion='1.0.0'\n",
            b"wasm",
        );
        sign_archive(&archive, &KeyPair::generate()).unwrap();

        let staged = dir.path().join("tampered.capsule");
        let input = File::open(&archive).unwrap();
        let mut source = tar::Archive::new(GzDecoder::new(input));
        let output = File::create(&staged).unwrap();
        let encoder = GzEncoder::new(output, Compression::default());
        let mut target = tar::Builder::new(encoder);
        for entry in source.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if path == Path::new("capsule.wasm") {
                bytes = b"tampered".to_vec();
            }
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            target
                .append_data(&mut header, path, bytes.as_slice())
                .unwrap();
        }
        target.finish().unwrap();
        assert!(verify_archive(&staged).is_err());
    }

    #[test]
    fn unsigned_archive_reports_digest() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("test.capsule");
        unsigned_archive(&archive, b"manifest", b"wasm");
        let ArtifactVerification::Unsigned { content_digest } = verify_archive(&archive).unwrap()
        else {
            panic!("expected unsigned artifact");
        };
        assert_eq!(content_digest.len(), 64);
    }

    #[test]
    fn archive_and_directory_use_same_digest() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("Capsule.toml"), b"manifest").unwrap();
        std::fs::write(source.join("capsule.wasm"), b"wasm").unwrap();
        let archive = dir.path().join("test.capsule");
        unsigned_archive(&archive, b"manifest", b"wasm");
        assert_eq!(
            verify_archive(&archive).unwrap().content_digest(),
            verify_directory(&source).unwrap().content_digest()
        );
    }
}
