//! Canonical archive digests for local capsule sources.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};

/// Compute the registry archive digest for a local capsule source.
///
/// Directories are canonicalized using the same deterministic archive builder
/// used by durable publication. Archive files are unpacked into a fresh
/// temporary directory, validated for safe regular-file/directory entries,
/// then canonicalized through that same builder. No principal store is opened
/// and no durable state is mutated.
pub fn archive_digest_for_source(source: &Path) -> anyhow::Result<String> {
    let archive = canonical_archive_for_source(source)?;
    Ok(blake3::hash(&archive).to_hex().to_string())
}

/// Compute the digest of the exact bytes supplied as a local archive source.
///
/// This is the identity used by install provenance before the verifier opens
/// and normalizes the archive. It is intentionally distinct from
/// [`archive_digest_for_source`], which identifies the durable canonical
/// archive produced after verification.
pub fn source_digest_for_archive(source: &Path) -> anyhow::Result<String> {
    if !source.is_file() {
        bail!(
            "capsule source is not a regular archive file: {}",
            source.display()
        );
    }
    let mut file = fs::File::open(source)
        .with_context(|| format!("open capsule archive source {}", source.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read capsule archive source {}", source.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn canonical_archive_for_source(source: &Path) -> anyhow::Result<Vec<u8>> {
    if source.is_dir() {
        return crate::storage::canonical_capsule_archive(source);
    }
    if !source.is_file() {
        bail!(
            "capsule source is neither a directory nor a regular file: {}",
            source.display()
        );
    }

    let file = fs::File::open(source)
        .with_context(|| format!("open capsule archive {}", source.display()))?;
    canonical_archive_from_reader(file, u64::MAX)
}

pub(crate) fn canonical_archive_from_reader(
    source: impl Read,
    expanded_limit: u64,
) -> anyhow::Result<Vec<u8>> {
    let staging = tempfile::tempdir().context("create source digest staging directory")?;
    let decoder = flate2::read::GzDecoder::new(source);
    let mut expanded = 0_u64;
    let mut count = 0_u64;
    // Bound raw decompression too: tar consumes GNU/PAX extension records
    // internally before yielding an entry, so entry sizes alone are insufficient.
    let budget = expanded_limit.saturating_add(4 * 1024 * 1024);
    let mut archive = tar::Archive::new(decoder.take(budget));
    let mut names = BTreeSet::new();
    for entry in archive.entries().context("read capsule archive entries")? {
        let mut entry = entry.context("read capsule archive entry")?;
        let path = entry.path().context("read capsule archive path")?;
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            bail!("capsule archive contains an unsafe path {}", path.display());
        }
        let name = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("capsule archive path is not UTF-8"))?
            .replace('\\', "/");
        if !names.insert(name.clone()) {
            bail!("capsule archive contains duplicate path {name}");
        }
        count = count.saturating_add(1);
        expanded = expanded
            .checked_add(entry.size())
            .ok_or_else(|| anyhow::anyhow!("archive size overflow"))?;
        if expanded > expanded_limit || (expanded_limit != u64::MAX && count > 4096) {
            bail!("archive expansion limit exceeded");
        }
        let entry_type = entry.header().entry_type();
        if !entry_type.is_dir() && !entry_type.is_file() {
            bail!("capsule archive contains a link or special file {name}");
        }
        let destination = staging.path().join(&path);
        if entry_type.is_dir() {
            fs::create_dir_all(&destination)
                .with_context(|| format!("create capsule archive directory {name}"))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create capsule archive parent for {name}"))?;
        }
        entry
            .unpack(&destination)
            .with_context(|| format!("unpack capsule archive file {name}"))?;
        // Drain the entry explicitly so malformed/truncated streams fail
        // before the canonical builder reads the staged tree.
        let mut sink = Vec::new();
        entry
            .read_to_end(&mut sink)
            .with_context(|| format!("read capsule archive file {name}"))?;
    }
    if archive.into_inner().limit() == 0 {
        bail!("archive decompression limit exceeded");
    }
    crate::storage::canonical_capsule_archive(staging.path())
}

#[cfg(test)]
mod tests {
    use super::{archive_digest_for_source, source_digest_for_archive};
    use std::fs;

    #[test]
    fn directory_digest_matches_canonical_archive_bytes() {
        let source = tempfile::tempdir().expect("source");
        fs::write(
            source.path().join("Capsule.toml"),
            b"[package]\nname='demo'\nversion='1.0.0'\n",
        )
        .expect("manifest");
        let archive = crate::canonical_capsule_archive(source.path()).expect("archive");
        let digest = archive_digest_for_source(source.path()).expect("digest");
        assert_eq!(digest, blake3::hash(&archive).to_hex().to_string());
    }

    #[test]
    fn archive_digest_is_canonicalized_before_hashing() {
        let source = tempfile::tempdir().expect("source");
        fs::write(
            source.path().join("Capsule.toml"),
            b"[package]\nname='demo'\nversion='1.0.0'\n",
        )
        .expect("manifest");
        fs::create_dir(source.path().join("assets")).expect("assets");
        fs::write(source.path().join("assets/value"), b"value").expect("asset");
        let archive = crate::canonical_capsule_archive(source.path()).expect("archive");
        let archive_path = source.path().join("demo.capsule");
        fs::write(&archive_path, &archive).expect("archive file");
        let digest = archive_digest_for_source(&archive_path).expect("digest");
        assert_eq!(digest, blake3::hash(&archive).to_hex().to_string());
    }

    #[test]
    fn source_digest_identifies_exact_archive_bytes() {
        let source = tempfile::NamedTempFile::new().expect("source");
        fs::write(source.path(), b"exact compressed bytes").expect("source bytes");
        let digest = source_digest_for_archive(source.path()).expect("digest");
        assert_eq!(
            digest,
            blake3::hash(b"exact compressed bytes").to_hex().to_string()
        );
    }
}
