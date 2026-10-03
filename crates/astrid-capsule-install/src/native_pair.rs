//! Read-only verification for unpublished native pair members.

use crate::{ArtifactProvenance, AuthorityDecision, InstallInspection, InstalledAuthority};
use anyhow::ensure;
use astrid_build::artifact::{self, ArtifactVerification};
use astrid_capsule::{capsule::CapsuleId, manifest::CapsuleManifest};
use astrid_core::kernel_api::{CapsuleInstallAuthority, CapsuleInstallEnv, EnvValueKind};

/// Verified bytes and proposed environment; no live storage handle is retained.
/// Fields are immutable and intentionally have no Debug representation.
pub struct VerifiedNativePairMember {
    archive: Vec<u8>,
    manifest: CapsuleManifest,
    authority: InstalledAuthority,
    env: Vec<CapsuleInstallEnv>,
}

impl VerifiedNativePairMember {
    /// Canonical unpublished archive bytes.
    pub fn archive(&self) -> &[u8] {
        &self.archive
    }
    /// Verified capsule manifest.
    pub fn manifest(&self) -> &CapsuleManifest {
        &self.manifest
    }
    /// Exact approved authority, including executable pin.
    pub fn authority(&self) -> &InstalledAuthority {
        &self.authority
    }
    /// Proposed generation environment; never written to live KV.
    pub fn env(&self) -> &[CapsuleInstallEnv] {
        &self.env
    }
    /// Read only the verified immutable executable, without extracting native files.
    pub fn executable(&self) -> anyhow::Result<Vec<u8>> {
        use std::io::Read;
        let path = &self.manifest.components[0].path;
        let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(&self.archive));
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries()? {
            let entry = entry?;
            if entry.path()?.as_ref() == path {
                let mut bytes = Vec::new();
                entry.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 64 * 1024 * 1024, "native executable limit");
                ensure!(
                    Some(blake3::hash(&bytes).to_hex().as_str())
                        == self.authority.approved_wasm_hash.as_deref(),
                    "native executable pin mismatch"
                );
                return Ok(bytes);
            }
        }
        anyhow::bail!("native executable absent")
    }
}

/// Verify and normalize a narrow native member without credentials or publication.
/// The runtime public key is supplied by the already initialized daemon.
/// All errors are deliberately bounded and omit archive/environment contents.
pub fn verify_native_pair_member(
    bytes: &[u8],
    id: &str,
    authority: CapsuleInstallAuthority,
    env: Vec<CapsuleInstallEnv>,
    runtime_public_key: &[u8; 32],
) -> anyhow::Result<VerifiedNativePairMember> {
    verify_member(bytes, id, authority, env, runtime_public_key)
        .map_err(|_| anyhow::anyhow!("native pair member verification failed"))
}

fn verify_member(
    bytes: &[u8],
    id: &str,
    authority: CapsuleInstallAuthority,
    env: Vec<CapsuleInstallEnv>,
    runtime_public_key: &[u8; 32],
) -> anyhow::Result<VerifiedNativePairMember> {
    ensure!(
        matches!(id, "codewall-enforcer" | "codewall-protocol"),
        "unsupported member"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
        "archive limit"
    );
    // Bound decompression before the provenance verifier allocates its inventory.
    let archive = crate::source_digest::canonical_archive_from_reader(
        std::io::Cursor::new(bytes),
        128 * 1024 * 1024,
    )?;
    ensure!(
        archive.len() <= 64 * 1024 * 1024,
        "normalized archive limit"
    );
    let verification = artifact::verify_archive_bytes(bytes)?;
    ensure!(
        artifact::verify_archive_bytes(&archive)?.content_digest() == verification.content_digest(),
        "normalization changed verified content"
    );
    let manifest = crate::read_archive_manifest_bytes(&archive)?;
    ensure!(
        manifest.package.name == id
            && manifest.components.len() == 1
            && manifest.uplinks.is_empty()
            && manifest.mcp_servers.is_empty(),
        "unsupported member identity or runtime"
    );
    let component = &manifest.components[0];
    let path = component
        .path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("component path"))?;
    ensure!(
        std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm")),
        "native pair requires WASM"
    );
    validate_env(&manifest, &env)?;
    let content_digest = verification.content_digest().to_owned();
    let provenance = match verification {
        ArtifactVerification::Unsigned { .. } => ArtifactProvenance::Unsigned,
        ArtifactVerification::Signed(verified) => {
            let signer = verified.signer.to_string();
            let signature = verified.signature.to_string();
            if verified.signer.as_bytes() == runtime_public_key {
                ArtifactProvenance::LocalRuntime { signer, signature }
            } else {
                ArtifactProvenance::ForeignRuntime { signer, signature }
            }
        },
    };
    let mut capabilities = manifest.capabilities.clone();
    if let Some(component_caps) = &component.capabilities {
        capabilities.merge_from(component_caps);
    }
    let inspection = InstallInspection {
        capsule_id: CapsuleId::new(id)?,
        version: manifest.package.version.clone(),
        content_digest: content_digest.clone(),
        provenance,
        capability_expansions: vec![],
        manifest_digest: crate::authority::digest_manifest(
            artifact::read_archive_text_bytes(&archive, "Capsule.toml")?.as_bytes(),
        ),
        requested_capabilities: capabilities,
    };
    let decision = match authority {
        CapsuleInstallAuthority::Automatic => AuthorityDecision::Automatic,
        CapsuleInstallAuthority::ExplicitApproval => {
            AuthorityDecision::ExplicitApproval { content_digest }
        },
        CapsuleInstallAuthority::OperatorDistribution => {
            AuthorityDecision::OperatorDistribution { content_digest }
        },
    };
    let mut authority = crate::authorize_install(&inspection, &decision)?;
    let hash = executable_hash(&archive, path)?;
    authority.wasm_hash_pinned = true;
    authority.approved_wasm_hash = Some(hash);
    Ok(VerifiedNativePairMember {
        archive,
        manifest,
        authority,
        env,
    })
}

fn executable_hash(archive: &[u8], path: &str) -> anyhow::Result<String> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(archive));
    let mut tar = tar::Archive::new(decoder);
    let mut hash = None;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.path()?.to_str() == Some(path) {
            let mut hasher = blake3::Hasher::new();
            std::io::copy(&mut entry, &mut hasher)?;
            hash = Some(hasher.finalize().to_hex().to_string());
        }
    }
    hash.ok_or_else(|| anyhow::anyhow!("missing executable"))
}

fn validate_env(manifest: &CapsuleManifest, env: &[CapsuleInstallEnv]) -> anyhow::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    ensure!(env.len() <= 64, "env limit");
    let mut total = 0_usize;
    for value in env {
        total = total
            .checked_add(value.value.len())
            .ok_or_else(|| anyhow::anyhow!("env limit"))?;
        ensure!(
            total <= 64 * 1024
                && value.key.len() <= 128
                && !value.key.is_empty()
                && !value.key.contains(['\0', ':'])
                && seen.insert(&value.key),
            "env limit"
        );
        let declaration = manifest
            .env
            .get(&value.key)
            .ok_or_else(|| anyhow::anyhow!("undeclared env"))?;
        ensure!(
            value.kind == EnvValueKind::Text
                && !declaration.env_type.eq_ignore_ascii_case("secret")
                && value.key != "CODEWALL_ENROLMENT_TOKEN",
            "shared or enrollment mutation forbidden"
        );
        ensure!(
            declaration.enum_values.is_empty() || declaration.enum_values.contains(&value.value),
            "env enum"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::kernel_api::{CapsuleInstallAuthority, CapsuleInstallEnv, EnvValueKind};

    fn archive() -> Vec<u8> {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("Capsule.toml"),
            "[package]\nname='codewall-enforcer'\nversion='1.0.0'\n[[component]]\nid='main'\nfile='main.wasm'\n[env.PIN]\ntype='text'\n[env.TOKEN]\ntype='secret'\n").unwrap();
        std::fs::write(directory.path().join("main.wasm"), b"\0asm\x01\0\0\0").unwrap();
        crate::canonical_capsule_archive(directory.path()).unwrap()
    }

    #[test]
    fn native_pair_archive_is_verified_without_publication() {
        let bytes = archive();
        let member = verify_native_pair_member(
            &bytes,
            "codewall-enforcer",
            CapsuleInstallAuthority::ExplicitApproval,
            vec![],
            &[0; 32],
        )
        .unwrap();
        assert_eq!(member.manifest().package.name, "codewall-enforcer");
        assert_eq!(member.archive(), bytes);
        assert!(member.authority().wasm_hash_pinned);
        assert!(
            verify_native_pair_member(
                &bytes,
                "codewall-enforcer",
                CapsuleInstallAuthority::Automatic,
                vec![],
                &[0; 32]
            )
            .is_err()
        );
        assert!(
            verify_native_pair_member(
                &bytes,
                "codewall-protocol",
                CapsuleInstallAuthority::ExplicitApproval,
                vec![],
                &[0; 32]
            )
            .is_err()
        );
        assert!(
            verify_native_pair_member(
                b"not an archive",
                "codewall-enforcer",
                CapsuleInstallAuthority::ExplicitApproval,
                vec![],
                &[0; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn native_pair_archive_requires_bound_signature_and_bounds_expansion() {
        let key = astrid_crypto::KeyPair::generate();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), archive()).unwrap();
        astrid_build::artifact::sign_archive(file.path(), &key).unwrap();
        let bytes = std::fs::read(file.path()).unwrap();
        assert!(
            verify_native_pair_member(
                &bytes,
                "codewall-enforcer",
                CapsuleInstallAuthority::Automatic,
                vec![],
                key.public_key_bytes()
            )
            .is_ok()
        );
        assert!(
            verify_native_pair_member(
                &bytes,
                "codewall-enforcer",
                CapsuleInstallAuthority::Automatic,
                vec![],
                &[0; 32]
            )
            .is_err()
        );
        let mut header = tar::Header::new_gnu();
        header.set_path("huge.wasm").unwrap();
        header.set_size(129 * 1024 * 1024);
        header.set_mode(0o600);
        header.set_cksum();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, header.as_bytes()).unwrap();
        std::io::Write::write_all(&mut encoder, &[0; 1024]).unwrap();
        let bomb = encoder.finish().unwrap();
        assert!(
            verify_native_pair_member(
                &bomb,
                "codewall-enforcer",
                CapsuleInstallAuthority::ExplicitApproval,
                vec![],
                &[0; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn native_pair_archive_rejects_secret_and_undeclared_env_without_echoing() {
        for (key, kind, value) in [
            ("TOKEN", EnvValueKind::Secret, "sensitive-marker"),
            ("TOKEN", EnvValueKind::Secret, ""),
            ("TOKEN", EnvValueKind::Text, "sensitive-marker"),
            ("UNKNOWN", EnvValueKind::Text, "sensitive-marker"),
        ] {
            let error = verify_native_pair_member(
                &archive(),
                "codewall-enforcer",
                CapsuleInstallAuthority::ExplicitApproval,
                vec![CapsuleInstallEnv {
                    key: key.into(),
                    kind,
                    value: value.into(),
                }],
                &[0; 32],
            )
            .err()
            .expect("reject");
            assert!(!format!("{error:#}").contains("sensitive-marker"));
        }
    }
}
