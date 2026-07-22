//! Capsule provenance classification and local installation authority.
//!
//! Artifact integrity, installation authority, and principal capsule access
//! are deliberately separate. A foreign signature proves bytes came from one
//! key; it does not grant those bytes authority on this runtime.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use astrid_build::artifact::{self, ArtifactVerification};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::manifest::{CapabilitiesDef, CapabilityExpansion, CapsuleManifest};
use astrid_core::PrincipalId;
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use serde::{Deserialize, Serialize};

use crate::paths::resolve_target_dir_for_in_workspace;

const AUTHORITY_RECEIPT_DIR: &str = "capsule-authority";
const RECEIPT_PATH_DOMAIN: &[u8] = b"astrid:capsule-authority-path:v1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"astrid:capsule-manifest:v1\0";

/// Provenance relationship between an artifact and this runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactProvenance {
    /// Signed by this installation's runtime identity.
    LocalRuntime {
        /// Full runtime public key.
        signer: String,
        /// Ed25519 capsule signature.
        signature: String,
    },
    /// Validly signed, but by another runtime identity.
    ForeignRuntime {
        /// Full foreign runtime public key.
        signer: String,
        /// Ed25519 capsule signature.
        signature: String,
    },
    /// No capsule provenance envelope was present.
    Unsigned,
}

impl ArtifactProvenance {
    /// Human-readable provenance label suitable for an approval prompt.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::LocalRuntime { .. } => "signed by this runtime",
            Self::ForeignRuntime { .. } => "signed by another runtime",
            Self::Unsigned => "unsigned",
        }
    }

    /// Signer key when the artifact is signed.
    #[must_use]
    pub fn signer(&self) -> Option<&str> {
        match self {
            Self::LocalRuntime { signer, .. } | Self::ForeignRuntime { signer, .. } => Some(signer),
            Self::Unsigned => None,
        }
    }
}

/// Read-only result presented before an install mutates runtime state.
#[derive(Debug, Clone)]
pub struct InstallInspection {
    /// Capsule identity declared by the inspected manifest.
    pub capsule_id: CapsuleId,
    /// Capsule version declared by the inspected manifest.
    pub version: String,
    /// Canonical digest binding the inspected content tree.
    pub content_digest: String,
    /// Relationship between the capsule signer and this runtime.
    pub provenance: ArtifactProvenance,
    /// Exact authority added beyond the currently accepted install snapshot.
    pub capability_expansions: Vec<CapabilityExpansion>,
    pub(crate) manifest_digest: String,
    pub(crate) requested_capabilities: CapabilitiesDef,
}

/// How a successfully-installed authority snapshot was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthoritySource {
    /// Artifact was signed by this runtime's local build identity.
    LocalRuntimeBuild,
    /// Human or trusted caller approved this exact artifact once.
    ExplicitApproval,
    /// Product/operator-owned distribution accepted this exact artifact.
    OperatorDistribution,
    /// Existing pre-authority install snapshotted during the runtime upgrade.
    LegacyMigration,
}

/// Persisted authority receipt for a capsule install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledAuthority {
    /// Receipt schema version.
    pub schema_version: u32,
    /// Path by which this exact artifact was accepted.
    pub source: AuthoritySource,
    /// Capsule identity covered by this receipt.
    pub capsule_id: String,
    /// Capsule version covered by this receipt.
    pub version: String,
    /// Canonical content digest approved before installation.
    pub content_digest: String,
    /// BLAKE3 digest of the exact approved `Capsule.toml` bytes.
    pub manifest_digest: String,
    /// Capsule signer public key, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Capsule Ed25519 signature, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Full manifest capability snapshot accepted for this install.
    pub approved_capabilities: CapabilitiesDef,
}

/// Read an installed authority receipt.
///
/// A missing receipt denotes an install made before authority receipts were
/// introduced. A present but malformed receipt is an error rather than a
/// legacy install, so corruption cannot silently discard an approval ceiling.
///
/// # Errors
///
/// Returns an error when the receipt cannot be read or decoded.
pub fn read_installed_authority(
    home: &AstridHome,
    target_dir: &Path,
) -> anyhow::Result<Option<InstalledAuthority>> {
    let paths = authority_paths(home, target_dir)?;
    if paths.pending.exists() {
        bail!(
            "capsule authority update is incomplete at {}; reinstall the capsule",
            paths.pending.display()
        );
    }
    let path = paths.active;
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read authority receipt {}", path.display()));
        },
    };
    let receipt = serde_json::from_str(&content)
        .with_context(|| format!("invalid authority receipt {}", path.display()))?;
    Ok(Some(receipt))
}

/// Remove the authority state for an uninstalled capsule.
///
/// # Errors
///
/// Returns an error when an install transaction is pending or receipt cleanup
/// fails.
pub fn remove_installed_authority(home: &AstridHome, target_dir: &Path) -> anyhow::Result<()> {
    let paths = authority_paths(home, target_dir)?;
    if paths.pending.exists() {
        bail!(
            "cannot remove capsule authority while an install transaction is pending at {}",
            paths.pending.display()
        );
    }
    for path in [paths.active, paths.previous] {
        match std::fs::remove_file(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to remove authority receipt {}", path.display())
                });
            },
        }
    }
    Ok(())
}

pub(crate) struct AuthorityReceiptTransaction {
    active: PathBuf,
    pending: PathBuf,
    previous: PathBuf,
    committed: bool,
}

impl AuthorityReceiptTransaction {
    pub(crate) fn stage(
        home: &AstridHome,
        target_dir: &Path,
        authority: &InstalledAuthority,
    ) -> anyhow::Result<Self> {
        let paths = authority_paths(home, target_dir)?;
        std::fs::create_dir_all(&paths.directory).with_context(|| {
            format!(
                "failed to create capsule authority directory {}",
                paths.directory.display()
            )
        })?;
        set_owner_private_dir(&paths.directory)?;

        if paths.pending.exists() {
            bail!(
                "an incomplete capsule authority update exists at {}; remove it only after inspecting the interrupted install",
                paths.pending.display()
            );
        }
        if paths.previous.exists() && paths.active.exists() {
            std::fs::remove_file(&paths.previous).with_context(|| {
                format!(
                    "failed to clean stale capsule authority backup {}",
                    paths.previous.display()
                )
            })?;
        }
        if paths.previous.exists() && !paths.active.exists() {
            std::fs::rename(&paths.previous, &paths.active).with_context(|| {
                format!(
                    "failed to recover capsule authority backup {}",
                    paths.previous.display()
                )
            })?;
        }

        let json = serde_json::to_vec_pretty(authority)
            .context("failed to serialize installed authority receipt")?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut pending = options.open(&paths.pending).with_context(|| {
            format!(
                "failed to stage capsule authority receipt {}",
                paths.pending.display()
            )
        })?;
        let write_result = (|| {
            pending
                .write_all(&json)
                .context("failed to write capsule authority receipt")?;
            pending
                .sync_all()
                .context("failed to sync capsule authority receipt")?;
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(error) = write_result {
            drop(pending);
            let _ = std::fs::remove_file(&paths.pending);
            return Err(error);
        }

        Ok(Self {
            active: paths.active,
            pending: paths.pending,
            previous: paths.previous,
            committed: false,
        })
    }

    pub(crate) fn commit(mut self) -> anyhow::Result<()> {
        let had_active = self.active.exists();
        if had_active {
            std::fs::rename(&self.active, &self.previous).with_context(|| {
                format!(
                    "failed to stage previous authority receipt {}",
                    self.active.display()
                )
            })?;
        }
        if let Err(error) = std::fs::rename(&self.pending, &self.active) {
            if had_active {
                let _ = std::fs::rename(&self.previous, &self.active);
            }
            return Err(error).with_context(|| {
                format!(
                    "failed to commit capsule authority receipt {}",
                    self.active.display()
                )
            });
        }
        self.committed = true;
        let _ = std::fs::remove_file(&self.previous);
        Ok(())
    }
}

impl Drop for AuthorityReceiptTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.pending);
            if self.previous.exists() && !self.active.exists() {
                let _ = std::fs::rename(&self.previous, &self.active);
            }
        }
    }
}

struct AuthorityPaths {
    directory: PathBuf,
    active: PathBuf,
    pending: PathBuf,
    previous: PathBuf,
}

fn authority_paths(home: &AstridHome, target_dir: &Path) -> anyhow::Result<AuthorityPaths> {
    let target = if target_dir.is_absolute() {
        target_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve relative capsule authority target")?
            .join(target_dir)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_PATH_DOMAIN);
    hasher.update(target.as_os_str().as_encoded_bytes());
    let name = hasher.finalize().to_hex().to_string();
    let directory = home.etc_dir().join(AUTHORITY_RECEIPT_DIR);
    Ok(AuthorityPaths {
        active: directory.join(format!("{name}.json")),
        pending: directory.join(format!("{name}.pending")),
        previous: directory.join(format!("{name}.previous")),
        directory,
    })
}

#[cfg(unix)]
fn set_owner_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Verify that an installed manifest stays within its accepted authority.
///
/// Receipts live under Astrid's kernel-owned `etc/` policy tree rather than
/// the principal or workspace VFS, so capsule filesystem grants cannot alter
/// their own ceilings.
///
/// # Errors
///
/// Returns an error for an incomplete/corrupt receipt, identity mismatch, or
/// capability expansion.
pub fn verify_installed_authority(
    home: &AstridHome,
    target_dir: &Path,
    manifest: &CapsuleManifest,
) -> anyhow::Result<()> {
    let manifest_bytes = std::fs::read(target_dir.join("Capsule.toml"))
        .context("failed to read installed capsule manifest")?;
    let current_manifest_digest = digest_manifest(&manifest_bytes);
    let Some(authority) = read_installed_authority(home, target_dir)? else {
        // Snapshot pre-authority installs once. The receipt is outside the
        // capsule VFS, so absence is a migration state rather than a permanent
        // fail-open mode a capsule can recreate by deleting a sidecar.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"astrid:legacy-capsule-authority:v1\0");
        hasher.update(&manifest_bytes);
        let migrated = InstalledAuthority {
            schema_version: 1,
            source: AuthoritySource::LegacyMigration,
            capsule_id: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            content_digest: hasher.finalize().to_hex().to_string(),
            manifest_digest: current_manifest_digest,
            signer: None,
            signature: None,
            approved_capabilities: manifest.capabilities.clone(),
        };
        AuthorityReceiptTransaction::stage(home, target_dir, &migrated)?.commit()?;
        return Ok(());
    };
    if authority.schema_version != 1 {
        bail!(
            "unsupported installed authority schema {}",
            authority.schema_version
        );
    }
    if authority.capsule_id != manifest.package.name
        || authority.version != manifest.package.version
    {
        bail!(
            "installed capsule identity/version differs from its authority receipt (approved {} {}, found {} {})",
            authority.capsule_id,
            authority.version,
            manifest.package.name,
            manifest.package.version
        );
    }
    let expansions = manifest
        .capabilities
        .expansions_from(&authority.approved_capabilities);
    if !expansions.is_empty() {
        let details = expansions
            .into_iter()
            .map(|expansion| format!("{}=[{}]", expansion.name, expansion.added.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "manifest exceeds its installed capability approval: {details}; reinstall and approve the expansion"
        );
    }
    if authority.manifest_digest != current_manifest_digest {
        bail!(
            "installed Capsule.toml differs from the exact manifest approved at install; reinstall the capsule"
        );
    }
    Ok(())
}

/// A decision bound to one previously inspected content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityDecision {
    /// Accept only when the artifact is signed by this runtime.
    Automatic,
    /// One-install approval for the exact digest.
    ExplicitApproval {
        /// Digest shown to and approved by the caller.
        content_digest: String,
    },
    /// Product/operator-owned distro acceptance for the exact digest.
    OperatorDistribution {
        /// Digest verified by the distribution install path.
        content_digest: String,
    },
}

struct InspectedArtifact {
    verification: ArtifactVerification,
    manifest_digest: String,
}

/// Inspect a `.capsule` archive before install mutation.
///
/// # Errors
///
/// Fails on malformed/tampered provenance, invalid manifests, or unsafe target
/// resolution.
pub fn inspect_archive_for_principal_with_layout(
    archive_path: &Path,
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let workspace_root = std::env::current_dir().ok();
    inspect_archive_for_principal_in_workspace(
        archive_path,
        home,
        target_principal,
        workspace,
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Inspect an archive using explicit workspace inputs.
///
/// # Errors
///
/// Fails on malformed/tampered provenance, invalid manifests, or unsafe target
/// resolution.
pub fn inspect_archive_for_principal_in_workspace(
    archive_path: &Path,
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let verification = artifact::verify_archive(archive_path)?;
    let manifest_text = artifact::read_archive_text(archive_path, "Capsule.toml")?;
    let manifest_digest = digest_manifest(manifest_text.as_bytes());
    let staged = tempfile::tempdir().context("failed to stage capsule manifest inspection")?;
    let manifest_path = staged.path().join("Capsule.toml");
    std::fs::write(&manifest_path, manifest_text)?;
    let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
        .context("failed to inspect capsule manifest")?;
    inspect_manifest(
        manifest,
        InspectedArtifact {
            verification,
            manifest_digest,
        },
        home,
        target_principal,
        workspace,
        workspace_root,
        workspace_layout,
    )
}

/// Inspect a local capsule directory before install mutation.
///
/// # Errors
///
/// Fails on malformed/tampered provenance, invalid manifests, links in a
/// signed content tree, or unsafe target resolution.
pub fn inspect_directory_for_principal_with_layout(
    source_dir: &Path,
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let workspace_root = std::env::current_dir().ok();
    inspect_directory_for_principal_in_workspace(
        source_dir,
        home,
        target_principal,
        workspace,
        workspace_root.as_deref(),
        workspace_layout,
    )
}

/// Inspect a directory using explicit workspace inputs.
///
/// # Errors
///
/// Fails on malformed/tampered provenance, invalid manifests, links in a
/// signed content tree, or unsafe target resolution.
pub fn inspect_directory_for_principal_in_workspace(
    source_dir: &Path,
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let verification = artifact::verify_directory(source_dir)?;
    let manifest_path = source_dir.join("Capsule.toml");
    let manifest_digest = digest_manifest(&std::fs::read(&manifest_path)?);
    let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
        .context("failed to inspect capsule manifest")?;
    inspect_manifest(
        manifest,
        InspectedArtifact {
            verification,
            manifest_digest,
        },
        home,
        target_principal,
        workspace,
        workspace_root,
        workspace_layout,
    )
}

/// Convert a bound decision into the receipt persisted by the installer.
///
/// # Errors
///
/// `Automatic` rejects foreign and unsigned artifacts. Bound decisions reject
/// a digest mismatch, preventing a changed artifact from reusing an approval.
pub fn authorize_install(
    inspection: &InstallInspection,
    decision: &AuthorityDecision,
) -> anyhow::Result<InstalledAuthority> {
    let source = match decision {
        AuthorityDecision::Automatic => {
            if !matches!(
                inspection.provenance,
                ArtifactProvenance::LocalRuntime { .. }
            ) {
                bail!(
                    "capsule '{}' is {}; explicit local approval is required",
                    inspection.capsule_id,
                    inspection.provenance.label()
                );
            }
            AuthoritySource::LocalRuntimeBuild
        },
        AuthorityDecision::ExplicitApproval { content_digest } => {
            ensure_bound_digest(inspection, content_digest)?;
            AuthoritySource::ExplicitApproval
        },
        AuthorityDecision::OperatorDistribution { content_digest } => {
            ensure_bound_digest(inspection, content_digest)?;
            AuthoritySource::OperatorDistribution
        },
    };
    let (signer, signature) = match &inspection.provenance {
        ArtifactProvenance::LocalRuntime { signer, signature }
        | ArtifactProvenance::ForeignRuntime { signer, signature } => {
            (Some(signer.clone()), Some(signature.clone()))
        },
        ArtifactProvenance::Unsigned => (None, None),
    };
    Ok(InstalledAuthority {
        schema_version: 1,
        source,
        capsule_id: inspection.capsule_id.as_str().to_string(),
        version: inspection.version.clone(),
        content_digest: inspection.content_digest.clone(),
        manifest_digest: inspection.manifest_digest.clone(),
        signer,
        signature,
        approved_capabilities: inspection.requested_capabilities.clone(),
    })
}

fn inspect_manifest(
    manifest: CapsuleManifest,
    artifact: InspectedArtifact,
    home: &AstridHome,
    target_principal: &PrincipalId,
    workspace: bool,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> anyhow::Result<InstallInspection> {
    let keypair = astrid_crypto::load_or_generate_keypair(&home.runtime_key_path())
        .context("failed to load local runtime identity")?;
    let content_digest = artifact.verification.content_digest().to_string();
    let provenance = match artifact.verification {
        ArtifactVerification::Unsigned { .. } => ArtifactProvenance::Unsigned,
        ArtifactVerification::Signed(verified) => {
            let signer = verified.signer.to_string();
            let signature = verified.signature.to_string();
            if verified.signer.as_bytes() == keypair.public_key_bytes() {
                ArtifactProvenance::LocalRuntime { signer, signature }
            } else {
                ArtifactProvenance::ForeignRuntime { signer, signature }
            }
        },
    };
    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let target_dir = resolve_target_dir_for_in_workspace(
        home,
        target_principal,
        capsule_id.as_str(),
        workspace,
        workspace_root,
        workspace_layout,
    )?;
    let approved = match read_installed_authority(home, &target_dir)? {
        Some(authority) => {
            if authority.schema_version != 1 || authority.capsule_id != capsule_id.as_str() {
                bail!("installed authority receipt does not match capsule '{capsule_id}'");
            }
            Some(authority.approved_capabilities)
        },
        None => None,
    }
    .or_else(|| {
        astrid_capsule::discovery::load_manifest(&target_dir.join("Capsule.toml"))
            .ok()
            .map(|installed| installed.capabilities)
    })
    .unwrap_or_default();
    let capability_expansions = manifest.capabilities.expansions_from(&approved);
    Ok(InstallInspection {
        capsule_id,
        version: manifest.package.version,
        content_digest,
        provenance,
        capability_expansions,
        manifest_digest: artifact.manifest_digest,
        requested_capabilities: manifest.capabilities,
    })
}

pub(crate) fn authority_for_install_source(
    source_dir: &Path,
    manifest: &CapsuleManifest,
    approved: Option<InstalledAuthority>,
) -> anyhow::Result<InstalledAuthority> {
    let verification = artifact::verify_directory(source_dir)?;
    let content_digest = verification.content_digest().to_string();
    let manifest_digest = digest_manifest(&std::fs::read(source_dir.join("Capsule.toml"))?);
    let (signer, signature) = verification_provenance(&verification);

    if let Some(approved) = approved {
        if approved.content_digest != content_digest {
            bail!(
                "capsule content changed after authority decision (approved {}, found {})",
                approved.content_digest,
                content_digest
            );
        }
        if approved.signer != signer || approved.signature != signature {
            bail!("capsule provenance changed after authority decision");
        }
        if approved.capsule_id != manifest.package.name
            || approved.version != manifest.package.version
        {
            bail!("capsule identity or version changed after authority decision");
        }
        if approved.manifest_digest != manifest_digest {
            bail!("capsule manifest changed after authority decision");
        }
        if approved.approved_capabilities != manifest.capabilities {
            bail!("capsule capabilities changed after authority decision");
        }
        return Ok(approved);
    }

    // Calling the legacy library install API is itself an operator-authority
    // action. User-facing CLI and daemon entry points use explicit decisions;
    // this path preserves the existing trusted embedding API while recording
    // the same exact content and capability ceiling.
    Ok(InstalledAuthority {
        schema_version: 1,
        source: AuthoritySource::OperatorDistribution,
        capsule_id: manifest.package.name.clone(),
        version: manifest.package.version.clone(),
        content_digest,
        manifest_digest,
        signer,
        signature,
        approved_capabilities: manifest.capabilities.clone(),
    })
}

fn verification_provenance(
    verification: &ArtifactVerification,
) -> (Option<String>, Option<String>) {
    match verification {
        ArtifactVerification::Signed(verified) => (
            Some(verified.signer.to_string()),
            Some(verified.signature.to_string()),
        ),
        ArtifactVerification::Unsigned { .. } => (None, None),
    }
}

fn digest_manifest(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn ensure_bound_digest(
    inspection: &InstallInspection,
    approved_digest: &str,
) -> anyhow::Result<()> {
    if inspection.content_digest != approved_digest {
        bail!(
            "capsule '{}' changed after authority review (approved {}, found {})",
            inspection.capsule_id,
            approved_digest,
            inspection.content_digest
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection(provenance: ArtifactProvenance) -> InstallInspection {
        InstallInspection {
            capsule_id: CapsuleId::new("example").unwrap(),
            version: "1.0.0".into(),
            content_digest: "abc".into(),
            provenance,
            capability_expansions: Vec::new(),
            manifest_digest: "manifest".into(),
            requested_capabilities: CapabilitiesDef::default(),
        }
    }

    #[test]
    fn automatic_accepts_only_same_runtime_signature() {
        let local = inspection(ArtifactProvenance::LocalRuntime {
            signer: "key".into(),
            signature: "sig".into(),
        });
        assert_eq!(
            authorize_install(&local, &AuthorityDecision::Automatic)
                .unwrap()
                .source,
            AuthoritySource::LocalRuntimeBuild
        );
        assert!(
            authorize_install(
                &inspection(ArtifactProvenance::ForeignRuntime {
                    signer: "key".into(),
                    signature: "sig".into(),
                }),
                &AuthorityDecision::Automatic,
            )
            .is_err()
        );
        assert!(
            authorize_install(
                &inspection(ArtifactProvenance::Unsigned),
                &AuthorityDecision::Automatic,
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_approval_is_bound_to_digest() {
        let input = inspection(ArtifactProvenance::Unsigned);
        assert!(
            authorize_install(
                &input,
                &AuthorityDecision::ExplicitApproval {
                    content_digest: "wrong".into(),
                },
            )
            .is_err()
        );
        assert_eq!(
            authorize_install(
                &input,
                &AuthorityDecision::ExplicitApproval {
                    content_digest: "abc".into(),
                },
            )
            .unwrap()
            .source,
            AuthoritySource::ExplicitApproval
        );
    }

    #[test]
    fn pending_authority_transaction_fails_closed_and_cleans_up_on_error() {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("home"));
        let target = temp.path().join("installed/example");
        let authority = authorize_install(
            &inspection(ArtifactProvenance::Unsigned),
            &AuthorityDecision::ExplicitApproval {
                content_digest: "abc".into(),
            },
        )
        .unwrap();

        let transaction = AuthorityReceiptTransaction::stage(&home, &target, &authority).unwrap();
        assert!(read_installed_authority(&home, &target).is_err());
        drop(transaction);
        assert!(read_installed_authority(&home, &target).unwrap().is_none());
    }
}
