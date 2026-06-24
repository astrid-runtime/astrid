//! Install-time capability approval (#995).
//!
//! A capsule's manifest is UNTRUSTED INPUT: the `[capabilities]` block is
//! whatever the capsule author wrote. Before this gate, those declared
//! capabilities became effective at load with no operator approval and no
//! distinction between a distro/admin/furniture install and a capsule a
//! user dropped on disk manually. This module is the fail-secure floor:
//!
//! 1. [`capability_fingerprint`] hashes the SECURITY-RELEVANT declared set
//!    (the full [`CapabilitiesDef`] plus the effective IPC publish/subscribe
//!    patterns) into a stable [`CapabilityFingerprint`] (BLAKE3 hex). Any change
//!    to a declared capability or IPC pattern changes the fingerprint, so a
//!    re-install that escalates requires a fresh approval.
//!
//! 2. The approval store ([`approve`] / [`is_approved`] / [`remove`]) records,
//!    per principal, the fingerprint an operator approved for a capsule. The
//!    records live under the principal's `.config/approvals/` directory —
//!    operator-owned, never mounted into a guest, and NOT carried along when a
//!    capsule directory is copied as furniture into another principal's home.
//!    A capsule therefore cannot forge, escalate, or relocate its own approval.
//!
//! 3. [`effective_capabilities`] is the pure decision: an approved capsule
//!    keeps its declared capabilities; an unapproved one is reduced to
//!    [`CapabilitiesDef::default`] (the empty, fail-closed set) so it loads
//!    INERT — present and discoverable, but with zero host-fn access.
//!
//! The engine consults this immediately before constructing the
//! [`ManifestSecurityGate`](super::ManifestSecurityGate); the install paths
//! (CLI manual prompt, distro/admin/furniture auto-approve) write the records;
//! [`migrate_grandfather_approvals`] approves everything already installed on
//! the first daemon boot after upgrade so nothing bricks.

use std::fmt;
use std::path::Path;

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use serde::{Deserialize, Serialize};

use crate::manifest::{CapabilitiesDef, CapsuleManifest};

/// A stable fingerprint of a capsule's approved capability surface.
///
/// Wraps the BLAKE3 hex of the canonical security-relevant declared set (see
/// [`capability_fingerprint`]). A newtype rather than a bare `String` so that an
/// approval comparison is type-checked against an approval comparison and can
/// never be confused with another hex value (e.g. a WASM content hash). Serde is
/// `transparent`, so the persisted JSON carries the bare hex string — the
/// on-disk format is identical to storing a `String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityFingerprint(String);

impl CapabilityFingerprint {
    /// Wrap an already-computed fingerprint hex string.
    ///
    /// Most callers obtain a fingerprint from [`capability_fingerprint`]; this
    /// constructor exists for the load/approve paths that round-trip the hex
    /// through the CLI or an on-disk record.
    #[must_use]
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// The fingerprint as its hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for CapabilityFingerprint {
    fn from(hex: String) -> Self {
        Self(hex)
    }
}

impl From<&str> for CapabilityFingerprint {
    fn from(hex: &str) -> Self {
        Self(hex.to_string())
    }
}

impl From<&CapabilityFingerprint> for CapabilityFingerprint {
    fn from(fp: &CapabilityFingerprint) -> Self {
        fp.clone()
    }
}

/// The on-disk approval record for a single capsule under a single principal.
///
/// Stored at `<principal_home>/.config/approvals/<capsule_id>.json`. The only
/// field that carries trust is `fingerprint`: an approval matches at load only
/// when its stored fingerprint equals the freshly computed one, so a capsule
/// whose declared capabilities changed since approval is treated as unapproved
/// until re-approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalRecord {
    /// BLAKE3 hex of the approved capability set (see [`capability_fingerprint`]).
    fingerprint: CapabilityFingerprint,
}

/// Canonical serialization of the security-relevant declared set, hashed to a
/// stable [`CapabilityFingerprint`].
///
/// The input is the full [`CapabilitiesDef`] PLUS the effective IPC publish and
/// subscribe patterns. The IPC pattern vectors are HashMap-backed (their order
/// is unspecified), so they are sorted before serialization — the fingerprint
/// is invariant under reordering of the `[publish]` / `[subscribe]` tables but
/// changes whenever any pattern is added, removed, or edited. `CapabilitiesDef`
/// serializes to a JSON object whose keys serde emits in a fixed order, so the
/// capability half is already canonical.
///
/// A change to ANY declared capability or IPC pattern changes the fingerprint,
/// which is the whole point: an operator approved a SPECIFIC capability surface,
/// and an upgrade that widens it must be re-approved.
#[must_use]
pub fn capability_fingerprint(manifest: &CapsuleManifest) -> CapabilityFingerprint {
    let mut publish = manifest.effective_ipc_publish_patterns();
    publish.sort_unstable();
    let mut subscribe = manifest.effective_ipc_subscribe_patterns();
    subscribe.sort_unstable();

    // A struct serialized with serde_json has a stable field order, so the
    // canonical form is `{capabilities, ipc_publish, ipc_subscribe}` with the
    // two vectors pre-sorted. `to_value` cannot fail for these plain types.
    let canonical = serde_json::json!({
        "capabilities": manifest.capabilities,
        "ipc_publish": publish,
        "ipc_subscribe": subscribe,
    });
    // `to_vec` on an already-constructed `Value` is infallible; fall back to an
    // empty slice rather than panicking so a fingerprint is always produced
    // (an empty input still yields a stable, distinct hash).
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    CapabilityFingerprint(astrid_crypto::ContentHash::hash(&bytes).to_hex())
}

/// The capability set a capsule should load with, given whether its current
/// fingerprint is approved.
///
/// This is the pure heart of the load-time gate, extracted so the enforcement
/// is unit-testable without a daemon: an approved capsule keeps its declared
/// capabilities verbatim; an unapproved capsule is reduced to the empty,
/// fail-closed [`CapabilitiesDef::default`] and therefore loads INERT.
#[must_use]
pub fn effective_capabilities(declared: &CapabilitiesDef, approved: bool) -> CapabilitiesDef {
    if approved {
        declared.clone()
    } else {
        CapabilitiesDef::default()
    }
}

/// Path of the approval record for `capsule_id` under `principal`.
fn record_path(home: &AstridHome, principal: &PrincipalId, capsule_id: &str) -> std::path::PathBuf {
    home.principal_home(principal)
        .approvals_dir()
        .join(format!("{capsule_id}.json"))
}

/// Record an operator approval of `fingerprint` for `capsule_id` under
/// `principal`.
///
/// Idempotent: re-approving overwrites any existing record (which is how a
/// re-approval after a capability change lands). Writes atomically
/// (temp file + rename) so a crash mid-write never leaves a partial — and
/// therefore unparseable, hence unapproved (fail-secure) — record.
///
/// # Errors
///
/// Returns an error if the approvals directory cannot be created or the record
/// cannot be written / renamed into place.
pub fn approve(
    home: &AstridHome,
    principal: impl Into<PrincipalId>,
    capsule_id: impl AsRef<str>,
    fingerprint: impl Into<CapabilityFingerprint>,
) -> std::io::Result<()> {
    let principal = principal.into();
    let capsule_id = capsule_id.as_ref();
    let dir = home.principal_home(&principal).approvals_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{capsule_id}.json"));

    let record = ApprovalRecord {
        fingerprint: fingerprint.into(),
    };
    let json = serde_json::to_string_pretty(&record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    std::io::Write::write_all(&mut tmp, json.as_bytes())?;
    tmp.persist(&path)
        .map_err(|e| std::io::Error::other(format!("failed to persist {}: {e}", path.display())))?;
    Ok(())
}

/// Whether `capsule_id` is approved for `principal` at exactly `fingerprint`.
///
/// True iff a record exists AND its stored fingerprint matches the argument
/// exactly. A missing record, an unreadable record, an unparseable record, or a
/// fingerprint mismatch all return `false` — every failure mode is fail-secure
/// (treated as unapproved → the capsule loads inert).
#[must_use]
pub fn is_approved(
    home: &AstridHome,
    principal: impl Into<PrincipalId>,
    capsule_id: impl AsRef<str>,
    fingerprint: impl Into<CapabilityFingerprint>,
) -> bool {
    let principal = principal.into();
    let fingerprint = fingerprint.into();
    let path = record_path(home, &principal, capsule_id.as_ref());
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    let Ok(record) = serde_json::from_slice::<ApprovalRecord>(&bytes) else {
        tracing::warn!(
            path = %path.display(),
            "capsule approval record is corrupt; treating as unapproved"
        );
        return false;
    };
    record.fingerprint == fingerprint
}

/// Remove the approval record for `capsule_id` under `principal`, if any.
///
/// Used on uninstall so a removed capsule's approval does not silently carry
/// over to a later, different capsule reinstalled under the same id. Absence is
/// success.
///
/// # Errors
///
/// Returns an error only if a record exists but cannot be removed.
pub fn remove(
    home: &AstridHome,
    principal: impl Into<PrincipalId>,
    capsule_id: impl AsRef<str>,
) -> std::io::Result<()> {
    let principal = principal.into();
    let path = record_path(home, &principal, capsule_id.as_ref());
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// One-time grandfather migration: approve every already-installed capsule for
/// its principal at its CURRENT fingerprint.
///
/// Run once on daemon startup. Without it, upgrading to the version that ships
/// the load-time gate would strip capabilities from every existing setup (no
/// approval records exist yet → every capsule would load inert). After it runs,
/// "no approval record" genuinely means unapproved, so a capsule dropped on disk
/// AFTER migration still loads inert.
///
/// Idempotent via a marker file under `etc/` (outside the `home://` VFS, so a
/// capsule cannot delete it to force a re-grandfather). When the marker exists
/// this is a no-op. The migration enumerates the install principal plus every
/// `etc/profiles/*.toml` principal, scans each principal's `capsules_dir()`, and
/// approves each discovered capsule at the fingerprint of its on-disk manifest.
///
/// Best-effort and non-fatal: a single unreadable manifest or unwritable record
/// is logged and skipped; the marker is only written if the sweep completed, so
/// a hard directory failure simply retries next boot (re-approval is idempotent).
pub fn migrate_grandfather_approvals(home: &AstridHome) {
    let marker = home.etc_dir().join(".capability-approvals-migrated");
    if marker.exists() {
        return;
    }

    tracing::info!(
        target: "astrid.audit.capsule.approval",
        "grandfathering install-time capability approvals for all pre-existing capsules (#995)"
    );

    let principals = migration_principals(home);

    let mut approved_count: usize = 0;
    for principal in &principals {
        approved_count = approved_count.saturating_add(grandfather_principal(home, principal));
    }

    // Mark complete. If `etc/` is missing or the write fails the migration
    // simply re-runs next boot (re-approving is idempotent), which is the
    // fail-secure direction.
    if let Err(e) = std::fs::create_dir_all(home.etc_dir()) {
        tracing::warn!(
            path = %home.etc_dir().display(),
            error = %e,
            "grandfather: failed to create etc dir for migration marker; migration will re-run next boot"
        );
    } else if let Err(e) = std::fs::write(&marker, b"1") {
        tracing::warn!(
            path = %marker.display(),
            error = %e,
            "grandfather: failed to write migration marker; migration will re-run next boot"
        );
    }

    tracing::info!(
        target: "astrid.audit.capsule.approval",
        approved = approved_count,
        principals = principals.len(),
        "grandfathered install-time capability approvals (#995)"
    );
}

/// The principals the grandfather migration covers: the install principal first
/// (always present), then every `etc/profiles/*.toml` principal, de-duplicated.
fn migration_principals(home: &AstridHome) -> Vec<PrincipalId> {
    let mut principals: Vec<PrincipalId> = vec![PrincipalId::default()];
    let profiles_dir = home.profiles_dir();
    let Ok(entries) = std::fs::read_dir(&profiles_dir) else {
        return principals;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let file_name = entry.file_name();
        let Some(stem) = file_name.to_str().and_then(|n| n.strip_suffix(".toml")) else {
            continue;
        };
        let Ok(principal) = PrincipalId::new(stem) else {
            continue;
        };
        if !principals.contains(&principal) {
            principals.push(principal);
        }
    }
    principals
}

/// Approve every capsule already installed under `principal` at its current
/// fingerprint. Returns the number of capsules approved.
fn grandfather_principal(home: &AstridHome, principal: &PrincipalId) -> usize {
    let capsules_dir = home.principal_home(principal).capsules_dir();
    let Ok(entries) = std::fs::read_dir(&capsules_dir) else {
        return 0;
    };
    let mut count: usize = 0;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = entry.path();
        let capsule_id = entry.file_name().to_string_lossy().into_owned();
        let manifest_path = dir.join("Capsule.toml");
        let manifest = match crate::discovery::load_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    capsule = %capsule_id,
                    %principal,
                    error = %e,
                    "grandfather: skipping capsule with unreadable manifest"
                );
                continue;
            },
        };
        let fingerprint = capability_fingerprint(&manifest);
        if let Err(e) = approve(home, principal, &capsule_id, fingerprint) {
            tracing::warn!(
                capsule = %capsule_id,
                %principal,
                error = %e,
                "grandfather: failed to write approval; capsule will load inert until approved"
            );
            continue;
        }
        count = count.saturating_add(1);
    }
    count
}

/// Whether `path` resolves inside the approval store under `principal_home_root`.
///
/// Defense in depth: the approval records live under `home://.config/approvals/`,
/// which is technically within the `home://` VFS mount. A capsule that declared
/// a broad enough `home://` write scope AND was approved could otherwise reach
/// in and forge or escalate another capsule's approval. The security gate calls
/// this to HARD-DENY any guest read/write that lands in the approvals tree,
/// regardless of the manifest allowlist — the store is operator-only.
#[must_use]
pub fn path_is_in_approval_store(
    path: impl AsRef<Path>,
    principal_home_root: impl AsRef<Path>,
) -> bool {
    let approvals = principal_home_root
        .as_ref()
        .join(".config")
        .join("approvals");
    path.as_ref().starts_with(&approvals)
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
