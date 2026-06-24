//! Distro signing-key trust store and verification policy.
//!
//! Trust is per-distro and pinned on first use (TOFU), with a small set
//! of compiled-in official keys that pin without prompting. The store
//! lives at `~/.astrid/trust/<distro-id>.pub`, one file per distro,
//! containing a single `ed25519:<base64>` line.
//!
//! ## Threat model
//!
//! The signature binds the *resolved artifacts* (the lock's per-capsule
//! blake3 hashes + manifest hash) to a key. The trust store answers
//! "should I believe this key for this distro?":
//!
//! - A **pinned** key is authoritative: a signature under it proceeds; a
//!   signature under a different key is a hard fail (defends against a
//!   compromised-mirror swapping the maintainer key) unless the operator
//!   explicitly opts in with `--accept-new-key`.
//! - An **official** key (compiled in) pins without prompting.
//! - A **third-party** key with no prior pin is trusted on first use and
//!   pinned, with the key reported so the operator can verify out of band.
//!
//! ## Not a chain of trust (yet)
//!
//! `[distro.signing].endorses` (successor key) is parsed and carried on
//! the wire but key-rotation chain verification is deferred. Rotating a
//! key today requires `--accept-new-key`.

use std::path::PathBuf;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;
use astrid_crypto::PublicKey;

use super::lock::DistroLock;
use super::sign;

/// Official `unicity-astrid` signing keys, compiled in. A key here pins
/// without prompting on first use. Changing this set requires rebuilding
/// the binary — that is the point: official trust is not runtime-mutable.
///
/// DECISION: empty placeholder — the real official key(s) are not part
/// of issue #964's spec. With this empty, official distros currently
/// take the TOFU path like any third party until a key is added here.
const OFFICIAL_KEYS: &[&str] = &[
    // "ed25519:<base64>",
];

/// What the trust check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustAction {
    /// Signature valid against the already-pinned key.
    PinnedMatch,
    /// No prior pin; key is an official key → verified and pinned.
    OfficialPinned,
    /// No prior pin; third-party key → trusted on first use and pinned.
    ToFuTrusted,
    /// Signature valid but key differed from the pin; operator passed
    /// `--accept-new-key` → re-pinned.
    NewKeyAccepted,
}

/// Outcome of a successful trust check.
#[derive(Debug)]
pub(crate) struct TrustOutcome {
    /// The key the distro was verified under.
    pub(crate) pubkey: PublicKey,
    /// Its `ed25519:<base64>` wire form.
    pub(crate) key_str: String,
    /// What policy decision was taken.
    pub(crate) action: TrustAction,
}

/// Path to the trust file for `distro_id`.
fn trust_path(home: &AstridHome, distro_id: &str) -> PathBuf {
    home.root().join("trust").join(format!("{distro_id}.pub"))
}

/// Read the pinned key for `distro_id`, if any.
fn read_pinned(home: &AstridHome, distro_id: &str) -> anyhow::Result<Option<PublicKey>> {
    let path = trust_path(home, distro_id);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let line = s.trim();
            let pk = sign::parse_pubkey(line)
                .with_context(|| format!("corrupt trust file {}", path.display()))?;
            Ok(Some(pk))
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Pin `key_str` for `distro_id`, atomically.
fn pin(home: &AstridHome, distro_id: &str, key_str: &str) -> anyhow::Result<()> {
    let path = trust_path(home, distro_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(home.root()))
        .context("failed to create temp file for trust pin")?;
    std::io::Write::write_all(&mut tmp, format!("{key_str}\n").as_bytes())
        .context("failed to write trust pin staging")?;
    // Windows `rename` (which `persist` uses) won't overwrite an existing
    // destination, so re-pinning (`--accept-new-key`) would fail there.
    // Remove any existing pin first; a missing file is expected and fine.
    match std::fs::remove_file(&path) {
        Ok(()) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => {
            return Err(e).with_context(|| {
                format!("failed to replace existing trust pin {}", path.display())
            });
        },
    }
    tmp.persist(&path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", path.display()))?;
    Ok(())
}

/// Is `key_str` one of the compiled-in official keys?
fn is_official(key_str: &str) -> bool {
    OFFICIAL_KEYS.contains(&key_str)
}

/// Verify a sealed distro's signature and apply the trust policy.
///
/// `manifest_pubkey` is the `[distro.signing].pubkey` declared in the
/// manifest. `sig_hex` is the `Distro.sig` contents. `lock` is the
/// resolved lock the signature covers.
///
/// # Errors
///
/// - signature does not verify (no override),
/// - key differs from the pin and `accept_new_key` is false,
/// - malformed key/signature.
pub(crate) fn verify_and_pin(
    home: &AstridHome,
    distro_id: &str,
    manifest_pubkey: &str,
    sig_hex: &str,
    lock: &DistroLock,
    accept_new_key: bool,
) -> anyhow::Result<TrustOutcome> {
    let pubkey = sign::parse_pubkey(manifest_pubkey)?;
    let key_str = sign::pubkey_to_wire(&pubkey);

    // The signature MUST verify under the manifest's declared key first —
    // a bad signature is fatal regardless of trust state. (Cases 1–5.)
    sign::verify_lock(lock, sig_hex, &pubkey)
        .context("distro signature is invalid — refusing to install")?;

    let pinned = read_pinned(home, distro_id)?;
    let action = match pinned {
        Some(pin_key) if pin_key == pubkey => TrustAction::PinnedMatch,
        Some(pin_key) => {
            // Valid signature, but under a key that differs from the pin.
            if !accept_new_key {
                bail!(
                    "distro '{distro_id}' is pinned to {} but this artifact is signed by {} — \
                     refusing. Re-run with --accept-new-key only if you trust the new key.",
                    sign::pubkey_to_wire(&pin_key),
                    key_str,
                );
            }
            pin(home, distro_id, &key_str)?;
            TrustAction::NewKeyAccepted
        },
        None if is_official(&key_str) => {
            pin(home, distro_id, &key_str)?;
            TrustAction::OfficialPinned
        },
        None => {
            // TOFU: pin and report.
            pin(home, distro_id, &key_str)?;
            TrustAction::ToFuTrusted
        },
    };

    audit_trust(distro_id, &key_str, action);

    Ok(TrustOutcome {
        pubkey,
        key_str,
        action,
    })
}

/// Mirror a trust decision into the audit trail.
///
/// DECISION: the `astrid-audit` crate's `AuditLog` is built for the
/// daemon (it needs a runtime `KeyPair` + `SurrealKV` chain). Spinning
/// that up for a one-shot CLI trust decision is the wrong tool, so per the
/// issue's explicit fallback we emit a structured `tracing` event that
/// the existing log pipeline captures. If the CLI later gains a
/// first-class audit handle, route this through it.
fn audit_trust(distro_id: &str, key_str: &str, action: TrustAction) {
    tracing::info!(
        target: "astrid.audit.distro_trust",
        distro = %distro_id,
        key = %key_str,
        action = ?action,
        "distro signing-key trust decision",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::distro::lock::{DistroLock, DistroLockMeta, LockedCapsule};
    use astrid_crypto::KeyPair;

    fn home() -> (tempfile::TempDir, AstridHome) {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        (dir, home)
    }

    fn sample_lock() -> DistroLock {
        DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "1970-01-01T00:00:00+00:00".into(),
            },
            capsules: vec![LockedCapsule {
                name: "cli".into(),
                version: "0.1.0".into(),
                source: "@org/cli".into(),
                hash: "blake3:abc".into(),
                resolved_ref: Some("v0.1.0".into()),
            }],
            manifest_hash: Some("blake3:def".into()),
        }
    }

    #[test]
    fn tofu_pins_on_first_use() {
        let (_d, home) = home();
        let kp = KeyPair::generate();
        let pubkey = sign::pubkey_to_wire(&kp.export_public_key());
        let lock = sample_lock();
        let sig = sign::sign_lock(&lock, &kp).unwrap();

        let out = verify_and_pin(&home, "test", &pubkey, &sig, &lock, false).unwrap();
        assert_eq!(out.action, TrustAction::ToFuTrusted);
        // Pinned now.
        assert_eq!(
            read_pinned(&home, "test").unwrap().unwrap(),
            kp.export_public_key()
        );
    }

    #[test]
    fn pinned_match_proceeds() {
        let (_d, home) = home();
        let kp = KeyPair::generate();
        let pubkey = sign::pubkey_to_wire(&kp.export_public_key());
        let lock = sample_lock();
        let sig = sign::sign_lock(&lock, &kp).unwrap();

        verify_and_pin(&home, "test", &pubkey, &sig, &lock, false).unwrap();
        let out = verify_and_pin(&home, "test", &pubkey, &sig, &lock, false).unwrap();
        assert_eq!(out.action, TrustAction::PinnedMatch);
    }

    #[test]
    fn wrong_pinned_key_hard_fails_without_override() {
        let (_d, home) = home();
        let kp = KeyPair::generate();
        let lock = sample_lock();

        // Pin kp first.
        let sig = sign::sign_lock(&lock, &kp).unwrap();
        verify_and_pin(
            &home,
            "test",
            &sign::pubkey_to_wire(&kp.export_public_key()),
            &sig,
            &lock,
            false,
        )
        .unwrap();

        // A different key, validly signing, must be refused.
        let kp2 = KeyPair::generate();
        let sig2 = sign::sign_lock(&lock, &kp2).unwrap();
        let err = verify_and_pin(
            &home,
            "test",
            &sign::pubkey_to_wire(&kp2.export_public_key()),
            &sig2,
            &lock,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("pinned"), "got: {err}");
    }

    #[test]
    fn new_key_accepted_with_override() {
        let (_d, home) = home();
        let kp = KeyPair::generate();
        let lock = sample_lock();
        let sig = sign::sign_lock(&lock, &kp).unwrap();
        verify_and_pin(
            &home,
            "test",
            &sign::pubkey_to_wire(&kp.export_public_key()),
            &sig,
            &lock,
            false,
        )
        .unwrap();

        let kp2 = KeyPair::generate();
        let sig2 = sign::sign_lock(&lock, &kp2).unwrap();
        let out = verify_and_pin(
            &home,
            "test",
            &sign::pubkey_to_wire(&kp2.export_public_key()),
            &sig2,
            &lock,
            true,
        )
        .unwrap();
        assert_eq!(out.action, TrustAction::NewKeyAccepted);
        assert_eq!(
            read_pinned(&home, "test").unwrap().unwrap(),
            kp2.export_public_key()
        );
    }

    #[test]
    fn invalid_signature_fails_regardless() {
        let (_d, home) = home();
        let kp = KeyPair::generate();
        let lock = sample_lock();
        // Sign a DIFFERENT lock, then present a tampered lock.
        let sig = sign::sign_lock(&lock, &kp).unwrap();
        let mut tampered = sample_lock();
        tampered.capsules[0].hash = "blake3:TAMPERED".into();

        let err = verify_and_pin(
            &home,
            "test",
            &sign::pubkey_to_wire(&kp.export_public_key()),
            &sig,
            &tampered,
            true, // even with override
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid"), "got: {err}");
    }

    /// Regression for #995: there is no compiled-in **blessed trust root**.
    ///
    /// "Distro-blessed" capability acceptance needs a verifiable anchor or it
    /// becomes an approval-bypass primitive. Today [`OFFICIAL_KEYS`] is empty by
    /// deliberate decision (not part of #964's spec), so no install source is
    /// treated as blessed: `is_official` returns false for every key and even
    /// official distros take the TOFU path like any third party.
    ///
    /// When a real official key is populated, `is_official` must return true for
    /// it — update this test to assert that instead of emptiness, and wire the
    /// blessed-set check into install-time capability acceptance.
    #[test]
    fn regression_995_no_compiled_in_blessed_trust_root() {
        assert!(
            OFFICIAL_KEYS.is_empty(),
            "#995: a blessed trust root is now populated — wire the blessed-set \
             check into install-time capability acceptance and update this test",
        );
        // A well-formed key is NOT recognised as official: nothing is blessed.
        let kp = KeyPair::generate();
        let key = sign::pubkey_to_wire(&kp.export_public_key());
        assert!(
            !is_official(&key),
            "no key can be official while OFFICIAL_KEYS is empty",
        );
    }
}
