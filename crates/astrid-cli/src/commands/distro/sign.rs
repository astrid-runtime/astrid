//! Distro signing primitives — canonical lock hashing and the
//! `Distro.sig` wire format.
//!
//! ## What gets signed
//!
//! The signature covers `blake3(canonical_json(lock))`, where the lock
//! is the resolved [`DistroLock`] (per-capsule blake3 hashes +
//! `manifest_hash`). Signing the lock — not the manifest text — binds
//! the signature to the *exact resolved artifacts*: a tampered capsule
//! changes its blake3, which changes the lock, which breaks the sig.
//!
//! ## Canonical JSON (DECISION)
//!
//! `canonical_json` is `serde_json::to_vec(lock)`. `serde_json`
//! serializes struct fields in declaration order and that order is
//! stable across builds, so the same lock value always serializes to
//! the same bytes. We do not sort map keys because the lock contains no
//! free-form maps in the signed path (capsules is a Vec, distro is a
//! fixed struct). This is intentionally simple and auditable; if a
//! free-form map is ever added to the lock, this function must switch
//! to a key-sorting canonicalizer.
//!
//! ## `Distro.sig` format (DECISION)
//!
//! Hex-encoded 64-byte ed25519 signature, single line, no prefix. Hex
//! over base64 for auditability (every byte is visible, copy-pastes
//! cleanly, no padding ambiguity).
//!
//! ## Domain separation (DECISION)
//!
//! [`astrid_crypto::KeyPair`] is the same ed25519 primitive used for
//! capability tokens, so a key reused across protocols could otherwise
//! enable cross-protocol signature confusion (a signature produced for
//! one protocol replayed as a valid signature in another). To prevent
//! this, the signed digest is domain-separated: we feed blake3 a fixed
//! protocol context tag — [`SIG_DOMAIN_TAG`] — followed by the canonical
//! lock bytes, and sign the resulting 32-byte hash. A signature over the
//! un-tagged digest therefore does not verify here, and vice versa. The
//! tag is prepended (rather than using `blake3::derive_key`'s keyed mode)
//! because the input is auditable as `tag || canonical_json(lock)`.

use anyhow::Context;
use astrid_crypto::{KeyPair, PublicKey, Signature};

use super::lock::DistroLock;

/// Fixed protocol-context tag prepended to the canonical lock bytes
/// before hashing, domain-separating distro-lock signatures from every
/// other use of [`astrid_crypto::KeyPair`] (e.g. capability tokens). The
/// trailing NUL is an unambiguous length-delimiter between the tag and
/// the lock payload. Bumping the `-vN` suffix is a wire-breaking change.
const SIG_DOMAIN_TAG: &[u8] = b"astrid-distro-lock-sig-v1\x00";

/// Serialize the lock to its canonical signing bytes.
pub(crate) fn canonical_lock_bytes(lock: &DistroLock) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(lock).context("failed to canonicalize Distro.lock for signing")
}

/// The 32-byte domain-separated blake3 digest the signature is computed
/// over: `blake3(SIG_DOMAIN_TAG || canonical_json(lock))`.
pub(crate) fn lock_signing_digest(lock: &DistroLock) -> anyhow::Result<[u8; 32]> {
    let bytes = canonical_lock_bytes(lock)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SIG_DOMAIN_TAG);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// Sign a lock with `keypair`, returning the hex `Distro.sig` contents.
pub(crate) fn sign_lock(lock: &DistroLock, keypair: &KeyPair) -> anyhow::Result<String> {
    let digest = lock_signing_digest(lock)?;
    let sig = keypair.sign(&digest);
    Ok(sig.to_hex())
}

/// Parse the `ed25519:<base64>` wire form into a [`PublicKey`].
pub(crate) fn parse_pubkey(wire: &str) -> anyhow::Result<PublicKey> {
    let b64 = wire
        .strip_prefix("ed25519:")
        .ok_or_else(|| anyhow::anyhow!("public key must be in 'ed25519:<base64>' form, got {wire:?}"))?;
    PublicKey::from_base64(b64)
        .map_err(|e| anyhow::anyhow!("invalid ed25519 public key: {e}"))
}

/// Render a [`PublicKey`] as `ed25519:<base64>`.
pub(crate) fn pubkey_to_wire(pk: &PublicKey) -> String {
    format!("ed25519:{}", pk.to_base64())
}

/// Verify a hex `Distro.sig` against a lock and a public key.
///
/// # Errors
///
/// Returns an error if the signature is malformed (not 64 hex bytes) or
/// does not verify against the lock's signing digest under `pubkey`.
pub(crate) fn verify_lock(
    lock: &DistroLock,
    sig_hex: &str,
    pubkey: &PublicKey,
) -> anyhow::Result<()> {
    let sig = Signature::from_hex(sig_hex.trim())
        .map_err(|e| anyhow::anyhow!("malformed Distro.sig (expected 64-byte hex): {e}"))?;
    let digest = lock_signing_digest(lock)?;
    pubkey
        .verify(&digest, &sig)
        .map_err(|_| anyhow::anyhow!("distro signature verification failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::distro::lock::{DistroLock, DistroLockMeta, LockedCapsule};

    fn sample_lock() -> DistroLock {
        DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "2026-01-01T00:00:00Z".into(),
            },
            capsules: vec![LockedCapsule {
                name: "astrid-capsule-cli".into(),
                version: "0.1.0".into(),
                source: "@org/cli".into(),
                hash: "blake3:abc".into(),
                resolved_ref: Some("v0.1.0".into()),
            }],
            manifest_hash: Some("blake3:def".into()),
        }
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let lock = sample_lock();
        assert_eq!(
            canonical_lock_bytes(&lock).unwrap(),
            canonical_lock_bytes(&sample_lock()).unwrap()
        );
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let kp = KeyPair::generate();
        let lock = sample_lock();
        let sig = sign_lock(&lock, &kp).unwrap();
        let pk = kp.export_public_key();
        assert!(verify_lock(&lock, &sig, &pk).is_ok());
    }

    #[test]
    fn verify_fails_on_tampered_lock() {
        let kp = KeyPair::generate();
        let lock = sample_lock();
        let sig = sign_lock(&lock, &kp).unwrap();
        let pk = kp.export_public_key();

        let mut tampered = sample_lock();
        tampered.capsules[0].hash = "blake3:TAMPERED".into();
        assert!(verify_lock(&tampered, &sig, &pk).is_err());
    }

    #[test]
    fn signature_over_untagged_digest_does_not_verify() {
        // A signature computed over the un-domain-separated digest
        // (`blake3(canonical_json(lock))`, no protocol tag) must NOT
        // verify under the domain-separated scheme. This is the
        // cross-protocol-confusion guard.
        let kp = KeyPair::generate();
        let lock = sample_lock();

        let untagged = *blake3::hash(&canonical_lock_bytes(&lock).unwrap()).as_bytes();
        let untagged_sig = kp.sign(&untagged).to_hex();

        let pk = kp.export_public_key();
        assert!(
            verify_lock(&lock, &untagged_sig, &pk).is_err(),
            "untagged signature must be rejected by the domain-separated verifier"
        );

        // Sanity: the properly-tagged signature still verifies.
        let tagged_sig = sign_lock(&lock, &kp).unwrap();
        assert!(verify_lock(&lock, &tagged_sig, &pk).is_ok());
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let kp = KeyPair::generate();
        let other = KeyPair::generate();
        let lock = sample_lock();
        let sig = sign_lock(&lock, &kp).unwrap();
        assert!(verify_lock(&lock, &sig, &other.export_public_key()).is_err());
    }

    #[test]
    fn pubkey_wire_roundtrips() {
        let kp = KeyPair::generate();
        let pk = kp.export_public_key();
        let wire = pubkey_to_wire(&pk);
        assert!(wire.starts_with("ed25519:"));
        let parsed = parse_pubkey(&wire).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn parse_pubkey_rejects_missing_prefix() {
        assert!(parse_pubkey("AAAA").is_err());
    }
}
