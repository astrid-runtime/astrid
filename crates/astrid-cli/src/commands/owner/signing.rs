//! Local external signing. No private key or path is part of a native request.

use super::Genesis;
use anyhow::{Context, Result};
use astrid_core::identity::hosted_owner::{HostedOwnerChallenge, HostedOwnerEnvelope};
use astrid_core::{FleetGenesis, FleetIdentity, UserGenesis, UserIdentity};
use ed25519_dalek::{Signer, SigningKey};

pub(super) fn prepare(public: &str) -> Result<Genesis> {
    let public: [u8; 32] = hex::decode(public)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte public key"))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)?;
    anyhow::ensure!(!verifying.is_weak(), "weak owner key");
    let now = chrono::Utc::now();
    let user = UserIdentity::from_genesis(UserGenesis::new(public, now))?;
    let fleet = FleetIdentity::from_genesis(FleetGenesis::new(user.uid, now))?;
    Ok(Genesis { user, fleet })
}

fn key(path: &std::path::Path) -> Result<SigningKey> {
    use std::io::Read;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .context("open external signing key")?
        .take(33)
        .read_to_end(&mut bytes)?;
    let key: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected raw 32-byte Ed25519 private key"))?;
    Ok(SigningKey::from_bytes(key))
}

pub(super) fn owner(
    mut challenge: HostedOwnerChallenge,
    path: &std::path::Path,
) -> Result<HostedOwnerEnvelope> {
    challenge.validate()?;
    let signer = key(path)?;
    anyhow::ensure!(
        signer.verifying_key().to_bytes() == *challenge.claim.initial_user_public_key(),
        "owner key does not match public genesis"
    );
    challenge.claim = challenge
        .claim
        .with_signature(signer.sign(&challenge.claim.canonical_message()).to_bytes());
    Ok(HostedOwnerEnvelope {
        challenge,
        deployment_signature: [0; 64],
    })
}

pub(super) fn authorize(
    mut envelope: HostedOwnerEnvelope,
    path: &std::path::Path,
) -> Result<HostedOwnerEnvelope> {
    envelope.challenge.validate()?;
    envelope.challenge.claim.verify_signature()?;
    let signer = key(path)?;
    anyhow::ensure!(
        signer.verifying_key().to_bytes() == envelope.challenge.policy.deployment_key,
        "deployment key does not match installed policy"
    );
    envelope.deployment_signature = signer.sign(&envelope.deployment_message()).to_bytes();
    envelope.verify()?;
    Ok(envelope)
}
