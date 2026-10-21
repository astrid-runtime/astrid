//! Hosted provisioning trusts the explicitly configured controlling host account.
//!
//! These facts never assert measured boot. AFOv1 context slots carry the
//! installation/session and selected native artifact commitments defined here.

use super::{FirstOwnerClaim, FleetIdentity, PrincipalUid, UserIdentity};
use core::num::NonZeroU64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Exact execution identity and registered device selected by the host administrator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerTarget {
    /// Admitted stable execution identity; aliases are display metadata only.
    pub principal: PrincipalUid,
    /// Exact Ed25519 native transport public key.
    pub public_key: [u8; 32],
}

/// Public offline administration input; an omitted target requires the explicit
/// native --target-default operation. This is never accepted by the socket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerConfiguration {
    /// Independent deployment authority's public key.
    pub deployment_key: [u8; 32],
    /// Strictly increasing host policy generation.
    pub generation: NonZeroU64,
    /// Finite Unix expiry.
    pub expires_at: NonZeroU64,
    /// Explicit fleet target, or omitted only with native --target-default.
    #[serde(default)]
    pub target: Option<HostedOwnerTarget>,
}

impl HostedOwnerConfiguration {
    /// Check public key, finite policy and exclusive explicit target selection
    /// before native admission can create execution records.
    ///
    /// # Errors
    /// Rejects ambiguous/missing target selection, weak keys or expired policy.
    pub fn validate_selection(
        &self,
        target_default: bool,
        now: u64,
    ) -> Result<(), HostedOwnerError> {
        if target_default == self.target.is_some() {
            return Err(HostedOwnerError::Invalid);
        }
        let key = VerifyingKey::from_bytes(&self.deployment_key)
            .map_err(|_| HostedOwnerError::Invalid)?;
        if key.is_weak() {
            return Err(HostedOwnerError::Invalid);
        }
        if let Some(target) = &self.target {
            let key = VerifyingKey::from_bytes(&target.public_key)
                .map_err(|_| HostedOwnerError::Invalid)?;
            if key.is_weak() {
                return Err(HostedOwnerError::Invalid);
            }
        }
        if now >= self.expires_at.get() {
            return Err(HostedOwnerError::Expired);
        }
        Ok(())
    }

    /// Materialize an exact policy after the native composition resolves its target.
    #[must_use]
    pub fn with_target(self, target: HostedOwnerTarget) -> HostedOwnerPolicy {
        HostedOwnerPolicy {
            deployment_key: self.deployment_key,
            generation: self.generation,
            expires_at: self.expires_at,
            target,
        }
    }
}

/// Explicit native-administrator deployment authorization policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerPolicy {
    /// Independently selected exact registered target; first socket login cannot choose it.
    pub target: HostedOwnerTarget,
    /// Public key of the external deployment signer, never the prospective owner.
    pub deployment_key: [u8; 32],
    /// Monotonic policy incarnation within this installation.
    pub generation: NonZeroU64,
    /// Last admissible Unix second; authorization is refused at this instant.
    pub expires_at: NonZeroU64,
}

/// Exact registered device incarnation captured under the native device gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerDevice {
    /// Stable execution identity, independently resolved from the handshake.
    pub principal: PrincipalUid,
    /// Exact registered Ed25519 transport credential.
    pub public_key: [u8; 32],
    /// Durable retirement fence, independent of the credential fingerprint.
    pub incarnation: Uuid,
}

/// Public signing packet emitted by a native, policy-configured installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerChallenge {
    /// Envelope grammar. Only version 1 has the context meanings below.
    pub version: u16,
    /// Native administrator's policy, rechecked from durable state at commit.
    pub policy: HostedOwnerPolicy,
    /// Durable installation identifier; host snapshot rollback is out of scope.
    pub installation: Uuid,
    /// Durable provisioning session, advanced by policy replacement/cancellation.
    pub session: Uuid,
    /// Digest of the selected native daemon executable, not verified boot.
    pub artifact: [u8; 32],
    /// Exact authenticated, currently registered target credential.
    pub device: HostedOwnerDevice,
    /// Immutable prospective owner identity. Display metadata is not authority.
    pub user: UserIdentity,
    /// Immutable fleet genesis, independently validated against the owner UID.
    pub fleet: FleetIdentity,
    /// Frozen `AFOv1` claim. Initially unsigned, then externally owner-signed.
    pub claim: FirstOwnerClaim,
}

/// Two-role authorization. No private signing material crosses the native socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerEnvelope {
    /// Complete public packet, including the owner's detached `AFOv1` signature.
    pub challenge: HostedOwnerChallenge,
    /// External deployment authorization over the versioned canonical statement.
    #[serde(
        serialize_with = "super::first_owner::serialize_signature",
        deserialize_with = "super::first_owner::deserialize_signature"
    )]
    pub deployment_signature: [u8; 64],
}

/// Closed validation failure vocabulary for hosted provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostedOwnerError {
    /// Unsupported version, malformed identity, key or commitment.
    #[error("invalid hosted-owner provisioning statement")]
    Invalid,
    /// Independent owner or deployment signature did not verify.
    #[error("hosted-owner signature verification failed")]
    Signature,
    /// Durable policy, device incarnation, session or enrollment changed.
    #[error("hosted-owner provisioning authority is stale")]
    Stale,
    /// Current authorization expired while waiting for admission.
    #[error("hosted-owner authorization expired")]
    Expired,
}

impl HostedOwnerPolicy {
    /// Validate the external deployment key independently of any owner claim.
    ///
    /// # Errors
    /// Refuses invalid or weak Ed25519 keys.
    pub fn validate(&self) -> Result<(), HostedOwnerError> {
        let key = VerifyingKey::from_bytes(&self.deployment_key)
            .map_err(|_| HostedOwnerError::Invalid)?;
        if key.is_weak() {
            return Err(HostedOwnerError::Invalid);
        }
        let target = VerifyingKey::from_bytes(&self.target.public_key)
            .map_err(|_| HostedOwnerError::Invalid)?;
        if target.is_weak() {
            return Err(HostedOwnerError::Invalid);
        }
        Ok(())
    }
}

impl HostedOwnerChallenge {
    /// Commitment filling the `AFOv1` machine-context slot in hosted grammar 1.
    #[must_use]
    pub fn installation_commitment(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("astrid hosted installation v1");
        hash.update(self.installation.as_bytes());
        hash.update(&self.policy.deployment_key);
        *hash.finalize().as_bytes()
    }

    /// Commitment filling the `AFOv1` boot-context slot; this is not measured boot.
    #[must_use]
    pub fn session_commitment(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("astrid hosted session v1");
        hash.update(self.session.as_bytes());
        hash.update(&self.policy.generation.get().to_le_bytes());
        hash.update(&self.policy.expires_at.get().to_le_bytes());
        hash.update(self.device.principal.as_bytes());
        hash.update(&self.device.public_key);
        hash.update(self.device.incarnation.as_bytes());
        *hash.finalize().as_bytes()
    }

    /// Validate every identity and hosted context mapping without accepting a signature.
    ///
    /// # Errors
    /// Rejects context substitution, noncanonical identity or unsupported grammar.
    pub fn validate(&self) -> Result<(), HostedOwnerError> {
        self.policy.validate()?;
        self.user
            .validate()
            .map_err(|_| HostedOwnerError::Invalid)?;
        self.fleet
            .validate()
            .map_err(|_| HostedOwnerError::Invalid)?;
        if self.version != 1
            || self.installation.is_nil()
            || self.session.is_nil()
            || self.device.incarnation.is_nil()
            || self.device.principal != self.policy.target.principal
            || self.device.public_key != self.policy.target.public_key
            || self.artifact == [0; 32]
            || self.claim.machine_context() != &self.installation_commitment()
            || self.claim.boot_context() != &self.session_commitment()
            || self.claim.kernel_identity() != &self.artifact
            || self.claim.system_generation() != &self.genesis_commitment()?
            || self.claim.user_uid() != self.user.uid
            || self.claim.fleet_uid() != self.fleet.uid
            || self.claim.principal_uid() != self.device.principal
            || self.claim.initial_user_public_key() != &self.user.genesis.initial_public_key
            || self.fleet.genesis.created_by != self.user.uid
            || self.policy.deployment_key == *self.claim.initial_user_public_key()
            || self.claim.expires_at() > self.policy.expires_at.get()
        {
            return Err(HostedOwnerError::Invalid);
        }
        Ok(())
    }

    /// Commitment to both canonical genesis records in the system-generation slot.
    ///
    /// # Errors
    /// Rejects malformed genesis encodings.
    pub fn genesis_commitment(&self) -> Result<[u8; 32], HostedOwnerError> {
        let mut hash = blake3::Hasher::new_derive_key("astrid hosted owner genesis v1");
        hash.update(
            &self
                .user
                .genesis
                .canonical_bytes()
                .map_err(|_| HostedOwnerError::Invalid)?,
        );
        hash.update(
            &self
                .fleet
                .genesis
                .canonical_bytes()
                .map_err(|_| HostedOwnerError::Invalid)?,
        );
        Ok(*hash.finalize().as_bytes())
    }
}

impl HostedOwnerEnvelope {
    /// Canonical deployment signing bytes: domain, version, policy key and `AFOv1`
    /// bytes followed by the owner's signature. `AFOv1` already commits installation,
    /// policy generation/expiry, session, selected artifact, device and genesis.
    #[must_use]
    pub fn deployment_message(&self) -> Vec<u8> {
        let mut bytes = b"ASTRID-HOSTED-OWNER-AUTHORIZATION".to_vec();
        bytes.extend_from_slice(&self.challenge.version.to_le_bytes());
        bytes.extend_from_slice(&self.challenge.policy.deployment_key);
        bytes.extend_from_slice(&self.challenge.claim.canonical_message());
        bytes.extend_from_slice(self.challenge.claim.signature());
        bytes
    }

    /// Check both independent signatures and every signed commitment.
    ///
    /// # Errors
    /// Rejects same-role keys, altered contexts, genesis or either invalid signature.
    pub fn verify(&self) -> Result<(), HostedOwnerError> {
        self.challenge.validate()?;
        self.challenge
            .claim
            .verify_signature()
            .map_err(|_| HostedOwnerError::Signature)?;
        let key = VerifyingKey::from_bytes(&self.challenge.policy.deployment_key)
            .map_err(|_| HostedOwnerError::Invalid)?;
        key.verify_strict(
            &self.deployment_message(),
            &Signature::from_bytes(&self.deployment_signature),
        )
        .map_err(|_| HostedOwnerError::Signature)
    }
}
