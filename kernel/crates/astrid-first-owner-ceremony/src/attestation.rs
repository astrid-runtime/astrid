//! Ed25519 attestations for the frozen two-signature contract.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::CeremonyError;
use crate::transcript::Transcript;
use crate::types::{DataKeyId, KEY_LEN, RecoveryMemberId, SIGNATURE_LEN, digest};

/// Signatures made by the candidate device and MachineEnrollmentAnchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwoPartyAttestation {
    device_signature: [u8; SIGNATURE_LEN],
    anchor_signature: [u8; SIGNATURE_LEN],
}

impl TwoPartyAttestation {
    pub const fn new(
        device_signature: [u8; SIGNATURE_LEN],
        anchor_signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            device_signature,
            anchor_signature,
        }
    }

    pub(crate) fn verify(self, transcript: &Transcript) -> Result<(), CeremonyError> {
        let canonical = transcript.canonical_bytes();
        let device = VerifyingKey::from_bytes(&transcript.owner_device_key().as_bytes())
            .map_err(|_| CeremonyError::AttestationInvalid)?;
        let anchor = VerifyingKey::from_bytes(&transcript.anchor_key().as_bytes())
            .map_err(|_| CeremonyError::AttestationInvalid)?;
        device
            .verify_strict(&canonical, &Signature::from_bytes(&self.device_signature))
            .map_err(|_| CeremonyError::AttestationInvalid)?;
        anchor
            .verify_strict(&canonical, &Signature::from_bytes(&self.anchor_signature))
            .map_err(|_| CeremonyError::AttestationInvalid)?;
        Ok(())
    }
}

/// The explicit authenticated-local-presence action being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceAction {
    Rotate,
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceProof {
    signature: [u8; SIGNATURE_LEN],
}

impl PresenceProof {
    pub const fn new(signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { signature }
    }

    pub(crate) fn verify(
        self,
        expected_key: [u8; KEY_LEN],
        action: PresenceAction,
        transcript: &Transcript,
    ) -> Result<(), CeremonyError> {
        let key =
            VerifyingKey::from_bytes(&expected_key).map_err(|_| CeremonyError::PresenceInvalid)?;
        let message = presence_message(action, transcript);
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| CeremonyError::PresenceInvalid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerRotationProof {
    signature: [u8; SIGNATURE_LEN],
}

impl OwnerRotationProof {
    pub const fn new(signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { signature }
    }

    pub(crate) fn verify(
        self,
        owner_key: [u8; KEY_LEN],
        current: &Transcript,
        next: &Transcript,
    ) -> Result<(), CeremonyError> {
        let key = VerifyingKey::from_bytes(&owner_key)
            .map_err(|_| CeremonyError::OwnerAuthorizationInvalid)?;
        let message = rotation_message(current, next);
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| CeremonyError::OwnerAuthorizationInvalid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryApproval {
    member: RecoveryMemberId,
    signature: [u8; SIGNATURE_LEN],
}

impl RecoveryApproval {
    pub fn try_new(
        member: RecoveryMemberId,
        signature: [u8; SIGNATURE_LEN],
    ) -> Result<Self, CeremonyError> {
        VerifyingKey::from_bytes(&member.as_bytes())
            .map_err(|_| CeremonyError::RecoveryApprovalsInvalid)?;
        Ok(Self { member, signature })
    }

    pub(crate) fn verify(
        &self,
        current: &Transcript,
        next: &Transcript,
    ) -> Result<(), CeremonyError> {
        let key = VerifyingKey::from_bytes(&self.member.as_bytes())
            .map_err(|_| CeremonyError::RecoveryApprovalsInvalid)?;
        let message = recovery_message(current, next);
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| CeremonyError::RecoveryApprovalsInvalid)
    }

    pub(crate) const fn member(self) -> RecoveryMemberId {
        self.member
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestructiveResetProof {
    next_data_key_id: DataKeyId,
    signature: [u8; SIGNATURE_LEN],
}

impl DestructiveResetProof {
    pub const fn new(next_data_key_id: DataKeyId, signature: [u8; SIGNATURE_LEN]) -> Self {
        Self {
            next_data_key_id,
            signature,
        }
    }

    pub const fn next_data_key_id(self) -> DataKeyId {
        self.next_data_key_id
    }

    pub(crate) fn verify(
        self,
        presence_key: [u8; KEY_LEN],
        current: &Transcript,
    ) -> Result<(), CeremonyError> {
        let key = VerifyingKey::from_bytes(&presence_key)
            .map_err(|_| CeremonyError::ResetProofInvalid)?;
        let message = reset_message(current, &self.next_data_key_id);
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| CeremonyError::ResetProofInvalid)
    }
}

pub fn presence_message(action: PresenceAction, transcript: &Transcript) -> [u8; KEY_LEN] {
    let action = match action {
        PresenceAction::Rotate => "rotate",
        PresenceAction::Recover => "recover",
    };
    digest(
        b"astrid.first-owner.presence.v1",
        &[action.as_bytes(), &transcript.canonical_bytes()],
    )
}

pub fn rotation_message(current: &Transcript, next: &Transcript) -> [u8; KEY_LEN] {
    digest(
        b"astrid.first-owner.rotation.v1",
        &[&current.canonical_bytes(), &next.canonical_bytes()],
    )
}

pub fn recovery_message(current: &Transcript, next: &Transcript) -> [u8; KEY_LEN] {
    digest(
        b"astrid.first-owner.lost-owner-recovery.v1",
        &[&current.canonical_bytes(), &next.canonical_bytes()],
    )
}

pub fn reset_message(current: &Transcript, next_data_key_id: &DataKeyId) -> [u8; KEY_LEN] {
    digest(
        b"astrid.first-owner.destructive-reset.v1",
        &[&current.canonical_bytes(), &next_data_key_id.as_bytes()],
    )
}
