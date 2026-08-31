//! Exact fixed-layout transcript and its BLAKE3 identity.

use crate::error::CeremonyError;
use crate::types::{
    AnchorKey, CeremonyNonce, DataKeyId, DeviceKey, KEY_LEN, MachineGeneration, PresenceKey,
    RecoveryPolicy, digest,
};

pub const MAGIC: &[u8; 8] = b"ASTRIDFO";
pub const TRANSCRIPT_VERSION: u8 = 1;
pub const RECOVERY_PRESENT_FLAG: u8 = 1;
pub const TRANSCRIPT_LEN: usize = 8 + 1 + 1 + 8 + KEY_LEN + (KEY_LEN * 5) + 8 + 2 + (KEY_LEN * 8);

const DEVICE_OFFSET: usize = 18 + KEY_LEN;
const ANCHOR_OFFSET: usize = DEVICE_OFFSET + KEY_LEN;
const PRESENCE_OFFSET: usize = ANCHOR_OFFSET + KEY_LEN;
const DATA_KEY_OFFSET: usize = PRESENCE_OFFSET + KEY_LEN;
const NONCE_OFFSET: usize = DATA_KEY_OFFSET + KEY_LEN;
pub const THRESHOLD_OFFSET: usize = NONCE_OFFSET + KEY_LEN;
pub const MEMBER_COUNT_OFFSET: usize = THRESHOLD_OFFSET + 1;
pub const MEMBERS_OFFSET: usize = MEMBER_COUNT_OFFSET + 1;

/// All fields bound by the candidate-device and anchor signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptInput {
    pub generation: MachineGeneration,
    pub owner_device_key: DeviceKey,
    pub anchor_key: AnchorKey,
    pub presence_key: PresenceKey,
    pub data_key_id: DataKeyId,
    pub ceremony_nonce: CeremonyNonce,
    pub recovery_policy: Option<RecoveryPolicy>,
}

/// A validated, canonically encoded ceremony statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transcript {
    generation: MachineGeneration,
    owner_device_key: DeviceKey,
    anchor_key: AnchorKey,
    presence_key: PresenceKey,
    data_key_id: DataKeyId,
    ceremony_nonce: CeremonyNonce,
    recovery_commitment: [u8; KEY_LEN],
    has_recovery_policy: bool,
}

impl Transcript {
    pub fn try_new(input: TranscriptInput) -> Result<Self, CeremonyError> {
        validate_key(
            input.owner_device_key.as_bytes(),
            CeremonyError::InvalidDeviceKey,
        )?;
        validate_key(input.anchor_key.as_bytes(), CeremonyError::InvalidAnchorKey)?;
        validate_key(
            input.presence_key.as_bytes(),
            CeremonyError::InvalidPresenceKey,
        )?;
        if input.owner_device_key
            == DeviceKey::try_from_bytes(input.anchor_key.as_bytes())
                .map_err(|_| CeremonyError::AttestationInvalid)?
            || input.owner_device_key
                == DeviceKey::try_from_bytes(input.presence_key.as_bytes())
                    .map_err(|_| CeremonyError::AttestationInvalid)?
        {
            return Err(CeremonyError::AttestationInvalid);
        }

        let recovery_commitment = input
            .recovery_policy
            .map_or_else(absent_recovery_commitment, RecoveryPolicy::commitment);
        Ok(Self {
            generation: input.generation,
            owner_device_key: input.owner_device_key,
            anchor_key: input.anchor_key,
            presence_key: input.presence_key,
            data_key_id: input.data_key_id,
            ceremony_nonce: input.ceremony_nonce,
            recovery_commitment,
            has_recovery_policy: input.recovery_policy.is_some(),
        })
    }

    pub const fn generation(self) -> MachineGeneration {
        self.generation
    }

    pub const fn owner_device_key(self) -> DeviceKey {
        self.owner_device_key
    }

    pub const fn anchor_key(self) -> AnchorKey {
        self.anchor_key
    }

    pub const fn presence_key(self) -> PresenceKey {
        self.presence_key
    }

    pub const fn data_key_id(self) -> DataKeyId {
        self.data_key_id
    }

    pub const fn ceremony_nonce(self) -> CeremonyNonce {
        self.ceremony_nonce
    }

    pub const fn has_recovery_policy(self) -> bool {
        self.has_recovery_policy
    }

    pub const fn recovery_commitment(self) -> [u8; KEY_LEN] {
        self.recovery_commitment
    }

    pub fn canonical_bytes(self) -> [u8; TRANSCRIPT_LEN] {
        let mut bytes = [0u8; TRANSCRIPT_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = TRANSCRIPT_VERSION;
        bytes[9] = if self.has_recovery_policy {
            RECOVERY_PRESENT_FLAG
        } else {
            0
        };
        bytes[10..18].copy_from_slice(&self.generation.get().to_be_bytes());
        bytes[18..DEVICE_OFFSET].copy_from_slice(&self.recovery_commitment);
        bytes[DEVICE_OFFSET..ANCHOR_OFFSET].copy_from_slice(&self.owner_device_key.as_bytes());
        bytes[ANCHOR_OFFSET..PRESENCE_OFFSET].copy_from_slice(&self.anchor_key.as_bytes());
        bytes[PRESENCE_OFFSET..DATA_KEY_OFFSET].copy_from_slice(&self.presence_key.as_bytes());
        bytes[DATA_KEY_OFFSET..NONCE_OFFSET].copy_from_slice(&self.data_key_id.as_bytes());
        bytes[NONCE_OFFSET..THRESHOLD_OFFSET].copy_from_slice(&self.ceremony_nonce.as_bytes());
        bytes
    }

    pub fn transcript_id(self) -> [u8; KEY_LEN] {
        digest(
            b"astrid.first-owner.transcript-id.v1",
            &[&self.canonical_bytes()],
        )
    }
}

pub(crate) fn absent_recovery_commitment() -> [u8; KEY_LEN] {
    digest(
        b"astrid.first-owner.recovery-policy-absent.v1",
        &[b"absent"],
    )
}

fn validate_key(bytes: [u8; KEY_LEN], error: CeremonyError) -> Result<(), CeremonyError> {
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| error)?;
    Ok(())
}
