//! Ceremony identities, bounded policy, and monotonic counters.

use crate::error::CeremonyError;

pub const KEY_LEN: usize = 32;
pub const DATA_KEY_ID_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const MAX_RECOVERY_MEMBERS: usize = 8;

macro_rules! byte_key {
    ($name:ident, $error:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            pub fn try_from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, CeremonyError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(CeremonyError::$error);
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(self) -> [u8; KEY_LEN] {
                self.0
            }
        }
    };
}

byte_key!(
    DeviceKey,
    InvalidDeviceKey,
    "The candidate owner's Ed25519 device key."
);
byte_key!(
    AnchorKey,
    InvalidAnchorKey,
    "The MachineEnrollmentAnchor's Ed25519 verification key."
);
byte_key!(
    PresenceKey,
    InvalidPresenceKey,
    "The explicitly enrolled authenticated-local-presence key."
);
byte_key!(
    RecoveryMemberId,
    InvalidRecoveryMemberKey,
    "A member key in a pre-enrolled threshold recovery policy."
);
byte_key!(
    DataKeyId,
    InvalidDataKeyId,
    "An opaque model identity for one data-key generation."
);
byte_key!(
    CeremonyNonce,
    InvalidNonce,
    "Caller-supplied freshness entropy bound into every transcript."
);

/// A non-zero machine generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineGeneration(u64);

impl MachineGeneration {
    pub const INITIAL: Self = Self(1);

    pub fn try_new(value: u64) -> Result<Self, CeremonyError> {
        if value == 0 {
            return Err(CeremonyError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, CeremonyError> {
        match self.0.checked_add(1) {
            Some(value) => Self::try_new(value),
            None => Err(CeremonyError::GenerationOverflow),
        }
    }
}

/// A threshold policy enrolled before owner loss. IDs are sorted and unique.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    threshold: u8,
    members: [Option<RecoveryMemberId>; MAX_RECOVERY_MEMBERS],
}

impl RecoveryPolicy {
    pub fn try_new(members: &[[u8; KEY_LEN]], threshold: u8) -> Result<Self, CeremonyError> {
        if members.is_empty()
            || members.len() > MAX_RECOVERY_MEMBERS
            || threshold == 0
            || usize::from(threshold) > members.len()
        {
            return Err(CeremonyError::InvalidRecoveryPolicy);
        }

        let mut values = [None; MAX_RECOVERY_MEMBERS];
        let mut index = 0;
        while index < members.len() {
            ed25519_dalek::VerifyingKey::from_bytes(&members[index])
                .map_err(|_| CeremonyError::InvalidRecoveryMemberKey)?;
            let member = RecoveryMemberId::try_from_bytes(members[index])?;
            if index != 0 {
                let Some(previous) = values[index - 1] else {
                    return Err(CeremonyError::InvalidRecoveryPolicy);
                };
                if previous >= member {
                    return Err(CeremonyError::InvalidRecoveryPolicy);
                }
            }
            values[index] = Some(member);
            index += 1;
        }

        Ok(Self {
            threshold,
            members: values,
        })
    }

    pub const fn threshold(self) -> u8 {
        self.threshold
    }

    pub fn member_count(self) -> u8 {
        self.members
            .iter()
            .filter(|member| member.is_some())
            .count() as u8
    }

    pub const fn member(self, index: usize) -> Option<RecoveryMemberId> {
        if index >= MAX_RECOVERY_MEMBERS {
            return None;
        }
        self.members[index]
    }

    pub(crate) fn commitment(self) -> [u8; KEY_LEN] {
        let mut bytes = [0u8; 2 + KEY_LEN * MAX_RECOVERY_MEMBERS];
        bytes[0] = self.threshold;
        bytes[1] = self.member_count();
        let mut index = 0;
        while index < MAX_RECOVERY_MEMBERS {
            let start = 2 + index * KEY_LEN;
            if let Some(member) = self.members[index] {
                bytes[start..start + KEY_LEN].copy_from_slice(&member.as_bytes());
            }
            index += 1;
        }
        digest(b"astrid.first-owner.recovery-policy.v1", &[&bytes])
    }
}

pub(crate) fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(core::str::from_utf8(domain).unwrap_or(""));
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
