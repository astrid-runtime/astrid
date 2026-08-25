//! Opaque candidate facts and placement/state domain types.

use crate::error::JournalError;

pub const DIGEST_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    pub(crate) const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CandidateInput {
    pub(crate) descriptor_identity: [u8; DIGEST_LEN],
    pub(crate) kernel_identity: [u8; DIGEST_LEN],
    pub(crate) plan_digest: [u8; DIGEST_LEN],
    pub(crate) object_root: [u8; DIGEST_LEN],
    pub(crate) closure_root: [u8; DIGEST_LEN],
    pub(crate) generation: u64,
    pub(crate) rollback_floor: u64,
    pub(crate) kernel_floor: u64,
    pub(crate) sysgen_floor: u64,
}

/// Facts are intentionally opaque. A later adapter constructs them from
/// already verified descriptor and closure objects; raw bytes and paths never
/// enter this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateFacts {
    descriptor_identity: Digest,
    kernel_identity: Digest,
    plan_digest: Digest,
    object_root: Digest,
    closure_root: Digest,
    generation: u64,
    rollback_floor: u64,
    kernel_floor: u64,
    sysgen_floor: u64,
}

impl CandidateFacts {
    /// Private adapter boundary. Production callers must add a verifier-owned
    /// adapter in this crate; tests use this only to model verified facts.
    #[allow(dead_code)]
    pub(crate) const fn from_verified(input: CandidateInput) -> Self {
        Self {
            descriptor_identity: Digest::from_bytes(input.descriptor_identity),
            kernel_identity: Digest::from_bytes(input.kernel_identity),
            plan_digest: Digest::from_bytes(input.plan_digest),
            object_root: Digest::from_bytes(input.object_root),
            closure_root: Digest::from_bytes(input.closure_root),
            generation: input.generation,
            rollback_floor: input.rollback_floor,
            kernel_floor: input.kernel_floor,
            sysgen_floor: input.sysgen_floor,
        }
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn rollback_floor(self) -> u64 {
        self.rollback_floor
    }

    pub(crate) const fn kernel_floor(self) -> u64 {
        self.kernel_floor
    }

    pub(crate) const fn sysgen_floor(self) -> u64 {
        self.sysgen_floor
    }

    pub(crate) const fn claim(self) -> CandidateClaim {
        CandidateClaim {
            descriptor_identity: self.descriptor_identity,
            kernel_identity: self.kernel_identity,
            plan_digest: self.plan_digest,
            object_root: self.object_root,
            closure_root: self.closure_root,
            generation: self.generation,
            rollback_floor: self.rollback_floor,
            kernel_floor: self.kernel_floor,
            sysgen_floor: self.sysgen_floor,
        }
    }
}

/// Persisted identity and policy claims. Journal bytes can reproduce these
/// values, but a claim never authorizes execution without a fresh
/// verifier-owned [`CandidateFacts`] rebind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CandidateClaim {
    descriptor_identity: Digest,
    kernel_identity: Digest,
    plan_digest: Digest,
    object_root: Digest,
    closure_root: Digest,
    generation: u64,
    rollback_floor: u64,
    kernel_floor: u64,
    sysgen_floor: u64,
}

impl CandidateClaim {
    pub(crate) const fn from_persisted(input: CandidateInput) -> Self {
        Self {
            descriptor_identity: Digest::from_bytes(input.descriptor_identity),
            kernel_identity: Digest::from_bytes(input.kernel_identity),
            plan_digest: Digest::from_bytes(input.plan_digest),
            object_root: Digest::from_bytes(input.object_root),
            closure_root: Digest::from_bytes(input.closure_root),
            generation: input.generation,
            rollback_floor: input.rollback_floor,
            kernel_floor: input.kernel_floor,
            sysgen_floor: input.sysgen_floor,
        }
    }

    pub(crate) fn matches(self, facts: CandidateFacts) -> bool {
        self == facts.claim()
    }

    pub(crate) const fn descriptor_identity(self) -> [u8; DIGEST_LEN] {
        self.descriptor_identity.as_bytes()
    }

    pub(crate) const fn kernel_identity(self) -> [u8; DIGEST_LEN] {
        self.kernel_identity.as_bytes()
    }

    pub(crate) const fn plan_digest(self) -> [u8; DIGEST_LEN] {
        self.plan_digest.as_bytes()
    }

    pub(crate) const fn object_root(self) -> [u8; DIGEST_LEN] {
        self.object_root.as_bytes()
    }

    pub(crate) const fn closure_root(self) -> [u8; DIGEST_LEN] {
        self.closure_root.as_bytes()
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn rollback_floor(self) -> u64 {
        self.rollback_floor
    }

    pub(crate) const fn kernel_floor(self) -> u64 {
        self.kernel_floor
    }

    pub(crate) const fn sysgen_floor(self) -> u64 {
        self.sysgen_floor
    }

    pub(crate) fn well_formed(self) -> bool {
        [
            self.descriptor_identity,
            self.kernel_identity,
            self.plan_digest,
            self.object_root,
            self.closure_root,
        ]
        .iter()
        .all(|digest| digest.0.iter().any(|byte| *byte != 0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    A = 1,
    B = 2,
}

impl Slot {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::A),
            2 => Some(Self::B),
            _ => None,
        }
    }

    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordState {
    Pending = 1,
    Confirmed = 2,
    Bad = 3,
}

impl RecordState {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Pending),
            2 => Some(Self::Confirmed),
            3 => Some(Self::Bad),
            _ => None,
        }
    }

    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingToken {
    pub(crate) record_seq: u64,
    pub(crate) boot_sequence: u64,
    pub(crate) slot: Slot,
    pub(crate) attempt: u8,
    pub(crate) claim: CandidateClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub state: RecordState,
    pub slot: Slot,
    pub attempt: u8,
    pub record_seq: u64,
    pub boot_sequence: u64,
    pub claim: CandidateClaim,
}

impl Frame {
    pub const fn token(self) -> PendingToken {
        PendingToken {
            record_seq: self.record_seq,
            boot_sequence: self.boot_sequence,
            slot: self.slot,
            attempt: self.attempt,
            claim: self.claim,
        }
    }
}

pub(crate) fn transition_is_valid(
    previous: Option<Frame>,
    next: Frame,
) -> Result<(), JournalError> {
    let Some(previous) = previous else {
        if next.state != RecordState::Pending || next.attempt != 1 {
            return Err(JournalError::InvalidTransition);
        }
        return Ok(());
    };
    if next.record_seq
        != previous
            .record_seq
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?
    {
        return Err(JournalError::InvalidTransition);
    }
    if next.boot_sequence < previous.boot_sequence {
        return Err(JournalError::BootSequenceNotMonotonic);
    }
    match (previous.state, next.state) {
        (RecordState::Pending, RecordState::Pending) => {
            if next.slot != previous.slot
                || next.claim != previous.claim
                || next.attempt != previous.attempt.saturating_add(1)
                || next.attempt > crate::policy::MAX_ATTEMPTS
                || next.boot_sequence == previous.boot_sequence
            {
                return Err(JournalError::InvalidTransition);
            }
        },
        (RecordState::Pending, RecordState::Confirmed | RecordState::Bad) => {
            if next.slot != previous.slot
                || next.claim != previous.claim
                || next.attempt != previous.attempt
                || (next.state == RecordState::Confirmed
                    && previous.attempt >= crate::policy::MAX_ATTEMPTS)
                || next.boot_sequence != previous.boot_sequence
            {
                return Err(JournalError::InvalidTransition);
            }
        },
        (RecordState::Confirmed | RecordState::Bad, RecordState::Pending) => {
            if next.attempt != 1 || next.boot_sequence == previous.boot_sequence {
                return Err(JournalError::InvalidTransition);
            }
        },
        _ => return Err(JournalError::InvalidTransition),
    }
    Ok(())
}
