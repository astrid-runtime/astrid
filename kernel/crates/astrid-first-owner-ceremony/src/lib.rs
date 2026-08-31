//! Private no_std first-owner transcript and state-machine model.
//!
//! This crate defines the accepted mechanics only. It does not provide a
//! production MachineEnrollmentAnchor adapter, storage durability, physical
//! locality, audit emission, a public ceremony API, or an authority source.
//! Callers remain responsible for all external authentication and durability.
#![no_std]

#[cfg(test)]
extern crate std;

mod attestation;
mod error;
mod machine;
mod transcript;
mod types;

pub use attestation::{
    DestructiveResetProof, OwnerRotationProof, PresenceAction, PresenceProof, RecoveryApproval,
    TwoPartyAttestation, presence_message, recovery_message, reset_message, rotation_message,
};
pub use error::CeremonyError;
pub use machine::{Authority, CeremonyMachine, CeremonyPhase, DestroyedDataKey};
pub use transcript::{
    MAGIC, MEMBER_COUNT_OFFSET, MEMBERS_OFFSET, RECOVERY_PRESENT_FLAG, THRESHOLD_OFFSET,
    TRANSCRIPT_LEN, TRANSCRIPT_VERSION, Transcript, TranscriptInput,
};
pub use types::{
    AnchorKey, CeremonyNonce, DATA_KEY_ID_LEN, DataKeyId, DeviceKey, KEY_LEN, MAX_RECOVERY_MEMBERS,
    MachineGeneration, NONCE_LEN, PresenceKey, RecoveryMemberId, RecoveryPolicy, SIGNATURE_LEN,
};

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests_attestation;
#[cfg(test)]
mod tests_cut_point;
#[cfg(test)]
mod tests_recovery;
#[cfg(test)]
mod tests_replay;
