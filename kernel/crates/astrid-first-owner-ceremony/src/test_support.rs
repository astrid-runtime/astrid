//! Deterministic signing helpers used only by sibling test modules.

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};

use crate::attestation::{
    DestructiveResetProof, OwnerRotationProof, PresenceAction, PresenceProof, RecoveryApproval,
    TwoPartyAttestation, presence_message, recovery_message, reset_message, rotation_message,
};
use crate::transcript::{Transcript, TranscriptInput};
use crate::types::{
    AnchorKey, CeremonyNonce, DataKeyId, DeviceKey, MachineGeneration, PresenceKey,
    RecoveryMemberId, RecoveryPolicy,
};

pub fn signing_key(seed: u8) -> SigningKey {
    let mut hasher = Hasher::new_derive_key("astrid.first-owner.test-seed.v1");
    hasher.update(&[seed]);
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}

pub fn bytes(seed: u8) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

pub fn device_key(seed: u8) -> DeviceKey {
    DeviceKey::try_from_bytes(bytes(seed)).expect("valid test device key")
}

pub fn anchor_key(seed: u8) -> AnchorKey {
    AnchorKey::try_from_bytes(bytes(seed)).expect("valid test anchor key")
}

pub fn presence_key(seed: u8) -> PresenceKey {
    PresenceKey::try_from_bytes(bytes(seed)).expect("valid test presence key")
}

pub fn data_key(seed: u8) -> DataKeyId {
    DataKeyId::try_from_bytes(bytes(seed)).expect("valid test data key")
}

pub fn recovery_policy() -> RecoveryPolicy {
    let mut members = [bytes(101), bytes(102), bytes(103)];
    members.sort_unstable();
    RecoveryPolicy::try_new(&members, 2).expect("valid policy")
}

pub fn base_input() -> TranscriptInput {
    TranscriptInput {
        generation: MachineGeneration::INITIAL,
        owner_device_key: device_key(1),
        anchor_key: anchor_key(2),
        presence_key: presence_key(3),
        data_key_id: data_key(90),
        ceremony_nonce: CeremonyNonce::try_from_bytes(bytes(5)).expect("valid nonce"),
        recovery_policy: None,
    }
}

pub fn successor_input(
    current: Transcript,
    owner_seed: u8,
    recovery_policy: Option<RecoveryPolicy>,
) -> TranscriptInput {
    TranscriptInput {
        generation: current.generation().next().expect("successor generation"),
        owner_device_key: device_key(owner_seed),
        anchor_key: current.anchor_key(),
        presence_key: current.presence_key(),
        data_key_id: current.data_key_id(),
        ceremony_nonce: current.ceremony_nonce(),
        recovery_policy,
    }
}

pub fn transcript(input: TranscriptInput) -> Transcript {
    Transcript::try_new(input).expect("valid test transcript")
}

pub fn attestation(input: TranscriptInput) -> TwoPartyAttestation {
    sign_two(transcript(input), 1, 2)
}

pub fn attestation_for(input: TranscriptInput, device_seed: u8) -> TwoPartyAttestation {
    sign_two(transcript(input), device_seed, 2)
}

pub fn sign_two(value: Transcript, device_seed: u8, anchor_seed: u8) -> TwoPartyAttestation {
    TwoPartyAttestation::new(
        signing_key(device_seed)
            .sign(&value.canonical_bytes())
            .to_bytes(),
        signing_key(anchor_seed)
            .sign(&value.canonical_bytes())
            .to_bytes(),
    )
}

pub fn presence(action: PresenceAction, value: Transcript, seed: u8) -> PresenceProof {
    PresenceProof::new(
        signing_key(seed)
            .sign(&presence_message(action, &value))
            .to_bytes(),
    )
}

pub fn owner_proof(current: Transcript, next: Transcript, seed: u8) -> OwnerRotationProof {
    OwnerRotationProof::new(
        signing_key(seed)
            .sign(&rotation_message(&current, &next))
            .to_bytes(),
    )
}

pub fn approval(current: Transcript, next: Transcript, member_seed: u8) -> RecoveryApproval {
    let member = RecoveryMemberId::try_from_bytes(bytes(member_seed)).expect("member");
    let signature = signing_key(member_seed)
        .sign(&recovery_message(&current, &next))
        .to_bytes();
    RecoveryApproval::try_new(member, signature).expect("valid approval")
}

pub fn reset_proof(
    current: Transcript,
    next_data_key: DataKeyId,
    seed: u8,
) -> DestructiveResetProof {
    DestructiveResetProof::new(
        next_data_key,
        signing_key(seed)
            .sign(&reset_message(&current, &next_data_key))
            .to_bytes(),
    )
}

pub fn fresh_machine() -> crate::machine::CeremonyMachine {
    crate::machine::CeremonyMachine::new(MachineGeneration::INITIAL, data_key(90))
}

pub fn enrolled(policy: Option<RecoveryPolicy>) -> crate::machine::CeremonyMachine {
    let mut machine = fresh_machine();
    let mut input = base_input();
    input.recovery_policy = policy;
    machine
        .begin_anchor_pending(input, policy, attestation(input))
        .expect("anchor pending");
    machine.begin_graph_pending().expect("graph pending");
    let value = transcript(input);
    machine
        .commit_graph(attestation(input))
        .expect("graph enrolled");
    machine
        .commit_anchor(sign_two(value, 1, 2))
        .expect("enrolled");
    machine
}
