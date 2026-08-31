use crate::attestation::TwoPartyAttestation;
use crate::error::CeremonyError;
use crate::test_support::{
    anchor_key, base_input, bytes, data_key, device_key, presence_key, sign_two, transcript,
};
use crate::transcript::{
    MEMBER_COUNT_OFFSET, MEMBERS_OFFSET, RECOVERY_PRESENT_FLAG, THRESHOLD_OFFSET, TRANSCRIPT_LEN,
    Transcript,
};
use crate::types::AnchorKey;
use crate::types::{CeremonyNonce, MachineGeneration, RecoveryPolicy};

#[test]
fn transcript_layout_is_fixed_and_canonical() {
    assert_eq!(TRANSCRIPT_LEN, 476);
    let value = transcript(base_input());
    let canonical = value.canonical_bytes();
    assert_eq!(&canonical[..8], crate::transcript::MAGIC);
    assert_eq!(canonical[8], crate::transcript::TRANSCRIPT_VERSION);
    assert_eq!(canonical[9], 0);
    assert_eq!(canonical[THRESHOLD_OFFSET], 0);
    assert_eq!(canonical[MEMBER_COUNT_OFFSET], 0);
    assert!(
        canonical[MEMBERS_OFFSET..MEMBERS_OFFSET + 256]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn transcript_id_binds_every_policy_and_identity_field() {
    let base = transcript(base_input());
    let changed = [
        {
            let mut input = base_input();
            input.generation = MachineGeneration::try_new(2).expect("generation");
            transcript(input)
        },
        {
            let mut input = base_input();
            input.owner_device_key = device_key(9);
            transcript(input)
        },
        {
            let mut input = base_input();
            input.anchor_key = anchor_key(9);
            transcript(input)
        },
        {
            let mut input = base_input();
            input.presence_key = presence_key(9);
            transcript(input)
        },
        {
            let mut input = base_input();
            input.data_key_id = data_key(9);
            transcript(input)
        },
        {
            let mut input = base_input();
            input.ceremony_nonce = CeremonyNonce::try_from_bytes(bytes(9)).expect("nonce");
            transcript(input)
        },
        {
            let mut input = base_input();
            input.recovery_policy = Some(crate::test_support::recovery_policy());
            transcript(input)
        },
    ];
    for value in changed {
        assert_ne!(base.transcript_id(), value.transcript_id());
    }
}

#[test]
fn recovery_policy_is_sorted_unique_and_thresholded() {
    assert_eq!(
        RecoveryPolicy::try_new(&[], 1),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[bytes(1), bytes(2)], 0),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[bytes(1), bytes(2)], 3),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[bytes(1), bytes(1)], 1),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[bytes(2), bytes(1)], 1),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[[0; 32]], 1),
        Err(CeremonyError::InvalidRecoveryPolicy)
    );
}

#[test]
fn both_distinct_signatures_must_verify_the_exact_transcript() {
    let value = transcript(base_input());
    assert!(sign_two(value, 1, 2).verify(&value).is_ok());

    let other = transcript({
        let mut input = base_input();
        input.ceremony_nonce = CeremonyNonce::try_from_bytes(bytes(6)).expect("nonce");
        input
    });
    assert_eq!(
        sign_two(value, 1, 2).verify(&other),
        Err(CeremonyError::AttestationInvalid)
    );
    assert_eq!(
        sign_two(value, 2, 2).verify(&value),
        Err(CeremonyError::AttestationInvalid)
    );
    assert_eq!(
        sign_two(value, 1, 1).verify(&value),
        Err(CeremonyError::AttestationInvalid)
    );
}

#[test]
fn invalid_or_ambiguous_identity_sets_fail_closed() {
    let mut invalid_anchor = base_input();
    invalid_anchor.anchor_key =
        AnchorKey::try_from_bytes([2; 32]).expect("non-zero invalid curve point");
    assert_eq!(
        Transcript::try_new(invalid_anchor),
        Err(CeremonyError::InvalidAnchorKey)
    );
    let mut same_anchor = base_input();
    same_anchor.anchor_key = anchor_key(1);
    assert_eq!(
        Transcript::try_new(same_anchor),
        Err(CeremonyError::AttestationInvalid)
    );
    let mut same_presence = base_input();
    same_presence.presence_key = presence_key(1);
    assert_eq!(
        Transcript::try_new(same_presence),
        Err(CeremonyError::AttestationInvalid)
    );
}

#[test]
fn policy_flag_and_commitment_must_match_the_supplied_policy() {
    let policy = crate::test_support::recovery_policy();
    let mut input = base_input();
    input.recovery_policy = Some(policy);
    let value = transcript(input);
    let canonical = value.canonical_bytes();
    assert_eq!(canonical[9], RECOVERY_PRESENT_FLAG);
    assert_eq!(canonical[THRESHOLD_OFFSET], 0);
    assert_eq!(value.recovery_commitment(), policy.commitment());
    assert_ne!(
        value.recovery_commitment(),
        crate::transcript::absent_recovery_commitment()
    );

    let forged = value.canonical_bytes();
    assert_ne!(forged[THRESHOLD_OFFSET], 2);
    assert_eq!(
        TwoPartyAttestation::new([0; 64], [0; 64]).verify(&value),
        Err(CeremonyError::AttestationInvalid)
    );
}
