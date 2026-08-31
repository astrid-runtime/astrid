use crate::attestation::{PresenceAction, recovery_message};
use crate::error::CeremonyError;
use crate::machine::{Authority, CeremonyPhase};
use crate::test_support::{
    approval, attestation, data_key, device_key, enrolled, owner_proof, presence, recovery_policy,
    reset_proof, successor_input, transcript,
};
#[test]
fn rotation_requires_owner_and_authenticated_presence() {
    let mut machine = enrolled(None);
    let current = machine.active_transcript().expect("enrolled transcript");
    let next_input = successor_input(current, 20, None);
    let next = transcript(next_input);

    let valid_attestation = crate::test_support::attestation_for(next_input, 20);
    let valid_presence = presence(PresenceAction::Rotate, next, 3);
    let valid_owner = owner_proof(current, next, 1);
    machine
        .rotate(
            next_input,
            None,
            valid_attestation,
            valid_presence,
            valid_owner,
        )
        .expect("rotation");
    assert_eq!(machine.authority(), Authority::Owner(device_key(20)));
}

#[test]
fn rotation_fails_closed_for_each_missing_authority() {
    let machine = enrolled(None);
    let current = machine.active_transcript().expect("current transcript");
    let next_input = successor_input(current, 20, None);
    let next = transcript(next_input);
    let attestation_valid = crate::test_support::attestation_for(next_input, 20);
    let presence_valid = presence(PresenceAction::Rotate, next, 3);
    let owner_valid = owner_proof(current, next, 1);

    let mut no_presence = machine;
    assert_eq!(
        no_presence.rotate(
            next_input,
            None,
            attestation_valid,
            presence(PresenceAction::Recover, next, 3),
            owner_valid
        ),
        Err(CeremonyError::PresenceInvalid)
    );
    assert_eq!(no_presence.authority(), Authority::Owner(device_key(1)));

    let mut wrong_owner = no_presence;
    assert_eq!(
        wrong_owner.rotate(
            next_input,
            None,
            attestation_valid,
            presence_valid,
            owner_proof(current, next, 9)
        ),
        Err(CeremonyError::OwnerAuthorizationInvalid)
    );
    assert_eq!(wrong_owner.authority(), Authority::Owner(device_key(1)));

    let same_owner_input = successor_input(current, 1, None);
    let same_owner = transcript(same_owner_input);
    assert_eq!(
        wrong_owner.rotate(
            same_owner_input,
            None,
            attestation(same_owner_input),
            presence(PresenceAction::Rotate, same_owner, 3),
            owner_proof(current, same_owner, 1)
        ),
        Err(CeremonyError::OwnerUnchanged)
    );
    assert_eq!(wrong_owner.authority(), Authority::Owner(device_key(1)));
}

#[test]
fn lost_owner_recovery_requires_pre_enrolled_threshold_policy() {
    let mut without_policy = enrolled(None);
    let current = without_policy
        .active_transcript()
        .expect("current transcript");
    let next_input = successor_input(current, 20, None);
    assert_eq!(
        without_policy.recover_lost_owner(
            next_input,
            crate::test_support::attestation_for(next_input, 20),
            presence(PresenceAction::Recover, transcript(next_input), 3),
            &[approval(current, transcript(next_input), 101)]
        ),
        Err(CeremonyError::PolicyRequired)
    );
    assert_eq!(without_policy.authority(), Authority::Owner(device_key(1)));
}

#[test]
fn recovery_accepts_exact_threshold_and_rejects_duplicate_or_foreign_members() {
    let policy = recovery_policy();
    let mut machine = enrolled(Some(policy));
    let current = machine.active_transcript().expect("current transcript");
    let next_input = successor_input(current, 20, Some(policy));
    let next = transcript(next_input);
    let valid_attestation = crate::test_support::attestation_for(next_input, 20);
    let valid_presence = presence(PresenceAction::Recover, next, 3);
    let first = approval(current, next, 101);
    let second = approval(current, next, 102);

    assert_eq!(
        machine.recover_lost_owner(next_input, valid_attestation, valid_presence, &[first]),
        Err(CeremonyError::RecoveryApprovalsInvalid)
    );
    assert_eq!(machine.authority(), Authority::Owner(device_key(1)));
    assert_eq!(
        machine.recover_lost_owner(
            next_input,
            valid_attestation,
            valid_presence,
            &[first, first]
        ),
        Err(CeremonyError::RecoveryApprovalsInvalid)
    );
    assert_eq!(
        machine.recover_lost_owner(
            next_input,
            valid_attestation,
            valid_presence,
            &[first, approval(current, next, 104)]
        ),
        Err(CeremonyError::RecoveryApprovalsInvalid)
    );
    machine
        .recover_lost_owner(
            next_input,
            valid_attestation,
            valid_presence,
            &[second, first],
        )
        .expect("threshold recovery");
    assert_eq!(machine.authority(), Authority::Owner(device_key(20)));
}

#[test]
fn recovery_signature_or_policy_mismatch_does_not_reactivate_owner() {
    let policy = recovery_policy();
    let mut machine = enrolled(Some(policy));
    let current = machine.active_transcript().expect("current transcript");
    let next_input = successor_input(current, 20, Some(policy));
    let next = transcript(next_input);
    let wrong_member = {
        use ed25519_dalek::Signer;
        let member =
            crate::types::RecoveryMemberId::try_from_bytes(crate::test_support::bytes(101))
                .expect("member");
        let signature = crate::test_support::signing_key(104)
            .sign(&recovery_message(&current, &next))
            .to_bytes();
        crate::attestation::RecoveryApproval::try_new(member, signature).expect("approval shape")
    };
    assert_eq!(
        machine.recover_lost_owner(
            next_input,
            crate::test_support::attestation_for(next_input, 20),
            presence(PresenceAction::Recover, next, 3),
            &[wrong_member, approval(current, next, 102)]
        ),
        Err(CeremonyError::RecoveryApprovalsInvalid)
    );
    assert_eq!(machine.authority(), Authority::Owner(device_key(1)));
}

#[test]
fn destructive_reset_advances_generation_and_destroys_the_live_data_key() {
    let mut machine = enrolled(None);
    let current = machine.active_transcript().expect("current transcript");
    let next_key = data_key(91);
    let destroyed = machine
        .destructive_reset(reset_proof(current, next_key, 3))
        .expect("destructive reset");
    assert_eq!(destroyed.id(), current.data_key_id());
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
    assert_eq!(machine.authority(), Authority::None);
    assert_eq!(machine.data_key_id(), next_key);
    assert_eq!(machine.generation().get(), 2);
    assert_eq!(machine.anchor_key(), None);
    assert_eq!(machine.recovery_policy(), None);
}

#[test]
fn destructive_reset_requires_signed_presence_and_a_new_data_key() {
    let mut machine = enrolled(None);
    let current = machine.active_transcript().expect("current transcript");
    let next_key = data_key(91);
    assert_eq!(
        machine.destructive_reset(reset_proof(current, next_key, 9)),
        Err(CeremonyError::ResetProofInvalid)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Enrolled);
    assert_eq!(machine.data_key_id(), current.data_key_id());
    assert_eq!(
        machine.destructive_reset(reset_proof(current, current.data_key_id(), 3)),
        Err(CeremonyError::TranscriptDataKey)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Enrolled);
}

#[test]
fn policy_backed_owner_cannot_bypass_threshold_with_destructive_reset() {
    let mut machine = enrolled(Some(recovery_policy()));
    let current = machine.active_transcript().expect("current transcript");
    assert_eq!(
        machine.destructive_reset(reset_proof(current, data_key(91), 3)),
        Err(CeremonyError::PolicyRequired)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Enrolled);
    assert_eq!(machine.authority(), Authority::Owner(device_key(1)));
}
