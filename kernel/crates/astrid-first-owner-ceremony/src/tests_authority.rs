use crate::attestation::TwoPartyAttestation;
use crate::error::CeremonyError;
use crate::machine::{Authority, CeremonyPhase};
use crate::test_support::{anchor_key, base_input, bytes, fresh_machine, presence_key, transcript};
use crate::transcript::{Transcript, TranscriptInput};
use crate::types::{DeviceKey, RecoveryPolicy};

fn input_with_member_alias(authority_seed: u8) -> TranscriptInput {
    let policy = RecoveryPolicy::try_new(&[bytes(authority_seed)], 1).expect("valid member key");
    let mut input = base_input();
    input.recovery_policy = Some(policy);
    input
}

#[test]
fn invalid_member_bytes_are_rejected_before_any_ceremony_acceptance() {
    assert_eq!(
        RecoveryPolicy::try_new(&[[2; 32]], 1),
        Err(CeremonyError::InvalidRecoveryMemberKey)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[bytes(1), [2; 32]], 2),
        Err(CeremonyError::InvalidRecoveryMemberKey)
    );
    assert_eq!(
        RecoveryPolicy::try_new(&[[0; 32]], 1),
        Err(CeremonyError::InvalidRecoveryMemberKey)
    );

    let machine = fresh_machine();
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
    assert_eq!(machine.authority(), Authority::None);
}

#[test]
fn core_authority_keys_are_pairwise_disjoint() {
    #[derive(Clone, Copy, Debug)]
    enum Alias {
        OwnerAnchor,
        OwnerPresence,
        AnchorPresence,
        OwnerRecovery,
        AnchorRecovery,
        PresenceRecovery,
    }

    let cases = [
        (Alias::OwnerAnchor, 1u8, 2u8),
        (Alias::OwnerPresence, 1, 3),
        (Alias::AnchorPresence, 2, 3),
        (Alias::OwnerRecovery, 1, 101),
        (Alias::AnchorRecovery, 2, 101),
        (Alias::PresenceRecovery, 3, 101),
    ];
    for (case, left, right) in cases {
        let input = match case {
            Alias::OwnerAnchor => {
                let mut input = base_input();
                input.anchor_key = anchor_key(left);
                input
            },
            Alias::OwnerPresence => {
                let mut input = base_input();
                input.presence_key = presence_key(left);
                input
            },
            Alias::AnchorPresence => {
                let mut input = base_input();
                input.anchor_key = anchor_key(left);
                input.presence_key = presence_key(left);
                input
            },
            Alias::OwnerRecovery | Alias::AnchorRecovery | Alias::PresenceRecovery => {
                input_with_member_alias(left)
            },
        };
        let _ = right;

        assert_eq!(
            Transcript::try_new(input),
            Err(CeremonyError::AuthorityKeyAliasing),
            "authority seeds {left} and {right} aliased"
        );
    }
}

#[test]
fn one_key_cannot_hold_presence_and_recovery_roles_for_lost_owner_recovery() {
    let policy = RecoveryPolicy::try_new(&[bytes(3)], 1).expect("valid member key");
    let mut input = base_input();
    input.presence_key = presence_key(3);
    input.recovery_policy = Some(policy);
    let mut machine = fresh_machine();

    assert_eq!(
        Transcript::try_new(input),
        Err(CeremonyError::AuthorityKeyAliasing)
    );
    assert_eq!(
        machine.begin_anchor_pending(
            input,
            input.recovery_policy,
            TwoPartyAttestation::new([0; 64], [0; 64])
        ),
        Err(CeremonyError::AuthorityKeyAliasing)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
    assert_eq!(machine.authority(), Authority::None);
}

#[test]
fn distinct_owner_anchor_presence_and_members_are_accepted() {
    let policy = RecoveryPolicy::try_new(&[bytes(101), bytes(102)], 2).expect("valid policy");
    let mut input = base_input();
    input.recovery_policy = Some(policy);
    assert!(Transcript::try_new(input).is_ok());
    let _ = DeviceKey::try_from_bytes(bytes(1)).expect("owner type");
    let _ = transcript(input);
}
