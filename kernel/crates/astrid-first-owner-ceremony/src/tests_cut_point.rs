use crate::error::CeremonyError;
use crate::machine::{Authority, CeremonyPhase};
use crate::test_support::{attestation, base_input, enrolled, fresh_machine, sign_two, transcript};

#[test]
fn authority_appears_only_after_the_final_anchor_commit() {
    let mut machine = fresh_machine();
    let input = base_input();
    let value = transcript(input);
    let signatures = sign_two(value, 1, 2);

    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
    assert_eq!(machine.authority(), Authority::None);
    machine
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    assert_eq!(machine.phase(), CeremonyPhase::AnchorPending);
    assert_eq!(machine.authority(), Authority::None);

    machine.begin_graph_pending().expect("graph pending");
    assert_eq!(machine.phase(), CeremonyPhase::GraphPending);
    assert_eq!(machine.authority(), Authority::None);

    machine.commit_graph(signatures).expect("graph enrolled");
    assert_eq!(machine.phase(), CeremonyPhase::GraphEnrolled);
    assert_eq!(machine.authority(), Authority::None);

    machine.commit_anchor(signatures).expect("enrolled");
    assert_eq!(machine.phase(), CeremonyPhase::Enrolled);
    assert_eq!(
        machine.authority(),
        Authority::Owner(value.owner_device_key())
    );
}

#[test]
fn out_of_order_transitions_do_not_move_or_authorize() {
    let mut machine = fresh_machine();
    assert_eq!(
        machine.begin_graph_pending(),
        Err(CeremonyError::NotAnchorPending)
    );
    assert_eq!(
        machine.commit_graph(attestation(base_input())),
        Err(CeremonyError::NotGraphPending)
    );
    assert_eq!(
        machine.commit_anchor(attestation(base_input())),
        Err(CeremonyError::NotGraphEnrolled)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
    assert_eq!(machine.authority(), Authority::None);

    let input = base_input();
    machine
        .begin_anchor_pending(input, None, attestation(input))
        .expect("anchor pending");
    assert_eq!(
        machine.commit_anchor(attestation(input)),
        Err(CeremonyError::NotGraphEnrolled)
    );
    assert_eq!(machine.phase(), CeremonyPhase::AnchorPending);
    assert_eq!(machine.authority(), Authority::None);
}

#[test]
fn graph_commit_requires_a_fresh_exact_two_signature_pair() {
    let mut machine = fresh_machine();
    let input = base_input();
    let signatures = attestation(input);
    machine
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    machine.begin_graph_pending().expect("graph pending");
    assert_eq!(
        machine.commit_graph(sign_two(transcript(input), 1, 1)),
        Err(CeremonyError::AttestationInvalid)
    );
    assert_eq!(machine.phase(), CeremonyPhase::GraphPending);
    assert_eq!(machine.authority(), Authority::None);
    machine.commit_graph(signatures).expect("graph commit");
}

#[test]
fn anchor_commit_requires_the_same_exact_two_signature_pair() {
    let mut machine = fresh_machine();
    let input = base_input();
    let signatures = attestation(input);
    machine
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    machine.begin_graph_pending().expect("graph pending");
    machine.commit_graph(signatures).expect("graph commit");
    assert_eq!(
        machine.commit_anchor(sign_two(transcript(input), 1, 1)),
        Err(CeremonyError::AttestationInvalid)
    );
    assert_eq!(machine.phase(), CeremonyPhase::GraphEnrolled);
    assert_eq!(machine.authority(), Authority::None);
    machine.commit_anchor(signatures).expect("anchor commit");
}

#[test]
fn policy_argument_must_equal_the_signed_policy_commitment() {
    let mut machine = fresh_machine();
    let policy = crate::test_support::recovery_policy();
    let mut signed = base_input();
    signed.recovery_policy = Some(policy);
    let mut unsigned = base_input();
    unsigned.recovery_policy = None;
    assert_eq!(
        machine.begin_anchor_pending(signed, None, attestation(signed)),
        Err(CeremonyError::TranscriptPolicy)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);

    let signed = unsigned;
    assert_eq!(
        machine.begin_anchor_pending(signed, Some(policy), attestation(signed)),
        Err(CeremonyError::TranscriptPolicy)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);

    let mut wrong_policy = base_input();
    wrong_policy.recovery_policy = Some(policy);
    assert_eq!(
        machine.begin_anchor_pending(wrong_policy, None, attestation(wrong_policy)),
        Err(CeremonyError::TranscriptPolicy)
    );
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);
}

#[test]
fn interrupted_graph_enrolled_state_confers_no_authority() {
    let mut partial = fresh_machine();
    let input = base_input();
    let signatures = attestation(input);
    partial
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    partial.begin_graph_pending().expect("graph pending");
    partial.commit_graph(signatures).expect("graph enrolled");
    assert_eq!(partial.authority(), Authority::None);

    let completed = enrolled(None);
    assert_eq!(
        completed.authority(),
        Authority::Owner(transcript(input).owner_device_key())
    );
    let _ = completed;
}
