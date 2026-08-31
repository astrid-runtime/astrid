use crate::error::CeremonyError;
use crate::machine::{Authority, CeremonyPhase};
use crate::test_support::{
    attestation, base_input, data_key, enrolled, fresh_machine, reset_proof, transcript,
};
use crate::types::MachineGeneration;

#[test]
fn replaying_a_start_into_any_later_phase_fails_closed() {
    let mut machine = fresh_machine();
    let input = base_input();
    let signatures = attestation(input);
    machine
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    assert_eq!(
        machine.begin_anchor_pending(input, None, signatures),
        Err(CeremonyError::NotFresh)
    );
    machine.begin_graph_pending().expect("graph pending");
    assert_eq!(
        machine.begin_anchor_pending(input, None, signatures),
        Err(CeremonyError::NotFresh)
    );
    machine.commit_graph(signatures).expect("graph committed");
    assert_eq!(
        machine.begin_anchor_pending(input, None, signatures),
        Err(CeremonyError::NotFresh)
    );
    machine.commit_anchor(signatures).expect("enrolled");
    assert_eq!(
        machine.begin_anchor_pending(input, None, signatures),
        Err(CeremonyError::NotFresh)
    );
}

#[test]
fn replaying_a_completed_cut_point_cannot_replace_active_state() {
    let mut machine = fresh_machine();
    let input = base_input();
    let signatures = attestation(input);
    machine
        .begin_anchor_pending(input, None, signatures)
        .expect("anchor pending");
    machine.begin_graph_pending().expect("graph pending");
    machine.commit_graph(signatures).expect("graph committed");
    assert_eq!(
        machine.commit_graph(signatures),
        Err(CeremonyError::NotGraphPending)
    );
    machine.commit_anchor(signatures).expect("enrolled");
    assert_eq!(
        machine.commit_graph(signatures),
        Err(CeremonyError::NotGraphPending)
    );
    assert_eq!(
        machine.commit_anchor(signatures),
        Err(CeremonyError::NotGraphEnrolled)
    );
    assert_eq!(
        machine.authority(),
        Authority::Owner(transcript(input).owner_device_key())
    );
}

#[test]
fn concurrent_same_generation_claimant_cannot_take_the_single_slot() {
    let mut machine = fresh_machine();
    let first_input = base_input();
    machine
        .begin_anchor_pending(first_input, None, attestation(first_input))
        .expect("first claimant");

    let mut second_input = base_input();
    second_input.owner_device_key = crate::test_support::device_key(20);
    assert_eq!(
        machine.begin_anchor_pending(
            second_input,
            None,
            crate::test_support::attestation_for(second_input, 20),
        ),
        Err(CeremonyError::NotFresh)
    );
    assert_eq!(machine.phase(), CeremonyPhase::AnchorPending);
    assert_eq!(machine.authority(), Authority::None);
}

#[test]
fn stale_generation_and_destroyed_data_key_are_rejected_after_reset() {
    let mut machine = enrolled(None);
    let old_input = base_input();
    let current = transcript(old_input);
    let next_key = data_key(91);
    let destroyed = machine
        .destructive_reset(reset_proof(current, next_key, 3))
        .expect("destructive reset");
    assert_eq!(destroyed.id(), current.data_key_id());
    assert_eq!(machine.phase(), CeremonyPhase::Fresh);

    assert_eq!(
        machine.begin_anchor_pending(old_input, None, attestation(old_input)),
        Err(CeremonyError::TranscriptGeneration)
    );
    let mut reused_key = old_input;
    reused_key.generation = MachineGeneration::try_new(2).expect("generation");
    assert_eq!(
        machine.begin_anchor_pending(reused_key, None, attestation(reused_key)),
        Err(CeremonyError::TranscriptDataKey)
    );
}
