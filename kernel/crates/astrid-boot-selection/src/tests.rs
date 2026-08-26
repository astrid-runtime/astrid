use crate::codec::{
    CHECKSUM_END, CHECKSUM_START, FRAME_LEN, RESERVED_START, decode_frame, encode_frame,
};
use crate::error::{JournalError, SelectionError};
use crate::journal::{JOURNAL_LEN, Journal};
use crate::policy::{MAX_ATTEMPTS, SelectionPolicy};
use crate::selector::{BootDecision, Selector, VerifiedCandidates};
use crate::types::{CandidateFacts, CandidateInput, Frame, RecordState, Slot};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn facts(byte: u8) -> CandidateFacts {
    facts_with_generation(byte, 10 + u64::from(byte))
}

fn facts_with_generation(byte: u8, generation: u64) -> CandidateFacts {
    CandidateFacts::from_verified(CandidateInput {
        descriptor_identity: digest(byte),
        kernel_identity: digest(byte.wrapping_add(1)),
        system_generation_identity: digest(byte.wrapping_add(5)),
        plan_digest: digest(byte.wrapping_add(2)),
        object_root: digest(byte.wrapping_add(3)),
        closure_root: digest(byte.wrapping_add(4)),
        generation,
        rollback_floor: 10 + u64::from(byte),
        kernel_floor: 10 + u64::from(byte),
        sysgen_floor: 10 + u64::from(byte),
        policy_generation: 10 + u64::from(byte),
    })
}

fn selector() -> Selector {
    Selector::new(SelectionPolicy::new(10, 10, 10, 10))
}

fn verified() -> VerifiedCandidates {
    VerifiedCandidates::from_verified(Some(facts(1)), Some(facts(2)))
}

fn bytes_with_frame(journal: Journal, index: usize, frame: &Frame) -> Journal {
    let mut bytes = journal.as_bytes();
    let start = index * FRAME_LEN;
    bytes[start..start + FRAME_LEN].copy_from_slice(&encode_frame(frame));
    Journal::from_bytes(&bytes).expect("fixed journal size")
}

fn second_frame(journal: Journal) -> Frame {
    let bytes = journal.as_bytes();
    let mut raw = [0u8; FRAME_LEN];
    raw.copy_from_slice(&bytes[FRAME_LEN..2 * FRAME_LEN]);
    decode_frame(&raw).expect("second frame")
}

#[test]
fn fixed_empty_journal_recovers() {
    assert_eq!(
        selector().recover(Journal::empty(), verified()),
        BootDecision::Recovery
    );
    assert_eq!(JOURNAL_LEN, 4736);
    assert_eq!(FRAME_LEN, 296);
    assert_eq!(CHECKSUM_END, FRAME_LEN);
}

#[test]
fn journal_size_is_exact_and_unknown_markers_fail_closed() {
    assert_eq!(
        Journal::from_bytes(&[0u8; JOURNAL_LEN - 1]),
        Err(JournalError::WrongLength)
    );
    assert_eq!(
        Journal::from_bytes(&[0u8; JOURNAL_LEN + 1]),
        Err(JournalError::WrongLength)
    );
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    for offset in [9, 10] {
        let mut bytes = confirmed.as_bytes();
        bytes[FRAME_LEN + offset] = 0xff;
        let malformed = Journal::from_bytes(&bytes).expect("fixed journal");
        assert_eq!(
            selector().recover(malformed, verified()),
            BootDecision::Recovery
        );
    }
}

#[test]
fn pending_attempt_one_has_zero_tail_and_recovers() {
    let pending = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first pending");
    let bytes = pending.journal().as_bytes();
    assert!(bytes[..FRAME_LEN].iter().any(|byte| *byte != 0));
    assert!(bytes[FRAME_LEN..].iter().all(|byte| *byte == 0));
    assert_eq!(pending.attempt(), 1);
    assert!(matches!(
        selector().recover(pending.journal(), verified()),
        BootDecision::Pending(trial) if trial.attempt() == 1 && trial.slot() == Slot::A
    ));
}

#[test]
fn confirm_requires_exact_latest_pending_token() {
    let pending = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("pending");
    let mut wrong = pending.token();
    wrong.record_seq = 99;
    assert_eq!(
        selector().confirm(pending.journal(), wrong),
        Err(SelectionError::Journal(JournalError::TokenMismatch))
    );
    let confirmed = selector()
        .confirm(pending.journal(), pending.token())
        .expect("confirm");
    assert!(matches!(
        selector().recover(confirmed, verified()),
        BootDecision::Confirmed(boot) if boot.slot() == Slot::A
    ));
}

#[test]
fn newest_pending_trial_beats_older_confirmed_and_bad_falls_back() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let newer = selector()
        .start_pending(confirmed, Slot::B, facts(2), 2)
        .expect("newer");
    assert!(matches!(
        selector().recover(newer.journal(), verified()),
        BootDecision::Pending(trial) if trial.slot() == Slot::B && trial.candidate() == facts(2)
    ));
    let bad = selector()
        .mark_bad(newer.journal(), newer.token())
        .expect("bad");
    assert!(matches!(
        selector().recover(bad, verified()),
        BootDecision::Confirmed(boot) if boot.slot() == Slot::A && boot.candidate() == facts(1)
    ));
}

#[test]
fn same_generation_still_uses_newest_record_sequence() {
    let first_facts = facts_with_generation(1, 20);
    let second_facts = facts_with_generation(2, 20);
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, first_facts, 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let newer = selector()
        .start_pending(confirmed, Slot::B, second_facts, 2)
        .expect("newer");
    assert!(matches!(
        selector().recover(newer.journal(), VerifiedCandidates::from_verified(
            Some(first_facts),
            Some(second_facts),
        )),
        BootDecision::Pending(trial) if trial.slot() == Slot::B && trial.candidate() == second_facts
    ));
}

#[test]
fn retry_attempts_are_bounded_and_exhausted_pending_falls_back() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("attempt one");
    let second = selector()
        .start_pending(first.journal(), Slot::A, facts(1), 2)
        .expect("attempt two");
    let third = selector()
        .start_pending(second.journal(), Slot::A, facts(1), 3)
        .expect("attempt three");
    assert_eq!(third.attempt(), MAX_ATTEMPTS);
    assert_eq!(
        selector().start_pending(third.journal(), Slot::A, facts(1), 4),
        Err(SelectionError::Journal(JournalError::AttemptsExhausted))
    );
    assert_eq!(
        selector().recover(third.journal(), verified()),
        BootDecision::Recovery
    );
}

#[test]
fn newer_bad_or_exhausted_same_slot_falls_back_to_confirmed() {
    let first_facts = facts(1);
    let newer_facts = facts(2);
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, first_facts, 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let pending = selector()
        .start_pending(confirmed, Slot::A, newer_facts, 2)
        .expect("newer");
    let bad = selector()
        .mark_bad(pending.journal(), pending.token())
        .expect("bad");
    assert!(matches!(
        selector().recover(bad, verified()),
        BootDecision::Confirmed(boot) if boot.slot() == Slot::A && boot.candidate() == first_facts
    ));

    let pending = selector()
        .start_pending(confirmed, Slot::A, newer_facts, 2)
        .expect("newer retry");
    let pending = selector()
        .start_pending(pending.journal(), Slot::A, newer_facts, 3)
        .expect("retry two");
    let exhausted = selector()
        .start_pending(pending.journal(), Slot::A, newer_facts, 4)
        .expect("retry three");
    assert!(matches!(
        selector().recover(exhausted.journal(), verified()),
        BootDecision::Confirmed(boot) if boot.slot() == Slot::A && boot.candidate() == first_facts
    ));
}

#[test]
fn failed_trial_claim_cannot_reauthorize_old_confirmation() {
    let candidate = facts(1);
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, candidate, 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let pending_frame = Frame {
        state: RecordState::Pending,
        slot: Slot::A,
        attempt: 1,
        record_seq: 2,
        boot_sequence: 2,
        claim: candidate.claim(),
    };
    let with_trial = bytes_with_frame(confirmed, 2, &pending_frame);
    let bad_frame = Frame {
        state: RecordState::Bad,
        record_seq: 3,
        ..pending_frame
    };
    let bad = bytes_with_frame(with_trial, 3, &bad_frame);
    assert_eq!(selector().recover(bad, verified()), BootDecision::Recovery);
}

#[test]
fn slot_swapped_failed_claim_falls_back_to_distinct_confirmation() {
    let first_facts = facts(1);
    let second_facts = facts(2);
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, first_facts, 1)
        .expect("first");
    let first_confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("first confirmed");
    let second = selector()
        .start_pending(first_confirmed, Slot::B, second_facts, 2)
        .expect("second");
    let second_confirmed = selector()
        .confirm(second.journal(), second.token())
        .expect("second confirmed");
    let swapped_trial = selector()
        .start_pending(second_confirmed, Slot::A, first_facts, 3)
        .expect("slot-swapped trial");
    let bad = selector()
        .mark_bad(swapped_trial.journal(), swapped_trial.token())
        .expect("bad");
    assert!(matches!(
        selector().recover(bad, verified()),
        BootDecision::Confirmed(boot)
            if boot.slot() == Slot::B && boot.candidate() == second_facts
    ));
}

fn corrupt_final_checksum(journal: Journal, frame_index: usize) -> Journal {
    let mut bytes = journal.as_bytes();
    bytes[frame_index * FRAME_LEN + CHECKSUM_START] ^= 1;
    Journal::from_bytes(&bytes).expect("fixed journal")
}

#[test]
fn same_slot_torn_attempt_three_or_bad_is_recovery() {
    let confirmed = {
        let first = selector()
            .start_pending(Journal::empty(), Slot::A, facts(1), 1)
            .expect("first");
        selector()
            .confirm(first.journal(), first.token())
            .expect("confirmed")
    };
    let trial_one = selector()
        .start_pending(confirmed, Slot::A, facts(2), 2)
        .expect("trial one");
    let trial_two = selector()
        .start_pending(trial_one.journal(), Slot::A, facts(2), 3)
        .expect("trial two");
    let trial_three = selector()
        .start_pending(trial_two.journal(), Slot::A, facts(2), 4)
        .expect("trial three");
    assert_eq!(
        selector().recover(corrupt_final_checksum(trial_three.journal(), 4), verified()),
        BootDecision::Recovery
    );

    let trial = selector()
        .start_pending(confirmed, Slot::A, facts(2), 2)
        .expect("bad trial");
    let bad = selector()
        .mark_bad(trial.journal(), trial.token())
        .expect("bad");
    assert_eq!(
        selector().recover(corrupt_final_checksum(bad, 3), verified()),
        BootDecision::Recovery
    );
}

#[test]
fn slot_swapped_torn_attempt_three_or_bad_is_recovery() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let first_confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("first confirmed");
    let second = selector()
        .start_pending(first_confirmed, Slot::B, facts(2), 2)
        .expect("second");
    let second_confirmed = selector()
        .confirm(second.journal(), second.token())
        .expect("second confirmed");
    let trial_one = selector()
        .start_pending(second_confirmed, Slot::B, facts(1), 3)
        .expect("slot-swapped trial one");
    let trial_two = selector()
        .start_pending(trial_one.journal(), Slot::B, facts(1), 4)
        .expect("slot-swapped trial two");
    let trial_three = selector()
        .start_pending(trial_two.journal(), Slot::B, facts(1), 5)
        .expect("slot-swapped trial three");
    assert_eq!(
        selector().recover(corrupt_final_checksum(trial_three.journal(), 6), verified()),
        BootDecision::Recovery
    );

    let trial = selector()
        .start_pending(second_confirmed, Slot::B, facts(1), 3)
        .expect("slot-swapped bad trial");
    let bad = selector()
        .mark_bad(trial.journal(), trial.token())
        .expect("bad");
    assert_eq!(
        selector().recover(corrupt_final_checksum(bad, 5), verified()),
        BootDecision::Recovery
    );
}

#[test]
fn each_independent_policy_floor_is_enforced() {
    let candidate = facts(1);
    let policies = [
        SelectionPolicy::new(12, 10, 10, 10),
        SelectionPolicy::new(10, 12, 10, 10),
        SelectionPolicy::new(10, 10, 12, 10),
        SelectionPolicy::new(10, 10, 10, 12),
    ];
    for policy in policies {
        assert_eq!(
            Selector::new(policy).start_pending(Journal::empty(), Slot::A, candidate, 1),
            Err(SelectionError::Journal(JournalError::Ineligible))
        );
    }
}

#[test]
fn stale_newer_pending_falls_back_to_confirmed() {
    let low_policy = Selector::new(SelectionPolicy::new(0, 0, 0, 0));
    let first = low_policy
        .start_pending(Journal::empty(), Slot::A, facts(2), 1)
        .expect("first");
    let confirmed = low_policy
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let newer = low_policy
        .start_pending(confirmed, Slot::B, facts(1), 2)
        .expect("newer");
    let high_policy = Selector::new(SelectionPolicy::new(12, 12, 12, 12));
    assert!(matches!(
        high_policy.recover(newer.journal(), verified()),
        BootDecision::Confirmed(boot) if boot.slot() == Slot::A
    ));
}

#[test]
fn nonzero_malformed_final_and_interior_corruption_recover() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("pending");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let mut bytes = confirmed.as_bytes();
    bytes[FRAME_LEN] = 0x55;
    let torn = Journal::from_bytes(&bytes).expect("journal");
    assert_eq!(selector().recover(torn, verified()), BootDecision::Recovery);
    let mut bytes = torn.as_bytes();
    bytes[2 * FRAME_LEN] = 0x66;
    let interior = Journal::from_bytes(&bytes).expect("journal");
    assert_eq!(
        selector().recover(interior, verified()),
        BootDecision::Recovery
    );
}

#[test]
fn empty_gap_and_later_nonzero_frame_are_interior_corruption() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let second = selector()
        .start_pending(confirmed, Slot::B, facts(2), 2)
        .expect("second");
    let bytes = second.journal().as_bytes();
    let mut gapped = [0u8; JOURNAL_LEN];
    gapped[..FRAME_LEN].copy_from_slice(&bytes[..FRAME_LEN]);
    gapped[2 * FRAME_LEN..3 * FRAME_LEN].copy_from_slice(&bytes[FRAME_LEN..2 * FRAME_LEN]);
    let journal = Journal::from_bytes(&gapped).expect("journal");
    assert_eq!(
        selector().recover(journal, verified()),
        BootDecision::Recovery
    );
}

#[test]
fn nonzero_reserved_checksum_and_marker_fail_closed() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("pending");
    let confirmed = selector()
        .confirm(first.journal(), first.token())
        .expect("confirmed");
    let mut bytes = confirmed.as_bytes();
    bytes[FRAME_LEN + RESERVED_START] = 1;
    let reserved = Journal::from_bytes(&bytes).expect("journal");
    assert_eq!(
        selector().recover(reserved, verified()),
        BootDecision::Recovery
    );
    let mut bytes = confirmed.as_bytes();
    bytes[FRAME_LEN + CHECKSUM_START] ^= 1;
    let checksum = Journal::from_bytes(&bytes).expect("journal");
    assert_eq!(
        selector().recover(checksum, verified()),
        BootDecision::Recovery
    );
    let mut bytes = confirmed.as_bytes();
    bytes[FRAME_LEN] = b'X';
    let marker = Journal::from_bytes(&bytes).expect("journal");
    assert_eq!(
        selector().recover(marker, verified()),
        BootDecision::Recovery
    );
}

#[test]
fn sequence_gaps_duplicates_decreases_and_boot_decreases_recover() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let second = selector()
        .start_pending(first.journal(), Slot::A, facts(1), 2)
        .expect("second");
    let frame = second_frame(second.journal());
    for record_seq in [0, 3, u64::MAX] {
        let bad = Frame {
            record_seq,
            ..frame
        };
        let journal = bytes_with_frame(second.journal(), 1, &bad);
        assert_eq!(
            selector().recover(journal, verified()),
            BootDecision::Recovery
        );
    }
    let bad_boot = Frame {
        boot_sequence: 1,
        ..frame
    };
    let journal = bytes_with_frame(second.journal(), 1, &bad_boot);
    assert_eq!(
        selector().recover(journal, verified()),
        BootDecision::Recovery
    );
}

#[test]
fn invalid_transition_and_fact_mismatch_recover_or_reject_token() {
    let first = selector()
        .start_pending(Journal::empty(), Slot::A, facts(1), 1)
        .expect("first");
    let frame = Frame {
        state: RecordState::Confirmed,
        slot: Slot::B,
        attempt: 1,
        record_seq: 1,
        boot_sequence: 1,
        claim: facts(1).claim(),
    };
    let invalid = bytes_with_frame(first.journal(), 1, &frame);
    assert_eq!(
        selector().recover(invalid, verified()),
        BootDecision::Recovery
    );
    let wrong_facts = selector().mark_bad(
        first.journal(),
        crate::types::PendingToken {
            claim: facts(2).claim(),
            ..first.token()
        },
    );
    assert_eq!(
        wrong_facts,
        Err(SelectionError::Journal(JournalError::TokenMismatch))
    );
}

#[test]
fn full_journal_stops_at_sixteen_contiguous_frames() {
    let mut journal = Journal::empty();
    let mut boot = 1;
    for index in 0..8 {
        let slot = if index % 2 == 0 { Slot::A } else { Slot::B };
        let candidate = facts(if index % 2 == 0 { 1 } else { 2 });
        let pending = selector()
            .start_pending(journal, slot, candidate, boot)
            .expect("pending");
        journal = selector()
            .confirm(pending.journal(), pending.token())
            .expect("confirmed");
        boot += 1;
    }
    assert_eq!(
        selector().start_pending(journal, Slot::A, facts(1), boot),
        Err(SelectionError::Journal(JournalError::Full))
    );
}

#[test]
fn every_valid_frame_boundary_recovers_without_reading_future_bytes() {
    let mut full = Journal::empty();
    for (index, boot) in (0..8).zip(1..=8) {
        let candidate = facts(if index % 2 == 0 { 1 } else { 2 });
        let pending = selector()
            .start_pending(full, Slot::A, candidate, boot)
            .expect("pending");
        full = selector()
            .confirm(pending.journal(), pending.token())
            .expect("confirmed");
    }
    let full_bytes = full.as_bytes();
    for count in 1..=16 {
        let mut prefix = [0u8; JOURNAL_LEN];
        prefix[..count * FRAME_LEN].copy_from_slice(&full_bytes[..count * FRAME_LEN]);
        let journal = Journal::from_bytes(&prefix).expect("fixed journal");
        assert!(!matches!(
            selector().recover(journal, verified()),
            BootDecision::Recovery
        ));
    }
}

#[test]
fn slot_is_only_placement_and_cannot_replace_facts() {
    let pending = selector()
        .start_pending(Journal::empty(), Slot::B, facts(1), 1)
        .expect("pending");
    assert_eq!(pending.slot(), Slot::B);
    assert_eq!(pending.candidate(), facts(1));
}

#[test]
fn untrusted_journal_needs_fresh_rebind_and_slot_swap_has_no_authority() {
    let pending = selector()
        .start_pending(Journal::empty(), Slot::B, facts(1), 1)
        .expect("pending");
    assert_eq!(
        selector().recover(pending.journal(), VerifiedCandidates::empty()),
        BootDecision::Recovery
    );
    assert_eq!(
        selector().recover(
            pending.journal(),
            VerifiedCandidates::from_verified(Some(facts(2)), None),
        ),
        BootDecision::Recovery
    );
    let frame = Frame {
        state: RecordState::Pending,
        slot: Slot::A,
        attempt: 1,
        record_seq: 0,
        boot_sequence: 1,
        claim: facts(1).claim(),
    };
    let swapped = bytes_with_frame(pending.journal(), 0, &frame);
    assert!(matches!(
        selector().recover(swapped, verified()),
        BootDecision::Pending(trial) if trial.slot() == Slot::A && trial.candidate() == facts(1)
    ));
}

#[test]
fn sequence_overflow_is_fail_closed() {
    let frame = Frame {
        state: RecordState::Pending,
        slot: Slot::A,
        attempt: 1,
        record_seq: u64::MAX,
        boot_sequence: 1,
        claim: facts(1).claim(),
    };
    let journal = bytes_with_frame(Journal::empty(), 0, &frame);
    assert_eq!(
        selector().recover(journal, verified()),
        BootDecision::Recovery
    );
    assert_eq!(
        super::selector::next_record_seq_for_test(Some(frame)),
        Err(SelectionError::Journal(JournalError::SequenceOverflow))
    );
    assert_eq!(journal.as_bytes().len(), JOURNAL_LEN);
}

#[test]
fn initial_confirmed_record_is_an_invalid_transition() {
    let frame = Frame {
        state: RecordState::Confirmed,
        slot: Slot::A,
        attempt: 1,
        record_seq: 0,
        boot_sequence: 1,
        claim: facts(1).claim(),
    };
    let journal = bytes_with_frame(Journal::empty(), 0, &frame);
    assert_eq!(
        selector().recover(journal, verified()),
        BootDecision::Recovery
    );
}
