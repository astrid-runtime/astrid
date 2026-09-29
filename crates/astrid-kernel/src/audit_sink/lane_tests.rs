use super::*;

fn alice() -> PrincipalId {
    PrincipalId::new("alice").expect("alice")
}

fn bob() -> PrincipalId {
    PrincipalId::new("bob").expect("bob")
}

#[test]
fn coverage_records_stay_individual_and_overflow_commits_to_their_payload() {
    let now = Instant::now();
    let time = Timestamp::now();
    let a = alice();
    let action = |id: &str| AuditAction::ApprovalRequested {
        action_type: "connect".into(),
        resource: "example.com".into(),
        request_id: Some(id.into()),
        actor: None,
    };
    let call = |id: &str| Call {
        action: action(id),
        outcome: HostCallOutcome::Ok,
        detail: String::new(),
        at: time,
    };
    let mut lanes = Lanes::new(2, false);
    assert_eq!(lanes.push_call(&a, call("first"), now), Pushed::Queued);
    assert_eq!(lanes.push_call(&a, call("first"), now), Pushed::Queued);
    assert_eq!(lanes.push_call(&a, call("lost"), now), Pushed::Lost);
    let slots = lanes.take(3, now);
    assert_eq!(slots.len(), 3);
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(1));
    for slot in &slots[..2] {
        let (_, _, action, authorization, _) = slot.request(&session);
        assert!(matches!(action, AuditAction::ApprovalRequested { .. }));
        assert!(
            matches!(authorization, AuthorizationProof::System { reason } if reason == "approval gate")
        );
    }
    let (_, _, AuditAction::HostCallLoss { calls, .. }, _, _) = slots[2].request(&session) else {
        panic!("overflow must be a signed loss record");
    };
    let lost = action("lost");
    let original = HostCallRef {
        action: &lost,
        outcome: HostCallOutcome::Ok,
        detail: "",
        at: &time,
    };
    assert!(calls.matches_calls(&[original]));
    let altered = action("different");
    assert!(!calls.matches_calls(&[HostCallRef {
        action: &altered,
        ..original
    }]));
}

fn read(path: &str, outcome: HostCallOutcome) -> Call {
    Call {
        action: AuditAction::FileRead {
            actor: None,
            path: path.to_owned(),
        },
        outcome,
        detail: if outcome == HostCallOutcome::Ok {
            String::new()
        } else {
            "reason".to_owned()
        },
        at: Timestamp::now(),
    }
}

fn describe(slot: &Slot) -> String {
    let kind = match &slot.kind {
        SlotKind::Run { .. } => "run",
        SlotKind::Loss { .. } => "loss",
        SlotKind::Admit { .. } => "admit",
        SlotKind::Gap { .. } => "gap",
    };
    format!("{}:{kind}:{}", slot.principal, slot.calls())
}

#[test]
fn consecutive_calls_fold_and_denials_split_runs() {
    let now = Instant::now();
    let mut lanes = Lanes::new(64, false);
    let a = alice();
    assert_eq!(
        lanes.push_call(&a, read("/1", HostCallOutcome::Ok), now),
        Pushed::Queued
    );
    assert_eq!(
        lanes.push_call(&a, read("/2", HostCallOutcome::Failed), now),
        Pushed::Folded
    );
    assert_eq!(
        lanes.push_call(&a, read("/x", HostCallOutcome::Denied), now),
        Pushed::Queued
    );
    assert_eq!(
        lanes.push_call(&a, read("/x", HostCallOutcome::Denied), now),
        Pushed::Folded
    );
    assert_eq!(
        lanes.push_call(&a, read("/y", HostCallOutcome::Denied), now),
        Pushed::Queued
    );
    assert_eq!(
        lanes.push_call(&a, read("/3", HostCallOutcome::Ok), now),
        Pushed::Queued
    );
    let taken: Vec<_> = lanes.take(64, now).iter().map(describe).collect();
    assert_eq!(
        taken,
        ["alice:run:2", "alice:run:2", "alice:run:1", "alice:run:1"]
    );
}

#[test]
fn take_keeps_each_chain_in_fifo_order_and_interleaves_by_arrival() {
    let now = Instant::now();
    let mut lanes = Lanes::new(64, false);
    let (a, b) = (alice(), bob());
    lanes.push_call(&a, read("/a1", HostCallOutcome::Denied), now);
    lanes.push_call(&b, read("/b1", HostCallOutcome::Ok), now);
    lanes.push_call(&a, read("/a2", HostCallOutcome::Ok), now);
    lanes.push_call(&b, read("/b2", HostCallOutcome::Denied), now);
    let first: Vec<_> = lanes.take(3, now).iter().map(describe).collect();
    assert_eq!(first, ["alice:run:1", "bob:run:1", "alice:run:1"]);
    // The tail slot left behind stays open for folding.
    assert_eq!(
        lanes.push_call(&b, read("/b2", HostCallOutcome::Denied), now),
        Pushed::Folded
    );
    let rest: Vec<_> = lanes.take(3, now).iter().map(describe).collect();
    assert_eq!(rest, ["bob:run:2"]);
    assert_eq!(lanes.queued_slots(), 0);
    assert!(lanes.pending_since().is_none());
}

#[test]
fn full_queue_accounts_overflow_in_one_bounded_loss_slot_per_chain() {
    let now = Instant::now();
    let mut lanes = Lanes::new(2, false);
    let (a, b) = (alice(), bob());
    lanes.push_call(&a, read("/1", HostCallOutcome::Denied), now);
    lanes.push_call(&a, read("/2", HostCallOutcome::Denied), now);
    // Full: distinct denials go into one loss slot per chain.
    for index in 3..10 {
        assert_eq!(
            lanes.push_call(&a, read(&format!("/{index}"), HostCallOutcome::Denied), now),
            Pushed::Lost
        );
    }
    assert_eq!(
        lanes.push_call(&b, read("/b", HostCallOutcome::Denied), now),
        Pushed::Lost
    );
    assert_eq!(
        lanes.queued_slots(),
        4,
        "capacity plus one loss slot per chain"
    );
    assert_eq!(
        (lanes.accepted, lanes.queue_full, lanes.queued_calls),
        (10, 8, 10)
    );

    // A call that can fold into a queued run still needs no capacity.
    let mut roomy = Lanes::new(1, false);
    roomy.push_call(&a, read("/r1", HostCallOutcome::Ok), now);
    assert_eq!(
        roomy.push_call(&a, read("/r2", HostCallOutcome::Ok), now),
        Pushed::Folded
    );

    // Loss slots count against capacity until they are written.
    let taken: Vec<_> = lanes.take(8, now).iter().map(describe).collect();
    assert_eq!(
        taken,
        ["alice:run:1", "alice:run:1", "alice:loss:7", "bob:loss:1"]
    );
}

#[test]
fn call_after_freed_capacity_follows_the_loss_slot() {
    let now = Instant::now();
    let mut lanes = Lanes::new(4, false);
    let a = alice();
    for index in 1..10 {
        lanes.push_call(&a, read(&format!("/{index}"), HostCallOutcome::Denied), now);
    }
    let taken: Vec<_> = lanes.take(2, now).iter().map(describe).collect();
    assert_eq!(taken, ["alice:run:1", "alice:run:1"]);
    // Below capacity again: the next call opens a run behind the loss slot,
    // so the loss entry keeps its place in the chain.
    assert_eq!(
        lanes.push_call(&a, read("/after", HostCallOutcome::Ok), now),
        Pushed::Queued
    );
    let rest: Vec<_> = lanes.take(8, now).iter().map(describe).collect();
    assert_eq!(
        rest,
        ["alice:run:1", "alice:run:1", "alice:loss:5", "alice:run:1"]
    );
}

#[test]
fn loss_slot_becomes_a_signed_loss_entry() {
    let now = Instant::now();
    let mut lanes = Lanes::new(1, false);
    let a = alice();
    lanes.push_call(&a, read("/1", HostCallOutcome::Denied), now);
    lanes.push_call(&a, read("/2", HostCallOutcome::Denied), now);
    lanes.push_call(&a, read("/3", HostCallOutcome::Ok), now);
    let slots = lanes.take(8, now);
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(7));
    let (_, principal, action, authorization, outcome) = slots[1].request(&session);
    assert_eq!(principal, a);
    let AuditAction::HostCallLoss { calls, reason } = action else {
        panic!("expected a loss entry");
    };
    assert_eq!((calls.count, reason.as_str()), (2, QUEUE_FULL));
    assert!(matches!(authorization, AuthorizationProof::System { .. }));
    assert!(matches!(outcome, AuditOutcome::Failure { .. }));
}

#[test]
fn gap_slot_precedes_everything_queued_for_its_chain() {
    let now = Instant::now();
    let mut lanes = Lanes::new(8, true);
    let a = alice();
    lanes.push_call(&a, read("/early", HostCallOutcome::Ok), now);
    lanes.push_gap_front(
        &a,
        &GapDuty {
            epoch: "run-1".into(),
            opened_at: Timestamp::now(),
            chains: vec!["alice".into()],
            reason: "unclean_shutdown".into(),
        },
        now,
    );
    assert_eq!(
        lanes.take_unregistered(),
        std::slice::from_ref(&a),
        "registered once"
    );
    let taken: Vec<_> = lanes.take(8, now).iter().map(describe).collect();
    assert_eq!(taken, ["alice:gap:0", "alice:run:1"]);
}

#[test]
fn abandoned_admission_is_dropped_before_it_is_written() {
    let now = Instant::now();
    let mut lanes = Lanes::new(8, false);
    let a = alice();
    let ticket = Arc::new(AdmitTicket::new());
    assert!(lanes.push_admit(
        &a,
        AuditAction::ProcessSpawn {
            actor: None,
            command: "rm".into()
        },
        Arc::clone(&ticket),
        now
    ));
    assert!(lanes.urgent());
    assert!(ticket.wait(Duration::from_millis(1)).is_err(), "times out");
    // The writer later resolves it: the abandoned state sticks.
    ticket.resolve(Ok(()));
    assert!(ticket.wait(Duration::from_millis(1)).is_err());
    assert!(lanes.take(8, now).is_empty());
    assert!(!lanes.urgent());
}

#[test]
fn admission_resolves_waiter() {
    let ticket = Arc::new(AdmitTicket::new());
    let waiter = {
        let ticket = Arc::clone(&ticket);
        std::thread::spawn(move || ticket.wait(Duration::from_secs(10)))
    };
    ticket.resolve(Ok(()));
    assert_eq!(waiter.join().expect("waiter"), Ok(()));

    let failed = AdmitTicket::new();
    failed.resolve(Err("log full".into()));
    assert_eq!(failed.wait(Duration::from_secs(1)), Err("log full".into()));
}

#[test]
fn chain_with_a_waiting_admission_is_taken_first() {
    let now = Instant::now();
    let mut lanes = Lanes::new(64, false);
    let (a, b) = (alice(), bob());
    for index in 0..4 {
        lanes.push_call(
            &b,
            read(&format!("/b{index}"), HostCallOutcome::Denied),
            now,
        );
    }
    lanes.push_call(&a, read("/a", HostCallOutcome::Denied), now);
    lanes.push_admit(
        &a,
        AuditAction::ProcessSpawn {
            actor: None,
            command: "rm".into(),
        },
        Arc::new(AdmitTicket::new()),
        now,
    );
    lanes.push_call(&a, read("/a-after", HostCallOutcome::Ok), now);
    let first: Vec<_> = lanes.take(3, now).iter().map(describe).collect();
    assert_eq!(first, ["alice:run:1", "alice:admit:0", "bob:run:1"]);
    assert!(!lanes.urgent());
    let rest: Vec<_> = lanes.take(8, now).iter().map(describe).collect();
    assert_eq!(rest, ["bob:run:1", "bob:run:1", "bob:run:1", "alice:run:1"]);
}
