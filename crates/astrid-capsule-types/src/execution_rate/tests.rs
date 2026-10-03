use super::*;

fn rate(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

#[test]
fn bulk_excess_survives_multiple_window_boundaries() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(
        ledger.charge(&1, rate(100), 450, now),
        Duration::from_secs(1)
    );
    for second in [1, 2] {
        assert_eq!(
            ledger.delay(&1, rate(100), now + Duration::from_secs(second)),
            Duration::from_secs(1)
        );
    }
    assert_eq!(
        ledger.delay(&1, rate(100), now + Duration::from_secs(3)),
        Duration::from_millis(500)
    );
    assert_eq!(
        ledger.delay(&1, rate(100), now + Duration::from_millis(3500)),
        Duration::ZERO
    );
}

#[test]
fn cloned_ledgers_share_debt_but_other_users_do_not() {
    let ledger = ExecutionRate::<u8>::default();
    let peer = ledger.clone();
    let now = Instant::now();
    assert_eq!(ledger.charge(&1, rate(100), 80, now), Duration::ZERO);
    assert_eq!(
        peer.charge(&1, rate(100), 80, now),
        Duration::from_millis(600)
    );
    assert_eq!(ledger.delay(&1, rate(100), now), Duration::from_millis(600));
    assert_eq!(peer.charge(&2, rate(100), 100, now), Duration::ZERO);
}

#[test]
fn stale_samples_cannot_mint_time_or_cancel_debt() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(
        ledger.charge(&1, rate(100), 200, now),
        Duration::from_secs(1)
    );
    assert_eq!(
        ledger.delay(&1, rate(100), now + Duration::from_millis(500)),
        Duration::from_millis(500)
    );
    assert_eq!(ledger.delay(&1, rate(100), now), Duration::from_millis(500));
    assert_eq!(
        ledger.delay(&1, rate(100), now + Duration::from_millis(500)),
        Duration::from_millis(500)
    );
}

#[test]
fn idle_time_cannot_bank_more_than_one_second() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(ledger.charge(&1, rate(100), 100, now), Duration::ZERO);
    assert_eq!(
        ledger.charge(&1, rate(100), 101, now + Duration::from_secs(100)),
        Duration::from_millis(10)
    );
}

#[test]
fn policy_changes_preserve_debt_and_use_old_rate_for_elapsed_time() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(
        ledger.charge(&1, rate(100), 200, now),
        Duration::from_secs(1)
    );
    assert_eq!(
        ledger.delay(&1, rate(200), now + Duration::from_millis(500)),
        Duration::from_millis(250)
    );
    assert_eq!(
        ledger.delay(&1, rate(200), now + Duration::from_millis(750)),
        Duration::ZERO
    );
}

#[test]
fn maximum_charge_at_minimum_rate_does_not_wrap_or_expire_after_one_second() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(
        ledger.charge(&1, rate(1), u64::MAX, now),
        Duration::from_secs(1)
    );
    assert_eq!(
        ledger.delay(&1, rate(1), now + Duration::from_secs(1)),
        Duration::from_secs(1)
    );
}

#[test]
fn fractional_repayment_is_not_rounded_away() {
    let ledger = ExecutionRate::<u8>::default();
    let now = Instant::now();
    assert_eq!(
        ledger.charge(&1, rate(3), 4, now),
        Duration::from_nanos(333_333_334)
    );
    assert_eq!(
        ledger.delay(&1, rate(3), now + Duration::from_nanos(333_333_333)),
        Duration::from_nanos(1)
    );
}

#[test]
fn zero_work_does_not_allocate_an_identity() {
    let ledger = ExecutionRate::<u64>::default();
    for key in 0..2_000 {
        assert_eq!(
            ledger.charge(&key, rate(100), 0, Instant::now()),
            Duration::ZERO
        );
    }
    assert!(ledger.balances.is_empty());
}

#[test]
fn churn_reclaims_repaid_identities_but_preserves_debt_and_partial_credit() {
    let ledger = ExecutionRate::<u64>::default();
    let now = Instant::now();
    for key in 0..2_000 {
        let _ = ledger.charge(&key, rate(100), 100, now);
    }
    let later = now + Duration::from_mins(2);
    let _ = ledger.charge(&2_001, rate(1), 1_000, now);
    // Partial credit is not disposable: eviction would mint another burst.
    let _ = ledger.charge(&2_002, rate(100), 50, later - Duration::from_millis(1));
    let _ = ledger.charge(&2_003, rate(100), 1, later);
    assert!(ledger.balances.len() < 10);
    assert_eq!(ledger.delay(&2_001, rate(1), later), Duration::from_secs(1));
    assert_eq!(
        ledger.charge(&2_002, rate(100), 100, later),
        Duration::from_millis(499)
    );
}

#[test]
fn stale_sample_after_eviction_cannot_mint_refill() {
    let ledger = ExecutionRate::<u64>::default();
    let now = Instant::now();
    for key in 0..2_000 {
        let _ = ledger.charge(&key, rate(100), 100, now);
    }
    let later = now + Duration::from_mins(2);
    let _ = ledger.charge(&2_001, rate(100), 1, later);
    assert!(!ledger.balances.contains_key(&0));
    assert_eq!(
        ledger.charge(&0, rate(100), 200, now),
        Duration::from_secs(1)
    );
    assert_eq!(ledger.delay(&0, rate(100), later), Duration::from_secs(1));
}
