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
