use super::*;

#[test]
fn settlement_after_registration_is_observed_before_listener_is_polled() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let limiter = FuelRateLimiter::default();
    let owner = PrincipalId::new("service").unwrap();
    let mut held = limiter
        .try_reserve(&owner, 100, 100, Instant::now())
        .unwrap();
    let mut changed = std::pin::pin!(limiter.capacity_changed(&owner));
    assert!(
        limiter
            .try_reserve(&owner, 100, 1, Instant::now())
            .is_none()
    );
    held.settle(10, Instant::now());
    assert_eq!(
        changed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(())
    );
    assert!(
        limiter
            .try_reserve(&owner, 100, 90, Instant::now())
            .is_some()
    );
}

#[test]
fn maximum_budget_cannot_wrap_admission_into_extra_capacity() {
    let limiter = FuelRateLimiter::default();
    let owner = PrincipalId::new("service").unwrap();
    let now = Instant::now();
    let _all = limiter
        .try_reserve(&owner, u64::MAX, u64::MAX, now)
        .unwrap();
    assert!(limiter.try_reserve(&owner, u64::MAX, 1, now).is_none());
}

#[test]
fn recorded_plus_reserved_overflow_is_over_budget() {
    let limiter = FuelRateLimiter::default();
    let owner = PrincipalId::new("service").unwrap();
    let now = Instant::now();
    let _held = limiter.try_reserve(&owner, u64::MAX, 1, now).unwrap();
    limiter.record(&owner, u64::MAX, now);
    assert!(limiter.over_budget(&owner, u64::MAX, now));
}

#[test]
fn retry_hint_follows_the_actual_window_and_is_not_an_admission() {
    let limiter = FuelRateLimiter::default();
    let owner = PrincipalId::new("service").unwrap();
    let start = Instant::now();
    assert_eq!(limiter.replenishment_delay(&owner, start), Duration::ZERO);
    let mut held = limiter.try_reserve(&owner, 100, 100, start).unwrap();
    assert_eq!(limiter.replenishment_delay(&owner, start), WINDOW);
    assert_eq!(
        limiter.replenishment_delay(&owner, start + Duration::from_millis(250)),
        Duration::from_millis(750)
    );
    let next = start + WINDOW;
    assert_eq!(limiter.replenishment_delay(&owner, next), Duration::ZERO);
    assert!(limiter.try_reserve(&owner, 100, 1, next).is_none());
    assert_eq!(limiter.replenishment_delay(&owner, next), WINDOW);
    held.settle(0, next);
    assert!(limiter.try_reserve(&owner, 100, 100, next).is_some());
}
