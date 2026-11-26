//! Enforce idle time across wall-clock changes and retain the wire expiry.
use super::lease_authority::callback::ClockObservation;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IDLE_TIMEOUT: Duration = Duration::from_hours(1);

#[derive(Clone, Copy)]
struct Clock {
    monotonic: Instant,
    wall: SystemTime,
}

impl Clock {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    fn epoch_secs(self) -> Option<u64> {
        Some(self.wall.duration_since(UNIX_EPOCH).ok()?.as_secs())
    }
}

struct Deadline {
    monotonic: Option<Instant>,
    epoch_secs: u64,
}

impl Deadline {
    fn from_clock(now: Clock) -> Option<Self> {
        Some(Self {
            monotonic: Some(now.monotonic.checked_add(IDLE_TIMEOUT)?),
            epoch_secs: now.epoch_secs()?.checked_add(IDLE_TIMEOUT.as_secs())?,
        })
    }

    fn live(&mut self, now: Clock) -> bool {
        let observation = ClockObservation {
            within_idle: self.monotonic.is_some_and(|end| now.monotonic <= end),
            now: now.epoch_secs(),
            expires: self.epoch_secs,
        };
        if observation.permits() {
            return true;
        }
        self.monotonic = None;
        false
    }

    fn renew(&mut self, now: Clock) {
        if self.live(now) {
            if let Some(next) = Self::from_clock(now) {
                *self = next;
            } else {
                self.monotonic = None;
            }
        }
    }
}

pub(super) struct LeaseExpiry(Mutex<Deadline>);

impl LeaseExpiry {
    pub(super) fn new() -> Result<Self, String> {
        Deadline::from_clock(Clock::now())
            .map(|deadline| Self(Mutex::new(deadline)))
            .ok_or_else(|| "cannot establish the native mount lease deadline".to_owned())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Deadline> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn live(&self) -> bool {
        self.lock().live(Clock::now())
    }

    pub(super) fn renew(&self) {
        self.lock().renew(Clock::now());
    }

    pub(super) fn epoch_secs(&self) -> u64 {
        self.lock().epoch_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> Clock {
        Clock {
            monotonic: Instant::now(),
            wall: UNIX_EPOCH
                .checked_add(Duration::from_secs(100_000))
                .unwrap(),
        }
    }

    #[test]
    fn backward_wall_time_cannot_extend_idle_time_or_revive_a_lease() {
        let start = clock();
        let mut deadline = Deadline::from_clock(start).unwrap();
        let late = Clock {
            monotonic: start.monotonic + IDLE_TIMEOUT + Duration::from_secs(1),
            wall: start.wall - Duration::from_secs(10),
        };
        assert!(!deadline.live(late));
        deadline.renew(late);
        assert!(!deadline.live(late));
    }

    #[test]
    fn missing_wall_time_refuses_issuance_and_permanently_closes_a_sampled_lease() {
        let start = clock();
        let missing = Clock {
            wall: UNIX_EPOCH - Duration::from_secs(1),
            ..start
        };
        assert!(Deadline::from_clock(missing).is_none());
        let mut deadline = Deadline::from_clock(start).unwrap();
        deadline.renew(missing);
        assert!(!deadline.live(start));
    }

    #[test]
    fn renewal_moves_both_deadlines_and_keeps_the_advertised_cutoff() {
        let start = clock();
        let mut deadline = Deadline::from_clock(start).unwrap();
        let active = Clock {
            monotonic: start.monotonic + IDLE_TIMEOUT,
            wall: start.wall + IDLE_TIMEOUT,
        };
        deadline.renew(active);
        assert_eq!(
            deadline.epoch_secs,
            active.epoch_secs().unwrap() + IDLE_TIMEOUT.as_secs()
        );
        assert!(deadline.live(Clock {
            monotonic: active.monotonic + IDLE_TIMEOUT,
            ..active
        }));
        let after_wall = Clock {
            wall: active.wall + IDLE_TIMEOUT + Duration::from_secs(1),
            ..active
        };
        assert!(!deadline.live(after_wall));
        assert!(!deadline.live(active));
    }
}
