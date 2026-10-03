//! Shared cooperative throttling. Measured overshoot is repaid, never discarded
//! by restarting a capsule or crossing a fixed-window boundary.

use super::UserCpuAllocation;
use astrid_capsule_types::execution_rate::ExecutionRate;
use astrid_core::PrincipalId;
use std::num::NonZeroU64;
use std::time::Duration;
use web_time::Instant;

/// Captured principal and user authority for a running guest. The runtime owns
/// sampling and must bound the delay between samples; this object owns debt.
#[derive(Clone)]
pub struct ExecutionThrottle {
    principal: PrincipalId,
    principal_limit: Option<NonZeroU64>,
    principals: ExecutionRate<PrincipalId>,
    user: Option<UserCpuAllocation>,
}

impl ExecutionThrottle {
    /// Whether an operator configured an aggregate user limit. Unconfigured
    /// personal runtimes retain their existing scheduler.
    #[must_use]
    pub(crate) fn has_user_limit(&self) -> bool {
        self.user.is_some()
    }

    /// Sample approximately one hundred times per allowance. This is a
    /// scheduling granularity, not a bound on a single guest operation.
    #[must_use]
    pub(crate) fn sampling_fuel(&self) -> u64 {
        let limit = self
            .principal_limit
            .into_iter()
            .chain(self.user.as_ref().map(|u| u.limit))
            .map(NonZeroU64::get)
            .min()
            .unwrap_or(u64::MAX);
        (limit / 100).max(1)
    }

    pub(super) fn new(
        principal: PrincipalId,
        principal_limit: Option<NonZeroU64>,
        principals: ExecutionRate<PrincipalId>,
        user: Option<UserCpuAllocation>,
    ) -> Self {
        Self {
            principal,
            principal_limit,
            principals,
            user,
        }
    }

    /// Charge the same observed fuel delta to both applicable authorities.
    /// The caller must not submit a cumulative counter more than once.
    pub fn charge(&self, fuel: u64) {
        let now = Instant::now();
        if let Some(limit) = self.principal_limit {
            let _ = self.principals.charge(&self.principal, limit, fuel, now);
        }
        if let Some(user) = &self.user {
            let _ = user.rate.charge(&user.user, user.limit, fuel, now);
        }
    }

    /// Current wait required by either authority. Zero is not a reservation:
    /// concurrent guests may accrue a bounded in-flight scheduling overshoot.
    #[must_use]
    pub fn delay(&self) -> Duration {
        let now = Instant::now();
        let principal = self.principal_limit.map_or(Duration::ZERO, |limit| {
            self.principals.delay(&self.principal, limit, now)
        });
        let user = self.user.as_ref().map_or(Duration::ZERO, |user| {
            user.rate.delay(&user.user, user.limit, now)
        });
        principal.max(user)
    }

    /// Await shared debt repayment without discarding guest state. Cancellation
    /// of this waiter does not erase already charged work.
    pub async fn wait(&self) {
        loop {
            let delay = self.delay();
            if delay.is_zero() {
                return;
            }
            astrid_runtime::time::sleep(delay).await;
        }
    }
}
