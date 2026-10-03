//! Joint admission: a principal exemption never waives its user's allocation.

use super::UserCpuAllocation;
use astrid_capsule_types::fuel_ledger::{FuelRateLimiter, FuelReservation};
use astrid_core::{PrincipalId, UserUid};
use std::num::NonZeroU64;
use web_time::Instant;

/// Captured authority for one execution. The caller resolves principal
/// exemptions before construction; zero retains the existing unlimited
/// principal convention, independently of the optional user limit.
pub struct ExecutionAllocation {
    principal: PrincipalId,
    principal_limit: u64,
    principal_ledger: FuelRateLimiter,
    user: Option<UserCpuAllocation>,
}

/// Both ceilings reserved before any guest instruction is admitted.
pub struct ExecutionReservation {
    principal: FuelReservation,
    user: Option<FuelReservation<UserUid>>,
}

/// Which authority refused an execution allowance.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutionDenied {
    /// Current principal capacity is already spent or reserved.
    #[error("principal exceeded in-flight CPU execution budget")]
    Principal,
    /// Current user capacity is already spent or reserved across principals.
    #[error("accountable user exceeded aggregate CPU execution budget")]
    User,
    /// This allowance cannot fit even in an empty window.
    #[error("execution allowance exceeds a configured CPU window")]
    AllowanceTooLarge,
}

impl ExecutionAllocation {
    /// Use the existing shared principal ledger, not a per-capsule replacement.
    #[must_use]
    pub fn new(
        principal: PrincipalId,
        principal_limit: u64,
        principal_ledger: FuelRateLimiter,
        user: Option<UserCpuAllocation>,
    ) -> Self {
        Self {
            principal,
            principal_limit,
            principal_ledger,
            user,
        }
    }

    /// Acquire both authorities without leaving a partial reservation on denial.
    ///
    /// # Errors
    /// Returns the refusing authority. No guest may execute on an error.
    pub fn try_reserve(&self, fuel: u64) -> Result<ExecutionReservation, ExecutionDenied> {
        let mut principal = self
            .principal_ledger
            .try_reserve(&self.principal, self.principal_limit, fuel, Instant::now())
            .ok_or(ExecutionDenied::Principal)?;
        let user = if let Some(allocation) = &self.user {
            match allocation.try_reserve(fuel) {
                Some(reservation) => Some(reservation),
                None => {
                    // No execution occurred; cancellation's conservative full
                    // charge would incorrectly spend another principal's budget.
                    principal.settle(0, Instant::now());
                    return Err(ExecutionDenied::User);
                },
            }
        } else {
            None
        };
        Ok(ExecutionReservation { principal, user })
    }

    /// Wait without retaining either partial allowance or restarting a service.
    ///
    /// # Errors
    /// An impossible allowance is rejected before waiting. The caller still
    /// must prove its execution quantum cannot exceed the granted amount.
    pub async fn reserve_when_available(
        &self,
        fuel: NonZeroU64,
    ) -> Result<ExecutionReservation, ExecutionDenied> {
        if (self.principal_limit != 0 && fuel.get() > self.principal_limit)
            || self
                .user
                .as_ref()
                .is_some_and(|user| fuel.get() > user.limit())
        {
            return Err(ExecutionDenied::AllowanceTooLarge);
        }
        loop {
            let denied = match self.try_reserve(fuel.get()) {
                Ok(reservation) => return Ok(reservation),
                Err(denied) => denied,
            };
            let now = Instant::now();
            let delay = match (&denied, &self.user) {
                (ExecutionDenied::User, Some(user)) => {
                    user.limiter.replenishment_delay(&user.user, now)
                },
                _ => self
                    .principal_ledger
                    .replenishment_delay(&self.principal, now),
            };
            astrid_runtime::time::sleep(delay).await;
        }
    }
}

impl ExecutionReservation {
    /// Settle both authorities to the same observed execution amount.
    /// Unsettled cancellation conservatively charges each full reservation.
    pub fn settle(&mut self, fuel: u64, now: Instant) {
        self.principal.settle(fuel, now);
        if let Some(user) = &mut self.user {
            user.settle(fuel, now);
        }
    }
}
