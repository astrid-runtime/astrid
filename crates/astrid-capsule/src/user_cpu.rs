//! Shared user execution accounting, independent of fleet access and human sessions.

use astrid_capsule_types::execution_rate::ExecutionRate;
use astrid_capsule_types::fuel_ledger::{FuelRateLimiter, FuelReservation};
use astrid_core::{PrincipalId, UserUid};
use astrid_storage::{OwnershipStore, PrincipalDirectory};

pub mod execution;
pub mod throttle;

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
mod tests;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;

/// One kernel-wide ledger shared by every capsule runtime.
pub struct UserCpuAccounting {
    ownership: Arc<OwnershipStore>,
    directory: PrincipalDirectory,
    default_limit: Option<NonZeroU64>,
    user_limits: BTreeMap<UserUid, NonZeroU64>,
    limiter: FuelRateLimiter<UserUid>,
    principal_rate: ExecutionRate<PrincipalId>,
    user_rate: ExecutionRate<UserUid>,
}

/// Allocation pinned for one execution. A principal-level exemption cannot
/// change this independently configured user ceiling.
#[derive(Clone)]
pub struct UserCpuAllocation {
    user: UserUid,
    limit: NonZeroU64,
    limiter: FuelRateLimiter<UserUid>,
    rate: ExecutionRate<UserUid>,
}

/// An execution quantum which cannot fit within its configured allocation.
#[derive(Debug, thiserror::Error)]
#[error("execution allowance {requested} exceeds the user CPU window {limit}")]
pub struct UserCpuAllowanceTooLarge {
    requested: NonZeroU64,
    limit: NonZeroU64,
}

impl UserCpuAccounting {
    /// Construct the shared authority using validated operator configuration.
    #[must_use]
    pub fn new(
        ownership: Arc<OwnershipStore>,
        directory: PrincipalDirectory,
        default_limit: Option<NonZeroU64>,
        user_limits: BTreeMap<UserUid, NonZeroU64>,
    ) -> Self {
        Self {
            ownership,
            directory,
            default_limit,
            user_limits,
            limiter: FuelRateLimiter::default(),
            principal_rate: ExecutionRate::default(),
            user_rate: ExecutionRate::default(),
        }
    }

    /// Resolve current accountability, never the historical assigning user.
    ///
    /// # Errors
    /// Configured accounting fails closed on missing attribution or storage
    /// failure. Unconfigured personal installs retain their existing limits.
    pub async fn resolve(
        &self,
        principal: &PrincipalId,
    ) -> Result<Option<UserCpuAllocation>, String> {
        if self.default_limit.is_none() && self.user_limits.is_empty() {
            return Ok(None);
        }
        let uid = self
            .directory
            .uid_for(principal)
            .map_err(|error| error.to_string())?;
        let graph = self
            .ownership
            .load()
            .await
            .map_err(|error| error.to_string())?;
        let user = graph.accountable_user(uid).ok_or_else(|| format!(
            "principal '{principal}' needs explicit resource-user assignment before using configured user CPU budgets"
        ))?;
        Ok(self
            .user_limits
            .get(&user)
            .copied()
            .or(self.default_limit)
            .map(|limit| UserCpuAllocation {
                user,
                limit,
                limiter: self.limiter.clone(),
                rate: self.user_rate.clone(),
            }))
    }

    /// Capture both accounting authorities for resumable cooperative execution.
    /// A zero principal limit retains the existing exemption convention; it
    /// never exempts the independently configured accountable user.
    ///
    /// # Errors
    /// Configured user limits refuse missing or ambiguous attribution.
    pub async fn execution_throttle(
        &self,
        principal: &PrincipalId,
        principal_limit: u64,
    ) -> Result<throttle::ExecutionThrottle, String> {
        Ok(throttle::ExecutionThrottle::new(
            principal.clone(),
            NonZeroU64::new(principal_limit),
            self.principal_rate.clone(),
            self.resolve(principal).await?,
        ))
    }
}

impl UserCpuAllocation {
    /// Wait for a bounded execution allowance without terminating the guest.
    ///
    /// No reservation is held while sleeping, so a stopped/cancelled waiter
    /// neither spends fuel nor strands capacity. The caller must establish an
    /// upper bound on guest work before using this allowance; a Wasmtime yield
    /// interval alone is not such a bound.
    ///
    /// # Errors
    /// Refuses an allowance larger than the user's entire window instead of
    /// waiting forever for an impossible reservation.
    pub async fn reserve_when_available(
        &self,
        fuel: NonZeroU64,
    ) -> Result<FuelReservation<UserUid>, UserCpuAllowanceTooLarge> {
        if fuel.get() > self.limit.get() {
            return Err(UserCpuAllowanceTooLarge {
                requested: fuel,
                limit: self.limit,
            });
        }
        loop {
            let now = web_time::Instant::now();
            if let Some(reservation) =
                self.limiter
                    .try_reserve(&self.user, self.limit.get(), fuel.get(), now)
            {
                return Ok(reservation);
            }
            // try_reserve rolls an expired window before returning None. Its
            // outstanding reservations may still occupy the entire allowance;
            // waiting for the next window avoids a busy retry loop in that case.
            let delay = self.limiter.replenishment_delay(&self.user, now);
            astrid_runtime::time::sleep(delay).await;
        }
    }

    /// Aggregate execution ceiling in guest fuel units per second.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit.get()
    }

    /// Reserve before execution; all principals of this user share this ledger.
    #[must_use]
    pub fn try_reserve(&self, fuel: u64) -> Option<FuelReservation<UserUid>> {
        self.limiter
            .try_reserve(&self.user, self.limit.get(), fuel, web_time::Instant::now())
    }
}
