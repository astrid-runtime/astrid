//! The bounded init/recovery state machine.

use astrid_system_generation::{ManifestIdentity, VerifiedGeneration};

use crate::driver::{Readiness, ServiceDriver};
use crate::error::{LifecycleError, PlanError};
use crate::types::{
    ComponentId, ComponentIds, LifecycleState, MAX_READINESS_POLLS, MAX_SERVICES,
    MAX_START_ATTEMPTS, MAX_STEPS,
};

/// Fixed protocol/DoS ceilings and the per-run budgets selected under them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanLimits {
    start_attempts: usize,
    readiness_polls: usize,
    steps: usize,
}

impl PlanLimits {
    pub const fn default() -> Self {
        Self {
            start_attempts: MAX_START_ATTEMPTS,
            readiness_polls: MAX_READINESS_POLLS,
            steps: MAX_STEPS,
        }
    }

    pub fn try_new(
        start_attempts: usize,
        readiness_polls: usize,
        steps: usize,
    ) -> Result<Self, PlanError> {
        if start_attempts == 0 {
            return Err(PlanError::ZeroStartAttempts);
        }
        if start_attempts > MAX_START_ATTEMPTS {
            return Err(PlanError::TooManyStartAttempts);
        }
        if readiness_polls == 0 {
            return Err(PlanError::ZeroReadinessPolls);
        }
        if readiness_polls > MAX_READINESS_POLLS {
            return Err(PlanError::TooManyReadinessPolls);
        }
        if steps == 0 {
            return Err(PlanError::ZeroStepBudget);
        }
        if steps > MAX_STEPS {
            return Err(PlanError::TooManySteps);
        }
        Ok(Self {
            start_attempts,
            readiness_polls,
            steps,
        })
    }

    pub const fn start_attempts(self) -> usize {
        self.start_attempts
    }

    pub const fn readiness_polls(self) -> usize {
        self.readiness_polls
    }

    pub const fn steps(self) -> usize {
        self.steps
    }
}

impl Default for PlanLimits {
    fn default() -> Self {
        Self::default()
    }
}

/// A verified, bounded lifecycle plan. The verified input is intentionally
/// reduced to its manifest identity and opaque component IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitPlan {
    generation: ManifestIdentity,
    components: ComponentIds,
    limits: PlanLimits,
    state: LifecycleState,
    started_mask: u8,
    retire_pending: bool,
    steps: usize,
}

impl InitPlan {
    /// Build a plan from verifier-owned facts and the manifest's component set.
    pub fn try_from_verified(verified: VerifiedGeneration) -> Result<Self, PlanError> {
        Self::try_from_verified_with_limits(verified, PlanLimits::default())
    }

    pub fn try_from_verified_with_limits(
        verified: VerifiedGeneration,
        limits: PlanLimits,
    ) -> Result<Self, PlanError> {
        let manifest = verified.manifest();
        let count = manifest.components().count();
        if count == 0 {
            return Err(PlanError::ZeroServices);
        }
        if count > MAX_SERVICES {
            return Err(PlanError::TooManyServices);
        }
        let mut ids = [None; MAX_SERVICES];
        let mut index = 0;
        while index < count {
            let Some(content_id) = manifest.components().digest(index) else {
                return Err(PlanError::InvalidComponentId);
            };
            let component = ComponentId::from_content_id(content_id);
            if component.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(PlanError::InvalidComponentId);
            }
            if index != 0 {
                let Some(previous) = ids[index - 1] else {
                    return Err(PlanError::InvalidComponentId);
                };
                if previous == component {
                    return Err(PlanError::DuplicateServices);
                }
                if previous > component {
                    return Err(PlanError::UnsortedServices);
                }
            }
            ids[index] = Some(component);
            index += 1;
        }
        let components = ComponentIds::from_array(ids, count as u8)?;
        Ok(Self {
            generation: verified.manifest_identity(),
            components,
            limits,
            state: LifecycleState::Verified,
            started_mask: 0,
            retire_pending: false,
            steps: 0,
        })
    }

    pub const fn state(self) -> LifecycleState {
        self.state
    }

    pub const fn admission_open(self) -> bool {
        self.state.admission_open()
    }

    pub const fn generation_identity(self) -> ManifestIdentity {
        self.generation
    }

    pub const fn manifest_identity(self) -> ManifestIdentity {
        self.generation
    }

    pub const fn components(self) -> ComponentIds {
        self.components
    }

    pub const fn component_count(self) -> usize {
        self.components.len()
    }

    pub const fn component(self, index: usize) -> Option<ComponentId> {
        self.components.get(index)
    }

    pub const fn limits(self) -> PlanLimits {
        self.limits
    }

    /// Execute start, bounded readiness, and one all-services publication.
    pub fn run<D: ServiceDriver>(
        &mut self,
        driver: &mut D,
    ) -> Result<(), LifecycleError<D::Error>> {
        match self.state {
            LifecycleState::Verified => {},
            LifecycleState::Failed if self.started_mask == 0 && !self.retire_pending => {},
            LifecycleState::Failed => return Err(LifecycleError::InvalidState(self.state)),
            state => return Err(LifecycleError::InvalidState(state)),
        }

        self.state = LifecycleState::Starting;
        self.steps = 0;
        self.started_mask = 0;

        let mut index = 0;
        while index < self.components.len() {
            let Some(component) = self.components.get(index) else {
                return self.fail(driver, LifecycleError::StepBudgetExceeded);
            };
            let mut attempts = 0;
            let mut started = false;
            while attempts < self.limits.start_attempts {
                if let Err(error) = self.step::<D>() {
                    return self.fail(driver, error);
                }
                match driver.start(component) {
                    Ok(()) => {
                        started = true;
                        break;
                    },
                    Err(_) => attempts += 1,
                }
            }
            if !started {
                return self.fail(driver, LifecycleError::StartAttemptsExhausted { component });
            }
            self.started_mask |= 1 << index;
            index += 1;
        }

        index = 0;
        while index < self.components.len() {
            let Some(component) = self.components.get(index) else {
                return self.fail(driver, LifecycleError::StepBudgetExceeded);
            };
            let mut polls = 0;
            let mut ready = false;
            while polls < self.limits.readiness_polls {
                if let Err(error) = self.step::<D>() {
                    return self.fail(driver, error);
                }
                match driver.poll_readiness(component) {
                    Ok(Readiness::Ready) => {
                        ready = true;
                        break;
                    },
                    Ok(Readiness::Pending) => polls += 1,
                    Err(error) => {
                        return self.fail(
                            driver,
                            LifecycleError::Readiness {
                                component,
                                source: error,
                            },
                        );
                    },
                }
            }
            if !ready {
                return self.fail(driver, LifecycleError::ReadinessTimeout { component });
            }
            index += 1;
        }

        self.state = LifecycleState::ReadyUnpublished;
        if let Err(error) = self.step::<D>() {
            return self.fail(driver, error);
        }
        if let Err(error) = driver.publish_generation(self.generation) {
            return self.fail(driver, LifecycleError::Publish { source: error });
        }
        self.state = LifecycleState::Published;
        self.retire_pending = true;
        Ok(())
    }

    /// Replace a failed/stopped plan with a fresh caller-selected verified
    /// generation. Slot selection, storage lookup, and reconciliation remain
    /// outside this crate.
    pub fn recover<D: ServiceDriver>(
        &mut self,
        fresh: VerifiedGeneration,
        driver: &mut D,
    ) -> Result<(), LifecycleError<D::Error>> {
        if fresh.manifest_identity() == self.generation {
            return Err(LifecycleError::Plan(PlanError::StaleGeneration));
        }
        let replacement = Self::try_from_verified_with_limits(fresh, self.limits)
            .map_err(LifecycleError::Plan)?;
        if self.state == LifecycleState::Stopping {
            return Err(LifecycleError::Plan(PlanError::RecoveryWhileActive));
        }
        let needs_stop = matches!(
            self.state,
            LifecycleState::Published | LifecycleState::Starting | LifecycleState::ReadyUnpublished
        ) || (self.state == LifecycleState::Failed
            && (self.started_mask != 0 || self.retire_pending));
        if needs_stop {
            self.stop(driver)?;
        }
        *self = replacement;
        Ok(())
    }

    /// Retire a published generation and stop started services in reverse order.
    /// Calling this after `Stopped` or `Failed` is idempotent.
    pub fn stop<D: ServiceDriver>(
        &mut self,
        driver: &mut D,
    ) -> Result<(), LifecycleError<D::Error>> {
        match self.state {
            LifecycleState::Stopped => return Ok(()),
            LifecycleState::Failed if self.started_mask == 0 && !self.retire_pending => {
                return Ok(());
            },
            LifecycleState::Verified => {
                self.state = LifecycleState::Stopped;
                return Ok(());
            },
            LifecycleState::Starting
            | LifecycleState::ReadyUnpublished
            | LifecycleState::Published => {},
            LifecycleState::Failed => {},
            LifecycleState::Stopping => return Ok(()),
        }

        let was_published = self.state == LifecycleState::Published || self.retire_pending;
        self.state = LifecycleState::Stopping;
        self.steps = 0;
        let mut primary: Option<LifecycleError<D::Error>> = None;
        if was_published
            && let Err(error) = self.step::<D>().and_then(|_| {
                driver
                    .retire(self.generation)
                    .map_err(|error| LifecycleError::Retire { source: error })
            })
        {
            primary = Some(error);
        } else if was_published {
            self.retire_pending = false;
        }
        let mut index = self.components.len();
        while index != 0 {
            index -= 1;
            if self.started_mask & (1 << index) == 0 {
                continue;
            }
            let Some(component) = self.components.get(index) else {
                self.state = LifecycleState::Failed;
                continue;
            };
            if let Err(error) = self.step::<D>().and_then(|_| {
                driver
                    .stop(component)
                    .map_err(|error| LifecycleError::Stop {
                        component,
                        source: error,
                    })
            }) {
                self.state = LifecycleState::Failed;
                if primary.is_none() || matches!(&error, LifecycleError::StepBudgetExceeded) {
                    primary = Some(error);
                }
                if matches!(&primary, Some(LifecycleError::StepBudgetExceeded)) {
                    break;
                }
            } else {
                self.started_mask &= !(1 << index);
            }
        }
        if let Some(error) = primary {
            self.state = LifecycleState::Failed;
            return Err(error);
        }
        self.state = LifecycleState::Stopped;
        Ok(())
    }

    fn fail<D: ServiceDriver>(
        &mut self,
        driver: &mut D,
        error: LifecycleError<D::Error>,
    ) -> Result<(), LifecycleError<D::Error>> {
        self.state = LifecycleState::Failed;
        match self.cleanup(driver) {
            Err(LifecycleError::StepBudgetExceeded) => Err(LifecycleError::StepBudgetExceeded),
            _ => Err(error),
        }
    }

    fn cleanup<D: ServiceDriver>(
        &mut self,
        driver: &mut D,
    ) -> Result<(), LifecycleError<D::Error>> {
        self.state = LifecycleState::Stopping;
        let mut cleanup_error: Option<LifecycleError<D::Error>> = None;
        let mut index = self.components.len();
        while index != 0 {
            index -= 1;
            if self.started_mask & (1 << index) == 0 {
                continue;
            }
            let Some(component) = self.components.get(index) else {
                continue;
            };
            // Reserve the call before invoking the driver. If the budget is
            // exhausted, retain this bit and let a later recovery retry it.
            if let Err(error) = self.step::<D>() {
                cleanup_error = Some(error);
                break;
            }
            match driver.stop(component) {
                Ok(()) => self.started_mask &= !(1 << index),
                Err(error) if cleanup_error.is_none() => {
                    cleanup_error = Some(LifecycleError::Stop {
                        component,
                        source: error,
                    });
                },
                Err(_) => {},
            }
        }
        self.state = LifecycleState::Failed;
        match cleanup_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn step<D: ServiceDriver>(&mut self) -> Result<(), LifecycleError<D::Error>> {
        if self.steps >= self.limits.steps {
            return Err(LifecycleError::StepBudgetExceeded);
        }
        self.steps = self
            .steps
            .checked_add(1)
            .ok_or(LifecycleError::StepBudgetExceeded)?;
        Ok(())
    }
}
