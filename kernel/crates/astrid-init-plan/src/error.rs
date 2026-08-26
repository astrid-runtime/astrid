//! Fail-closed construction and lifecycle errors.

use crate::types::{ComponentId, LifecycleState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    ZeroServices,
    TooManyServices,
    InvalidComponentId,
    DuplicateServices,
    UnsortedServices,
    ZeroStartAttempts,
    TooManyStartAttempts,
    ZeroReadinessPolls,
    TooManyReadinessPolls,
    ZeroStepBudget,
    TooManySteps,
    StaleGeneration,
    RecoveryWhileActive,
}

impl PlanError {
    pub const fn as_reason(self) -> &'static str {
        match self {
            Self::ZeroServices => "zero_services",
            Self::TooManyServices => "too_many_services",
            Self::InvalidComponentId => "invalid_component_id",
            Self::DuplicateServices => "duplicate_services",
            Self::UnsortedServices => "unsorted_services",
            Self::ZeroStartAttempts => "zero_start_attempts",
            Self::TooManyStartAttempts => "too_many_start_attempts",
            Self::ZeroReadinessPolls => "zero_readiness_polls",
            Self::TooManyReadinessPolls => "too_many_readiness_polls",
            Self::ZeroStepBudget => "zero_step_budget",
            Self::TooManySteps => "too_many_steps",
            Self::StaleGeneration => "stale_generation",
            Self::RecoveryWhileActive => "recovery_while_active",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LifecycleError<E> {
    Plan(PlanError),
    InvalidState(LifecycleState),
    StartAttemptsExhausted { component: ComponentId },
    ReadinessTimeout { component: ComponentId },
    StepBudgetExceeded,
    Readiness { component: ComponentId, source: E },
    Publish { source: E },
    Retire { source: E },
    Stop { component: ComponentId, source: E },
}

impl<E> LifecycleError<E> {
    pub const fn as_reason(&self) -> &'static str {
        match self {
            Self::Plan(_) => "plan",
            Self::InvalidState(_) => "invalid_state",
            Self::StartAttemptsExhausted { .. } => "start_attempts_exhausted",
            Self::ReadinessTimeout { .. } => "readiness_timeout",
            Self::StepBudgetExceeded => "step_budget_exceeded",
            Self::Readiness { .. } => "readiness",
            Self::Publish { .. } => "publish",
            Self::Retire { .. } => "retire",
            Self::Stop { .. } => "stop",
        }
    }
}
