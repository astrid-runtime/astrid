//! Opaque staging and fail-closed revalidation before native dispatch.

#[cfg(not(test))]
use astrid_system_generation::{ContentId, ManifestIdentity};

use super::admission;
use super::manager::{self, DomainState};
#[cfg(not(test))]
use super::stop::StopLifecycle;
use super::types::{BindError, DomainHandle, Scenario};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageError {
    Admission(admission::AdmissionError),
    Domain(manager::PrepareError),
    NotPrepared,
    ScenarioMismatch,
    StaleDomain,
    Releasing,
    ReleaseFailed,
    Stop(super::stop::StopError),
}

impl StageError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Admission(error) => error.as_reason(),
            Self::Domain(error) => error.as_reason(),
            Self::NotPrepared => "domain_not_prepared",
            Self::ScenarioMismatch => "domain_scenario_mismatch",
            Self::StaleDomain => "staged_domain_stale",
            Self::Releasing => "domain_releasing",
            Self::ReleaseFailed => "domain_release_failed",
            Self::Stop(error) => error.as_reason(),
        }
    }
}

/// The verifier-owned triad and manager context that authorize one dispatch.
/// Construction and mutation stay private to this module.
#[derive(Clone, Copy)]
pub(crate) struct StagedStart<G, C> {
    handle: DomainHandle,
    manifest_identity: G,
    component_id: C,
    scenario: Scenario,
    context: manager::StartContext,
}

impl<G, C> StagedStart<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    fn validate_identity(&self, manifest_identity: G, component_id: C) -> Result<(), StageError> {
        if manifest_identity != self.manifest_identity {
            return Err(StageError::Admission(
                admission::AdmissionError::SubstitutedIdentity,
            ));
        }
        if component_id != self.component_id {
            return Err(StageError::Admission(
                admission::AdmissionError::ComponentMismatch,
            ));
        }
        Ok(())
    }

    fn validate_observation_state(
        &self,
        state: DomainState,
        scenario: Scenario,
    ) -> Result<DomainState, StageError> {
        match state {
            DomainState::Prepared | DomainState::Running | DomainState::Blocked => {
                if scenario != self.scenario {
                    return Err(StageError::ScenarioMismatch);
                }
                Ok(state)
            },
            DomainState::Releasing => Err(StageError::Releasing),
            DomainState::Reclaimed => Err(StageError::StaleDomain),
            DomainState::ReleaseFailed => Err(StageError::ReleaseFailed),
        }
    }

    fn revalidate(
        &self,
        manifest_identity: G,
        component_id: C,
        state: DomainState,
        scenario: Scenario,
    ) -> Result<(), StageError> {
        match self.validate_observation_state(state, scenario)? {
            DomainState::Prepared => self.validate_identity(manifest_identity, component_id),
            _ => Err(StageError::NotPrepared),
        }
    }

    fn authorize_dispatch(
        &self,
        manifest_identity: G,
        component_id: C,
        state: DomainState,
        scenario: Scenario,
        context: manager::StartContext,
    ) -> Result<manager::StartContext, StageError> {
        self.revalidate(manifest_identity, component_id, state, scenario)?;
        if context != self.context {
            return Err(StageError::Domain(manager::PrepareError::Bind(
                BindError::Malformed,
            )));
        }
        Ok(context)
    }
}

#[cfg(not(test))]
impl StagedStart<ManifestIdentity, ContentId> {
    #[cfg(not(test))]
    pub(crate) fn observe(&self) -> Result<DomainState, StageError> {
        let observed = manager::staged_state(self.handle).map_err(StageError::Domain)?;
        let manifest_identity = admission::confirm_start(self.handle, self.component_id)
            .map_err(|error| self.classify_admission_error(error, observed))?;
        self.validate_identity(manifest_identity, self.component_id)?;
        let Some((state, scenario)) = observed else {
            return Err(StageError::Admission(
                admission::AdmissionError::StaleDomain,
            ));
        };
        self.validate_observation_state(state, scenario)
    }

    #[cfg(not(test))]
    fn classify_admission_error(
        &self,
        error: admission::AdmissionError,
        observed: Option<(DomainState, Scenario)>,
    ) -> StageError {
        match (error, observed) {
            (admission::AdmissionError::StaleDomain, Some((DomainState::Releasing, _))) => {
                StageError::Releasing
            },
            (admission::AdmissionError::StaleDomain, Some((DomainState::ReleaseFailed, _))) => {
                StageError::ReleaseFailed
            },
            (error, _) => StageError::Admission(error),
        }
    }
}

#[cfg(not(test))]
pub(crate) fn stage_start(
    handle: DomainHandle,
    component_id: ContentId,
    scenario: Scenario,
) -> Result<StagedStart<ManifestIdentity, ContentId>, StageError> {
    let manifest_identity =
        admission::confirm_start(handle, component_id).map_err(StageError::Admission)?;
    let context = manager::stage_context(handle, scenario).map_err(StageError::Domain)?;
    Ok(StagedStart {
        handle,
        manifest_identity,
        component_id,
        scenario,
        context,
    })
}

#[cfg(not(test))]
pub(crate) fn dispatch_start(
    staged: StagedStart<ManifestIdentity, ContentId>,
) -> Result<(), StageError> {
    if staged.observe()? != DomainState::Prepared {
        return Err(StageError::NotPrepared);
    }
    let stop = StopLifecycle::stage(
        staged.handle,
        staged.manifest_identity,
        staged.component_id,
        staged.scenario,
    )
    .map_err(StageError::Stop)?;
    let context =
        manager::stage_context(staged.handle, staged.scenario).map_err(StageError::Domain)?;
    staged.authorize_dispatch(
        staged.manifest_identity,
        staged.component_id,
        DomainState::Prepared,
        staged.scenario,
        context,
    )?;
    manager::start_running(
        staged.handle,
        context,
        stop,
        staged.manifest_identity,
        staged.component_id,
    )
    .map_err(StageError::Domain)?;
    if staged.observe()? != DomainState::Running {
        return Err(StageError::Domain(manager::PrepareError::Bind(
            BindError::Malformed,
        )));
    }
    manager::enter_running(staged.handle, context)
}

#[cfg(test)]
mod tests {
    use super::super::types::{DomainGeneration, DomainHandle, DomainId};
    use super::{StageError, StagedStart};
    use crate::domains::admission::AdmissionError;
    use crate::domains::manager::DomainState;
    use crate::domains::manager::PrepareError;
    use crate::domains::manager::StartContext;
    use crate::domains::types::BindError;
    use crate::domains::types::Scenario;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestGeneration(u8);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestComponent(u8);

    const GENERATION: TestGeneration = TestGeneration(1);
    const SUBSTITUTED: TestGeneration = TestGeneration(2);
    const COMPONENT: TestComponent = TestComponent(3);
    const MISMATCHED: TestComponent = TestComponent(4);

    fn handle() -> DomainHandle {
        DomainHandle::new(DomainId(0), DomainGeneration(1))
    }

    fn context(scenario: Scenario) -> StartContext {
        StartContext::new(scenario, 0x1000, 0x2000, 4, 0x3000)
    }

    fn staged(scenario: Scenario) -> StagedStart<TestGeneration, TestComponent> {
        StagedStart {
            handle: handle(),
            manifest_identity: GENERATION,
            component_id: COMPONENT,
            scenario,
            context: context(scenario),
        }
    }

    #[test]
    fn prepared_triad_and_scenario_revalidate() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.revalidate(GENERATION, COMPONENT, DomainState::Prepared, Scenario::Exit),
            Ok(())
        );
    }

    #[test]
    fn substituted_or_mismatched_triad_fails_before_transition() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.revalidate(
                SUBSTITUTED,
                COMPONENT,
                DomainState::Prepared,
                Scenario::Exit
            ),
            Err(StageError::Admission(
                crate::domains::admission::AdmissionError::SubstitutedIdentity
            ))
        );
        assert_eq!(
            staged.revalidate(
                GENERATION,
                MISMATCHED,
                DomainState::Prepared,
                Scenario::Exit
            ),
            Err(StageError::Admission(
                crate::domains::admission::AdmissionError::ComponentMismatch
            ))
        );
    }

    #[test]
    fn observation_accepts_only_authorized_live_states() {
        let staged = staged(Scenario::Exit);
        for (state, expected) in [
            (DomainState::Prepared, DomainState::Prepared),
            (DomainState::Running, DomainState::Running),
            (DomainState::Blocked, DomainState::Blocked),
        ] {
            assert_eq!(
                staged.validate_observation_state(state, Scenario::Exit),
                Ok(expected)
            );
        }
    }

    #[test]
    fn release_observation_failure_reasons_are_exact() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.validate_observation_state(DomainState::Releasing, Scenario::Exit),
            Err(StageError::Releasing)
        );
        assert_eq!(
            staged.validate_observation_state(DomainState::Reclaimed, Scenario::Exit),
            Err(StageError::StaleDomain)
        );
        assert_eq!(
            staged.validate_observation_state(DomainState::ReleaseFailed, Scenario::Exit),
            Err(StageError::ReleaseFailed)
        );
    }

    #[test]
    fn observation_scenario_mismatch_fails() {
        let staged = staged(Scenario::Exit);
        for state in [
            DomainState::Prepared,
            DomainState::Running,
            DomainState::Blocked,
        ] {
            assert_eq!(
                staged.validate_observation_state(state, Scenario::PageFault),
                Err(StageError::ScenarioMismatch)
            );
        }
    }

    #[test]
    fn observation_identity_equality_is_required() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.validate_identity(SUBSTITUTED, COMPONENT),
            Err(StageError::Admission(AdmissionError::SubstitutedIdentity))
        );
        assert_eq!(
            staged.validate_identity(GENERATION, MISMATCHED),
            Err(StageError::Admission(AdmissionError::ComponentMismatch))
        );
        assert_eq!(staged.validate_identity(GENERATION, COMPONENT), Ok(()));
    }

    #[test]
    fn dispatch_running_or_blocked_is_not_prepared() {
        let staged = staged(Scenario::Exit);
        for state in [DomainState::Running, DomainState::Blocked] {
            assert_eq!(
                staged.authorize_dispatch(
                    GENERATION,
                    COMPONENT,
                    state,
                    Scenario::Exit,
                    context(Scenario::Exit),
                ),
                Err(StageError::NotPrepared)
            );
        }
    }

    #[test]
    fn dispatch_release_states_fail_before_transition() {
        let staged = staged(Scenario::Exit);
        for (state, expected) in [
            (DomainState::Releasing, StageError::Releasing),
            (DomainState::Reclaimed, StageError::StaleDomain),
            (DomainState::ReleaseFailed, StageError::ReleaseFailed),
        ] {
            assert_eq!(
                staged.authorize_dispatch(
                    GENERATION,
                    COMPONENT,
                    state,
                    Scenario::Exit,
                    context(Scenario::Exit),
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn mismatched_dispatch_scenario_fails() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.revalidate(
                GENERATION,
                COMPONENT,
                DomainState::Prepared,
                Scenario::PageFault
            ),
            Err(StageError::ScenarioMismatch)
        );
    }

    #[test]
    fn reclaimed_dispatch_state_is_stale() {
        let staged = staged(Scenario::Exit);
        assert_eq!(
            staged.revalidate(
                GENERATION,
                COMPONENT,
                DomainState::Reclaimed,
                Scenario::Exit
            ),
            Err(StageError::StaleDomain)
        );
        assert_eq!(
            staged.revalidate(
                GENERATION,
                COMPONENT,
                DomainState::ReleaseFailed,
                Scenario::Exit
            ),
            Err(StageError::ReleaseFailed)
        );
    }

    #[test]
    fn dispatch_authorization_revalidates_state_and_context() {
        let staged = staged(Scenario::Exit);
        let current = context(Scenario::Exit);
        let substituted_context = context(Scenario::PageFault);

        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                COMPONENT,
                DomainState::Prepared,
                Scenario::Exit,
                current
            ),
            Ok(current)
        );
        assert_eq!(
            staged.authorize_dispatch(
                SUBSTITUTED,
                COMPONENT,
                DomainState::Prepared,
                Scenario::Exit,
                current
            ),
            Err(StageError::Admission(AdmissionError::SubstitutedIdentity))
        );
        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                MISMATCHED,
                DomainState::Prepared,
                Scenario::Exit,
                current
            ),
            Err(StageError::Admission(AdmissionError::ComponentMismatch))
        );
        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                COMPONENT,
                DomainState::Running,
                Scenario::Exit,
                current
            ),
            Err(StageError::NotPrepared)
        );
        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                COMPONENT,
                DomainState::Reclaimed,
                Scenario::Exit,
                current
            ),
            Err(StageError::StaleDomain)
        );
        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                COMPONENT,
                DomainState::Prepared,
                Scenario::PageFault,
                current
            ),
            Err(StageError::ScenarioMismatch)
        );
        assert_eq!(
            staged.authorize_dispatch(
                GENERATION,
                COMPONENT,
                DomainState::Prepared,
                Scenario::Exit,
                substituted_context
            ),
            Err(StageError::Domain(PrepareError::Bind(BindError::Malformed)))
        );
    }
}
