//! Opaque staging and fail-closed revalidation before native dispatch.

#[cfg(not(test))]
use astrid_system_generation::{ContentId, ManifestIdentity};

use super::admission;
use super::manager::{self, DomainState};
use super::types::{BindError, DomainHandle, Scenario};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageError {
    Admission(admission::AdmissionError),
    Domain(manager::PrepareError),
    NotPrepared,
    ScenarioMismatch,
    StaleDomain,
}

impl StageError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Admission(error) => error.as_reason(),
            Self::Domain(error) => error.as_reason(),
            Self::NotPrepared => "domain_not_prepared",
            Self::ScenarioMismatch => "domain_scenario_mismatch",
            Self::StaleDomain => "staged_domain_stale",
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
    fn revalidate(
        &self,
        manifest_identity: G,
        component_id: C,
        state: DomainState,
        scenario: Scenario,
    ) -> Result<(), StageError> {
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
        match state {
            DomainState::Prepared => {
                if scenario != self.scenario {
                    return Err(StageError::ScenarioMismatch);
                }
            },
            DomainState::Running | DomainState::Blocked | DomainState::Releasing => {
                return Err(StageError::NotPrepared);
            },
            DomainState::Reclaimed | DomainState::ReleaseFailed => {
                return Err(StageError::StaleDomain);
            },
        }
        Ok(())
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
    let manifest_identity = admission::confirm_start(staged.handle, staged.component_id)
        .map_err(StageError::Admission)?;
    let (state, scenario) = manager::staged_state(staged.handle).map_err(StageError::Domain)?;
    let context =
        manager::stage_context(staged.handle, staged.scenario).map_err(StageError::Domain)?;
    let context = staged.authorize_dispatch(
        manifest_identity,
        staged.component_id,
        state,
        scenario,
        context,
    )?;
    manager::start_running(staged.handle, context).map_err(StageError::Domain)?;
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
    fn non_prepared_or_mismatched_dispatch_state_fails() {
        let staged = staged(Scenario::Exit);
        for state in [
            DomainState::Running,
            DomainState::Blocked,
            DomainState::Releasing,
        ] {
            assert_eq!(
                staged.revalidate(GENERATION, COMPONENT, state, Scenario::Exit),
                Err(StageError::NotPrepared)
            );
        }
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
        for state in [DomainState::Reclaimed, DomainState::ReleaseFailed] {
            assert_eq!(
                staged.revalidate(GENERATION, COMPONENT, state, Scenario::Exit),
                Err(StageError::StaleDomain)
            );
        }
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
