//! Private binding from verified generation identity to native domains.

use spin::Mutex;

use astrid_system_generation::{ContentId, ManifestIdentity};

use super::manager;
use super::types::{DomainHandle, SLOT_CAPACITY};

#[cfg(not(test))]
use crate::closure::AdmittedGeneration;

#[cfg(not(test))]
use super::types::Scenario;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Unverified,
    AlreadyInstalled,
    ComponentMismatch,
    UnknownDomain,
    SubstitutedIdentity,
    StaleDomain,
}

impl AdmissionError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Unverified => "unverified_generation",
            Self::AlreadyInstalled => "generation_already_installed",
            Self::ComponentMismatch => "admission_component_mismatch",
            Self::UnknownDomain => "unknown_admitted_domain",
            Self::SubstitutedIdentity => "substituted_generation_identity",
            Self::StaleDomain => "stale_admitted_domain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedIdentity<G, C> {
    manifest_identity: G,
    component_id: C,
}

#[derive(Clone, Copy)]
struct AdmissionRecord<G, C> {
    handle: DomainHandle,
    identity: AdmittedIdentity<G, C>,
    live: bool,
}

#[derive(Clone, Copy)]
struct AdmissionState<G, C> {
    identity: Option<AdmittedIdentity<G, C>>,
    records: [Option<AdmissionRecord<G, C>>; SLOT_CAPACITY],
}

impl<G, C> AdmissionState<G, C>
where
    G: Copy + PartialEq,
    C: Copy + PartialEq,
{
    const fn new() -> Self {
        Self {
            identity: None,
            records: [None; SLOT_CAPACITY],
        }
    }

    fn install(&mut self, manifest_identity: G, component_id: C) -> Result<(), AdmissionError> {
        if self.identity.is_some() {
            return Err(AdmissionError::AlreadyInstalled);
        }
        self.identity = Some(AdmittedIdentity {
            manifest_identity,
            component_id,
        });
        Ok(())
    }

    fn expected(&self, component_id: C) -> Result<AdmittedIdentity<G, C>, AdmissionError> {
        let identity = self.identity.ok_or(AdmissionError::Unverified)?;
        if identity.component_id != component_id {
            return Err(AdmissionError::ComponentMismatch);
        }
        Ok(identity)
    }

    fn record(&mut self, handle: DomainHandle, expected: AdmittedIdentity<G, C>) {
        let slot = handle.id().0 as usize;
        if slot < SLOT_CAPACITY {
            self.records[slot] = Some(AdmissionRecord {
                handle,
                identity: expected,
                live: true,
            });
        }
    }

    fn bound_identity(&self, handle: DomainHandle, component_id: C) -> Result<G, AdmissionError> {
        let expected = self.expected(component_id)?;
        let slot = handle.id().0 as usize;
        if slot >= SLOT_CAPACITY {
            return Err(AdmissionError::UnknownDomain);
        }
        let Some(record) = self.records[slot] else {
            return Err(AdmissionError::UnknownDomain);
        };
        if record.handle != handle || record.identity != expected {
            return Err(AdmissionError::SubstitutedIdentity);
        }
        if !record.live {
            return Err(AdmissionError::StaleDomain);
        }
        Ok(record.identity.manifest_identity)
    }

    fn release(&mut self, handle: DomainHandle) {
        let slot = handle.id().0 as usize;
        if let Some(record) = self.records.get_mut(slot).and_then(Option::as_mut)
            && record.handle == handle
            && record.live
        {
            record.live = false;
        }
    }
}

static ADMISSIONS: Mutex<AdmissionState<ManifestIdentity, ContentId>> =
    Mutex::new(AdmissionState::new());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrepareError {
    Admission(AdmissionError),
    Domain(manager::PrepareError),
}

impl PrepareError {
    pub(crate) const fn as_reason(self) -> &'static str {
        match self {
            Self::Admission(error) => error.as_reason(),
            Self::Domain(error) => error.as_reason(),
        }
    }
}

#[cfg(not(test))]
pub(crate) fn install(admitted: &AdmittedGeneration) -> Result<(), AdmissionError> {
    let manifest_identity = admitted.manifest_identity();
    let component_id = admitted.component_id();
    let mut state = ADMISSIONS.lock();
    state.records = [None; SLOT_CAPACITY];
    state.install(manifest_identity, component_id)
}

#[cfg(not(test))]
pub(crate) fn prepare(
    raw: &[u8],
    expected_identity: ContentId,
    scenario: Scenario,
) -> Result<DomainHandle, PrepareError> {
    let expected = ADMISSIONS
        .lock()
        .expected(expected_identity)
        .map_err(PrepareError::Admission)?;
    let handle =
        manager::prepare(raw, expected_identity, scenario).map_err(PrepareError::Domain)?;
    ADMISSIONS.lock().record(handle, expected);
    Ok(handle)
}

#[cfg(not(test))]
pub(crate) fn confirm_start(
    handle: DomainHandle,
    expected_identity: ContentId,
) -> Result<ManifestIdentity, AdmissionError> {
    let manifest_identity = ADMISSIONS
        .lock()
        .bound_identity(handle, expected_identity)?;
    if manager::is_stale(handle) {
        return Err(AdmissionError::StaleDomain);
    }
    Ok(manifest_identity)
}

#[cfg(not(test))]
pub(crate) fn release(handle: DomainHandle) {
    ADMISSIONS.lock().release(handle);
}

#[cfg(test)]
mod tests {
    use super::super::types::{DomainGeneration, DomainHandle, DomainId, SLOT_CAPACITY};
    use super::{AdmissionError, AdmissionState, AdmittedIdentity};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestGeneration(u8);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestComponent(u8);

    const GENERATION_A: TestGeneration = TestGeneration(1);
    const GENERATION_B: TestGeneration = TestGeneration(2);
    const COMPONENT_A: TestComponent = TestComponent(3);
    const COMPONENT_B: TestComponent = TestComponent(4);

    fn handle(slot: u64, generation: u64) -> DomainHandle {
        DomainHandle::new(DomainId(slot), DomainGeneration(generation))
    }

    fn installed() -> AdmissionState<TestGeneration, TestComponent> {
        let mut state = AdmissionState::new();
        state.install(GENERATION_A, COMPONENT_A).unwrap();
        state
    }

    #[test]
    fn unverified_component_and_reinstall_are_rejected() {
        let mut state = AdmissionState::new();
        assert_eq!(state.expected(COMPONENT_A), Err(AdmissionError::Unverified));
        state.install(GENERATION_A, COMPONENT_A).unwrap();
        assert_eq!(
            state.install(GENERATION_B, COMPONENT_B),
            Err(AdmissionError::AlreadyInstalled)
        );
    }

    #[test]
    fn cross_generation_component_is_rejected() {
        let state = installed();
        assert_eq!(
            state.expected(COMPONENT_B),
            Err(AdmissionError::ComponentMismatch)
        );
    }

    #[test]
    fn unknown_or_substituted_handle_is_rejected() {
        let mut state = installed();
        assert_eq!(
            state.bound_identity(handle(0, 1), COMPONENT_A),
            Err(AdmissionError::UnknownDomain)
        );
        state.record(handle(0, 1), state.expected(COMPONENT_A).unwrap());
        assert_eq!(
            state.bound_identity(handle(0, 2), COMPONENT_A),
            Err(AdmissionError::SubstitutedIdentity)
        );
        assert_eq!(
            state.bound_identity(handle(1, 1), COMPONENT_A),
            Err(AdmissionError::UnknownDomain)
        );
    }

    #[test]
    fn split_record_tuple_is_rejected() {
        let mut state = installed();
        state.record(
            handle(0, 1),
            AdmittedIdentity {
                manifest_identity: GENERATION_B,
                component_id: COMPONENT_A,
            },
        );
        assert_eq!(
            state.bound_identity(handle(0, 1), COMPONENT_A),
            Err(AdmissionError::SubstitutedIdentity)
        );
    }

    #[test]
    fn released_handle_is_stale() {
        let mut state = installed();
        state.record(handle(0, 1), state.expected(COMPONENT_A).unwrap());
        state.release(handle(0, 1));
        assert_eq!(
            state.bound_identity(handle(0, 1), COMPONENT_A),
            Err(AdmissionError::StaleDomain)
        );
    }

    #[test]
    fn release_preserves_other_slots_and_ignores_substitutes() {
        let mut state = AdmissionState::new();
        state.install(GENERATION_A, COMPONENT_A).unwrap();
        state.record(handle(0, 1), state.expected(COMPONENT_A).unwrap());
        state.record(handle(1, 2), state.expected(COMPONENT_A).unwrap());
        state.release(handle(0, 2));
        assert_eq!(
            state.bound_identity(handle(0, 1), COMPONENT_A),
            Ok(GENERATION_A)
        );
        assert_eq!(
            state.bound_identity(handle(1, 2), COMPONENT_A),
            Ok(GENERATION_A)
        );
        assert!(SLOT_CAPACITY >= 2);
    }
}
