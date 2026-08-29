//! Private binding from verified generation identity to native domains.

use spin::Mutex;

use astrid_system_generation::{ContentId, ManifestIdentity};

use super::manager;
#[cfg(not(test))]
use super::types::Scenario;
use super::types::{DomainHandle, SLOT_CAPACITY};

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
pub(crate) struct AdmittedIdentity {
    manifest_identity: ManifestIdentity,
    component_id: ContentId,
}

#[derive(Clone, Copy)]
struct AdmissionRecord {
    handle: DomainHandle,
    identity: AdmittedIdentity,
}

#[derive(Clone, Copy)]
struct AdmissionState {
    identity: Option<AdmittedIdentity>,
    records: [Option<AdmissionRecord>; SLOT_CAPACITY],
}

impl AdmissionState {
    const fn new() -> Self {
        Self {
            identity: None,
            records: [None; SLOT_CAPACITY],
        }
    }

    fn install(
        &mut self,
        manifest_identity: ManifestIdentity,
        component_id: ContentId,
    ) -> Result<(), AdmissionError> {
        if self.identity.is_some() {
            return Err(AdmissionError::AlreadyInstalled);
        }
        self.identity = Some(AdmittedIdentity {
            manifest_identity,
            component_id,
        });
        Ok(())
    }

    fn expected(&self, component_id: ContentId) -> Result<AdmittedIdentity, AdmissionError> {
        let identity = self.identity.ok_or(AdmissionError::Unverified)?;
        if identity.component_id != component_id {
            return Err(AdmissionError::ComponentMismatch);
        }
        Ok(identity)
    }

    fn record(&mut self, handle: DomainHandle, expected: AdmittedIdentity) {
        let slot = handle.id().0 as usize;
        if slot < SLOT_CAPACITY {
            self.records[slot] = Some(AdmissionRecord {
                handle,
                identity: expected,
            });
        }
    }

    fn bound_identity(
        &self,
        handle: DomainHandle,
        component_id: ContentId,
    ) -> Result<ManifestIdentity, AdmissionError> {
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
        Ok(record.identity.manifest_identity)
    }
}

static ADMISSIONS: Mutex<AdmissionState> = Mutex::new(AdmissionState::new());

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
pub(crate) fn install(
    manifest_identity: ManifestIdentity,
    component_id: ContentId,
) -> Result<(), AdmissionError> {
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
