//! Fixed-capacity opaque identities and lifecycle states.

use astrid_system_generation::ContentId;

use crate::error::PlanError;

pub const DIGEST_LEN: usize = 32;
pub const MAX_SERVICES: usize = 8;
pub const MAX_START_ATTEMPTS: usize = 3;
/// The maximum number of readiness observations for one component.
pub const MAX_READINESS_POLLS: usize = 8;
/// The maximum number of driver calls in one lifecycle execution.
pub const MAX_STEPS: usize = 128;

type StartedMaskStorage = u8;
const STARTED_MASK_CAPACITY: usize = core::mem::size_of::<StartedMaskStorage>() * 8;

const _: () = assert!(MAX_SERVICES == STARTED_MASK_CAPACITY);

/// Tracks which component slots have been started and need teardown.
///
/// The storage width is intentionally private: changing it derives a new
/// capacity, and the assertion above requires `MAX_SERVICES` to match the
/// mask's representable range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StartedMask(StartedMaskStorage);

impl StartedMask {
    const LOWEST_BIT: StartedMaskStorage = 1;

    const fn bit(index: usize) -> Option<StartedMaskStorage> {
        if index < STARTED_MASK_CAPACITY {
            Some(Self::LOWEST_BIT << index)
        } else {
            None
        }
    }

    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) const fn contains(self, index: usize) -> bool {
        match Self::bit(index) {
            Some(bit) => self.0 & bit != 0,
            None => false,
        }
    }

    pub(crate) fn set(&mut self, index: usize) -> bool {
        let Some(bit) = Self::bit(index) else {
            return false;
        };
        self.0 |= bit;
        true
    }

    pub(crate) fn clear(&mut self, index: usize) -> bool {
        let Some(bit) = Self::bit(index) else {
            return false;
        };
        self.0 &= !bit;
        true
    }

    pub(crate) const fn reverse_indices(self, upper_bound: usize) -> StartedMaskIter {
        let next = if upper_bound < STARTED_MASK_CAPACITY {
            upper_bound
        } else {
            STARTED_MASK_CAPACITY
        };
        StartedMaskIter { mask: self, next }
    }
}

pub(crate) struct StartedMaskIter {
    mask: StartedMask,
    next: usize,
}

impl Iterator for StartedMaskIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next != 0 {
            self.next -= 1;
            if self.mask.contains(self.next) {
                return Some(self.next);
            }
        }
        None
    }
}

/// An opaque component identity selected by the already-trusted caller.
///
/// This type carries no path, principal, guest, or service policy data. It has
/// no public constructor: only the verified-generation adapter can create one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentId([u8; DIGEST_LEN]);

impl ComponentId {
    pub const fn as_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }

    pub(crate) const fn from_content_id(id: ContentId) -> Self {
        Self(id.as_bytes())
    }
}

/// A bounded, sorted, duplicate-free component list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentIds {
    values: [Option<ComponentId>; MAX_SERVICES],
    count: u8,
}

impl ComponentIds {
    pub(crate) fn from_array(
        values: [Option<ComponentId>; MAX_SERVICES],
        count: u8,
    ) -> Result<Self, PlanError> {
        if count == 0 {
            return Err(PlanError::ZeroServices);
        }
        if usize::from(count) > MAX_SERVICES {
            return Err(PlanError::TooManyServices);
        }
        let mut index = 0;
        while index < usize::from(count) {
            if values[index].is_none() {
                return Err(PlanError::InvalidComponentId);
            }
            if index != 0 {
                let Some(previous) = values[index - 1] else {
                    return Err(PlanError::InvalidComponentId);
                };
                let Some(current) = values[index] else {
                    return Err(PlanError::InvalidComponentId);
                };
                if previous == current {
                    return Err(PlanError::DuplicateServices);
                }
                if previous > current {
                    return Err(PlanError::UnsortedServices);
                }
            }
            index += 1;
        }
        while index < MAX_SERVICES {
            if values[index].is_some() {
                return Err(PlanError::TooManyServices);
            }
            index += 1;
        }
        Ok(Self { values, count })
    }

    pub const fn len(self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    pub const fn get(self, index: usize) -> Option<ComponentId> {
        if index >= self.count as usize {
            None
        } else {
            self.values[index]
        }
    }

    pub const fn iter(self) -> ComponentIdsIter {
        ComponentIdsIter {
            ids: self,
            index: 0,
        }
    }

    pub const fn as_array(self) -> [Option<ComponentId>; MAX_SERVICES] {
        self.values
    }
}

pub struct ComponentIdsIter {
    ids: ComponentIds,
    index: usize,
}

impl Iterator for ComponentIdsIter {
    type Item = ComponentId;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.ids.get(self.index);
        self.index += usize::from(value.is_some());
        value
    }
}

impl core::fmt::Debug for ComponentIdsIter {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentIdsIter")
            .finish_non_exhaustive()
    }
}

/// Lifecycle states exposed by the oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    Verified,
    Starting,
    ReadyUnpublished,
    Published,
    Stopping,
    Stopped,
    Failed,
}

impl LifecycleState {
    pub const fn admission_open(self) -> bool {
        matches!(self, Self::Published)
    }
}
