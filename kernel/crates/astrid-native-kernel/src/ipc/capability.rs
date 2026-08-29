//! Opaque per-domain capability slots and fixed capability accounting.

use core::num::NonZeroU64;

use super::abi::CAP_SLOTS_PER_DOMAIN;
use super::error::IpcError;

pub(crate) const DOMAIN_SLOTS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DomainToken {
    slot: CapSlot,
    generation: NonZeroU64,
}

impl DomainToken {
    pub(crate) fn new(slot: u64, generation: u64) -> Option<Self> {
        let slot = CapSlot::try_new(slot as usize).ok()?;
        Some(Self {
            slot,
            generation: NonZeroU64::new(generation)?,
        })
    }

    pub(crate) const fn slot(self) -> CapSlot {
        self.slot
    }

    pub(crate) const fn generation(self) -> NonZeroU64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CapSlot(u8);

impl CapSlot {
    pub(crate) const fn try_new(value: usize) -> Result<Self, IpcError> {
        if value < CAP_SLOTS_PER_DOMAIN {
            Ok(Self(value as u8))
        } else {
            Err(IpcError::Malformed)
        }
    }

    pub(crate) const fn get(self) -> u8 {
        self.0
    }

    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rights(u16);

impl Rights {
    pub(crate) const SEND: Self = Self(1);
    pub(crate) const RECV: Self = Self(2);
    pub(crate) const GRANT: Self = Self(4);
    pub(crate) const IDENTIFY: Self = Self(8);
    pub(crate) const ALL: Self = Self(15);

    pub(crate) const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 && bits != 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub(crate) const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub(crate) const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(crate) const fn bits(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerivationLink {
    pub(crate) domain: DomainToken,
    pub(crate) slot: CapSlot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capability {
    pub(crate) endpoint: super::EndpointId,
    pub(crate) rights: Rights,
    pub(crate) generation: super::ObjectGeneration,
    pub(crate) parent: Option<DerivationLink>,
}

#[derive(Clone, Copy)]
pub(super) struct CapTable {
    owner: Option<DomainToken>,
    slots: [Option<Capability>; CAP_SLOTS_PER_DOMAIN],
}

impl CapTable {
    pub(super) const fn unowned() -> Self {
        Self {
            owner: None,
            slots: [None; CAP_SLOTS_PER_DOMAIN],
        }
    }

    pub(super) fn reset(&mut self, owner: DomainToken) {
        self.owner = Some(owner);
        self.slots = [None; CAP_SLOTS_PER_DOMAIN];
    }

    pub(super) const fn owner(&self) -> Option<DomainToken> {
        self.owner
    }

    pub(super) fn get(&self, domain: DomainToken, slot: CapSlot) -> Option<Capability> {
        if self.owner == Some(domain) {
            self.slots[slot.index()]
        } else {
            None
        }
    }

    pub(super) fn install(
        &mut self,
        domain: DomainToken,
        slot: CapSlot,
        capability: Capability,
    ) -> Result<(), IpcError> {
        if self.owner != Some(domain) || self.slots[slot.index()].is_some() {
            return Err(IpcError::NoSpace);
        }
        self.slots[slot.index()] = Some(capability);
        Ok(())
    }

    pub(super) fn remove(&mut self, domain: DomainToken, slot: CapSlot) -> Option<Capability> {
        if self.owner != Some(domain) {
            return None;
        }
        self.slots[slot.index()].take()
    }

    pub(super) fn free_slot(&self, domain: DomainToken) -> Option<CapSlot> {
        if self.owner != Some(domain) {
            return None;
        }
        (0..CAP_SLOTS_PER_DOMAIN)
            .map(CapSlot::try_new)
            .filter_map(Result::ok)
            .find(|slot| self.slots[slot.index()].is_none())
    }

    pub(super) fn count(&self, domain: DomainToken) -> usize {
        if self.owner != Some(domain) {
            return 0;
        }
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub(super) fn capability_at(&self, index: usize) -> Option<Capability> {
        self.slots.get(index).copied().flatten()
    }

    pub(super) fn remove_index(&mut self, domain: DomainToken, index: usize) -> bool {
        if self.owner != Some(domain) {
            return false;
        }
        self.slots.get_mut(index).map(Option::take).is_some()
    }
}
