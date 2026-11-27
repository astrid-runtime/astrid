//! Principal root identity and generation.
use super::ObjectId;
use vstd::prelude::*;

verus! {
/// Monotonic generation of one principal root.
///
/// A generation is scoped by principal and advances only after a successful
/// compare-and-swap. The newtype prevents generations from being confused
/// with byte counts, epochs, or other numeric storage fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootGeneration(u64);

impl RootGeneration {
    pub closed spec fn value(self) -> u64 { self.0 }

    pub(crate) proof fn same_value(self,other:Self)
        requires self.value() == other.value(), ensures self == other,
    {}

    /// Construct a root generation from its persisted value.
    #[must_use]
    pub const fn new(value: u64) -> (generation:Self) ensures generation.value() == value {
        Self(value)
    }

    /// Return the persisted numeric generation.
    #[must_use]
    pub const fn get(self) -> (n:u64) ensures n == self.value() {
        self.0
    }

    /// Advance to the next generation.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// Current committed root of a principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootState {
    /// Monotonically increasing compare-and-swap generation.
    pub generation: RootGeneration,
    /// Immutable commit object naming the principal state.
    pub commit: ObjectId,
}

impl RootState {
    /// Compare the generation and full immutable commit identity.
    pub(crate) fn same(self,other:Self) -> (equal:bool)
        ensures equal == (self == other),
    {
        if self.generation.get() != other.generation.get() ||
            self.commit.as_bytes().as_slice() != other.commit.as_bytes().as_slice() { return false; }
        proof {
            self.generation.same_value(other.generation);
            assert(self.commit.digest() =~= other.commit.digest());
            ObjectId::same_digest(self.commit,other.commit);
        }
        true
    }
}
}

impl RootGeneration {
    /// Generation assigned to a principal's first committed root.
    pub const INITIAL: Self = Self(0);
}
