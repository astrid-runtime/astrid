//! Typed identities and rows for the private relation projection.

use core::num::NonZeroU64;

/// Rows visible in one page. This is a private protocol ceiling, not a
/// configuration knob.
pub const RELATION_PAGE_ROWS: usize = 16;
/// Per-reader delta-ring ceiling. Losing older deltas is a resnapshot, never
/// an extrapolation.
pub const DELTA_RING_ENTRIES: usize = 32;
/// Matches the landed native-domain slot count.
pub const READER_SLOTS: usize = 2;
pub(crate) const MAX_RELATION_ROWS: usize = 64;
pub(crate) const MAX_OBJECT_OBSERVATIONS: usize = 16;

/// Opaque, kernel-assigned domain projection identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainProjectionToken(NonZeroU64);

impl DomainProjectionToken {
    pub(crate) const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Caller-known capability-table slot in the landed eight-slot domain table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilitySlot(u8);

impl CapabilitySlot {
    pub const fn try_new(value: usize) -> Option<Self> {
        if value < 8 {
            Some(Self(value as u8))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Projection view of the landed, distinct capability-object generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityGeneration(NonZeroU64);

impl CapabilityGeneration {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Opaque kernel-assigned endpoint or domain object identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectToken(NonZeroU64);

impl ObjectToken {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectKind {
    Domain,
    Endpoint,
}

/// Authority inputs that are not objects are represented only at this
/// projection boundary and deliberately produce no relation row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityObject {
    Domain(ObjectToken),
    Endpoint(ObjectToken),
    Message,
}

impl AuthorityObject {
    pub const fn relation_kind(self) -> Option<ObjectKind> {
        match self {
            Self::Domain(_) => Some(ObjectKind::Domain),
            Self::Endpoint(_) => Some(ObjectKind::Endpoint),
            Self::Message => None,
        }
    }

    pub const fn token(self) -> Option<ObjectToken> {
        match self {
            Self::Domain(token) | Self::Endpoint(token) => Some(token),
            Self::Message => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectRef {
    kind: ObjectKind,
    token: ObjectToken,
}

impl ObjectRef {
    pub const fn new(kind: ObjectKind, token: ObjectToken) -> Self {
        Self { kind, token }
    }

    pub const fn kind(self) -> ObjectKind {
        self.kind
    }

    pub const fn token(self) -> ObjectToken {
        self.token
    }
}

/// Projection view of the landed rights bits. No relation-only right exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationRights(u16);

impl RelationRights {
    pub const SEND: Self = Self(1);
    pub const RECV: Self = Self(2);
    pub const GRANT: Self = Self(4);
    pub const IDENTIFY: Self = Self(8);
    pub(crate) const ALL_BITS: u16 = 15;

    pub const fn from_landed(bits: u16) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 && bits != 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// Full exported capability-instance identity, including all three components
/// needed to distinguish reuse across domains and object generations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityInstance {
    domain: DomainProjectionToken,
    slot: CapabilitySlot,
    generation: CapabilityGeneration,
}

impl CapabilityInstance {
    pub const fn new(
        domain: DomainProjectionToken,
        slot: CapabilitySlot,
        generation: CapabilityGeneration,
    ) -> Self {
        Self {
            domain,
            slot,
            generation,
        }
    }

    pub const fn domain(self) -> DomainProjectionToken {
        self.domain
    }

    pub const fn slot(self) -> CapabilitySlot {
        self.slot
    }

    pub const fn generation(self) -> CapabilityGeneration {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelationKey {
    Object {
        scope: DomainProjectionToken,
        object: ObjectRef,
    },
    Holds {
        scope: DomainProjectionToken,
        capability: CapabilityInstance,
        object: ObjectRef,
    },
    Derives {
        scope: DomainProjectionToken,
        parent: CapabilityInstance,
        child: CapabilityInstance,
    },
}

impl RelationKey {
    pub const fn scope(self) -> DomainProjectionToken {
        match self {
            Self::Object { scope, .. }
            | Self::Holds { scope, .. }
            | Self::Derives { scope, .. } => scope,
        }
    }

    pub(crate) const fn object_tokens(self) -> [Option<ObjectToken>; 2] {
        match self {
            Self::Object { object, .. } => [Some(object.token()), None],
            Self::Holds { object, .. } => [Some(object.token()), None],
            Self::Derives { .. } => [None, None],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationState {
    Object,
    Holds { rights: RelationRights },
    Derives,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relation {
    key: RelationKey,
    state: RelationState,
}

impl Relation {
    pub const fn object(scope: DomainProjectionToken, object: ObjectRef) -> Self {
        Self {
            key: RelationKey::Object { scope, object },
            state: RelationState::Object,
        }
    }

    pub const fn holds(
        scope: DomainProjectionToken,
        capability: CapabilityInstance,
        object: ObjectRef,
        rights: RelationRights,
    ) -> Self {
        Self {
            key: RelationKey::Holds {
                scope,
                capability,
                object,
            },
            state: RelationState::Holds { rights },
        }
    }

    pub const fn derives(
        scope: DomainProjectionToken,
        parent: CapabilityInstance,
        child: CapabilityInstance,
    ) -> Self {
        Self {
            key: RelationKey::Derives {
                scope,
                parent,
                child,
            },
            state: RelationState::Derives,
        }
    }

    pub const fn key(self) -> RelationKey {
        self.key
    }

    pub const fn state(self) -> RelationState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationChange {
    Upsert(Relation),
    Delete(RelationKey),
}

impl RelationChange {
    pub(crate) const fn key(self) -> RelationKey {
        match self {
            Self::Upsert(relation) => relation.key(),
            Self::Delete(key) => key,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimOutcome {
    ReleaseFailed,
    ReclaimBlocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimObservation {
    scope: DomainProjectionToken,
    object: ObjectToken,
    outcome: ReclaimOutcome,
}

impl ReclaimObservation {
    pub const fn new(
        scope: DomainProjectionToken,
        object: ObjectToken,
        outcome: ReclaimOutcome,
    ) -> Self {
        Self {
            scope,
            object,
            outcome,
        }
    }

    pub const fn scope(self) -> DomainProjectionToken {
        self.scope
    }

    pub const fn object(self) -> ObjectToken {
        self.object
    }

    pub const fn outcome(self) -> ReclaimOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    Denied,
    NoSpace,
    Resurrection,
    ReaderSlotsExhausted,
    ResnapshotRequired,
}
