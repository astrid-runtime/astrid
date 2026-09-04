//! Canonical durable owner grammar and its runtime admission boundary.

use crate::engine::PrincipalCodec;
use crate::error::{StorageError, StorageResult};
use astrid_core::FleetUid;
use astrid_core::UserUid;
use astrid_core::identity::PrincipalUid;

/// Explicit owner of one durable state root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateOwner {
    /// Kernel-owned state that must not consume a user's storage quota.
    System,
    /// State owned by one validated Astrid principal.
    Principal(PrincipalUid),
    /// State shared by the admitted members of one user-owned fleet.
    Fleet(FleetUid),
    /// State owned by one validated human user.
    User(UserUid),
}

/// Frozen owner domain admitted by [`StateOwnerCodecV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateOwnerV1 {
    /// Kernel-owned state.
    System,
    /// State owned by one validated principal.
    Principal(PrincipalUid),
}

impl From<StateOwnerV1> for StateOwner {
    fn from(owner: StateOwnerV1) -> Self {
        match owner {
            StateOwnerV1::System => Self::System,
            StateOwnerV1::Principal(principal) => Self::Principal(principal),
        }
    }
}

/// Canonical codec for [`StateOwnerV1`].
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV1;

impl PrincipalCodec<StateOwnerV1> for StateOwnerCodecV1 {
    fn encode(&self, owner: &StateOwnerV1) -> Vec<u8> {
        match owner {
            StateOwnerV1::System => vec![0],
            StateOwnerV1::Principal(principal) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(1);
                bytes.extend_from_slice(principal.as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwnerV1> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwnerV1::System),
            (1, principal) if principal.len() == 32 => {
                let uid = PrincipalUid::from_bytes(<[u8; 32]>::try_from(principal).ok()?);
                Some(StateOwnerV1::Principal(uid))
            },
            _ => None,
        }
    }
}

/// Version-two canonical owner grammar with explicit fleet and user tags.
///
/// The version-one `System` and `Principal` encodings remain byte-for-byte
/// stable. Fleet ownership is tag `2` and human-user ownership is tag `3`;
/// neither is represented as a synthetic principal or hidden beneath system
/// authority. This pure codec is for explicit wire and specification tooling;
/// active runtime storage uses the private runtime codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV2;

impl PrincipalCodec<StateOwner> for StateOwnerCodecV2 {
    fn encode(&self, owner: &StateOwner) -> Vec<u8> {
        match owner {
            StateOwner::System => vec![0],
            StateOwner::Principal(principal) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(1);
                bytes.extend_from_slice(principal.as_bytes());
                bytes
            },
            StateOwner::Fleet(fleet) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(2);
                bytes.extend_from_slice(fleet.as_bytes());
                bytes
            },
            StateOwner::User(user) => {
                let mut bytes = Vec::with_capacity(33);
                bytes.push(3);
                bytes.extend_from_slice(user.as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwner> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwner::System),
            (1, principal) if principal.len() == 32 => {
                let uid = PrincipalUid::from_bytes(<[u8; 32]>::try_from(principal).ok()?);
                Some(StateOwner::Principal(uid))
            },
            (2, fleet) if fleet.len() == 32 => {
                let uid = FleetUid::from_bytes(<[u8; 32]>::try_from(fleet).ok()?);
                Some(StateOwner::Fleet(uid))
            },
            (3, user) if user.len() == 32 => {
                let uid = UserUid::from_bytes(<[u8; 32]>::try_from(user).ok()?);
                Some(StateOwner::User(uid))
            },
            _ => None,
        }
    }
}

mod runtime_codec {
    use super::{StateOwner, StateOwnerCodecV2};
    use crate::engine::{DurableError, PrincipalCodec};

    /// Active-runtime admission barrier over the complete V2 owner grammar.
    ///
    /// Accepted owners delegate to the pure V2 codec. Human users remain
    /// representable to explicit wire tooling but are not admitted to runtime
    /// durable storage or recovery until a separate authority freeze activates
    /// that domain. The private sibling module keeps this identity out of the
    /// public API while opaque projection aliases expose its supported views.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RuntimeStateOwnerCodecV2;

    impl PrincipalCodec<StateOwner> for RuntimeStateOwnerCodecV2 {
        fn encode(&self, owner: &StateOwner) -> Vec<u8> {
            match owner {
                // The infallible wire interface has no error channel. Canonical
                // validation rejects the empty owner before a record is written.
                StateOwner::User(_) => Vec::new(),
                StateOwner::System | StateOwner::Principal(_) | StateOwner::Fleet(_) => {
                    StateOwnerCodecV2.encode(owner)
                },
            }
        }

        fn decode(&self, bytes: &[u8]) -> Option<StateOwner> {
            StateOwnerCodecV2
                .decode(bytes)
                .filter(|owner| !matches!(owner, StateOwner::User(_)))
        }

        fn admit_principal(&self, owner: &StateOwner) -> Result<(), DurableError> {
            match owner {
                StateOwner::User(_) => Err(DurableError::UnsupportedPrincipal),
                StateOwner::System | StateOwner::Principal(_) | StateOwner::Fleet(_) => Ok(()),
            }
        }
    }
}

pub(crate) use runtime_codec::RuntimeStateOwnerCodecV2;

pub(crate) fn ensure_runtime_state_owner_admitted(owner: &StateOwner) -> StorageResult<()> {
    RuntimeStateOwnerCodecV2
        .admit_principal(owner)
        .map_err(|_| {
            StorageError::Internal(
                "user StateOwner is not admitted by runtime owner codec V2".to_owned(),
            )
        })
}
