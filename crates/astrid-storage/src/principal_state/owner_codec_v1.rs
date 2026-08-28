use crate::engine::PrincipalCodec;
use astrid_core::PrincipalUid;

use super::StateOwner;

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
