use crate::engine::PrincipalCodec;
use astrid_core::{FleetUid, PrincipalUid, UserUid};

use super::StateOwner;

/// Version-three canonical owner grammar with an explicit user tag.
///
/// The version-one and version-two encodings remain byte-for-byte stable.
/// Human-user ownership is appended under tag `3`; it is never represented
/// as a synthetic principal or conflated with system authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV3;

impl PrincipalCodec<StateOwner> for StateOwnerCodecV3 {
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
