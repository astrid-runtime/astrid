//! Portable owner references.

use crate::{
    CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError,
    encoding::{check_header, write_header},
};

/// Owner named by a portable resource descriptor.
///
/// Principal and fleet bytes are lossless references to the existing Astrid
/// identity types. This crate intentionally does not define another principal
/// or fleet UID type. [`OwnerId`] is descriptive data, never proof that its
/// holder controls the named owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OwnerId {
    /// Kernel-owned system state.
    System,
    /// Existing `astrid_core::PrincipalUid` bytes.
    Principal([u8; 32]),
    /// Existing `astrid_core::FleetUid` bytes.
    Fleet([u8; 32]),
}

impl OwnerId {
    /// Canonical encoding size: header, owner class and 32-byte payload.
    pub const ENCODED_LEN: usize = 36;

    /// Construct a principal owner reference from UID bytes.
    #[must_use]
    pub const fn principal(bytes: [u8; 32]) -> Self {
        Self::Principal(bytes)
    }

    /// Construct a fleet owner reference from UID bytes.
    #[must_use]
    pub const fn fleet(bytes: [u8; 32]) -> Self {
        Self::Fleet(bytes)
    }
}

impl CanonicalEncode for OwnerId {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError> {
        write_header(output, Self::ENCODED_LEN, CanonicalTypeTag::OwnerId)?;
        output[3..].fill(0);
        match self {
            Self::System => output[3] = 0,
            Self::Principal(bytes) => {
                output[3] = 1;
                output[4..36].copy_from_slice(bytes);
            },
            Self::Fleet(bytes) => {
                output[3] = 2;
                output[4..36].copy_from_slice(bytes);
            },
        }
        Ok(())
    }
}

impl CanonicalDecode for OwnerId {
    fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError> {
        check_header(input, Self::ENCODED_LEN, CanonicalTypeTag::OwnerId)?;
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&input[4..36]);
        match input[3] {
            0 if bytes == [0; 32] => Ok(Self::System),
            0 => Err(EncodingError::NonCanonical),
            1 => Ok(Self::Principal(bytes)),
            2 => Ok(Self::Fleet(bytes)),
            value => Err(EncodingError::UnknownDiscriminant(u16::from(value))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_golden_vectors() {
        let owner = OwnerId::Principal([0x5a; 32]);
        let mut encoded = [0_u8; OwnerId::ENCODED_LEN];
        owner.encode_canonical(&mut encoded).unwrap();
        let mut expected = [0x5a; OwnerId::ENCODED_LEN];
        expected[0] = 1;
        expected[1] = 20;
        expected[2] = 0;
        expected[3] = 1;
        assert_eq!(encoded, expected);
        assert_eq!(OwnerId::decode_canonical(&encoded), Ok(owner));

        OwnerId::System.encode_canonical(&mut encoded).unwrap();
        assert_eq!(
            encoded,
            [
                1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn owner_rejects_noncanonical_system_and_unknown_tag() {
        let mut input = [0_u8; OwnerId::ENCODED_LEN];
        input[0] = 1;
        input[1] = 20;
        input[4] = 1;
        assert_eq!(
            OwnerId::decode_canonical(&input),
            Err(EncodingError::NonCanonical)
        );
        input[4] = 0;
        input[3] = 3;
        assert_eq!(
            OwnerId::decode_canonical(&input),
            Err(EncodingError::UnknownDiscriminant(3))
        );
    }
}
