//! Closed portable resource-right vocabulary.

use crate::{
    CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError,
    encoding::{check_header, write_header},
};

/// Closed set of portable resource operation classes.
///
/// These bits describe requested or admitted operations. They are not a
/// capability and have no effect until checked by a live enforcement point.
/// Each resource kind defines which operation classes apply; this portable
/// type does not perform that admission decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u64", into = "u64"))]
pub struct Rights(u64);

impl Rights {
    /// No rights.
    pub const NONE: Self = Self(0);
    /// Observe resource state or content.
    pub const READ: Self = Self(1 << 0);
    /// Change resource state or content.
    pub const WRITE: Self = Self(1 << 1);
    /// Invoke the resource's primary operation.
    pub const USE: Self = Self(1 << 2);
    /// Create a subordinate resource.
    pub const CREATE: Self = Self(1 << 3);
    /// Remove or retire a resource.
    pub const DELETE: Self = Self(1 << 4);
    /// Derive attenuated authority for another subject.
    pub const DELEGATE: Self = Self(1 << 5);
    /// Permit concurrent authority for another subject.
    pub const SHARE: Self = Self(1 << 6);
    /// Move exclusive authority to another subject.
    pub const TRANSFER: Self = Self(1 << 7);
    /// Inspect resource metadata and accounting state.
    pub const INSPECT: Self = Self(1 << 8);
    /// Change lifecycle or administrative settings.
    pub const MANAGE: Self = Self(1 << 9);
    /// Every defined right.
    pub const ALL: Self = Self((1 << 10) - 1);

    /// Construct only when every bit is part of the closed vocabulary.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the canonical raw bitset.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether this set contains every requested right.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Whether this set is a subset of `other`.
    #[must_use]
    pub const fn is_subset(self, other: Self) -> bool {
        other.contains(self)
    }

    /// Intersection of two closed rights sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Attenuate this set to rights also present in `limit`.
    #[must_use]
    pub const fn attenuate(self, limit: Self) -> Self {
        self.intersection(limit)
    }
}

impl TryFrom<u64> for Rights {
    type Error = EncodingError;

    fn try_from(bits: u64) -> Result<Self, Self::Error> {
        Self::from_bits(bits).ok_or(EncodingError::UnknownRights(bits))
    }
}

impl From<Rights> for u64 {
    fn from(rights: Rights) -> Self {
        rights.bits()
    }
}

impl CanonicalEncode for Rights {
    fn encoded_len(&self) -> usize {
        11
    }

    fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError> {
        write_header(output, 11, CanonicalTypeTag::Rights)?;
        output[3..11].copy_from_slice(&self.0.to_le_bytes());
        Ok(())
    }
}

impl CanonicalDecode for Rights {
    fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError> {
        check_header(input, 11, CanonicalTypeTag::Rights)?;
        let bits = u64::from_le_bytes(
            input[3..11]
                .try_into()
                .map_err(|_| EncodingError::InvalidLength)?,
        );
        Self::try_from(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_subset_intersection_and_attenuation_are_closed() {
        let read_write = Rights::from_bits(Rights::READ.bits() | Rights::WRITE.bits()).unwrap();
        assert!(Rights::READ.is_subset(read_write));
        assert!(read_write.contains(Rights::WRITE));
        assert_eq!(read_write.intersection(Rights::READ), Rights::READ);
        assert_eq!(read_write.attenuate(Rights::USE), Rights::NONE);
        assert!(Rights::from_bits(1 << 63).is_none());
    }

    #[test]
    fn rights_golden_and_negative_vectors() {
        let mut encoded = [0_u8; 11];
        Rights::MANAGE.encode_canonical(&mut encoded).unwrap();
        assert_eq!(encoded, [1, 30, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Rights::decode_canonical(&encoded), Ok(Rights::MANAGE));

        encoded[10] = 0x80;
        assert_eq!(
            Rights::decode_canonical(&encoded),
            Err(EncodingError::UnknownRights((1_u64 << 63) | (1 << 9)))
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unknown_rights() {
        use serde::Deserialize;
        use serde::de::value::{Error, U64Deserializer};

        let decoder = U64Deserializer::<Error>::new(1 << 63);
        assert!(Rights::deserialize(decoder).is_err());
    }
}
