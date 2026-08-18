//! Closed resource classifications, lifecycle states and result codes.

use crate::{
    CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError,
    encoding::{check_header, write_header},
};

macro_rules! canonical_enum {
    ($(#[$meta:meta])* $name:ident, $tag:ident { $($variant:ident = $value:literal,)+ }) => {
        $(#[$meta])*
        #[repr(u16)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub enum $name {
            $($variant = $value,)+
        }

        impl $name {
            /// Stable numeric code used by canonical encodings.
            #[must_use]
            pub const fn code(self) -> u16 {
                self as u16
            }

            /// Decode a code from the closed vocabulary.
            ///
            /// # Errors
            ///
            /// Returns [`EncodingError::UnknownDiscriminant`] for unknown codes.
            pub const fn from_code(code: u16) -> Result<Self, EncodingError> {
                match code {
                    $($value => Ok(Self::$variant),)+
                    value => Err(EncodingError::UnknownDiscriminant(value)),
                }
            }
        }

        impl CanonicalEncode for $name {
            fn encoded_len(&self) -> usize {
                5
            }

            fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError> {
                write_header(output, 5, CanonicalTypeTag::$tag)?;
                output[3..5].copy_from_slice(&self.code().to_le_bytes());
                Ok(())
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError> {
                check_header(input, 5, CanonicalTypeTag::$tag)?;
                let code = u16::from_le_bytes([input[3], input[4]]);
                Self::from_code(code)
            }
        }
    };
}

canonical_enum! {
    /// Broad, policy-neutral class of a resource.
    ResourceKind, ResourceKind {
        Storage = 1,
        Compute = 2,
        Network = 3,
        Service = 4,
        Secret = 5,
        Device = 6,
        Process = 7,
        Stream = 8,
        SemanticObject = 9,
    }
}

canonical_enum! {
    /// Lifecycle state reported for a portable resource.
    ResourceLifecycleState, ResourceLifecycleState {
        Declared = 1,
        Verified = 2,
        Installed = 3,
        Reserved = 4,
        Active = 5,
        Draining = 6,
        Revoking = 7,
        Terminal = 8,
        Reclaimed = 9,
    }
}

canonical_enum! {
    /// Permitted shape of an authority transfer, interpreted by admission.
    TransferClass, TransferClass {
        None = 1,
        Delegate = 2,
        Share = 3,
        Move = 4,
    }
}

canonical_enum! {
    /// Stable machine-readable resource error category.
    ResourceErrorCode, ResourceErrorCode {
        InvalidDescriptor = 1,
        UnsupportedVersion = 2,
        NonCanonical = 3,
        UnknownResourceKind = 4,
        UnknownRight = 5,
        StaleGeneration = 6,
        RetiredGeneration = 7,
        WrongOwner = 8,
        MissingRight = 9,
        Revoked = 10,
        Exhausted = 11,
        Unavailable = 12,
        Cancelled = 13,
        Unsupported = 14,
        Internal = 15,
    }
}

canonical_enum! {
    /// Stable machine-readable operation outcome category.
    ResourceOutcomeCode, ResourceOutcomeCode {
        Succeeded = 1,
        Denied = 2,
        Cancelled = 3,
        Failed = 4,
        Revoked = 5,
        Exhausted = 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_enum_golden_and_unknown_vectors() {
        let mut encoded = [0_u8; 5];
        ResourceKind::Service
            .encode_canonical(&mut encoded)
            .unwrap();
        assert_eq!(encoded, [1, 50, 0, 4, 0]);
        assert_eq!(
            ResourceKind::decode_canonical(&encoded),
            Ok(ResourceKind::Service)
        );

        assert_eq!(
            ResourceKind::decode_canonical(&[1, 50, 0, 0xff, 0xff]),
            Err(EncodingError::UnknownDiscriminant(u16::MAX))
        );
        assert_eq!(
            ResourceKind::decode_canonical(&[2, 50, 0, 4, 0]),
            Err(EncodingError::UnknownVersion(2))
        );
        assert!(matches!(
            ResourceLifecycleState::decode_canonical(&encoded),
            Err(EncodingError::WrongTypeTag { .. })
        ));
    }
}
