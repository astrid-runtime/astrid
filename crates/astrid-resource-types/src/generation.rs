//! Checked generation and epoch counters.

use core::num::NonZeroU64;

use crate::{
    CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError,
    encoding::{check_header, write_header},
};

/// Failure to advance a generation domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationError;

mod private {
    pub trait Sealed {}
}

/// Closed trait implemented by Astrid generation newtypes.
pub trait GenerationValue: private::Sealed + Copy + Eq {
    /// First valid generation.
    const INITIAL: Self;

    /// Construct from a non-zero raw value.
    fn from_raw(raw: u64) -> Option<Self>;

    /// Expose the non-zero raw value.
    fn get(self) -> u64;

    /// Return the next generation without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError`] at `u64::MAX`.
    fn checked_next(self) -> Result<Self, GenerationError> {
        self.get()
            .checked_add(1)
            .and_then(Self::from_raw)
            .ok_or(GenerationError)
    }
}

macro_rules! generation_type {
    ($name:ident, $tag:ident, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(NonZeroU64);

        impl $name {
            /// First valid value.
            pub const INITIAL: Self = Self(NonZeroU64::MIN);

            /// Construct from a non-zero raw value.
            #[must_use]
            pub const fn from_raw(raw: u64) -> Option<Self> {
                match NonZeroU64::new(raw) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            /// Return the raw non-zero value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }

            /// Return the next value without wrapping.
            ///
            /// # Errors
            ///
            /// Returns [`GenerationError`] at `u64::MAX`.
            pub fn checked_next(self) -> Result<Self, GenerationError> {
                <Self as GenerationValue>::checked_next(self)
            }
        }

        impl private::Sealed for $name {}

        impl GenerationValue for $name {
            const INITIAL: Self = Self::INITIAL;

            fn from_raw(raw: u64) -> Option<Self> {
                Self::from_raw(raw)
            }

            fn get(self) -> u64 {
                self.get()
            }
        }

        impl CanonicalEncode for $name {
            fn encoded_len(&self) -> usize {
                11
            }

            fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError> {
                write_header(output, 11, CanonicalTypeTag::$tag)?;
                output[3..11].copy_from_slice(&self.get().to_le_bytes());
                Ok(())
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError> {
                check_header(input, 11, CanonicalTypeTag::$tag)?;
                let raw = u64::from_le_bytes(
                    input[3..11]
                        .try_into()
                        .map_err(|_| EncodingError::InvalidLength)?,
                );
                Self::from_raw(raw).ok_or(EncodingError::InvalidGeneration)
            }
        }
    };
}

generation_type!(
    ObjectGeneration,
    ObjectGeneration,
    "Generation of a reusable object slot."
);
generation_type!(
    AuthorityEpoch,
    AuthorityEpoch,
    "Epoch of the live authority decision."
);
generation_type!(
    LifecycleGeneration,
    LifecycleGeneration,
    "Generation of a resource lifecycle transition stream."
);
generation_type!(
    ProviderGeneration,
    ProviderGeneration,
    "Generation of a provider registration or incarnation."
);

/// Stateful live generation domain that retires this instance on exhaustion.
///
/// Once advancing `u64::MAX` is attempted, this instance discards its active
/// value and every later advance on the same instance fails. The arithmetic
/// never wraps into a value that could make a stale reference valid again.
///
/// This process-local value is not durable retirement proof. A host table that
/// owns reusable slots or generation domains must atomically persist a
/// retirement tombstone when exhaustion occurs. Recovery must honor that
/// tombstone and must not reconstruct the retired slot or domain with
/// [`Self::from_generation`]. Persistence and table behavior intentionally
/// remain outside this crate.
#[derive(Debug, PartialEq, Eq)]
pub struct GenerationDomain<G: GenerationValue> {
    current: Option<G>,
}

impl<G: GenerationValue> GenerationDomain<G> {
    /// Start at the first valid generation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: Some(G::INITIAL),
        }
    }

    /// Start a live domain from an existing active generation.
    ///
    /// Host-table recovery must not call this for a slot or domain whose
    /// durable retirement tombstone is present.
    #[must_use]
    pub const fn from_generation(generation: G) -> Self {
        Self {
            current: Some(generation),
        }
    }

    /// Return the active generation, if this domain is not retired.
    #[must_use]
    pub const fn current(&self) -> Option<G> {
        self.current
    }

    /// Whether this live domain instance has retired.
    #[must_use]
    pub const fn is_retired(&self) -> bool {
        self.current.is_none()
    }

    /// Advance, retiring this live domain instance on exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError`] when exhaustion occurs or the domain was
    /// already retired.
    pub fn advance(&mut self) -> Result<G, GenerationError> {
        let Some(current) = self.current else {
            return Err(GenerationError);
        };
        match current.checked_next() {
            Ok(next) => {
                self.current = Some(next);
                Ok(next)
            },
            Err(error) => {
                self.current = None;
                Err(error)
            },
        }
    }
}

impl<G: GenerationValue> Default for GenerationDomain<G> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_golden_vector_is_little_endian_and_versioned() {
        let generation = ObjectGeneration::from_raw(0x0102_0304_0506_0708).unwrap();
        let mut encoded = [0_u8; 11];
        generation.encode_canonical(&mut encoded).unwrap();
        assert_eq!(encoded, [1, 40, 0, 8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(ObjectGeneration::decode_canonical(&encoded), Ok(generation));
    }

    #[test]
    fn zero_generation_is_non_canonical() {
        assert_eq!(
            ObjectGeneration::decode_canonical(&[1, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(EncodingError::InvalidGeneration)
        );
    }

    #[test]
    fn generation_and_rights_domains_reject_each_others_bytes() {
        use crate::Rights;

        macro_rules! rejects_as {
            ($bytes:expr, $($target:ty),+ $(,)?) => {
                $(assert!(matches!(
                    <$target>::decode_canonical(&$bytes),
                    Err(EncodingError::WrongTypeTag { .. })
                ));)+
            };
        }

        let mut object = [0_u8; 11];
        ObjectGeneration::INITIAL
            .encode_canonical(&mut object)
            .unwrap();
        let mut authority = [0_u8; 11];
        AuthorityEpoch::INITIAL
            .encode_canonical(&mut authority)
            .unwrap();
        let mut lifecycle = [0_u8; 11];
        LifecycleGeneration::INITIAL
            .encode_canonical(&mut lifecycle)
            .unwrap();
        let mut provider = [0_u8; 11];
        ProviderGeneration::INITIAL
            .encode_canonical(&mut provider)
            .unwrap();
        let mut rights = [0_u8; 11];
        Rights::READ.encode_canonical(&mut rights).unwrap();

        rejects_as!(
            object,
            AuthorityEpoch,
            LifecycleGeneration,
            ProviderGeneration,
            Rights
        );
        rejects_as!(
            authority,
            ObjectGeneration,
            LifecycleGeneration,
            ProviderGeneration,
            Rights
        );
        rejects_as!(
            lifecycle,
            ObjectGeneration,
            AuthorityEpoch,
            ProviderGeneration,
            Rights
        );
        rejects_as!(
            provider,
            ObjectGeneration,
            AuthorityEpoch,
            LifecycleGeneration,
            Rights
        );
        rejects_as!(
            rights,
            ObjectGeneration,
            AuthorityEpoch,
            LifecycleGeneration,
            ProviderGeneration
        );
    }

    #[test]
    fn arithmetic_never_wraps_and_live_instance_stays_retired() {
        let maximum = ObjectGeneration::from_raw(u64::MAX).unwrap();
        assert_eq!(maximum.checked_next(), Err(GenerationError));

        let mut domain = GenerationDomain::from_generation(maximum);
        assert_eq!(domain.advance(), Err(GenerationError));
        assert!(domain.is_retired());
        assert_eq!(domain.current(), None);
        assert_eq!(domain.advance(), Err(GenerationError));
        assert!(domain.is_retired());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_cannot_construct_zero_generation() {
        use serde::Deserialize;
        use serde::de::value::{Error, U64Deserializer};

        let decoder = U64Deserializer::<Error>::new(0);
        assert!(ObjectGeneration::deserialize(decoder).is_err());
    }
}
