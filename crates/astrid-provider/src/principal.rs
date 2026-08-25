//! Host-internal principal seam. Not a stamp and not a grant.

use astrid_resource_types::{CanonicalDecode, CanonicalEncode, OwnerId};

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, write_header,
};
use crate::error::ProviderError;

/// Host-internal 32-byte principal identity.
///
/// This is the seam a later accepted stamp can map into. It is not
/// `StampedInvocation`, not a lease, and not a grant. Construction from an
/// [`OwnerId`] accepts only [`OwnerId::Principal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostPrincipal([u8; 32]);

impl HostPrincipal {
    /// Exact encoded length, including the nested owner descriptor.
    pub const ENCODED_LEN: usize = 39;

    /// Construct from trusted principal UID bytes.
    #[must_use]
    pub const fn from_principal_uid_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the exact principal bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lift a portable owner reference into this host seam.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::TypeMismatch`] unless `owner` is a principal.
    pub const fn try_from_owner(owner: OwnerId) -> Result<Self, ProviderError> {
        match owner {
            OwnerId::Principal(bytes) => Ok(Self(bytes)),
            OwnerId::System | OwnerId::Fleet(_) => Err(ProviderError::TypeMismatch),
        }
    }

    /// Descriptive owner reference. Not proof of control.
    #[must_use]
    pub const fn as_owner(self) -> OwnerId {
        OwnerId::principal(self.0)
    }
}

impl DescriptorEncode for HostPrincipal {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        crate::encoding::require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::HostPrincipal)?;
        self.as_owner()
            .encode_canonical(
                output
                    .get_mut(3..Self::ENCODED_LEN)
                    .ok_or(ProviderError::InvalidLength)?,
            )
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

impl DescriptorDecode for HostPrincipal {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        crate::encoding::require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::HostPrincipal)?;
        let owner = OwnerId::decode_canonical(
            input
                .get(3..Self::ENCODED_LEN)
                .ok_or(ProviderError::InvalidLength)?,
        )
        .map_err(|_| ProviderError::ResourceEncoding)?;
        Self::try_from_owner(owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::{CanonicalEncode, ResourceId};

    #[test]
    fn principal_rejects_system_and_fleet_owners() {
        assert_eq!(
            HostPrincipal::try_from_owner(OwnerId::System),
            Err(ProviderError::TypeMismatch)
        );
        assert_eq!(
            HostPrincipal::try_from_owner(OwnerId::fleet([0x22; 32])),
            Err(ProviderError::TypeMismatch)
        );
        let principal = HostPrincipal::from_principal_uid_bytes([0x11; 32]);
        assert_eq!(
            HostPrincipal::try_from_owner(principal.as_owner()),
            Ok(principal)
        );
    }

    #[test]
    fn principal_encoding_is_not_a_resource_id() {
        let principal = HostPrincipal::from_principal_uid_bytes([0x11; 32]);
        let mut encoded = [0_u8; HostPrincipal::ENCODED_LEN];
        principal.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(HostPrincipal::decode_descriptor(&encoded), Ok(principal));

        let mut resource = [0_u8; 35];
        ResourceId::from_bytes([0x11; 32])
            .encode_canonical(&mut resource)
            .unwrap();
        assert_eq!(
            HostPrincipal::decode_descriptor(&resource),
            Err(ProviderError::InvalidLength)
        );
        assert_eq!(
            ResourceId::decode_canonical(&encoded),
            Err(astrid_resource_types::EncodingError::InvalidLength)
        );
    }

    #[test]
    fn nested_system_owner_bytes_cannot_become_a_principal() {
        let mut encoded = [0_u8; HostPrincipal::ENCODED_LEN];
        HostPrincipal::from_principal_uid_bytes([0x11; 32])
            .encode_descriptor(&mut encoded)
            .unwrap();
        let mut system = [0_u8; OwnerId::ENCODED_LEN];
        OwnerId::System.encode_canonical(&mut system).unwrap();
        encoded[3..].copy_from_slice(&system);
        assert_eq!(
            HostPrincipal::decode_descriptor(&encoded),
            Err(ProviderError::TypeMismatch)
        );
    }
}
