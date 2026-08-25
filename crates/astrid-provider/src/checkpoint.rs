//! Checkpoint blob identity. Never a pid, handle, or lease.

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, write_header, write_nested,
};
use crate::error::ProviderError;
use crate::instance::{AdmittedInstance, InstanceId};
use crate::provider::ProviderIdentity;
use astrid_resource_types::OwnerId;

use crate::closure::ApplicationClosure;

/// Provider-local checkpoint blob identity.
///
/// This is not [`astrid_resource_types::ResourceId`], not a process id, and not
/// a live handle. Restore yields a new descriptor; portal rebinding is host work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CheckpointBlobId([u8; 32]);

impl CheckpointBlobId {
    /// Exact encoded length.
    pub const ENCODED_LEN: usize = 35;

    /// Construct from provider-local blob bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the exact blob identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Checkpoint descriptor bound to provider, instance, application, and owner.
///
/// This is not an admission table and not a grant. Restore cannot change the
/// bound identities; portal rebinding stays on the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    provider: ProviderIdentity,
    admitted: AdmittedInstance,
    blob: CheckpointBlobId,
}

impl Checkpoint {
    /// Exact encoded length, including nested identities.
    pub const ENCODED_LEN: usize = 259;

    /// Bind a blob to an admitted instance. Provider identity is copied from
    /// the closure so a cross-provider encoding cannot be honest-constructed.
    #[must_use]
    pub const fn from_instance(instance: AdmittedInstance, blob: CheckpointBlobId) -> Self {
        Self {
            provider: ProviderIdentity::from_closure(instance.closure()),
            admitted: instance,
            blob,
        }
    }

    /// Provider incarnation bound to this checkpoint.
    #[must_use]
    pub const fn provider(self) -> ProviderIdentity {
        self.provider
    }

    /// Instance slot named by this checkpoint.
    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.admitted.id()
    }

    /// Bound admitted-instance descriptor. Not a grant.
    #[must_use]
    pub const fn admitted(self) -> AdmittedInstance {
        self.admitted
    }

    /// Application closure bound to this checkpoint.
    #[must_use]
    pub const fn closure(self) -> ApplicationClosure {
        self.admitted.closure()
    }

    /// Owner reference bound to this checkpoint. Not proof of control.
    #[must_use]
    pub const fn owner(self) -> OwnerId {
        self.admitted.owner()
    }

    /// Provider-local blob identity. Not a live handle.
    #[must_use]
    pub const fn blob(self) -> CheckpointBlobId {
        self.blob
    }

    pub(crate) fn check_consistent(self) -> Result<(), ProviderError> {
        let expected = ProviderIdentity::from_closure(self.admitted.closure());
        if expected == self.provider {
            Ok(())
        } else {
            Err(ProviderError::NonCanonical)
        }
    }
}

impl DescriptorEncode for CheckpointBlobId {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::CheckpointBlobId)?;
        output
            .get_mut(3..Self::ENCODED_LEN)
            .ok_or(ProviderError::InvalidLength)?
            .copy_from_slice(&self.0);
        Ok(())
    }
}

impl DescriptorDecode for CheckpointBlobId {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::CheckpointBlobId)?;
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(
            input
                .get(3..Self::ENCODED_LEN)
                .ok_or(ProviderError::InvalidLength)?,
        );
        Ok(Self(bytes))
    }
}

impl DescriptorEncode for Checkpoint {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::Checkpoint)?;
        let offset = write_nested(output, 3, &self.provider)?;
        let offset = write_nested(output, offset, &self.admitted)?;
        write_nested(output, offset, &self.blob)?;
        Ok(())
    }
}

impl DescriptorDecode for Checkpoint {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::Checkpoint)?;
        let (provider, offset) =
            read_nested::<ProviderIdentity>(input, 3, ProviderIdentity::ENCODED_LEN)?;
        let (admitted, offset) =
            read_nested::<AdmittedInstance>(input, offset, AdmittedInstance::ENCODED_LEN)?;
        let (blob, _) =
            read_nested::<CheckpointBlobId>(input, offset, CheckpointBlobId::ENCODED_LEN)?;
        let checkpoint = Self {
            provider,
            admitted,
            blob,
        };
        checkpoint.check_consistent()?;
        Ok(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::honest_instance;
    use crate::null::NullProvider;
    use astrid_resource_types::{CanonicalDecode, CanonicalEncode, ProviderId, ResourceId};

    #[test]
    fn checkpoint_blob_is_not_a_resource_id() {
        let blob = CheckpointBlobId::from_bytes([0xab; 32]);
        let mut encoded = [0_u8; CheckpointBlobId::ENCODED_LEN];
        blob.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(CheckpointBlobId::decode_descriptor(&encoded), Ok(blob));

        let mut resource = [0_u8; 35];
        ResourceId::from_bytes([0xab; 32])
            .encode_canonical(&mut resource)
            .unwrap();
        assert_eq!(
            CheckpointBlobId::decode_descriptor(&resource),
            Err(ProviderError::WrongTypeTag {
                expected: ProviderTypeTag::CheckpointBlobId.code(),
                actual: ProviderTypeTag::HostPrincipal.code(),
            })
        );
        assert_eq!(
            ResourceId::decode_canonical(&encoded),
            Err(astrid_resource_types::EncodingError::UnknownTypeTag(12))
        );
        let checkpoint = Checkpoint::from_instance(honest_instance(), blob);
        assert_eq!(checkpoint.provider(), NullProvider::identity_value());
        let mut full = [0_u8; Checkpoint::ENCODED_LEN];
        checkpoint.encode_descriptor(&mut full).unwrap();
        assert_eq!(Checkpoint::decode_descriptor(&full), Ok(checkpoint));
        let mut leftover = [0_u8; Checkpoint::ENCODED_LEN + 1];
        leftover[..Checkpoint::ENCODED_LEN].copy_from_slice(&full);
        leftover[Checkpoint::ENCODED_LEN] = 1;
        assert_eq!(
            Checkpoint::decode_descriptor(&leftover),
            Err(ProviderError::InvalidLength)
        );
    }

    #[test]
    fn checkpoint_rejects_inconsistent_provider_identity() {
        let checkpoint =
            Checkpoint::from_instance(honest_instance(), CheckpointBlobId::from_bytes([0xab; 32]));
        let mut encoded = [0_u8; Checkpoint::ENCODED_LEN];
        checkpoint.encode_descriptor(&mut encoded).unwrap();
        let other = ProviderIdentity::new(
            ProviderId::from_bytes([0xb5; 32]),
            checkpoint.provider().generation(),
        );
        let mut other_bytes = [0_u8; ProviderIdentity::ENCODED_LEN];
        other.encode_descriptor(&mut other_bytes).unwrap();
        encoded[3..3 + ProviderIdentity::ENCODED_LEN].copy_from_slice(&other_bytes);
        assert_eq!(
            Checkpoint::decode_descriptor(&encoded),
            Err(ProviderError::NonCanonical)
        );
    }
}
