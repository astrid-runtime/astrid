//! Checkpoint blob identity. Never a pid, handle, or lease.

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, write_header, write_nested,
};
use crate::error::ProviderError;
use crate::instance::InstanceId;

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

/// Checkpoint descriptor for one instance blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    instance: InstanceId,
    blob: CheckpointBlobId,
}

impl Checkpoint {
    /// Exact encoded length, including nested instance identity.
    pub const ENCODED_LEN: usize = 87;

    /// Bind a blob to an instance slot.
    #[must_use]
    pub const fn new(instance: InstanceId, blob: CheckpointBlobId) -> Self {
        Self { instance, blob }
    }

    /// Instance this checkpoint names.
    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }

    /// Provider-local blob identity. Not a live handle.
    #[must_use]
    pub const fn blob(self) -> CheckpointBlobId {
        self.blob
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
        let offset = write_nested(output, 3, &self.instance)?;
        write_nested(output, offset, &self.blob)?;
        Ok(())
    }
}

impl DescriptorDecode for Checkpoint {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::Checkpoint)?;
        let (instance, offset) = read_nested::<InstanceId>(input, 3, InstanceId::ENCODED_LEN)?;
        let (blob, _) =
            read_nested::<CheckpointBlobId>(input, offset, CheckpointBlobId::ENCODED_LEN)?;
        Ok(Self::new(instance, blob))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::{CanonicalDecode, CanonicalEncode, ObjectGeneration, ResourceId};

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
        let checkpoint = Checkpoint::new(
            InstanceId::new(ResourceId::from_bytes([1; 32]), ObjectGeneration::INITIAL),
            blob,
        );
        let mut full = [0_u8; Checkpoint::ENCODED_LEN];
        checkpoint.encode_descriptor(&mut full).unwrap();
        assert_eq!(Checkpoint::decode_descriptor(&full), Ok(checkpoint));
    }
}
