//! Instance identity and admitted-instance descriptors. Not an admission table.

use astrid_resource_types::{ObjectGeneration, OwnerId, ResourceId};

use crate::closure::{ApplicationClosure, decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested, write_header,
    write_nested,
};
use crate::error::ProviderError;

/// Reusable instance slot: one resource plus its object generation.
///
/// Distinct from [`astrid_resource_types::ResourceKind`] and from a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstanceId {
    resource: ResourceId,
    generation: ObjectGeneration,
}

impl InstanceId {
    /// Exact encoded length, including nested resource encodings.
    pub const ENCODED_LEN: usize = 49;

    /// Bind an instance slot to a resource generation.
    #[must_use]
    pub const fn new(resource: ResourceId, generation: ObjectGeneration) -> Self {
        Self {
            resource,
            generation,
        }
    }

    /// Resource this instance names. Not a live handle.
    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }

    /// Object generation of this instance slot.
    #[must_use]
    pub const fn generation(self) -> ObjectGeneration {
        self.generation
    }
}

/// Descriptor of an admitted instance. Not the admission table and not a grant.
///
/// Account and budget identities are omitted so this value cannot look like a
/// live [`ResourceAuthority`] envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmittedInstance {
    id: InstanceId,
    closure: ApplicationClosure,
    owner: OwnerId,
}

impl AdmittedInstance {
    /// Exact encoded length, including nested descriptors.
    pub const ENCODED_LEN: usize = 172;

    /// Construct a descriptive admission record.
    #[must_use]
    pub const fn new(id: InstanceId, closure: ApplicationClosure, owner: OwnerId) -> Self {
        Self { id, closure, owner }
    }

    /// Instance slot named by this descriptor.
    #[must_use]
    pub const fn id(self) -> InstanceId {
        self.id
    }

    /// Application closure bound to this instance.
    #[must_use]
    pub const fn closure(self) -> ApplicationClosure {
        self.closure
    }

    /// Owner reference. Not proof of control and not a principal stamp.
    #[must_use]
    pub const fn owner(self) -> OwnerId {
        self.owner
    }
}

impl DescriptorEncode for InstanceId {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        crate::encoding::require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::InstanceId)?;
        let offset = encode_resource(output, 3, &self.resource)?;
        encode_resource(output, offset, &self.generation)?;
        Ok(())
    }
}

impl DescriptorDecode for InstanceId {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        crate::encoding::require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::InstanceId)?;
        let (resource, offset) = decode_resource::<ResourceId>(input, 3, 35)?;
        let (generation, _) = decode_resource::<ObjectGeneration>(input, offset, 11)?;
        Ok(Self::new(resource, generation))
    }
}

impl DescriptorEncode for AdmittedInstance {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        crate::encoding::require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::AdmittedInstance)?;
        let offset = write_nested(output, 3, &self.id)?;
        let offset = write_nested(output, offset, &self.closure)?;
        encode_resource(output, offset, &self.owner)?;
        Ok(())
    }
}

impl DescriptorDecode for AdmittedInstance {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        crate::encoding::require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::AdmittedInstance)?;
        let (id, offset) = read_nested::<InstanceId>(input, 3, InstanceId::ENCODED_LEN)?;
        let (closure, offset) =
            read_nested::<ApplicationClosure>(input, offset, ApplicationClosure::ENCODED_LEN)?;
        let (owner, _) = decode_resource::<OwnerId>(input, offset, OwnerId::ENCODED_LEN)?;
        Ok(Self::new(id, closure, owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::null::NULL_PROVIDER_ID;
    use astrid_resource_types::{
        ApplicationGenerationRef, CanonicalDecode, CanonicalEncode, ProviderGeneration,
    };

    fn sample_instance() -> InstanceId {
        InstanceId::new(
            ResourceId::from_bytes([0x31; 32]),
            ObjectGeneration::INITIAL,
        )
    }

    #[test]
    fn instance_id_is_not_a_bare_resource_encoding() {
        let instance = sample_instance();
        let mut encoded = [0_u8; InstanceId::ENCODED_LEN];
        instance.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(InstanceId::decode_descriptor(&encoded), Ok(instance));

        let mut resource = [0_u8; 35];
        instance.resource().encode_canonical(&mut resource).unwrap();
        assert_eq!(
            InstanceId::decode_descriptor(&resource),
            Err(ProviderError::InvalidLength)
        );
        assert_eq!(
            ResourceId::decode_canonical(&encoded),
            Err(astrid_resource_types::EncodingError::InvalidLength)
        );
    }

    #[test]
    fn provider_generation_bytes_are_not_object_generation() {
        let instance = sample_instance();
        let mut encoded = [0_u8; InstanceId::ENCODED_LEN];
        instance.encode_descriptor(&mut encoded).unwrap();
        let mut provider_generation = [0_u8; 11];
        ProviderGeneration::INITIAL
            .encode_canonical(&mut provider_generation)
            .unwrap();
        encoded[38..49].copy_from_slice(&provider_generation);
        assert_eq!(
            InstanceId::decode_descriptor(&encoded),
            Err(ProviderError::ResourceEncoding)
        );
    }

    #[test]
    fn admitted_instance_roundtrip_is_not_a_grant() {
        let admitted = AdmittedInstance::new(
            sample_instance(),
            ApplicationClosure::new(
                ApplicationGenerationRef::from_bytes([0x21; 32]),
                NULL_PROVIDER_ID,
                ProviderGeneration::INITIAL,
            ),
            OwnerId::principal([0x11; 32]),
        );
        let mut encoded = [0_u8; AdmittedInstance::ENCODED_LEN];
        admitted.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(AdmittedInstance::decode_descriptor(&encoded), Ok(admitted));
    }
}
