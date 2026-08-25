//! Semantic object identity bound to [`ResourceId`].

use astrid_resource_types::{CanonicalDecode, CanonicalEncode, ResourceId};

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, write_header,
};
use crate::error::ProjectionError;

/// Identity of a projected semantic object.
///
/// The object is a view of exactly one [`ResourceId`]. It cannot be constructed
/// from a string name, schema topic, or [`astrid_resource_types::ResourceKind`].
/// Knowing the identifier is not a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticObjectId {
    resource: ResourceId,
}

impl SemanticObjectId {
    /// Bind a projection identity to a resource identity.
    #[must_use]
    pub const fn for_resource(resource: ResourceId) -> Self {
        Self { resource }
    }

    /// Resource this projection names. Not a live handle.
    #[must_use]
    pub const fn resource(self) -> ResourceId {
        self.resource
    }
}

impl DescriptorEncode for SemanticObjectId {
    fn encoded_len(&self) -> usize {
        38
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != 38 {
            return Err(ProjectionError::InvalidLength);
        }
        write_header(output, ProjectionTypeTag::SemanticObjectId)?;
        self.resource
            .encode_canonical(&mut output[3..38])
            .map_err(|_| ProjectionError::ResourceEncoding)
    }
}

impl DescriptorDecode for SemanticObjectId {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        if input.len() != 38 {
            return Err(ProjectionError::InvalidLength);
        }
        check_header(input, ProjectionTypeTag::SemanticObjectId)?;
        let resource = ResourceId::decode_canonical(&input[3..38])
            .map_err(|_| ProjectionError::ResourceEncoding)?;
        Ok(Self { resource })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::ResourceKind;

    #[test]
    fn object_id_is_not_a_bare_resource_encoding() {
        let resource = ResourceId::from_bytes([0x11; 32]);
        let object = SemanticObjectId::for_resource(resource);
        let mut object_bytes = [0_u8; 38];
        object.encode_descriptor(&mut object_bytes).unwrap();
        let mut resource_bytes = [0_u8; 35];
        resource.encode_canonical(&mut resource_bytes).unwrap();
        assert_ne!(object_bytes.as_slice(), resource_bytes.as_slice());
        assert_eq!(
            ResourceId::decode_canonical(&object_bytes),
            Err(astrid_resource_types::EncodingError::InvalidLength)
        );
        assert_eq!(
            SemanticObjectId::decode_descriptor(&resource_bytes),
            Err(ProjectionError::InvalidLength)
        );
        assert_eq!(object.resource(), resource);
    }

    #[test]
    fn resource_kind_semantic_object_is_not_projection_identity() {
        let mut kind = [0_u8; 5];
        ResourceKind::SemanticObject
            .encode_canonical(&mut kind)
            .unwrap();
        assert_eq!(
            SemanticObjectId::decode_descriptor(&kind),
            Err(ProjectionError::InvalidLength)
        );
    }
}
