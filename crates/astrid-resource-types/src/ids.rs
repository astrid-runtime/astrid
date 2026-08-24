//! Opaque fixed-width identities carried by resource descriptors.

use crate::{
    CanonicalDecode, CanonicalEncode, CanonicalTypeTag, EncodingError,
    encoding::{check_header, write_header},
};

macro_rules! portable_id {
    ($name:ident, $size:literal, $tag:ident, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name([u8; $size]);

        impl $name {
            /// Construct the identity from its exact bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            /// Return the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl CanonicalEncode for $name {
            fn encoded_len(&self) -> usize {
                $size + 3
            }

            fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError> {
                write_header(output, $size + 3, CanonicalTypeTag::$tag)?;
                output[3..].copy_from_slice(&self.0);
                Ok(())
            }
        }

        impl CanonicalDecode for $name {
            fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError> {
                check_header(input, $size + 3, CanonicalTypeTag::$tag)?;
                let mut bytes = [0_u8; $size];
                bytes.copy_from_slice(&input[3..]);
                Ok(Self(bytes))
            }
        }
    };
}

portable_id!(
    ResourceId,
    32,
    ResourceId,
    "Stable identity of a resource object."
);
portable_id!(
    ResourceTypeId,
    32,
    ResourceTypeId,
    "Stable identity of a resource type or schema."
);
portable_id!(
    DerivationId,
    16,
    DerivationId,
    "Identity joining an admitted resource to its derivation record."
);
portable_id!(
    ProviderId,
    32,
    ProviderId,
    "Stable identity of an execution provider."
);
portable_id!(
    ApplicationGenerationRef,
    32,
    ApplicationGenerationRef,
    "Opaque reference to an immutable application generation."
);
portable_id!(
    SystemGenerationRef,
    32,
    SystemGenerationRef,
    "Opaque reference to an immutable system generation."
);
portable_id!(
    AccountId,
    16,
    AccountId,
    "Identity of an accounting domain."
);
portable_id!(BudgetId, 16, BudgetId, "Identity of an admitted budget.");
portable_id!(
    CausalRequestId,
    16,
    CausalRequestId,
    "Identity of the request that causally initiated work."
);
portable_id!(
    OperationId,
    16,
    OperationId,
    "Identity of one resource operation."
);

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! rejects_as {
        ($bytes:expr, $($target:ty),+ $(,)?) => {
            $(assert!(matches!(
                <$target>::decode_canonical(&$bytes),
                Err(EncodingError::WrongTypeTag { .. })
            ));)+
        };
    }

    #[test]
    fn resource_id_golden_vector() {
        let id = ResourceId::from_bytes([0xabu8; 32]);
        let mut encoded = [0_u8; 35];
        id.encode_canonical(&mut encoded).unwrap();
        let mut expected = [0xabu8; 35];
        expected[0] = 1;
        expected[1] = 1;
        expected[2] = 0;
        assert_eq!(encoded, expected);
        assert_eq!(ResourceId::decode_canonical(&encoded), Ok(id));
    }

    #[test]
    fn opaque_id_rejects_malformed_and_unknown_version() {
        assert_eq!(
            ResourceId::decode_canonical(&[1; 34]),
            Err(EncodingError::InvalidLength)
        );
        let mut encoded = [0_u8; 35];
        encoded[0] = 2;
        assert_eq!(
            ResourceId::decode_canonical(&encoded),
            Err(EncodingError::UnknownVersion(2))
        );

        encoded[0] = 1;
        encoded[1..3].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            ResourceId::decode_canonical(&encoded),
            Err(EncodingError::UnknownTypeTag(u16::MAX))
        );
    }

    #[test]
    fn same_width_resource_domains_reject_each_others_bytes() {
        let mut resource = [0_u8; 35];
        ResourceId::from_bytes([1; 32])
            .encode_canonical(&mut resource)
            .unwrap();
        let mut resource_type = [0_u8; 35];
        ResourceTypeId::from_bytes([2; 32])
            .encode_canonical(&mut resource_type)
            .unwrap();
        let mut provider = [0_u8; 35];
        ProviderId::from_bytes([3; 32])
            .encode_canonical(&mut provider)
            .unwrap();
        let mut application = [0_u8; 35];
        ApplicationGenerationRef::from_bytes([4; 32])
            .encode_canonical(&mut application)
            .unwrap();
        let mut system = [0_u8; 35];
        SystemGenerationRef::from_bytes([5; 32])
            .encode_canonical(&mut system)
            .unwrap();

        rejects_as!(
            resource,
            ResourceTypeId,
            ProviderId,
            ApplicationGenerationRef,
            SystemGenerationRef
        );
        rejects_as!(
            resource_type,
            ResourceId,
            ProviderId,
            ApplicationGenerationRef,
            SystemGenerationRef
        );
        rejects_as!(
            provider,
            ResourceId,
            ResourceTypeId,
            ApplicationGenerationRef,
            SystemGenerationRef
        );
        rejects_as!(
            application,
            ResourceId,
            ResourceTypeId,
            ProviderId,
            SystemGenerationRef
        );
        rejects_as!(
            system,
            ResourceId,
            ResourceTypeId,
            ProviderId,
            ApplicationGenerationRef
        );
    }

    #[test]
    fn same_width_operation_domains_reject_each_others_bytes() {
        let mut derivation = [0_u8; 19];
        DerivationId::from_bytes([6; 16])
            .encode_canonical(&mut derivation)
            .unwrap();
        let mut account = [0_u8; 19];
        AccountId::from_bytes([7; 16])
            .encode_canonical(&mut account)
            .unwrap();
        let mut budget = [0_u8; 19];
        BudgetId::from_bytes([8; 16])
            .encode_canonical(&mut budget)
            .unwrap();
        let mut request = [0_u8; 19];
        CausalRequestId::from_bytes([9; 16])
            .encode_canonical(&mut request)
            .unwrap();
        let mut operation = [0_u8; 19];
        OperationId::from_bytes([10; 16])
            .encode_canonical(&mut operation)
            .unwrap();

        rejects_as!(
            derivation,
            AccountId,
            BudgetId,
            CausalRequestId,
            OperationId
        );
        rejects_as!(
            account,
            DerivationId,
            BudgetId,
            CausalRequestId,
            OperationId
        );
        rejects_as!(
            budget,
            DerivationId,
            AccountId,
            CausalRequestId,
            OperationId
        );
        rejects_as!(request, DerivationId, AccountId, BudgetId, OperationId);
        rejects_as!(
            operation,
            DerivationId,
            AccountId,
            BudgetId,
            CausalRequestId
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn alloc_helper_returns_exact_canonical_bytes() {
        let id = OperationId::from_bytes([7; 16]);
        let encoded = id.to_canonical_vec();
        assert_eq!(encoded.len(), id.encoded_len());
        assert_eq!(OperationId::decode_canonical(&encoded), Ok(id));
    }
}
