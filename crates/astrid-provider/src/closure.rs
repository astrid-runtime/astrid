//! Immutable application-generation plus provider identity.

use astrid_resource_types::{
    ApplicationGenerationRef, CanonicalDecode, CanonicalEncode, ProviderGeneration, ProviderId,
};

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested, write_header,
    write_nested,
};
use crate::error::ProviderError;

/// Named application generation bound to one provider incarnation.
///
/// This is a descriptor, not an install record and not a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApplicationClosure {
    application: ApplicationGenerationRef,
    provider: ProviderId,
    provider_generation: ProviderGeneration,
}

impl ApplicationClosure {
    /// Exact encoded length, including nested resource encodings.
    pub const ENCODED_LEN: usize = 84;

    /// Bind an application generation to a provider identity.
    #[must_use]
    pub const fn new(
        application: ApplicationGenerationRef,
        provider: ProviderId,
        provider_generation: ProviderGeneration,
    ) -> Self {
        Self {
            application,
            provider,
            provider_generation,
        }
    }

    /// Immutable application generation. Not a system generation.
    #[must_use]
    pub const fn application(self) -> ApplicationGenerationRef {
        self.application
    }

    /// Provider this closure names.
    #[must_use]
    pub const fn provider(self) -> ProviderId {
        self.provider
    }

    /// Provider incarnation. Distinct from object and lifecycle generations.
    #[must_use]
    pub const fn provider_generation(self) -> ProviderGeneration {
        self.provider_generation
    }
}

impl DescriptorEncode for ApplicationClosure {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        crate::encoding::require_exact_len(output, Self::ENCODED_LEN)?;
        write_header(output, ProviderTypeTag::ApplicationClosure)?;
        let offset = write_nested(output, 3, &EncodedId(self.application))?;
        let offset = write_nested(output, offset, &EncodedId(self.provider))?;
        write_nested(output, offset, &EncodedGeneration(self.provider_generation))?;
        Ok(())
    }
}

impl DescriptorDecode for ApplicationClosure {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        crate::encoding::require_exact_len(input, Self::ENCODED_LEN)?;
        check_header(input, ProviderTypeTag::ApplicationClosure)?;
        let (application, offset) =
            read_nested::<EncodedId<ApplicationGenerationRef>>(input, 3, 35)?;
        let (provider, offset) = read_nested::<EncodedId<ProviderId>>(input, offset, 35)?;
        let (provider_generation, _) =
            read_nested::<EncodedGeneration<ProviderGeneration>>(input, offset, 11)?;
        Ok(Self::new(application.0, provider.0, provider_generation.0))
    }
}

struct EncodedId<T>(T);

impl<T: CanonicalEncode> DescriptorEncode for EncodedId<T> {
    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        self.0
            .encode_canonical(output)
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

impl<T: CanonicalDecode> DescriptorDecode for EncodedId<T> {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        T::decode_canonical(input)
            .map(Self)
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

struct EncodedGeneration<T>(T);

impl<T: CanonicalEncode> DescriptorEncode for EncodedGeneration<T> {
    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        self.0
            .encode_canonical(output)
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

impl<T: CanonicalDecode> DescriptorDecode for EncodedGeneration<T> {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        T::decode_canonical(input)
            .map(Self)
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

pub(crate) fn encode_resource<T: CanonicalEncode>(
    output: &mut [u8],
    offset: usize,
    value: &T,
) -> Result<usize, ProviderError> {
    write_nested(output, offset, &EncodedIdRef(value))
}

pub(crate) fn decode_resource<T: CanonicalDecode>(
    input: &[u8],
    offset: usize,
    len: usize,
) -> Result<(T, usize), ProviderError> {
    let (wrapper, end) = read_nested::<EncodedId<T>>(input, offset, len)?;
    Ok((wrapper.0, end))
}

struct EncodedIdRef<'a, T>(&'a T);

impl<T: CanonicalEncode> DescriptorEncode for EncodedIdRef<'_, T> {
    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        self.0
            .encode_canonical(output)
            .map_err(|_| ProviderError::ResourceEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::{CanonicalEncode, SystemGenerationRef};

    #[test]
    fn closure_roundtrip_rejects_system_generation_bytes() {
        let closure = ApplicationClosure::new(
            ApplicationGenerationRef::from_bytes([0x21; 32]),
            ProviderId::from_bytes([0x22; 32]),
            ProviderGeneration::INITIAL,
        );
        let mut encoded = [0_u8; ApplicationClosure::ENCODED_LEN];
        closure.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(ApplicationClosure::decode_descriptor(&encoded), Ok(closure));

        let mut system = [0_u8; 35];
        SystemGenerationRef::from_bytes([0x21; 32])
            .encode_canonical(&mut system)
            .unwrap();
        encoded[3..38].copy_from_slice(&system);
        assert_eq!(
            ApplicationClosure::decode_descriptor(&encoded),
            Err(ProviderError::ResourceEncoding)
        );
    }
}
