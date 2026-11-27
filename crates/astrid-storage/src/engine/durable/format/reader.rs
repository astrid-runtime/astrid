//! Bounds-checked primitives shared by durable frame decoders.

#[cfg(test)]
use super::IdentityScheme;

#[cfg(test)]
pub(super) struct SliceReader<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}

#[cfg(test)]
impl<'a> SliceReader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(super) fn references(
        &mut self,
        scheme: IdentityScheme,
        count: usize,
    ) -> Result<Vec<super::ObjectReference>, &'static str> {
        super::verified_record::reference_list(self.bytes, &mut self.offset, scheme.into(), count)
            .map_err(super::verified_record::BodyError::detail)
    }
}

impl super::verified_record::TagError {
    pub(super) fn detail(self) -> &'static str {
        use super::root_wire::ReadError;
        match self {
            Self::Read(ReadError::Overflow(_)) => "frame length overflow",
            Self::Read(ReadError::Truncated) => "truncated frame payload",
            Self::LengthOverflow => "identity digest length overflow",
            Self::Zero => "identity tag fields must be non-zero",
            Self::Scheme => "unsupported identity algorithm or construction version",
            Self::DigestLength => "identity digest length does not match the supported scheme",
        }
    }
}

impl super::verified_record::BodyError {
    pub(super) fn detail(self) -> &'static str {
        use super::root_wire::ReadError;
        use super::verified_record::{HeaderError, PayloadError, ReferenceError};
        match self {
            Self::Header(HeaderError::Read(e))
            | Self::Payload(PayloadError::Read(e))
            | Self::Reference(ReferenceError::Read(e)) => match e {
                ReadError::Overflow(_) => "frame length overflow",
                ReadError::Truncated => "truncated frame payload",
            },
            Self::Header(HeaderError::Kind) => "unknown object-kind code",
            Self::Header(HeaderError::Version) => "object-format version must be non-zero",
            Self::Header(HeaderError::Class) => "unknown object-class code",
            Self::Reference(ReferenceError::Length) | Self::Payload(PayloadError::Length) => {
                "length is not process-addressable"
            },
            Self::Reference(ReferenceError::Target(e)) => e.detail(),
            Self::Reference(ReferenceError::Kind) => "unknown reference-kind code",
            Self::Capacity => "reference count exceeds frame capacity",
            Self::Allocation => "reference allocation failed",
            Self::Trailing => "trailing object-frame bytes",
            Self::Order => "non-canonical object references",
        }
    }
}
