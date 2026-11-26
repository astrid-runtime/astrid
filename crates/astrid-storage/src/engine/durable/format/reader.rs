//! Bounds-checked primitives shared by durable frame decoders.

use super::{IdentityScheme, ObjectId};

pub(super) struct SliceReader<'a> {
    bytes: &'a [u8],
    pub(super) offset: usize,
}

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
        reserved: Vec<super::ObjectReference>,
    ) -> Result<Vec<super::ObjectReference>, &'static str> {
        use super::root_wire::ReadError;
        use super::verified_record::{self, ReferenceError};
        verified_record::read_many(
            self.bytes,
            &mut self.offset,
            scheme.into(),
            count,
            reserved,
            |label, id, kind| {
                super::ObjectReference::new(
                    super::ReferenceLabel::new(label.to_vec()),
                    ObjectId::new(id),
                    kind,
                )
            },
        )
        .map_err(|e| match e {
            ReferenceError::Read(ReadError::Overflow(_)) => "frame length overflow",
            ReferenceError::Read(ReadError::Truncated) => "truncated frame payload",
            ReferenceError::Length => "length is not process-addressable",
            ReferenceError::Target(e) => e.detail(),
            ReferenceError::Kind => "unknown reference-kind code",
        })
    }

    pub(super) fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, &'static str> {
        super::verified_record::identity(self.bytes, &mut self.offset, scheme.into())
            .map(ObjectId::new)
            .map_err(super::verified_record::TagError::detail)
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
