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

    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or("frame length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated frame payload")?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("truncated u8 field")
    }

    pub(super) fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| "truncated u16 field")?,
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| "truncated u32 field")?,
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| "truncated u64 field")?,
        ))
    }

    pub(super) fn usize_len(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.u64()?).map_err(|_| "length is not process-addressable")
    }

    pub(super) fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, &'static str> {
        let algorithm = self.u16()?;
        let construction = self.u16()?;
        let digest_len =
            usize::try_from(self.u32()?).map_err(|_| "identity digest length overflow")?;
        if algorithm == 0 || construction == 0 || digest_len == 0 {
            return Err("identity tag fields must be non-zero");
        }
        let digest = self.take(digest_len)?;
        if algorithm != scheme.algorithm() || construction != scheme.construction() {
            return Err("unsupported identity algorithm or construction version");
        }
        digest
            .try_into()
            .map(ObjectId::new)
            .map_err(|_| "identity digest length does not match the supported scheme")
    }
}
