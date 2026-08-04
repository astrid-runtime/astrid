//! Shared format-one canonical encoding helpers.

use alloc::vec::Vec;

use super::PhysicalModelError;

pub(super) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), PhysicalModelError> {
        self.u64(u64::try_from(value.len()).map_err(|_| PhysicalModelError::LengthOverflow)?);
        self.raw(value);
        Ok(())
    }

    pub(super) fn count(&mut self, count: usize) -> Result<(), PhysicalModelError> {
        self.u64(u64::try_from(count).map_err(|_| PhysicalModelError::LengthOverflow)?);
        Ok(())
    }
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn finish(self) -> Result<(), PhysicalModelError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PhysicalModelError::TrailingBytes)
        }
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], PhysicalModelError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PhysicalModelError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, PhysicalModelError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(PhysicalModelError::Truncated)
    }

    pub(super) fn u16(&mut self) -> Result<u16, PhysicalModelError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PhysicalModelError::Truncated)?,
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, PhysicalModelError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PhysicalModelError::Truncated)?,
        ))
    }

    pub(super) fn u64(&mut self) -> Result<u64, PhysicalModelError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PhysicalModelError::Truncated)?,
        ))
    }

    pub(super) fn length(&mut self) -> Result<usize, PhysicalModelError> {
        usize::try_from(self.u64()?).map_err(|_| PhysicalModelError::LengthOverflow)
    }

    pub(super) fn bytes(&mut self) -> Result<&'a [u8], PhysicalModelError> {
        let length = self.length()?;
        self.take(length)
    }

    pub(super) fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, PhysicalModelError>,
    ) -> Result<Option<T>, PhysicalModelError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            _ => Err(PhysicalModelError::InvalidOptionTag),
        }
    }
}
