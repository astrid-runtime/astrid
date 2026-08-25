//! Non-authoritative presentation labels and metadata.
//!
//! These values are host-experience hints. They cannot mint, copy, widen, or
//! substitute authority. Limits are encoding ceilings, not config knobs:
//! changing them is a descriptor-version bump.

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, take, write_header,
};
use crate::error::ProjectionError;

/// Maximum UTF-8 bytes in a display label (one presentation line).
pub const LABEL_MAX_BYTES: usize = 256;
/// Maximum presentation attributes on one snapshot.
pub const METADATA_MAX_ENTRIES: usize = 8;
/// Maximum UTF-8 bytes in a metadata key.
pub const METADATA_KEY_MAX_BYTES: usize = 32;
/// Maximum UTF-8 bytes in a metadata value.
pub const METADATA_VALUE_MAX_BYTES: usize = 128;
/// Maximum encoded metadata bytes. Encoding ceiling, not a config knob.
const METADATA_MAX_ENCODED_BYTES: usize = 1300;

/// Display label. Never a grant, handle, or invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentationLabel {
    bytes: [u8; LABEL_MAX_BYTES],
    len: u16,
}

impl PresentationLabel {
    /// Empty label.
    pub const EMPTY: Self = Self {
        bytes: [0; LABEL_MAX_BYTES],
        len: 0,
    };

    /// Parse a UTF-8 label.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::LabelTooLong`] or [`ProjectionError::InvalidUtf8`].
    pub fn from_utf8(text: &[u8]) -> Result<Self, ProjectionError> {
        if text.len() > LABEL_MAX_BYTES {
            return Err(ProjectionError::LabelTooLong);
        }
        let parsed = core::str::from_utf8(text).map_err(|_| ProjectionError::InvalidUtf8)?;
        let mut bytes = [0_u8; LABEL_MAX_BYTES];
        let slot = bytes
            .get_mut(..parsed.len())
            .ok_or(ProjectionError::LabelTooLong)?;
        slot.copy_from_slice(parsed.as_bytes());
        let len = u16::try_from(parsed.len()).map_err(|_| ProjectionError::LabelTooLong)?;
        Ok(Self { bytes, len })
    }

    /// UTF-8 view of the label.
    ///
    /// # Panics
    ///
    /// Panics if stored bytes are not UTF-8. Constructors reject non-UTF-8 input.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let len = usize::from(self.len);
        core::str::from_utf8(self.bytes.get(..len).unwrap_or(&[]))
            .expect("labels are UTF-8 by construction")
    }
}

impl DescriptorEncode for PresentationLabel {
    fn encoded_len(&self) -> usize {
        5_usize
            .checked_add(usize::from(self.len))
            .expect("label length is bounded by LABEL_MAX_BYTES")
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != self.encoded_len() {
            return Err(ProjectionError::InvalidLength);
        }
        write_header(output, ProjectionTypeTag::PresentationLabel)?;
        let len = usize::from(self.len);
        let header = output.get_mut(3..5).ok_or(ProjectionError::InvalidLength)?;
        header.copy_from_slice(&self.len.to_le_bytes());
        output
            .get_mut(5..)
            .and_then(|rest| rest.get_mut(..len))
            .ok_or(ProjectionError::InvalidLength)?
            .copy_from_slice(
                self.bytes
                    .get(..len)
                    .ok_or(ProjectionError::InvalidLength)?,
            );
        Ok(())
    }
}

impl DescriptorDecode for PresentationLabel {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        check_header(input, ProjectionTypeTag::PresentationLabel)?;
        let (len_bytes, offset) = take(input, 3, 2)?;
        let len = u16::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        );
        if usize::from(len) > LABEL_MAX_BYTES {
            return Err(ProjectionError::LabelTooLong);
        }
        let (body, end) = take(input, offset, usize::from(len))?;
        if end != input.len() {
            return Err(ProjectionError::NonCanonical);
        }
        Self::from_utf8(body)
    }
}

/// One presentation attribute. Keys and values are not policy language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PresentationAttr {
    key: [u8; METADATA_KEY_MAX_BYTES],
    key_len: u8,
    value: [u8; METADATA_VALUE_MAX_BYTES],
    value_len: u8,
}

impl PresentationAttr {
    const EMPTY: Self = Self {
        key: [0; METADATA_KEY_MAX_BYTES],
        key_len: 0,
        value: [0; METADATA_VALUE_MAX_BYTES],
        value_len: 0,
    };

    fn from_pair(key: &str, value: &str) -> Result<Self, ProjectionError> {
        if key.is_empty() {
            return Err(ProjectionError::EmptyMetadataKey);
        }
        if key.len() > METADATA_KEY_MAX_BYTES || value.len() > METADATA_VALUE_MAX_BYTES {
            return Err(ProjectionError::MetadataLimit);
        }
        let mut attr = Self::EMPTY;
        attr.key
            .get_mut(..key.len())
            .ok_or(ProjectionError::MetadataLimit)?
            .copy_from_slice(key.as_bytes());
        attr.value
            .get_mut(..value.len())
            .ok_or(ProjectionError::MetadataLimit)?
            .copy_from_slice(value.as_bytes());
        attr.key_len = u8::try_from(key.len()).map_err(|_| ProjectionError::MetadataLimit)?;
        attr.value_len = u8::try_from(value.len()).map_err(|_| ProjectionError::MetadataLimit)?;
        Ok(attr)
    }

    fn key_bytes(&self) -> &[u8] {
        self.key.get(..usize::from(self.key_len)).unwrap_or(&[])
    }

    fn value_bytes(&self) -> &[u8] {
        self.value.get(..usize::from(self.value_len)).unwrap_or(&[])
    }

    fn encoded_body_len(&self) -> usize {
        2_usize
            .checked_add(usize::from(self.key_len))
            .and_then(|n| n.checked_add(usize::from(self.value_len)))
            .expect("attribute sizes are bounded")
    }
}

/// Bounded presentation attributes. Not a rights map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentationMetadata {
    attrs: [PresentationAttr; METADATA_MAX_ENTRIES],
    count: u8,
}

impl PresentationMetadata {
    /// No presentation attributes.
    pub const EMPTY: Self = Self {
        attrs: [PresentationAttr::EMPTY; METADATA_MAX_ENTRIES],
        count: 0,
    };

    /// Construct from UTF-8 pairs. Keys are unique and stored in sorted order.
    ///
    /// # Errors
    ///
    /// Rejects empty keys, oversize fields, too many entries, and duplicates.
    pub fn try_from_pairs(pairs: &[(&str, &str)]) -> Result<Self, ProjectionError> {
        if pairs.len() > METADATA_MAX_ENTRIES {
            return Err(ProjectionError::MetadataLimit);
        }
        let mut attrs = [PresentationAttr::EMPTY; METADATA_MAX_ENTRIES];
        let mut count = 0_u8;
        for (key, value) in pairs {
            let index = usize::from(count);
            let slot = attrs.get_mut(index).ok_or(ProjectionError::MetadataLimit)?;
            *slot = PresentationAttr::from_pair(key, value)?;
            count = count.checked_add(1).ok_or(ProjectionError::MetadataLimit)?;
        }
        sort_attrs(&mut attrs, count);
        reject_duplicate_keys(&attrs, count)?;
        Ok(Self { attrs, count })
    }

    /// Number of stored attributes.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether there are no attributes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate key/value pairs in canonical key order.
    ///
    /// # Panics
    ///
    /// Panics if stored bytes are not UTF-8. Constructors reject non-UTF-8 input.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attrs.iter().take(usize::from(self.count)).map(|attr| {
            let key = core::str::from_utf8(attr.key_bytes())
                .expect("metadata keys are UTF-8 by construction");
            let value = core::str::from_utf8(attr.value_bytes())
                .expect("metadata values are UTF-8 by construction");
            (key, value)
        })
    }
}

fn sort_attrs(attrs: &mut [PresentationAttr; METADATA_MAX_ENTRIES], count: u8) {
    attrs
        .get_mut(..usize::from(count))
        .unwrap_or(&mut [])
        .sort_unstable_by(|left, right| left.key_bytes().cmp(right.key_bytes()));
}

fn reject_duplicate_keys(
    attrs: &[PresentationAttr; METADATA_MAX_ENTRIES],
    count: u8,
) -> Result<(), ProjectionError> {
    let occupied = attrs.get(..usize::from(count)).unwrap_or(&[]);
    if occupied
        .windows(2)
        .any(|pair| pair[0].key_bytes() == pair[1].key_bytes())
    {
        return Err(ProjectionError::DuplicateMetadataKey);
    }
    Ok(())
}

impl DescriptorEncode for PresentationMetadata {
    fn encoded_len(&self) -> usize {
        let mut total = 4_usize;
        for attr in self.attrs.iter().take(usize::from(self.count)) {
            total = total
                .checked_add(attr.encoded_body_len())
                .expect("metadata size is bounded");
        }
        total
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != self.encoded_len() {
            return Err(ProjectionError::InvalidLength);
        }
        write_header(output, ProjectionTypeTag::PresentationMetadata)?;
        let count_slot = output.get_mut(3).ok_or(ProjectionError::InvalidLength)?;
        *count_slot = self.count;
        let mut offset = 4_usize;
        for attr in self.attrs.iter().take(usize::from(self.count)) {
            offset = write_attr(output, offset, attr)?;
        }
        if offset != output.len() {
            return Err(ProjectionError::NonCanonical);
        }
        Ok(())
    }
}

fn write_attr(
    output: &mut [u8],
    offset: usize,
    attr: &PresentationAttr,
) -> Result<usize, ProjectionError> {
    let key = attr.key_bytes();
    let value = attr.value_bytes();
    let key_slot = output
        .get_mut(offset)
        .ok_or(ProjectionError::InvalidLength)?;
    *key_slot = attr.key_len;
    let after_key_len = offset
        .checked_add(1)
        .ok_or(ProjectionError::InvalidLength)?;
    output
        .get_mut(after_key_len..)
        .and_then(|rest| rest.get_mut(..key.len()))
        .ok_or(ProjectionError::InvalidLength)?
        .copy_from_slice(key);
    let value_len_at = after_key_len
        .checked_add(key.len())
        .ok_or(ProjectionError::InvalidLength)?;
    let value_len_slot = output
        .get_mut(value_len_at)
        .ok_or(ProjectionError::InvalidLength)?;
    *value_len_slot = attr.value_len;
    let after_value_len = value_len_at
        .checked_add(1)
        .ok_or(ProjectionError::InvalidLength)?;
    output
        .get_mut(after_value_len..)
        .and_then(|rest| rest.get_mut(..value.len()))
        .ok_or(ProjectionError::InvalidLength)?
        .copy_from_slice(value);
    after_value_len
        .checked_add(value.len())
        .ok_or(ProjectionError::InvalidLength)
}

impl DescriptorDecode for PresentationMetadata {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        check_header(input, ProjectionTypeTag::PresentationMetadata)?;
        let (count_bytes, mut offset) = take(input, 3, 1)?;
        let count = count_bytes[0];
        if usize::from(count) > METADATA_MAX_ENTRIES {
            return Err(ProjectionError::MetadataLimit);
        }
        let mut pairs = [("", ""); METADATA_MAX_ENTRIES];
        for index in 0..usize::from(count) {
            let (key, value, next) = take_pair(input, offset)?;
            offset = next;
            let slot = pairs.get_mut(index).ok_or(ProjectionError::MetadataLimit)?;
            *slot = (key, value);
        }
        if offset != input.len() {
            return Err(ProjectionError::NonCanonical);
        }
        let decoded = Self::try_from_pairs(pairs.get(..usize::from(count)).unwrap_or(&[]))?;
        reject_non_canonical_metadata(input, &decoded)?;
        Ok(decoded)
    }
}

fn reject_non_canonical_metadata(
    input: &[u8],
    decoded: &PresentationMetadata,
) -> Result<(), ProjectionError> {
    if decoded.encoded_len() != input.len() {
        return Err(ProjectionError::NonCanonical);
    }
    let mut canonical = [0_u8; METADATA_MAX_ENCODED_BYTES];
    let slot = canonical
        .get_mut(..input.len())
        .ok_or(ProjectionError::MetadataLimit)?;
    decoded.encode_descriptor(slot)?;
    if slot != input {
        return Err(ProjectionError::NonCanonical);
    }
    Ok(())
}

fn take_pair(input: &[u8], offset: usize) -> Result<(&str, &str, usize), ProjectionError> {
    let (key_len_bytes, next) = take(input, offset, 1)?;
    let (key, next) = take(input, next, usize::from(key_len_bytes[0]))?;
    let (value_len_bytes, next) = take(input, next, 1)?;
    let (value, next) = take(input, next, usize::from(value_len_bytes[0]))?;
    let key = core::str::from_utf8(key).map_err(|_| ProjectionError::InvalidUtf8)?;
    let value = core::str::from_utf8(value).map_err(|_| ProjectionError::InvalidUtf8)?;
    Ok((key, value, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_sorts_and_rejects_duplicates() {
        let meta = PresentationMetadata::try_from_pairs(&[("b", "2"), ("a", "1")]).unwrap();
        let collected: [&str; 2] = {
            let mut keys = [""; 2];
            for (index, (key, _)) in meta.iter().enumerate() {
                keys[index] = key;
            }
            keys
        };
        assert_eq!(collected, ["a", "b"]);
        assert_eq!(
            PresentationMetadata::try_from_pairs(&[("a", "1"), ("a", "2")]),
            Err(ProjectionError::DuplicateMetadataKey)
        );
        assert_eq!(
            PresentationLabel::from_utf8(&[0xff]),
            Err(ProjectionError::InvalidUtf8)
        );
    }

    #[test]
    fn unsorted_metadata_bytes_are_non_canonical() {
        let meta = PresentationMetadata::try_from_pairs(&[("a", "1"), ("b", "2")]).unwrap();
        let mut buf = [0_u8; 32];
        let n = meta.encoded_len();
        meta.encode_descriptor(&mut buf[..n]).unwrap();
        assert_eq!(PresentationMetadata::decode_descriptor(&buf[..n]), Ok(meta));
        let attrs = buf.get_mut(4..12).unwrap();
        let (left, right) = attrs.split_at_mut(4);
        left.swap_with_slice(right);
        assert_eq!(
            PresentationMetadata::decode_descriptor(&buf[..n]),
            Err(ProjectionError::NonCanonical)
        );
    }
}
