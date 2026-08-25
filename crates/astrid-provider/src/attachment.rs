//! Opaque attachment and stream descriptors. Not host paths.

use astrid_projection::SemanticObjectId;
use astrid_projection::{
    DescriptorDecode as ProjectionDecode, DescriptorEncode as ProjectionEncode,
};
use astrid_resource_types::ObjectGeneration;

use crate::closure::{decode_resource, encode_resource};
use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProviderTypeTag, check_header, read_nested,
    require_exact_len, require_zero_padding, take, write_header, write_nested,
};
use crate::error::ProviderError;

/// Maximum attachments on one job. Encoding ceiling, not a config knob.
pub const ATTACHMENT_MAX: usize = 4;
/// Maximum streams on one job. Encoding ceiling, not a config knob.
pub const STREAM_MAX: usize = 4;

/// Opaque attached object. Not a guest host path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttachmentDescriptor {
    object: SemanticObjectId,
    generation: ObjectGeneration,
}

/// Opaque stream object. Not a live fd or socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamDescriptor {
    object: SemanticObjectId,
    generation: ObjectGeneration,
}

impl AttachmentDescriptor {
    /// Exact encoded length, including nested encodings.
    pub const ENCODED_LEN: usize = 52;

    /// Bind an attachment to a projected object generation.
    #[must_use]
    pub const fn new(object: SemanticObjectId, generation: ObjectGeneration) -> Self {
        Self { object, generation }
    }

    /// Projected object this attachment names.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Object generation of the attachment.
    #[must_use]
    pub const fn generation(self) -> ObjectGeneration {
        self.generation
    }
}

impl StreamDescriptor {
    /// Exact encoded length, including nested encodings.
    pub const ENCODED_LEN: usize = 52;

    /// Bind a stream to a projected object generation.
    #[must_use]
    pub const fn new(object: SemanticObjectId, generation: ObjectGeneration) -> Self {
        Self { object, generation }
    }

    /// Projected object this stream names.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Object generation of the stream.
    #[must_use]
    pub const fn generation(self) -> ObjectGeneration {
        self.generation
    }
}

/// Bounded attachment list. Unused slots encode as zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentSet {
    items: [Option<AttachmentDescriptor>; ATTACHMENT_MAX],
    count: u8,
}

/// Bounded stream list. Unused slots encode as zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSet {
    items: [Option<StreamDescriptor>; STREAM_MAX],
    count: u8,
}

impl AttachmentSet {
    /// Exact encoded length, including unused zero padding.
    pub const ENCODED_LEN: usize = 212;
    /// Empty attachment list.
    pub const EMPTY: Self = Self {
        items: [None; ATTACHMENT_MAX],
        count: 0,
    };

    /// Construct from unique attachment descriptors.
    ///
    /// # Errors
    ///
    /// Rejects oversize sets and duplicate object identities.
    pub fn try_from_descriptors(
        descriptors: &[AttachmentDescriptor],
    ) -> Result<Self, ProviderError> {
        build_set(
            descriptors,
            ProviderError::AttachmentLimit,
            ProviderError::DuplicateAttachment,
        )
        .map(|(items, count)| Self { items, count })
    }

    /// Number of stored attachments.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether there are no attachments.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate attachments in stored order.
    pub fn iter(&self) -> impl Iterator<Item = AttachmentDescriptor> + '_ {
        self.items.iter().take(self.len()).filter_map(|item| *item)
    }
}

impl StreamSet {
    /// Exact encoded length, including unused zero padding.
    pub const ENCODED_LEN: usize = 212;
    /// Empty stream list.
    pub const EMPTY: Self = Self {
        items: [None; STREAM_MAX],
        count: 0,
    };

    /// Construct from unique stream descriptors.
    ///
    /// # Errors
    ///
    /// Rejects oversize sets and duplicate object identities.
    pub fn try_from_descriptors(descriptors: &[StreamDescriptor]) -> Result<Self, ProviderError> {
        build_set(
            descriptors,
            ProviderError::StreamLimit,
            ProviderError::DuplicateStream,
        )
        .map(|(items, count)| Self { items, count })
    }

    /// Number of stored streams.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether there are no streams.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate streams in stored order.
    pub fn iter(&self) -> impl Iterator<Item = StreamDescriptor> + '_ {
        self.items.iter().take(self.len()).filter_map(|item| *item)
    }
}

fn build_set<T: Copy + ObjectNamed, const N: usize>(
    descriptors: &[T],
    limit: ProviderError,
    duplicate: ProviderError,
) -> Result<([Option<T>; N], u8), ProviderError> {
    if descriptors.len() > N {
        return Err(limit);
    }
    reject_duplicate_objects(descriptors, duplicate)?;
    let mut items = [None; N];
    for (index, descriptor) in descriptors.iter().enumerate() {
        let slot = items.get_mut(index).ok_or(limit)?;
        *slot = Some(*descriptor);
    }
    Ok((items, u8::try_from(descriptors.len()).map_err(|_| limit)?))
}

trait ObjectNamed {
    fn object(&self) -> SemanticObjectId;
}

impl ObjectNamed for AttachmentDescriptor {
    fn object(&self) -> SemanticObjectId {
        self.object
    }
}

impl ObjectNamed for StreamDescriptor {
    fn object(&self) -> SemanticObjectId {
        self.object
    }
}

fn reject_duplicate_objects<T: ObjectNamed>(
    descriptors: &[T],
    duplicate: ProviderError,
) -> Result<(), ProviderError> {
    for (index, item) in descriptors.iter().enumerate() {
        if descriptors
            .get(index.checked_add(1).unwrap_or(descriptors.len())..)
            .unwrap_or(&[])
            .iter()
            .any(|other| other.object() == item.object())
        {
            return Err(duplicate);
        }
    }
    Ok(())
}

fn encode_named_pair(
    output: &mut [u8],
    tag: ProviderTypeTag,
    expected: usize,
    object: SemanticObjectId,
    generation: ObjectGeneration,
) -> Result<(), ProviderError> {
    require_exact_len(output, expected)?;
    write_header(output, tag)?;
    let mut object_bytes = [0_u8; 38];
    object
        .encode_descriptor(&mut object_bytes)
        .map_err(|_| ProviderError::ProjectionEncoding)?;
    output
        .get_mut(3..41)
        .ok_or(ProviderError::InvalidLength)?
        .copy_from_slice(&object_bytes);
    encode_resource(output, 41, &generation)?;
    Ok(())
}

fn decode_named_pair(
    input: &[u8],
    tag: ProviderTypeTag,
    expected: usize,
) -> Result<(SemanticObjectId, ObjectGeneration), ProviderError> {
    require_exact_len(input, expected)?;
    check_header(input, tag)?;
    let object =
        SemanticObjectId::decode_descriptor(input.get(3..41).ok_or(ProviderError::InvalidLength)?)
            .map_err(|_| ProviderError::ProjectionEncoding)?;
    let (generation, _) = decode_resource::<ObjectGeneration>(input, 41, 11)?;
    Ok((object, generation))
}

impl DescriptorEncode for AttachmentDescriptor {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        encode_named_pair(
            output,
            ProviderTypeTag::AttachmentDescriptor,
            Self::ENCODED_LEN,
            self.object,
            self.generation,
        )
    }
}

impl DescriptorDecode for AttachmentDescriptor {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        let (object, generation) = decode_named_pair(
            input,
            ProviderTypeTag::AttachmentDescriptor,
            Self::ENCODED_LEN,
        )?;
        Ok(Self::new(object, generation))
    }
}

impl DescriptorEncode for StreamDescriptor {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        encode_named_pair(
            output,
            ProviderTypeTag::StreamDescriptor,
            Self::ENCODED_LEN,
            self.object,
            self.generation,
        )
    }
}

impl DescriptorDecode for StreamDescriptor {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        let (object, generation) =
            decode_named_pair(input, ProviderTypeTag::StreamDescriptor, Self::ENCODED_LEN)?;
        Ok(Self::new(object, generation))
    }
}

fn encode_padded_set<T: DescriptorEncode + Copy>(
    output: &mut [u8],
    tag: ProviderTypeTag,
    expected: usize,
    count: u8,
    items: impl Iterator<Item = T>,
) -> Result<(), ProviderError> {
    require_exact_len(output, expected)?;
    output.fill(0);
    write_header(output, tag)?;
    let count_slot = output.get_mut(3).ok_or(ProviderError::InvalidLength)?;
    *count_slot = count;
    let mut offset = 4_usize;
    for item in items {
        offset = write_nested(output, offset, &item)?;
    }
    Ok(())
}

fn decode_padded_set<T: DescriptorDecode + Copy + ObjectNamed, const N: usize>(
    input: &[u8],
    tag: ProviderTypeTag,
    expected: usize,
    item_len: usize,
    limit: ProviderError,
    duplicate: ProviderError,
) -> Result<([Option<T>; N], u8), ProviderError> {
    require_exact_len(input, expected)?;
    check_header(input, tag)?;
    let (count_bytes, mut offset) = take(input, 3, 1)?;
    let count = count_bytes[0];
    if usize::from(count) > N {
        return Err(limit);
    }
    let mut items = [None; N];
    let mut seen = [None; N];
    for index in 0..usize::from(count) {
        let (item, next) = read_nested::<T>(input, offset, item_len)?;
        if seen
            .iter()
            .take(index)
            .any(|prior| prior.is_some_and(|object| object == item.object()))
        {
            return Err(duplicate);
        }
        let seen_slot = seen.get_mut(index).ok_or(limit)?;
        *seen_slot = Some(item.object());
        let slot = items.get_mut(index).ok_or(limit)?;
        *slot = Some(item);
        offset = next;
    }
    require_zero_padding(input.get(offset..).ok_or(ProviderError::InvalidLength)?)?;
    Ok((items, count))
}

impl DescriptorEncode for AttachmentSet {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        encode_padded_set(
            output,
            ProviderTypeTag::AttachmentSet,
            Self::ENCODED_LEN,
            self.count,
            self.iter(),
        )
    }
}

impl DescriptorDecode for AttachmentSet {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        let (items, count) = decode_padded_set::<AttachmentDescriptor, ATTACHMENT_MAX>(
            input,
            ProviderTypeTag::AttachmentSet,
            Self::ENCODED_LEN,
            AttachmentDescriptor::ENCODED_LEN,
            ProviderError::AttachmentLimit,
            ProviderError::DuplicateAttachment,
        )?;
        Ok(Self { items, count })
    }
}

impl DescriptorEncode for StreamSet {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        encode_padded_set(
            output,
            ProviderTypeTag::StreamSet,
            Self::ENCODED_LEN,
            self.count,
            self.iter(),
        )
    }
}

impl DescriptorDecode for StreamSet {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError> {
        let (items, count) = decode_padded_set::<StreamDescriptor, STREAM_MAX>(
            input,
            ProviderTypeTag::StreamSet,
            Self::ENCODED_LEN,
            StreamDescriptor::ENCODED_LEN,
            ProviderError::StreamLimit,
            ProviderError::DuplicateStream,
        )?;
        Ok(Self { items, count })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::ResourceId;

    fn object(byte: u8) -> SemanticObjectId {
        SemanticObjectId::for_resource(ResourceId::from_bytes([byte; 32]))
    }

    #[test]
    fn attachment_is_not_a_stream_and_rejects_duplicates() {
        let attachment = AttachmentDescriptor::new(object(1), ObjectGeneration::INITIAL);
        let stream = StreamDescriptor::new(object(1), ObjectGeneration::INITIAL);
        let mut encoded = [0_u8; AttachmentDescriptor::ENCODED_LEN];
        attachment.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(
            StreamDescriptor::decode_descriptor(&encoded),
            Err(ProviderError::WrongTypeTag {
                expected: ProviderTypeTag::StreamDescriptor.code(),
                actual: ProviderTypeTag::AttachmentDescriptor.code(),
            })
        );
        assert_eq!(
            AttachmentSet::try_from_descriptors(&[attachment, attachment]),
            Err(ProviderError::DuplicateAttachment)
        );
        assert_eq!(
            StreamSet::try_from_descriptors(&[stream, stream]),
            Err(ProviderError::DuplicateStream)
        );
        let set = AttachmentSet::try_from_descriptors(&[attachment]).unwrap();
        let mut set_bytes = [0_u8; AttachmentSet::ENCODED_LEN];
        set.encode_descriptor(&mut set_bytes).unwrap();
        assert_eq!(AttachmentSet::decode_descriptor(&set_bytes), Ok(set));
    }
}
