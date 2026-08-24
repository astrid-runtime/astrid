//! Immutable snapshot and update descriptors.

use astrid_resource_types::{CanonicalDecode, CanonicalEncode, ResourceTypeId};

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, take, write_header,
};
use crate::error::ProjectionError;
use crate::object::SemanticObjectId;
use crate::presentation::{PresentationLabel, PresentationMetadata};
use crate::revision::ProjectionRevision;

/// Uninhabited type: presentation cannot produce a live invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveInvocation {}

/// Immutable projection snapshot. Not a handle table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionSnapshot {
    object: SemanticObjectId,
    type_id: ResourceTypeId,
    revision: ProjectionRevision,
    label: PresentationLabel,
    metadata: PresentationMetadata,
}

impl ProjectionSnapshot {
    /// Construct a snapshot at an explicit revision.
    #[must_use]
    pub const fn new(
        object: SemanticObjectId,
        type_id: ResourceTypeId,
        revision: ProjectionRevision,
        label: PresentationLabel,
        metadata: PresentationMetadata,
    ) -> Self {
        Self {
            object,
            type_id,
            revision,
            label,
            metadata,
        }
    }

    /// Object this snapshot names.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Schema/type reference. Not `SchemaCatalog` and not a string topic.
    #[must_use]
    pub const fn type_id(self) -> ResourceTypeId {
        self.type_id
    }

    /// Snapshot revision.
    #[must_use]
    pub const fn revision(self) -> ProjectionRevision {
        self.revision
    }

    /// Presentation label. Not authority.
    #[must_use]
    pub const fn label(self) -> PresentationLabel {
        self.label
    }

    /// Presentation metadata. Not a rights or grant map.
    #[must_use]
    pub const fn metadata(self) -> PresentationMetadata {
        self.metadata
    }

    /// Apply a successor update.
    ///
    /// Labels and metadata may change. They still cannot invoke.
    ///
    /// # Errors
    ///
    /// Rejects object mismatch, schema/type confusion, and stale revisions.
    pub fn apply(&self, update: &ProjectionUpdate) -> Result<Self, ProjectionError> {
        if self.object != update.object {
            return Err(ProjectionError::UnknownObject);
        }
        if self.type_id != update.type_id {
            return Err(ProjectionError::TypeMismatch);
        }
        if self.revision != update.from {
            return Err(ProjectionError::StaleRevision {
                found: self.revision.get(),
                requested: update.from.get(),
            });
        }
        Ok(Self::new(
            self.object,
            self.type_id,
            update.to,
            update.label,
            update.metadata,
        ))
    }

    /// Presentation never becomes a live invocation.
    ///
    /// # Errors
    ///
    /// Always [`ProjectionError::NotAnInvocation`].
    pub const fn as_live_invocation(&self) -> Result<LiveInvocation, ProjectionError> {
        let _ = self;
        Err(ProjectionError::NotAnInvocation)
    }
}

/// Immutable successor descriptor. `to` is always `from.checked_next()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionUpdate {
    object: SemanticObjectId,
    type_id: ResourceTypeId,
    from: ProjectionRevision,
    to: ProjectionRevision,
    label: PresentationLabel,
    metadata: PresentationMetadata,
}

impl ProjectionUpdate {
    /// Build the unique successor update for `from`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ExhaustedRevision`] at `u64::MAX`.
    pub fn advance(
        object: SemanticObjectId,
        type_id: ResourceTypeId,
        from: ProjectionRevision,
        label: PresentationLabel,
        metadata: PresentationMetadata,
    ) -> Result<Self, ProjectionError> {
        Ok(Self {
            object,
            type_id,
            from,
            to: from.checked_next()?,
            label,
            metadata,
        })
    }

    /// Object this update names.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Schema/type that must match the stored snapshot.
    #[must_use]
    pub const fn type_id(self) -> ResourceTypeId {
        self.type_id
    }

    /// Expected current revision.
    #[must_use]
    pub const fn from(self) -> ProjectionRevision {
        self.from
    }

    /// Resulting revision.
    #[must_use]
    pub const fn to(self) -> ProjectionRevision {
        self.to
    }

    /// Presentation label carried by the successor. Not authority.
    #[must_use]
    pub const fn label(self) -> PresentationLabel {
        self.label
    }

    /// Presentation metadata carried by the successor. Not a grant map.
    #[must_use]
    pub const fn metadata(self) -> PresentationMetadata {
        self.metadata
    }
}

fn write_identity_prefix(
    output: &mut [u8],
    tag: ProjectionTypeTag,
    object: SemanticObjectId,
    type_id: ResourceTypeId,
) -> Result<(), ProjectionError> {
    write_header(output, tag)?;
    object.encode_descriptor(
        output
            .get_mut(3..41)
            .ok_or(ProjectionError::InvalidLength)?,
    )?;
    type_id
        .encode_canonical(
            output
                .get_mut(41..76)
                .ok_or(ProjectionError::InvalidLength)?,
        )
        .map_err(|_| ProjectionError::ResourceEncoding)?;
    Ok(())
}

fn encode_presentation_tail(
    output: &mut [u8],
    offset: usize,
    label: &PresentationLabel,
    metadata: &PresentationMetadata,
) -> Result<(), ProjectionError> {
    let label_len = label.encoded_len();
    label.encode_descriptor(
        output
            .get_mut(offset..)
            .and_then(|rest| rest.get_mut(..label_len))
            .ok_or(ProjectionError::InvalidLength)?,
    )?;
    let meta_at = offset
        .checked_add(label_len)
        .ok_or(ProjectionError::InvalidLength)?;
    metadata.encode_descriptor(
        output
            .get_mut(meta_at..)
            .ok_or(ProjectionError::InvalidLength)?,
    )
}

impl DescriptorEncode for ProjectionSnapshot {
    fn encoded_len(&self) -> usize {
        87_usize
            .checked_add(self.label.encoded_len())
            .and_then(|n| n.checked_add(self.metadata.encoded_len()))
            .expect("snapshot size is bounded")
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != self.encoded_len() {
            return Err(ProjectionError::InvalidLength);
        }
        write_identity_prefix(
            output,
            ProjectionTypeTag::ProjectionSnapshot,
            self.object,
            self.type_id,
        )?;
        self.revision.encode_descriptor(
            output
                .get_mut(76..87)
                .ok_or(ProjectionError::InvalidLength)?,
        )?;
        encode_presentation_tail(output, 87, &self.label, &self.metadata)
    }
}

fn decode_prefix(
    input: &[u8],
    tag: ProjectionTypeTag,
) -> Result<(SemanticObjectId, ResourceTypeId, ProjectionRevision, usize), ProjectionError> {
    check_header(input, tag)?;
    let (object_bytes, offset) = take(input, 3, 38)?;
    let object = SemanticObjectId::decode_descriptor(object_bytes)?;
    let (type_bytes, offset) = take(input, offset, 35)?;
    let type_id = ResourceTypeId::decode_canonical(type_bytes)
        .map_err(|_| ProjectionError::ResourceEncoding)?;
    let (rev_bytes, offset) = take(input, offset, 11)?;
    let revision = ProjectionRevision::decode_descriptor(rev_bytes)?;
    Ok((object, type_id, revision, offset))
}

fn decode_label_at(
    input: &[u8],
    offset: usize,
) -> Result<(PresentationLabel, usize), ProjectionError> {
    check_header(
        input.get(offset..).ok_or(ProjectionError::InvalidLength)?,
        ProjectionTypeTag::PresentationLabel,
    )?;
    let (len_bytes, _) = take(
        input,
        offset
            .checked_add(3)
            .ok_or(ProjectionError::InvalidLength)?,
        2,
    )?;
    let label_body = usize::from(u16::from_le_bytes(
        len_bytes
            .try_into()
            .map_err(|_| ProjectionError::InvalidLength)?,
    ));
    let label_len = 5_usize
        .checked_add(label_body)
        .ok_or(ProjectionError::InvalidLength)?;
    let (label_bytes, next) = take(input, offset, label_len)?;
    Ok((PresentationLabel::decode_descriptor(label_bytes)?, next))
}

impl DescriptorDecode for ProjectionSnapshot {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        let (object, type_id, revision, offset) =
            decode_prefix(input, ProjectionTypeTag::ProjectionSnapshot)?;
        let (label, offset) = decode_label_at(input, offset)?;
        let metadata = PresentationMetadata::decode_descriptor(
            input.get(offset..).ok_or(ProjectionError::InvalidLength)?,
        )?;
        Ok(Self::new(object, type_id, revision, label, metadata))
    }
}

impl DescriptorEncode for ProjectionUpdate {
    fn encoded_len(&self) -> usize {
        98_usize
            .checked_add(self.label.encoded_len())
            .and_then(|n| n.checked_add(self.metadata.encoded_len()))
            .expect("update size is bounded")
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != self.encoded_len() {
            return Err(ProjectionError::InvalidLength);
        }
        write_identity_prefix(
            output,
            ProjectionTypeTag::ProjectionUpdate,
            self.object,
            self.type_id,
        )?;
        self.from.encode_descriptor(
            output
                .get_mut(76..87)
                .ok_or(ProjectionError::InvalidLength)?,
        )?;
        self.to.encode_descriptor(
            output
                .get_mut(87..98)
                .ok_or(ProjectionError::InvalidLength)?,
        )?;
        encode_presentation_tail(output, 98, &self.label, &self.metadata)
    }
}

impl DescriptorDecode for ProjectionUpdate {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        let (object, type_id, from, offset) =
            decode_prefix(input, ProjectionTypeTag::ProjectionUpdate)?;
        let (to_bytes, offset) = take(input, offset, 11)?;
        let to = ProjectionRevision::decode_descriptor(to_bytes)?;
        if to != from.checked_next()? {
            return Err(ProjectionError::NonCanonical);
        }
        let (label, offset) = decode_label_at(input, offset)?;
        let metadata = PresentationMetadata::decode_descriptor(
            input.get(offset..).ok_or(ProjectionError::InvalidLength)?,
        )?;
        Self::advance(object, type_id, from, label, metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_resource_types::{ResourceId, ResourceTypeId};

    fn sample() -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            SemanticObjectId::for_resource(ResourceId::from_bytes([1; 32])),
            ResourceTypeId::from_bytes([2; 32]),
            ProjectionRevision::INITIAL,
            PresentationLabel::from_utf8(b"alpha").unwrap(),
            PresentationMetadata::EMPTY,
        )
    }

    #[test]
    fn snapshot_roundtrip_and_is_not_invocation() {
        let snap = sample();
        let mut buf = [0_u8; 256];
        let n = snap.encoded_len();
        snap.encode_descriptor(&mut buf[..n]).unwrap();
        let decoded = ProjectionSnapshot::decode_descriptor(&buf[..n]).unwrap();
        assert_eq!(decoded, snap);
        assert_eq!(
            snap.as_live_invocation(),
            Err(ProjectionError::NotAnInvocation)
        );
        assert!(ProjectionSnapshot::decode_descriptor(&buf[..=n]).is_err());
    }

    #[test]
    fn stale_and_type_mismatch_reject_updates() {
        let snap = sample();
        let other_type = ResourceTypeId::from_bytes([9; 32]);
        let stale = ProjectionUpdate::advance(
            snap.object(),
            snap.type_id(),
            snap.revision().checked_next().unwrap(),
            snap.label(),
            snap.metadata(),
        )
        .unwrap();
        assert!(matches!(
            snap.apply(&stale),
            Err(ProjectionError::StaleRevision { .. })
        ));
        let confused = ProjectionUpdate::advance(
            snap.object(),
            other_type,
            snap.revision(),
            snap.label(),
            snap.metadata(),
        )
        .unwrap();
        assert_eq!(snap.apply(&confused), Err(ProjectionError::TypeMismatch));
    }
}
