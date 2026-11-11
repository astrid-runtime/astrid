//! Sealed native writes awaiting authoritative content publication.

use std::path::PathBuf;

use super::StagedContentId;
use super::format::StagingIntent;
use crate::content::{ChunkingProfile, ContentName};
use crate::principal_state::StateOwner;
use crate::principal_state::native_io::PrivateFileIdentity;

/// One sealed native write awaiting authoritative content publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyStagedContent {
    pub(super) staging_root: PathBuf,
    pub(super) path: PathBuf,
    pub(super) sequence: u64,
    pub(super) id: StagedContentId,
    pub(super) owner: StateOwner,
    pub(super) name: ContentName,
    pub(super) profile: ChunkingProfile,
    pub(super) logical_bytes: u64,
    pub(super) source_identity: PrivateFileIdentity,
}

impl ReadyStagedContent {
    pub(super) fn from_intent(
        staging_root: PathBuf,
        path: PathBuf,
        intent: StagingIntent,
        source_identity: PrivateFileIdentity,
    ) -> Self {
        Self {
            staging_root,
            path,
            sequence: intent.sequence,
            id: intent.id,
            owner: intent.owner,
            name: intent.name,
            profile: intent.profile,
            logical_bytes: intent.logical_bytes,
            source_identity,
        }
    }

    pub(super) fn intent(&self) -> StagingIntent {
        StagingIntent {
            sequence: self.sequence,
            id: self.id,
            owner: self.owner,
            name: self.name.clone(),
            profile: self.profile,
            logical_bytes: self.logical_bytes,
        }
    }

    /// Return the close-order sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the opaque staging identifier.
    #[must_use]
    pub const fn id(&self) -> StagedContentId {
        self.id
    }

    /// Return the authoritative state owner.
    #[must_use]
    pub const fn owner(&self) -> &StateOwner {
        &self.owner
    }

    /// Return the principal content name.
    #[must_use]
    pub const fn name(&self) -> &ContentName {
        &self.name
    }

    /// Return the staged byte length.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Return the pinned chunking profile selected at write creation.
    #[must_use]
    pub const fn profile(&self) -> ChunkingProfile {
        self.profile
    }

    pub(in crate::principal_state) fn content_path(&self) -> PathBuf {
        self.path.clone()
    }
}
