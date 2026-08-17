//! Public workspace branch metadata and store binding types.

use std::fmt;
use std::sync::Arc;

use astrid_core::{PrincipalUid, WorkspaceUid};

use crate::content::{ContentName, PrincipalContentError, PrincipalContentStore};
use crate::content_dag::ContentError;
use crate::engine::PrincipalProjectionError;
use crate::filesystem::FilesystemError;
use crate::storage_model::{ModelError, ObjectId};

/// Typed metadata for one owner-internal workspace branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceBranchDescriptor<P> {
    pub(super) owner: P,
    pub(super) id: WorkspaceUid,
    pub(super) binding_uid: Option<PrincipalUid>,
    pub(super) target_prefix: Option<ContentName>,
    pub(super) base_content_root: Option<ObjectId>,
    pub(super) current_content_root: Option<ObjectId>,
}

impl<P> WorkspaceBranchDescriptor<P> {
    pub(super) fn new(
        owner: P,
        id: WorkspaceUid,
        binding_uid: Option<PrincipalUid>,
        target_prefix: Option<ContentName>,
        base_content_root: Option<ObjectId>,
        current_content_root: Option<ObjectId>,
    ) -> Self {
        Self {
            owner,
            id,
            binding_uid,
            target_prefix,
            base_content_root,
            current_content_root,
        }
    }

    /// Borrow the accountable owner identity.
    #[must_use]
    pub const fn owner(&self) -> &P {
        &self.owner
    }

    /// Return the opaque branch identifier.
    #[must_use]
    pub const fn id(&self) -> WorkspaceUid {
        self.id
    }

    /// Return the immutable principal identity authorized to use this branch.
    #[must_use]
    pub const fn binding_uid(&self) -> Option<PrincipalUid> {
        self.binding_uid
    }

    /// Return the canonical owner-catalog attachment selector.
    #[must_use]
    pub fn target_prefix(&self) -> Option<&ContentName> {
        self.target_prefix.as_ref()
    }

    /// Return the owner content root captured when this branch began.
    #[must_use]
    pub const fn base_content_root(&self) -> Option<ObjectId> {
        self.base_content_root
    }

    /// Return the branch's current immutable working content root.
    #[must_use]
    pub const fn current_content_root(&self) -> Option<ObjectId> {
        self.current_content_root
    }
}

/// Failure while creating, mutating, or publishing a workspace branch.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceBranchError {
    /// The requested branch does not exist for this owner.
    #[error("workspace branch {0} does not exist")]
    NotFound(WorkspaceUid),
    /// The opaque branch identifier is already present for this owner.
    #[error("workspace branch {0} already exists")]
    AlreadyExists(WorkspaceUid),
    /// Another live branch already claims this principal/prefix attachment.
    #[error(
        "workspace binding for principal {binding_uid} and prefix {target_prefix:?} already exists"
    )]
    BindingAlreadyExists {
        /// Principal identity claiming the attachment.
        binding_uid: PrincipalUid,
        /// Canonical owner-catalog attachment selector.
        target_prefix: ContentName,
    },
    /// The owner content root changed since branch creation.
    #[error(
        "workspace branch {branch} has stale base: expected {base:?}, current owner content is {current:?}"
    )]
    StaleBase {
        /// Branch being promoted.
        branch: WorkspaceUid,
        /// Root captured at branch creation.
        base: Option<ObjectId>,
        /// Current owner content root.
        current: Option<ObjectId>,
    },
    /// The supplied branch mutation conflicts with filesystem semantics.
    #[error("workspace filesystem operation failed: {0}")]
    Filesystem(#[from] FilesystemError),
    /// The authoritative content projection rejected an operation.
    #[error("workspace content operation failed: {0}")]
    Content(#[from] PrincipalContentError),
    /// The immutable graph or owner-root transaction was rejected.
    #[error("workspace projection failed: {0}")]
    Projection(#[from] PrincipalProjectionError),
    /// A persisted branch component did not match its canonical grammar.
    #[error("invalid workspace branch graph {object:?}: {detail}")]
    InvalidGraph {
        /// Invalid immutable object.
        object: ObjectId,
        /// Stable diagnostic detail.
        detail: &'static str,
    },
    /// A branch could not be admitted without exceeding the accountable owner quota.
    #[error("workspace branch quota exceeded: {used} > {limit}")]
    QuotaExceeded {
        /// Proposed owner logical usage.
        used: u64,
        /// Current owner limit.
        limit: u64,
    },
    /// Too many branch records would make the owner state unbounded.
    #[error("workspace branch limit exceeded")]
    BranchLimitExceeded,
    /// The attachment selector was not in canonical path-prefix form.
    #[error("invalid workspace target prefix: {detail}")]
    InvalidTargetPrefix {
        /// Stable validation detail.
        detail: &'static str,
    },
}

/// Lifecycle state of a durable workspace binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceBindingLifecycle {
    /// The branch is live and may be mounted and mutated.
    Live,
    /// Promotion committed and the branch was replaced by a terminal receipt.
    Promoted,
}

/// Durable UID-keyed binding metadata reconstructed from one owner root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceBranchBinding<P> {
    descriptor: WorkspaceBranchDescriptor<P>,
    lifecycle: WorkspaceBindingLifecycle,
}

impl<P> WorkspaceBranchBinding<P> {
    pub(super) fn new(
        descriptor: WorkspaceBranchDescriptor<P>,
        lifecycle: WorkspaceBindingLifecycle,
    ) -> Self {
        Self {
            descriptor,
            lifecycle,
        }
    }

    /// Borrow the accountable owner identity.
    #[must_use]
    pub const fn owner(&self) -> &P {
        self.descriptor.owner()
    }

    /// Return the immutable acting principal UID.
    #[must_use]
    pub const fn binding_uid(&self) -> Option<PrincipalUid> {
        self.descriptor.binding_uid()
    }

    /// Return the opaque branch identifier.
    #[must_use]
    pub const fn branch_id(&self) -> WorkspaceUid {
        self.descriptor.id()
    }

    /// Return the canonical owner-catalog attachment selector.
    #[must_use]
    pub fn target_prefix(&self) -> Option<&ContentName> {
        self.descriptor.target_prefix()
    }

    /// Return the owner content root captured at begin/fork.
    #[must_use]
    pub const fn base_content_root(&self) -> Option<ObjectId> {
        self.descriptor.base_content_root()
    }

    /// Return the current immutable working content root.
    #[must_use]
    pub const fn current_content_root(&self) -> Option<ObjectId> {
        self.descriptor.current_content_root()
    }

    /// Return the durable lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> WorkspaceBindingLifecycle {
        self.lifecycle
    }

    /// Borrow the underlying branch descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &WorkspaceBranchDescriptor<P> {
        &self.descriptor
    }
}

impl From<ModelError> for WorkspaceBranchError {
    fn from(error: ModelError) -> Self {
        Self::Projection(PrincipalProjectionError::Model(error))
    }
}

impl From<ContentError> for WorkspaceBranchError {
    fn from(error: ContentError) -> Self {
        Self::Content(error.into())
    }
}

/// Durable branch manager bound to one authoritative principal content store.
pub struct WorkspaceBranchStore<P: Ord, E> {
    pub(super) content: Arc<PrincipalContentStore<P, E>>,
}

impl<P: Ord, E> Clone for WorkspaceBranchStore<P, E> {
    fn clone(&self) -> Self {
        Self {
            content: Arc::clone(&self.content),
        }
    }
}

impl<P: Ord, E> fmt::Debug for WorkspaceBranchStore<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceBranchStore")
            .finish_non_exhaustive()
    }
}

impl<P: Ord, E> WorkspaceBranchStore<P, E> {
    /// Bind workspace branches to an existing authoritative content store.
    #[must_use]
    pub fn new(content: Arc<PrincipalContentStore<P, E>>) -> Self {
        Self { content }
    }

    /// Return the underlying owner content store.
    #[must_use]
    pub fn content(&self) -> Arc<PrincipalContentStore<P, E>> {
        Arc::clone(&self.content)
    }
}
