//! Host-neutral projection descriptors for Astrid.
//!
//! A projection names typed state, object identity, schema/type references,
//! revisions, and presentation labels. It is never identity, authority, consent,
//! or policy. Serialized descriptors and labels cannot mint a live invocation,
//! action handle, lease, or grant.
//!
//! [`SemanticObjectId`] is bound to [`astrid_resource_types::ResourceId`]. It is
//! not a string name and not [`astrid_resource_types::ResourceKind::SemanticObject`].
//!
//! Descriptor bytes are not canonical Astrid authority and never confer a
//! live invocation. This crate has no Serde surface in WP4-A.
//!
//! This crate contains no `ActionHandle` table, `ServiceLease`, `ResourceAuthority`,
//! admit/start, receipts, `SchemaCatalog`, WIT, or provider behavior.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod action_descriptor;
mod encoding;
mod error;
mod fixtures;
mod object;
mod presentation;
mod revision;
mod snapshot;
mod view;

pub use action_descriptor::{
    ACTION_BINDING_BYTES, ACTION_DESCRIPTOR_ENCODED_LEN, ActionDescriptor, ActionDescriptorFacts,
    ActionDigest, ActionEligibility, ActionExpiry, ActionGeneration, ActionObservation,
    ActionPrincipal, ActionScope,
};
pub use encoding::{CANONICAL_VERSION, DescriptorDecode, DescriptorEncode, ProjectionTypeTag};
pub use error::ProjectionError;
pub use fixtures::{honest_snapshot, honest_two_object_view};
pub use object::SemanticObjectId;
pub use presentation::{
    LABEL_MAX_BYTES, METADATA_KEY_MAX_BYTES, METADATA_MAX_ENTRIES, METADATA_VALUE_MAX_BYTES,
    PresentationLabel, PresentationMetadata,
};
pub use revision::ProjectionRevision;
pub use snapshot::{LiveInvocation, ProjectionSnapshot, ProjectionUpdate};
pub use view::ProjectionView;
