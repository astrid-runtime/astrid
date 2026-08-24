//! Host-neutral execution-provider descriptors for Astrid.
//!
//! This crate names application closures, admitted-instance descriptors, structured
//! jobs, opaque attachments and streams, checkpoint blob identity, and execution
//! receipts. It is never identity, authority, consent, or policy. Descriptors and
//! receipts cannot mint a live handle, lease, or grant.
//!
//! Workload and vendor names are fixtures elsewhere. Types and traits here do not
//! encode a guest OS, device vendor, or named interpreter.
//!
//! [`HostPrincipal`] is the host-internal seam for a later accepted stamp. This
//! crate does not depend on capsule stamp types. Live host authority checks remain
//! on the host; this crate is not an admission table and not a grant.
//!
//! This crate contains no image harness, guest runtime, public WIT, SDK,
//! gateway, process ABI, `SchemaCatalog`, storage, `ServiceLease`,
//! `ActionHandle`, or live authority substitute.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod adapter;
mod argv;
mod attachment;
mod checkpoint;
mod closure;
mod encoding;
mod error;
mod fixtures;
mod instance;
mod job;
mod null;
mod principal;
mod provider;
mod receipt;

pub use adapter::CapsuleAdapter;
pub use argv::{ARG_MAX_BYTES, ARGV_MAX, JobArg, JobArgv};
pub use attachment::{
    ATTACHMENT_MAX, AttachmentDescriptor, AttachmentSet, STREAM_MAX, StreamDescriptor, StreamSet,
};
pub use checkpoint::{Checkpoint, CheckpointBlobId};
pub use closure::ApplicationClosure;
pub use encoding::{CANONICAL_VERSION, DescriptorDecode, DescriptorEncode, ProviderTypeTag};
pub use error::ProviderError;
pub use fixtures::{honest_closure, honest_instance, honest_job, honest_principal};
pub use instance::{AdmittedInstance, InstanceId};
pub use job::Job;
pub use null::{NULL_PROVIDER_GENERATION, NULL_PROVIDER_ID, NullProvider};
pub use principal::HostPrincipal;
pub use provider::{
    ExecutionProvider, ProviderIdentity, check_binding, check_provider, check_start,
};
pub use receipt::{ExecutionOutcome, ExecutionReceipt, LiveHandle};
