//! Durable copy-on-write workspace branches over one principal content root.
//!
//! A branch is an owner-internal component of the principal graph.  It is not
//! represented by a synthetic principal and it never uses a host directory as
//! a backing store.  The branch record owns two immutable content-catalog roots
//! (the base and the current working view); catalog path-copy operations then
//! share every unchanged file and chunk object with the owner and other
//! branches.

pub use astrid_core::WorkspaceUid;

use crate::content::{PrincipalContentError, PrincipalContentStore};
use crate::engine::PrincipalProjectionEngine;
use crate::storage_model::{
    ObjectFormatVersion, ObjectId, ObjectRecord, ObjectReference, ReferenceKind,
};

use super::{root_from_record, validate_catalog};

mod codec;
mod filesystem;
mod helpers;
mod lifecycle;
mod model;
mod operations;

#[cfg(test)]
mod tests;

pub use filesystem::WorkspaceFilesystem;
pub use model::{
    WorkspaceBindingLifecycle, WorkspaceBranchBinding, WorkspaceBranchDescriptor,
    WorkspaceBranchError, WorkspaceBranchStore,
};

const BRANCH_REF_PREFIX_BYTES: &[u8] = b"workspace/";
const BRANCH_RECEIPT_PREFIX_BYTES: &[u8] = b"workspace-promoted/";
const BRANCH_BASE_LABEL: &[u8] = b"base";
const BRANCH_WORKING_LABEL: &[u8] = b"working";
const BRANCH_MAGIC: &[u8] = b"astrid-workspace-branch-v1\0";
const BRANCH_RECEIPT_MAGIC: &[u8] = b"astrid-workspace-promoted-v1\0";
const BRANCH_FORMAT: ObjectFormatVersion = ObjectFormatVersion::V1;
const MAX_WORKSPACE_BRANCHES: usize = 128;
const UID_BYTES: usize = 16;

// Private imports so child modules can keep using `super::Name`.
#[allow(unused_imports)]
use super::{
    CatalogRoot, CatalogSummary, CatalogValue, ContentHeader, EngineIdentity, EngineSource,
    build_catalog, delete, insert, list, lookup,
};
#[allow(unused_imports)]
use crate::content::{ContentEntry, ContentName};
#[allow(unused_imports)]
use crate::content_dag::{
    ContentReadError, build_content, open_content, read_opened_content, read_opened_content_range,
};
#[allow(unused_imports)]
use crate::engine::PrincipalProjectionError;
#[allow(unused_imports)]
use crate::filesystem::{FilesystemEntry, FilesystemEntryKind, FilesystemError, FilesystemPath};
#[allow(unused_imports)]
use crate::storage_model::{ModelError, ObjectClass, ObjectKind, ReferenceLabel};
#[allow(unused_imports)]
use astrid_core::PrincipalUid;
#[allow(unused_imports)]
use codec::{
    decode_branch_record, decode_promotion_receipt, make_branch_record, make_branch_record_for_uid,
    make_promotion_receipt_for_uid,
};
#[allow(unused_imports)]
use helpers::{
    BranchState, hydrate_root, is_workspace_receipt_label, map_read_error,
    parse_workspace_receipt_uid, parse_workspace_uid, qualify_name, selected_catalog,
    selected_name, validate_target_prefix, workspace_receipt_label, workspace_ref_label,
};

pub(crate) fn is_workspace_branch_label(label: &[u8]) -> bool {
    label.starts_with(BRANCH_REF_PREFIX_BYTES)
}

pub(crate) fn workspace_branch_quota<P, E>(
    store: &PrincipalContentStore<P, E>,
    owner: &P,
    reference: &ObjectReference,
) -> Result<u64, PrincipalContentError>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    workspace_branch_quota_from_loader(reference, &mut |object| {
        store.load_required_for(owner, object)
    })
}

pub(crate) fn workspace_branch_quota_from_loader(
    reference: &ObjectReference,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<u64, PrincipalContentError> {
    let Some(id) = parse_workspace_uid(reference.label().as_bytes()) else {
        return Err(PrincipalContentError::InvalidGraph {
            object: reference.target(),
            detail: "workspace branch label is malformed",
        });
    };
    if reference.kind() != ReferenceKind::Owns {
        return Err(PrincipalContentError::InvalidGraph {
            object: reference.target(),
            detail: "workspace branch reference is not owning",
        });
    }
    let record = load(reference.target())?;
    let branch =
        decode_branch_record(reference.target(), &record, id).map_err(|error| match error {
            WorkspaceBranchError::InvalidGraph { object, detail } => {
                PrincipalContentError::InvalidGraph { object, detail }
            },
            _ => PrincipalContentError::InvalidGraph {
                object: reference.target(),
                detail: "workspace branch record could not be decoded",
            },
        })?;
    let base = validate_catalog(hydrate_root(branch.base, load)?, load)?;
    let working = validate_catalog(hydrate_root(branch.working, load)?, load)?;
    if base.root != branch.base.map(|root| root.object)
        || working.root != branch.working.map(|root| root.object)
    {
        return Err(PrincipalContentError::InvalidGraph {
            object: reference.target(),
            detail: "workspace branch catalog validation root disagrees",
        });
    }
    Ok(working.summary.quota_bytes)
}
