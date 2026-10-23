//! Authenticated, path-copy workspace directory. Index state is durable; only
//! scalar validation proofs may be retained in the governed projection cache.

use std::collections::BTreeMap;

use super::{
    BRANCH_MAGIC, BRANCH_RECEIPT_MAGIC, BranchState, CatalogRoot, CatalogSummary, CatalogValue,
    ContentHeader, ContentName, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, PrincipalContentError, PrincipalContentStore, PrincipalProjectionEngine,
    PrincipalUid, ReferenceKind, ReferenceLabel, UID_BYTES, WorkspaceBindingLifecycle,
    WorkspaceBranchBinding, WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore,
    WorkspaceUid, decode_branch_record, decode_promotion_receipt, hydrate_root,
    is_workspace_branch_label, is_workspace_receipt_label, parse_workspace_receipt_uid,
    parse_workspace_uid, root_from_record, validate_catalog,
};
use crate::content::catalog::tree::{self, DirectoryLayout};
use crate::engine::{ProjectionCacheEntry, ProjectionCacheKey, ProjectionCachePayload};

mod edit;
mod legacy;
mod read;
mod transition;
mod validation;

pub(crate) const DIRECTORY_LABEL: &[u8] = b"workspace-directory";
pub(crate) const PROOF_CACHE_KEY: ProjectionCacheKey = ProjectionCacheKey::new(5);
const DIRECTORY_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(3) {
    Some(version) => version,
    None => unreachable!(),
};
const VALUE_LABEL: &[u8] = b"workspace-record";
// Per leaf, reserve one encoded leaf and one encoded binary branch, including
// their owning reference labels, kinds and 32-byte targets. A binary directory
// has fewer branches than leaves, so this conservatively charges all index
// metadata without needing a second independently trusted counter.
const NODE_QUOTA_BYTES: u64 = 17 + 1 + 32 + 16 + 57 + 2 + 64 + 4 + 5;

struct WorkspaceLayout;

impl DirectoryLayout for WorkspaceLayout {
    const VERSION: ObjectFormatVersion = DIRECTORY_VERSION;
    const VALUE_LABEL: &'static [u8] = VALUE_LABEL;

    fn summarize(
        name: &ContentName,
        value: CatalogValue,
    ) -> Result<CatalogSummary, PrincipalContentError> {
        let bytes = u64::try_from(name.as_str().len())
            .map_err(|_| PrincipalContentError::AccountingOverflow)?;
        Ok(CatalogSummary {
            logical_bytes: value.logical_bytes,
            quota_bytes: value
                .logical_bytes
                .checked_add(bytes)
                .and_then(|charge| charge.checked_add(NODE_QUOTA_BYTES))
                .ok_or(PrincipalContentError::AccountingOverflow)?,
            entries: 1,
        })
    }

    fn validate_value(
        name: &ContentName,
        value: CatalogValue,
        load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    ) -> Result<(), PrincipalContentError> {
        validation::validate_row(name, value, load)
    }
}

/// Scalar proof of a fully authenticated immutable directory, never a decoded
/// branch collection. Private fields prevent callers from minting a proof.
#[derive(Clone, Copy)]
pub(crate) struct DirectoryProof {
    root: CatalogRoot,
}

impl ProjectionCachePayload for DirectoryProof {
    fn retained_bytes(&self) -> u64 {
        u64::try_from(std::mem::size_of::<Self>()).unwrap_or(u64::MAX)
    }
}

impl DirectoryProof {
    pub(crate) fn quota_for(&self, object: ObjectId) -> Option<u64> {
        if self.root.object == object {
            Some(self.root.summary.quota_bytes)
        } else {
            None
        }
    }
}

/// Single-use admission token minted only by `edit_directory` after an
/// authenticated prior proof and a checked delta (or a full migration
/// validation). Finish consumes it; it is deliberately non-`Clone`.
pub(in super::super) struct DirectoryCommitReceipt {
    proof: Option<DirectoryProof>,
    previous: Option<ObjectId>,
}

impl DirectoryCommitReceipt {
    fn into_parts(self) -> (Option<DirectoryProof>, Option<ObjectId>) {
        (self.proof, self.previous)
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static FULL_DIRECTORY_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn workspace_key_hex(id: WorkspaceUid) -> String {
    // §13.3: plain 32 lowercase hex, never WorkspaceUid Display (`workspace/...`).
    hex::encode(id.as_bytes())
}

fn principal_key_hex(uid: PrincipalUid) -> String {
    // PrincipalUid Display is already plain 64 hex; encode bytes explicitly.
    hex::encode(uid.as_bytes())
}

fn key(tag: &str, id: WorkspaceUid) -> Result<ContentName, PrincipalContentError> {
    ContentName::new(format!("{tag}/{}", workspace_key_hex(id)))
        .map_err(PrincipalContentError::InvalidName)
}

fn uid_prefix(uid: PrincipalUid) -> String {
    format!("u/{}/", principal_key_hex(uid))
}

fn binding_key(branch: &BranchState) -> Result<Option<ContentName>, PrincipalContentError> {
    branch
        .binding_uid
        .map(|uid| {
            let prefix =
                branch
                    .target_prefix
                    .as_ref()
                    .ok_or(PrincipalContentError::InvalidGraph {
                        object: ObjectId::new([0; 32]),
                        detail: "bound workspace has no prefix",
                    })?;
            ContentName::new(format!("{}{prefix}", uid_prefix(uid)))
                .map_err(PrincipalContentError::InvalidName)
        })
        .transpose()
}

fn content_error(error: WorkspaceBranchError) -> PrincipalContentError {
    match error {
        WorkspaceBranchError::Content(error) => error,
        WorkspaceBranchError::Projection(error) => error.into(),
        WorkspaceBranchError::InvalidGraph { object, detail } => {
            PrincipalContentError::InvalidGraph { object, detail }
        },
        _ => PrincipalContentError::InvalidGraph {
            object: ObjectId::new([0; 32]),
            detail: "invalid workspace directory value",
        },
    }
}

fn decode_row(
    object: ObjectId,
    record: &ObjectRecord,
) -> Result<(BranchState, bool), PrincipalContentError> {
    let promoted = record.canonical_bytes().starts_with(BRANCH_RECEIPT_MAGIC);
    let magic = if promoted {
        BRANCH_RECEIPT_MAGIC
    } else {
        BRANCH_MAGIC
    };
    let bytes = record
        .canonical_bytes()
        .get(magic.len()..magic.len().saturating_add(UID_BYTES))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PrincipalContentError::InvalidGraph {
            object,
            detail: "workspace directory value has no branch identifier",
        })?;
    let id = WorkspaceUid::from_bytes(bytes);
    let branch = if promoted {
        decode_promotion_receipt(object, record, id)
    } else {
        decode_branch_record(object, record, id)
    }
    .map_err(content_error)?;
    Ok((branch, promoted))
}

fn row_charge(
    record: &ObjectRecord,
    branch: &BranchState,
    promoted: bool,
) -> Result<u64, PrincipalContentError> {
    let metadata = record.references().iter().try_fold(
        u64::try_from(record.canonical_bytes().len())
            .map_err(|_| PrincipalContentError::AccountingOverflow)?,
        |bytes, reference| {
            bytes
                .checked_add(33)
                .and_then(|bytes| {
                    bytes.checked_add(u64::try_from(reference.label().as_bytes().len()).ok()?)
                })
                .ok_or(PrincipalContentError::AccountingOverflow)
        },
    )?;
    metadata
        .checked_add(if promoted {
            0
        } else {
            branch.working.map_or(0, |root| root.summary.quota_bytes)
        })
        .ok_or(PrincipalContentError::AccountingOverflow)
}

pub(crate) fn validate_from_loader(
    reference: &ObjectReference,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<DirectoryProof, PrincipalContentError> {
    validation::validate(reference, load)
}

pub(crate) fn quota_for_store<P, E>(
    store: &PrincipalContentStore<P, E>,
    owner: &P,
    reference: &ObjectReference,
) -> Result<u64, PrincipalContentError>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    if let Some(entry) =
        store
            .engine
            .load_projection_cache(owner, reference.target(), PROOF_CACHE_KEY)
        && let Some(proof) = entry.downcast::<DirectoryProof>()
        && let Some(quota) = proof.quota_for(reference.target())
    {
        return Ok(quota);
    }
    let proof = validate_from_loader(reference, &mut |object| {
        store.load_required_for(owner, object)
    })?;
    let quota = proof.root.summary.quota_bytes;
    let _ = store.engine.retain_projection_cache(
        owner,
        reference.target(),
        PROOF_CACHE_KEY,
        ProjectionCacheEntry::new(proof),
    );
    Ok(quota)
}

fn inventory_prefix(uid: PrincipalUid) -> String {
    format!("a/{}/", principal_key_hex(uid))
}

fn inventory_key(branch: &BranchState) -> Result<Option<ContentName>, PrincipalContentError> {
    branch
        .binding_uid
        .map(|uid| {
            ContentName::new(format!(
                "{}{}",
                inventory_prefix(uid),
                workspace_key_hex(branch.id)
            ))
            .map_err(PrincipalContentError::InvalidName)
        })
        .transpose()
}

#[cfg(test)]
pub(super) fn receipt_object<P, E>(
    branches: &WorkspaceBranchStore<P, E>,
    owner: &P,
    root: CatalogRoot,
    id: WorkspaceUid,
) -> ObjectId
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    tree::lookup_with_layout::<WorkspaceLayout>(Some(root), &key("r", id).unwrap(), &mut |object| {
        branches.content.load_required_for(owner, object)
    })
    .unwrap()
    .unwrap()
    .file
}

#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod tests;

pub(super) enum WorkspaceBindingLookup<P> {
    Legacy,
    Indexed(Option<WorkspaceBranchBinding<P>>),
}
