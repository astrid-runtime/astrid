//! Preserve the historical flat encoding for cleanup at a full owner quota.
//! A growth operation migrates and charges the indexed layout; cleanup must
//! not require additional quota just to release already-admitted state.

use super::{
    BTreeMap, ContentHeader, DirectoryCommitReceipt, ObjectId, ObjectRecord, ObjectReference,
    PrincipalContentError, PrincipalProjectionEngine, ReferenceLabel, WorkspaceBranchError,
    WorkspaceBranchStore, WorkspaceUid, decode_row, parse_workspace_receipt_uid,
    parse_workspace_uid,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn edit_legacy_cleanup(
        &self,
        owner: &P,
        header: &mut ContentHeader,
        records: &BTreeMap<ObjectId, ObjectRecord>,
        id: WorkspaceUid,
        replacement: Option<(ObjectId, bool)>,
    ) -> Result<DirectoryCommitReceipt, WorkspaceBranchError> {
        let removed_quota = self
            .decode_legacy_branches(owner, header)?
            .into_iter()
            .find(|branch| branch.id == id)
            .and_then(|branch| branch.working)
            .map_or(0, |root| root.summary.quota_bytes);
        let replacement = replacement
            .map(|(object, promoted)| {
                let record = records
                    .get(&object)
                    .ok_or(WorkspaceBranchError::InvalidGraph {
                        object,
                        detail: "legacy cleanup replacement is missing",
                    })?;
                let (branch, actual) = decode_row(object, record)?;
                if !promoted || !actual || branch.id != id {
                    return Err(WorkspaceBranchError::InvalidGraph {
                        object,
                        detail: "legacy cleanup replacement is not the matching receipt",
                    });
                }
                Ok(ObjectReference::owns(
                    ReferenceLabel::new(format!("workspace-promoted/{id}").into_bytes()),
                    object,
                ))
            })
            .transpose()?;
        header.other_quota_bytes = header
            .other_quota_bytes
            .checked_sub(removed_quota)
            .ok_or(PrincipalContentError::AccountingOverflow)?;
        header.preserved_state.retain(|reference| {
            parse_workspace_uid(reference.label().as_bytes()) != Some(id)
                && parse_workspace_receipt_uid(reference.label().as_bytes()) != Some(id)
        });
        if let Some(reference) = replacement {
            header.preserved_state.push(reference);
        }
        Ok(DirectoryCommitReceipt {
            proof: None,
            previous: None,
        })
    }
}
