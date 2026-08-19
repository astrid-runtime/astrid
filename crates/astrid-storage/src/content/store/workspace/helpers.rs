//! Branch labels, prefix selection, and catalog helpers for workspace stores.

use std::collections::BTreeMap;

use astrid_core::PrincipalUid;

use crate::content::{ContentName, PrincipalContentError};
use crate::content_dag::ContentReadError;
use crate::engine::PrincipalProjectionError;
use crate::storage_model::{ObjectId, ObjectRecord, ReferenceLabel};

use super::{
    BRANCH_RECEIPT_PREFIX_BYTES, CatalogRoot, CatalogValue, WorkspaceBranchError, WorkspaceUid,
    build_catalog, list, root_from_record,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BranchState {
    pub(super) id: WorkspaceUid,
    pub(super) binding_uid: Option<PrincipalUid>,
    pub(super) target_prefix: Option<ContentName>,
    pub(super) base: Option<CatalogRoot>,
    pub(super) working: Option<CatalogRoot>,
}

fn branch_label(id: WorkspaceUid) -> String {
    id.to_string()
}

pub(super) fn is_workspace_receipt_label(label: &[u8]) -> bool {
    label.starts_with(BRANCH_RECEIPT_PREFIX_BYTES)
}

pub(super) fn validate_target_prefix(
    target_prefix: Option<ContentName>,
) -> Result<Option<ContentName>, WorkspaceBranchError> {
    let Some(prefix) = target_prefix else {
        return Ok(None);
    };
    let value = prefix.as_str();
    if value.is_empty() || value.starts_with('/') || value.ends_with('/') || value.contains("//") {
        return Err(WorkspaceBranchError::InvalidTargetPrefix {
            detail: "prefix must be a non-empty canonical slash-separated path",
        });
    }
    if value
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(WorkspaceBranchError::InvalidTargetPrefix {
            detail: "prefix cannot contain dot path segments",
        });
    }
    Ok(Some(prefix))
}

pub(super) fn workspace_ref_label(id: WorkspaceUid) -> ReferenceLabel<Vec<u8>> {
    ReferenceLabel::new(branch_label(id).into_bytes())
}

pub(super) fn workspace_receipt_label(id: WorkspaceUid) -> ReferenceLabel<Vec<u8>> {
    ReferenceLabel::new(format!("workspace-promoted/{id}").into_bytes())
}

pub(super) fn parse_workspace_uid(label: &[u8]) -> Option<WorkspaceUid> {
    std::str::from_utf8(label).ok()?.parse().ok()
}

pub(super) fn parse_workspace_receipt_uid(label: &[u8]) -> Option<WorkspaceUid> {
    let suffix = label.strip_prefix(BRANCH_RECEIPT_PREFIX_BYTES)?;
    std::str::from_utf8(suffix).ok()?.parse().ok()
}

pub(super) fn hydrate_root(
    root: Option<CatalogRoot>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
) -> Result<Option<CatalogRoot>, PrincipalContentError> {
    root.map(|root| load(root.object).and_then(|record| root_from_record(root.object, &record)))
        .transpose()
}

pub(super) fn selected_catalog(
    root: Option<CatalogRoot>,
    target_prefix: Option<&ContentName>,
    load: &mut impl FnMut(ObjectId) -> Result<ObjectRecord, PrincipalContentError>,
    identify: &impl Fn(&ObjectRecord) -> ObjectId,
) -> Result<(Option<CatalogRoot>, BTreeMap<ObjectId, ObjectRecord>), WorkspaceBranchError> {
    let Some(prefix) = target_prefix else {
        return Ok((root, BTreeMap::new()));
    };
    let mut entries = BTreeMap::new();
    for entry in list(root, load)? {
        let full = entry.name().as_str();
        if full == prefix.as_str() {
            return Err(WorkspaceBranchError::InvalidTargetPrefix {
                detail: "prefix cannot attach over an existing file",
            });
        }
        let Some(relative) = full
            .strip_prefix(prefix.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))
        else {
            continue;
        };
        if relative.is_empty() {
            continue;
        }
        let name =
            ContentName::new(relative.to_owned()).map_err(PrincipalContentError::InvalidName)?;
        entries.insert(
            name,
            CatalogValue {
                file: entry.file(),
                logical_bytes: entry.logical_bytes(),
            },
        );
    }
    build_catalog(&entries, identify).map_err(WorkspaceBranchError::Content)
}

pub(super) fn selected_name(full: &ContentName, target_prefix: Option<&ContentName>) -> bool {
    target_prefix.is_none_or(|prefix| {
        full.as_str() == prefix.as_str()
            || full
                .as_str()
                .strip_prefix(prefix.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

pub(super) fn qualify_name(
    relative: &ContentName,
    target_prefix: Option<&ContentName>,
) -> Result<ContentName, WorkspaceBranchError> {
    target_prefix.map_or_else(
        || Ok(relative.clone()),
        |prefix| {
            ContentName::new(format!("{}/{}", prefix.as_str(), relative.as_str()))
                .map_err(PrincipalContentError::InvalidName)
                .map_err(WorkspaceBranchError::Content)
        },
    )
}

pub(super) fn map_read_error(
    error: ContentReadError<PrincipalProjectionError>,
) -> WorkspaceBranchError {
    match error {
        ContentReadError::Content(error) => WorkspaceBranchError::Content(error.into()),
        ContentReadError::Source(error) => WorkspaceBranchError::Projection(error),
    }
}
