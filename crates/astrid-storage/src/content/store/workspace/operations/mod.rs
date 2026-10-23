//! Public workspace branch store operations.

use std::collections::BTreeMap;

use astrid_core::PrincipalUid;

use crate::content::{ContentEntry, ContentName, PrincipalContentError};
use crate::content_dag::{
    build_content, open_content, read_opened_content, read_opened_content_range,
};
use crate::engine::{PrincipalProjectionEngine, PrincipalProjectionError};
use crate::storage_model::{ModelError, ObjectId, ObjectRecord};

use super::super::pending_catalog::retain_final_catalog_records;

use super::{
    EngineIdentity, EngineSource, WorkspaceBindingLifecycle, WorkspaceBranchBinding,
    WorkspaceBranchDescriptor, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceFilesystem,
    WorkspaceUid, list, list_prefix as catalog_list_prefix, lookup, make_branch_record,
    make_branch_record_for_uid, make_promotion_receipt_for_uid, map_read_error,
    parse_workspace_receipt_uid, prefix_exists as catalog_prefix_exists, selected_catalog,
    validate_target_prefix,
};

impl<P: Ord, E> WorkspaceBranchStore<P, E> {
    /// Bind a filesystem view to one owner and branch identifier.
    #[must_use]
    pub fn filesystem(&self, owner: P, branch: WorkspaceUid) -> WorkspaceFilesystem<P, E> {
        WorkspaceFilesystem {
            branches: self.clone(),
            owner,
            branch,
        }
    }
}

mod bindings;
mod files;
mod lifecycle;
mod publication;
mod rename;
