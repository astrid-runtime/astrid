//! Verify final host bytes against their authenticated durable generation.

use std::path::Path;

use astrid_core::platform_fs::PrivateProjectionInspection;

use super::super::{
    AstridHome, RuntimePrincipalStore, StateOwner, active, content_name_from_relative,
    restoration::read::AuthenticatedContentReader, tree_error,
};
use crate::StorageResult;

pub(super) fn verify_file(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    receipt: &active::ActiveProjectionReceipt,
    inspection: &PrivateProjectionInspection,
    relative: &Path,
) -> StorageResult<()> {
    let name = content_name_from_relative(&home.root().join(relative), home.root())?;
    if super::super::is_excluded(name.as_str()) {
        return Ok(());
    }
    let (expected, length) = receipt.inventory_object(name.as_str())?.ok_or_else(|| {
        tree_error(
            relative,
            "retirement source is not in the durable inventory",
        )
    })?;
    let handle = store
        .content()
        .open_read(&StateOwner::System, &name)
        .map_err(|error| tree_error(relative, format!("open retirement content: {error}")))?
        .ok_or_else(|| tree_error(relative, "retirement content disappeared"))?;
    if handle.descriptor().file() != expected || handle.descriptor().logical_bytes() != length {
        return Err(tree_error(
            relative,
            "retirement content changed after inventory validation",
        ));
    }
    let mut reader = AuthenticatedContentReader::new(&handle);
    if !inspection
        .matches_private_file_from(relative, length, &mut reader)
        .map_err(|error| tree_error(relative, format!("compare retirement source: {error}")))?
    {
        return Err(tree_error(
            relative,
            "retirement source bytes differ from durable publication",
        ));
    }
    Ok(())
}
