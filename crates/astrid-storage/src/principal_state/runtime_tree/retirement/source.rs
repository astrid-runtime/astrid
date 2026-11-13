//! Verify final host bytes against their authenticated durable generation.

use std::path::Path;

use astrid_core::dirs::PreparedProjectionRetirement;

use super::super::{
    AstridHome, RuntimePrincipalStore, StateOwner, active, content_name_from_relative,
    restoration::read::AuthenticatedContentReader, tree_error,
};
use crate::StorageResult;

/// Exclusions affect content admission, not Core's complete namespace checks.
pub(super) fn should_check(relative: &Path) -> bool {
    let Some(name) = relative.to_str() else {
        // Invalid UTF-8 must reach the fallible source-name validator; never
        // grant an exclusion by lossy conversion.
        return true;
    };
    #[cfg(windows)]
    {
        !super::super::is_excluded(&super::super::normalize_relative_path(name))
    }
    #[cfg(not(windows))]
    {
        !super::super::is_excluded(name)
    }
}

pub(super) fn verify_file(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    receipt: &active::ActiveProjectionReceipt,
    source: &mut std::fs::File,
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
    if !PreparedProjectionRetirement::matches_file_from(source, length, &mut reader)
        .map_err(|error| tree_error(relative, format!("compare retirement source: {error}")))?
    {
        return Err(tree_error(
            relative,
            "retirement source bytes differ from durable publication",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_read_selection_keeps_exclusions_and_checks_unknown_sources() {
        assert!(!should_check(Path::new("run/daemon.pid")));
        assert!(!should_check(Path::new("astrid-daemon")));
        assert!(should_check(Path::new("config.toml")));
        #[cfg(windows)]
        assert!(!should_check(Path::new("run\\daemon.pid")));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let invalid = std::ffi::OsStr::from_bytes(b"run/\xff");
            assert!(should_check(Path::new(invalid)));
            assert!(should_check(Path::new("run\\daemon.pid")));
        }
    }
}
