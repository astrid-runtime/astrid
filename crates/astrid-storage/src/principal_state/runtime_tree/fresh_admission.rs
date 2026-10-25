//! Retry abandoned bootstrap without admitting incomplete populated homes.

use super::{
    ACTIVE_PROJECTION_NAME, AstridHome, RUNTIME_KEY_PROJECTION, ReceiptPhase,
    RuntimePrincipalStore, STAGING_JOURNAL_PROJECTION, StateOwner, StorageResult, active,
    establish_active_receipt, restore_published_projection, tree_error,
    validate_surviving_projection,
};

pub(in crate::principal_state) fn restore(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    if !restore_if_bootstrap(home, store)? {
        return Err(tree_error(
            home.root(),
            "fresh admission retry refuses populated or retiring authority",
        ));
    }
    Ok(())
}

/// The caller has already proved the empty birth receipt. A false result is
/// classification only: it must not restore or import any host projection.
pub(in crate::principal_state) fn restore_if_bootstrap(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<bool> {
    validate_surviving_projection(home.root(), home.root())?;
    if !bootstrap_roots(home, store)? {
        return Ok(false);
    }
    let layout_version = home
        .layout_version()
        .map_err(|error| tree_error(home.root(), error))?;
    let scanned = super::scan(home.root())?;
    // Logging starts after admission but before the component ledger exists.
    // Keep these diagnostics on the host; they cannot seed durable authority.
    if scanned.iter().any(|entry| {
        let name = entry.name().as_str();
        !super::projection::is_bootstrap_projection_name(name) && !name.starts_with("log/")
    }) {
        return Err(tree_error(
            home.root(),
            "fresh admission retry refuses unadmitted host files",
        ));
    }
    // A missing receipt is possible between initial projection publication and
    // ACTIVE establishment. The current roots above, not the birth receipt,
    // prove that this window has never acquired application authority.
    let key_name = super::ContentName::new(RUNTIME_KEY_PROJECTION)
        .map_err(|error| tree_error(home.root(), error))?;
    if store
        .content
        .describe(&StateOwner::System, &key_name)
        .map_err(|error| tree_error(home.root(), error))?
        .is_some()
    {
        super::retirement_recovery::volume_file(home, store, RUNTIME_KEY_PROJECTION, 32)?;
    } else {
        // Fresh admission may have generated the host key after publishing the
        // first projection. Preserve that private identity across retry; a
        // crash before key generation has no identity to restore yet.
        match std::fs::symlink_metadata(home.runtime_key_path()) {
            Ok(metadata) => {
                astrid_core::platform_fs::validate_private_file(&home.runtime_key_path())
                    .map_err(|error| tree_error(home.root(), error))?;
                if metadata.len() != 32 {
                    return Err(tree_error(home.root(), "invalid bootstrap signing key"));
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(tree_error(home.root(), error)),
        }
    }
    if layout_version.is_none() {
        super::seed_layout_version(home, store)?;
    }
    if super::retirement_recovery::volume_file(
        home,
        store,
        "etc/layout-version",
        astrid_core::dirs::LAYOUT_VERSION.len() as u64,
    )? != astrid_core::dirs::LAYOUT_VERSION.as_bytes()
    {
        return Err(tree_error(
            home.root(),
            "fresh admission retry has invalid layout sentinel",
        ));
    }
    restore_published_projection(home, store, &store.content)?;
    establish_active_receipt(home, store)?;
    Ok(true)
}

fn bootstrap_roots(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<bool> {
    let roots = store
        .engine
        .roots()
        .map_err(|error| tree_error(home.root(), error))?;
    if roots.iter().any(|(owner, _)| *owner != StateOwner::System)
        || store
            .runtime_kv
            .entry_count_for_owner(&StateOwner::System)?
            != 0
    {
        return Ok(false);
    }
    let entries = store
        .content
        .list(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), error))?;
    if entries.iter().any(|entry| {
        !matches!(
            entry.name().as_str(),
            "etc/layout-version"
                | RUNTIME_KEY_PROJECTION
                | STAGING_JOURNAL_PROJECTION
                | ACTIVE_PROJECTION_NAME
        )
    }) {
        return Ok(false);
    }
    if let Some(receipt) = active::read_relocatable(home, store)?
        && (receipt.phase() != ReceiptPhase::Active || !receipt.root_matches(home)?)
    {
        return Ok(false);
    }
    Ok(true)
}
