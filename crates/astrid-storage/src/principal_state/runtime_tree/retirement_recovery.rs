//! Restore retirement custody without importing any surviving host bytes.

use super::{
    AstridHome, ContentName, RUNTIME_KEY_PROJECTION, ReceiptPhase, RuntimePrincipalStore,
    StateOwner, StorageResult, active, establish_active_receipt, restore_published_projection,
    scan, tree_error, validate_retiring_host_subset, validate_surviving_projection,
};

pub(in crate::principal_state) fn restore(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<()> {
    validate_surviving_projection(home.root(), home.root())?;
    let receipt = active::read(home, store)?
        .ok_or_else(|| tree_error(home.root(), "interrupted retirement has no durable receipt"))?;
    if receipt.phase() != ReceiptPhase::Retiring {
        return Err(tree_error(
            home.root(),
            "interrupted retirement requires a RETIRING receipt",
        ));
    }
    let scanned = scan(home.root())?;
    validate_retiring_host_subset(home, &receipt, &scanned)?;
    // Successful recovery must restore an existing signing identity, never
    // allow kernel startup to mint a replacement for missing durable identity.
    let key = volume_file(home, store, RUNTIME_KEY_PROJECTION, 32)?;
    if key.len() != 32 {
        return Err(tree_error(
            home.root(),
            "retirement volume has no 32-byte runtime signing key",
        ));
    }
    if volume_file(
        home,
        store,
        "etc/layout-version",
        astrid_core::dirs::LAYOUT_VERSION.len() as u64,
    )? != astrid_core::dirs::LAYOUT_VERSION.as_bytes()
    {
        return Err(tree_error(
            home.root(),
            "retirement volume has no current layout sentinel",
        ));
    }
    // Deliberately bypass ordinary bootstrap, key-sidecar preservation, and
    // ACTIVE publication. Every materialized byte comes from this volume.
    restore_published_projection(home, store, &store.content)?;
    establish_active_receipt(home, store)
}

fn volume_file(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    name: &str,
    expected_bytes: u64,
) -> StorageResult<Vec<u8>> {
    let name = ContentName::new(name).map_err(|error| tree_error(home.root(), error))?;
    let metadata = store
        .content()
        .describe(&StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), format!("retirement volume is missing {name}")))?;
    if metadata.logical_bytes() != expected_bytes {
        return Err(tree_error(
            home.root(),
            format!("retirement volume has invalid length for {name}"),
        ));
    }
    store
        .content()
        .read(&StateOwner::System, &name)
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), format!("retirement volume is missing {name}")))
}
