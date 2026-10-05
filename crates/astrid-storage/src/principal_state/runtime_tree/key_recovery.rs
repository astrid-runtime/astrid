//! Preserve installer residue without granting it runtime identity authority.

use std::io::Read;

use super::{AstridHome, ContentName, RUNTIME_KEY_PROJECTION, ReceiptPhase, RuntimePrincipalStore};
use super::{StateOwner, StorageResult, active, tree_error};
use crate::principal_state::native_io::PrivateDirectory;

/// Called only by singleton-owned volume open, before any host reconciliation.
pub(super) fn recover(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<bool> {
    if !home
        .requires_stopped_key_recovery()
        .map_err(|error| tree_error(home.root(), error))?
    {
        return Ok(false);
    }
    let receipt = active::read(home, store)?;
    if home.root().join("etc").exists() && receipt.is_none() {
        return Err(tree_error(
            home.root(),
            "partial key recovery projection has no durable recovery intent",
        ));
    }
    if let Some(receipt) = receipt
        && (receipt.phase() != ReceiptPhase::Retiring
            || !receipt.contains_inventory_name(RUNTIME_KEY_PROJECTION))
    {
        return Err(tree_error(
            home.root(),
            "runtime-key residue is not a stopped projection",
        ));
    }
    // A clean stop clears its receipt. An interrupted retirement retains its
    // same-root RETIRING inventory. Neither permits a new sidecar to seed an
    // identity missing from the existing authenticated content catalogue.
    let key_name =
        ContentName::new(RUNTIME_KEY_PROJECTION).map_err(|error| tree_error(home.root(), error))?;
    let metadata = store
        .content()
        .describe(&StateOwner::System, &key_name)
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), "volume has no authoritative runtime key"))?;
    if metadata.logical_bytes() != 32 {
        return Err(tree_error(
            home.root(),
            "volume runtime key is not a 32-byte signing key",
        ));
    }
    let authority = store
        .content()
        .read(&StateOwner::System, &key_name)
        .map_err(|error| tree_error(home.root(), error))?
        .ok_or_else(|| tree_error(home.root(), "volume has no authoritative runtime key"))?;
    if authority.len() != 32 {
        return Err(tree_error(
            home.root(),
            "volume runtime key is not a 32-byte signing key",
        ));
    }

    let directory = PrivateDirectory::open(&home.keys_dir())?;
    let mut file = directory.open_file(std::path::Path::new("runtime.key"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|error| tree_error(home.root(), error))?;
        let owner = std::fs::metadata(home.root())
            .map_err(|error| tree_error(home.root(), error))?
            .uid();
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(tree_error(
                home.root(),
                "runtime-key residue handle is not private",
            ));
        }
    }
    let mut residue = [0; 32];
    file.read_exact(&mut residue)
        .map_err(|error| tree_error(home.root(), error))?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|error| tree_error(home.root(), error))?
        != 0
    {
        return Err(tree_error(
            home.root(),
            "runtime-key residue changed size during recovery",
        ));
    }
    // Content-addressing makes retry idempotent. The run namespace is never
    // projected or ingested as live configuration; evidence stays System-owned
    // inside the volume, not as another secret-bearing host sidecar.
    let evidence = ContentName::new(format!(
        "run/.recovered-runtime-keys/{}.key",
        blake3::hash(&residue).to_hex()
    ))
    .map_err(|error| tree_error(home.root(), error))?;
    store
        .content()
        .put(&StateOwner::System, &evidence, &residue)
        .map_err(|error| tree_error(home.root(), error))?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), error))?;
    // Recovery starts from a clean-stop home without an ACTIVE receipt. Before
    // restoring any host bytes, publish the existing RETIRING inventory for
    // this root: partial projection is volume-authoritative, never new input.
    // Reopening then follows the ordinary RETIRING reconciliation path.
    record_recovery_intent(home, store)?;
    discard_sentinel_staging(home)?;
    tracing::warn!("preserved stopped-install runtime-key residue; restoring volume identity");
    Ok(true)
}

fn discard_sentinel_staging(home: &AstridHome) -> StorageResult<()> {
    let etc = home.root().join("etc");
    if !etc.try_exists().map_err(|error| tree_error(&etc, error))? {
        return Ok(());
    }
    let directory = PrivateDirectory::open(&etc)?;
    for name in directory.entries()? {
        if !astrid_core::platform_fs::is_private_atomic_staging_name(&name) {
            return Err(tree_error(
                &etc,
                "unexpected sentinel recovery staging entry",
            ));
        }
        astrid_core::platform_fs::validate_private_file(&etc.join(&name))
            .map_err(|error| tree_error(&etc, error))?;
        // Resolve and remove relative to the captured private directory. The
        // same-root RETIRING receipt was checked before reaching this cleanup;
        // incomplete staging bytes never enter the volume catalogue.
        let file = directory.open_file(std::path::Path::new(&name))?;
        directory.remove_file(std::path::Path::new(&name))?;
        drop(file);
    }
    directory.sync()
}

fn record_recovery_intent(home: &AstridHome, store: &RuntimePrincipalStore) -> StorageResult<()> {
    super::seed_layout_version(home, store)?;
    let entries = super::active_projection_entries(home, store)?;
    let intent = super::receipt_ingest(home, ReceiptPhase::Retiring, &entries)?;
    store.replace_contiguous_files_removing_exact(StateOwner::System, [intent], &[], None)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush key recovery intent: {error}")))
}
