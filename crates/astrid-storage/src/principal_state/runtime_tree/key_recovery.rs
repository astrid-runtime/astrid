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
    if let Some(receipt) = active::read(home, store)?
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
    tracing::warn!("preserved stopped-install runtime-key residue; restoring volume identity");
    Ok(true)
}
