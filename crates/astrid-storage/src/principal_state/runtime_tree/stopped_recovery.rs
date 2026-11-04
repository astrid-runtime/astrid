//! Recover bounded stopped-home residues exclusively from volume authority.

use std::io::Read;

use super::restoration::PreparedRestoration;
use super::{AstridHome, ContentName, RUNTIME_KEY_PROJECTION, ReceiptPhase, RuntimePrincipalStore};
use super::{StateOwner, StorageResult, active, tree_error};
use crate::principal_state::native_io::PrivateDirectory;

/// Called only by singleton-owned volume open, before any host reconciliation.
pub(super) fn recover<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> StorageResult<Option<PreparedRestoration<'a>>> {
    match home
        .stopped_projection_recovery()
        .map_err(|error| tree_error(home.root(), error))?
    {
        None => return Ok(None),
        Some(astrid_core::dirs::StoppedProjectionRecovery::Sentinel) => {
            return recover_sentinel(home, store);
        },
        Some(astrid_core::dirs::StoppedProjectionRecovery::RuntimeKey) => {},
    }
    recover_key(home, store)
}

fn recover_sentinel<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> StorageResult<Option<PreparedRestoration<'a>>> {
    let receipt = active::read(home, store)?.ok_or_else(|| {
        tree_error(
            home.root(),
            "partial sentinel restoration has no durable recovery intent",
        )
    })?;
    if receipt.phase() != ReceiptPhase::Retiring
        || !receipt.contains_inventory_name("etc/layout-version")
    {
        return Err(tree_error(
            home.root(),
            "partial sentinel restoration lacks its RETIRING inventory",
        ));
    }
    // A valid older receipt can describe a subset of today's catalogue.
    // Cover the complete current inventory before touching even staging bytes.
    // Legacy receipts without a staging scope keep the narrow etc shape cleanup;
    // scoped receipts authorize only exact-scope temps. Recognition never deletes.
    let legacy_etc_cleanup = receipt.staging_scope().is_none();
    let mut prepared = super::restoration::record_intent(home, store)?;
    discard_sentinel_staging(home, &mut prepared, legacy_etc_cleanup, Some(&receipt))?;
    Ok(Some(prepared))
}

fn recover_key<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> StorageResult<Option<PreparedRestoration<'a>>> {
    let receipt = active::read(home, store)?;
    if home.root().join("etc").exists() && receipt.is_none() {
        return Err(tree_error(
            home.root(),
            "partial key recovery projection has no durable recovery intent",
        ));
    }
    if let Some(receipt) = &receipt
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
    super::seed_layout_version(home, store)?;
    let legacy_etc_cleanup = receipt
        .as_ref()
        .is_none_or(|receipt| receipt.staging_scope().is_none());
    let mut prepared = super::restoration::record_intent(home, store)?;
    discard_sentinel_staging(home, &mut prepared, legacy_etc_cleanup, receipt.as_ref())?;
    tracing::warn!("preserved stopped-install runtime-key residue; restoring volume identity");
    Ok(Some(prepared))
}

fn discard_sentinel_staging(
    home: &AstridHome,
    prepared: &mut PreparedRestoration<'_>,
    legacy_etc_cleanup: bool,
    original: Option<&active::ActiveProjectionReceipt>,
) -> StorageResult<()> {
    let etc = home.root().join("etc");
    if !etc.try_exists().map_err(|error| tree_error(&etc, error))? {
        return Ok(());
    }
    let directory = PrivateDirectory::open(&etc)?;
    let names = directory.entries()?;
    let scope = prepared.staging_scope();
    let mut legacy_names = Vec::new();
    let mut scoped_names = Vec::new();
    let eligible_parents = original.map(super::restoration::eligible_file_parents);
    for name in &names {
        // Structural recognition admits both shapes; deletion authority stays
        // split. Legacy receipts never delete scoped names, and scoped
        // receipts never use the legacy etc shape policy.
        if astrid_core::platform_fs::is_private_atomic_staging_name(name) {
            if !legacy_etc_cleanup {
                return Err(tree_error(
                    &etc,
                    "legacy sentinel staging entry is outside the durable restoration scope",
                ));
            }
            legacy_names.push(name.clone());
            continue;
        }
        if astrid_core::platform_fs::is_scoped_private_staging_name(name) {
            if legacy_etc_cleanup {
                return Err(tree_error(
                    &etc,
                    "scoped sentinel staging entry is not accepted by legacy shape policy",
                ));
            }
            if !scope.matches_temporary_basename(name) {
                return Err(tree_error(
                    &etc,
                    "sentinel staging entry is outside the durable restoration scope",
                ));
            }
            let receipt = original.ok_or_else(|| {
                tree_error(
                    &etc,
                    "scoped staging cleanup lacks its original RETIRING receipt",
                )
            })?;
            let relative = std::path::Path::new("etc").join(name);
            let content_name = ContentName::new(format!("etc/{}", name.to_string_lossy()))
                .map_err(|error| tree_error(&etc, error))?;
            if receipt.staging_scope() != Some(scope)
                || !eligible_parents.as_ref().is_some_and(|parents| {
                    super::restoration::parent_is_eligible(parents, &relative)
                })
                || receipt.contains_inventory_name(content_name.as_str())
                || prepared
                    .store()
                    .content()
                    .describe(&StateOwner::System, &content_name)
                    .map_err(|error| tree_error(&etc, error))?
                    .is_some()
            {
                return Err(tree_error(
                    &etc,
                    "sentinel staging entry lacks original inventory authority",
                ));
            }
            scoped_names.push(name.clone());
            continue;
        }
        return Err(tree_error(
            &etc,
            "unexpected sentinel recovery staging entry",
        ));
    }
    if legacy_names.is_empty() && scoped_names.is_empty() {
        return Ok(());
    }
    // The same durable-intent writer used by restoration owns cleanup too.
    // It binds each leaf to the root device and current Linux mount identity.
    // Private-file contract is enforced at the rooted removal boundary.
    let writer = prepared.writer()?;
    let cleanup = (|| {
        for name in legacy_names {
            let relative = std::path::Path::new("etc").join(&name);
            writer
                .remove_authorized_private_leaf(&relative)
                .map_err(|error| tree_error(&etc, error))?;
        }
        for name in scoped_names {
            let relative = std::path::Path::new("etc").join(&name);
            writer
                .remove_staging(&relative, scope)
                .map_err(|error| tree_error(&etc, error))?;
        }
        Ok(())
    })();
    super::restoration::finish_cleanup(home, writer, cleanup)
}
