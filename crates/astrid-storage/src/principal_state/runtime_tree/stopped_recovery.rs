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
    let mut prepared = super::restoration::record_intent(home, store)?;
    discard_sentinel_staging(home, &mut prepared, Some(&receipt))?;
    prepared.ensure_scoped_intent()?;
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
    let mut prepared = super::restoration::record_intent(home, store)?;
    discard_sentinel_staging(home, &mut prepared, receipt.as_ref())?;
    prepared.ensure_scoped_intent()?;
    tracing::warn!("preserved stopped-install runtime-key residue; restoring volume identity");
    Ok(Some(prepared))
}

fn authorizes_legacy_etc_cleanup(original: Option<&active::ActiveProjectionReceipt>) -> bool {
    // Key-only / receiptless stopped homes must not inherit legacy etc deletion.
    // Require the original same-root Retiring inventory that named etc/layout-version.
    original.is_some_and(|receipt| {
        receipt.staging_scope().is_none() && receipt.contains_inventory_name("etc/layout-version")
    })
}

fn discard_sentinel_staging(
    home: &AstridHome,
    prepared: &mut PreparedRestoration<'_>,
    original: Option<&active::ActiveProjectionReceipt>,
) -> StorageResult<()> {
    let etc = home.root().join("etc");
    if !etc.try_exists().map_err(|error| tree_error(&etc, error))? {
        return Ok(());
    }
    let directory = PrivateDirectory::open(&etc)?;
    let names = directory.entries()?;
    let authority = SentinelCleanupAuthority {
        directory: &etc,
        store: prepared.store(),
        original,
        parents: original
            .map(super::restoration::eligible_file_parents)
            .unwrap_or_default(),
        scope: prepared.staging_scope(),
    };
    let removals = names
        .iter()
        .map(|name| authority.authorize(name))
        .collect::<StorageResult<Vec<_>>>()?;
    if removals.is_empty() {
        return Ok(());
    }
    // Classification confers only receipt/name authority. The same rooted
    // writer validates the current private leaf and identity at removal.
    let writer = prepared.writer()?;
    let cleanup = removals.into_iter().try_for_each(|removal| {
        removal
            .remove(writer)
            .map_err(|error| tree_error(&etc, error))
    });
    super::restoration::finish_cleanup(home, writer, cleanup)
}

struct SentinelCleanupAuthority<'a> {
    directory: &'a std::path::Path,
    store: &'a RuntimePrincipalStore,
    original: Option<&'a active::ActiveProjectionReceipt>,
    parents: std::collections::BTreeSet<String>,
    scope: Option<astrid_core::platform_fs::StagingScope>,
}

enum AuthorizedSentinelTemporary {
    Legacy(ContentName),
    Scoped(ContentName, astrid_core::platform_fs::StagingScope),
}

impl SentinelCleanupAuthority<'_> {
    fn authorize(&self, name: &std::ffi::OsStr) -> StorageResult<AuthorizedSentinelTemporary> {
        use astrid_core::platform_fs::{
            is_private_atomic_staging_name, is_scoped_private_staging_name,
        };

        let scope = if is_private_atomic_staging_name(name) {
            if !authorizes_legacy_etc_cleanup(self.original) {
                return Err(tree_error(
                    self.directory,
                    "legacy sentinel staging entry is outside the durable restoration scope",
                ));
            }
            None
        } else if is_scoped_private_staging_name(name) {
            let scope = self.scope.ok_or_else(|| {
                tree_error(
                    self.directory,
                    "scoped sentinel staging entry is not accepted by legacy shape policy",
                )
            })?;
            if !scope.matches_temporary_basename(name) {
                return Err(tree_error(
                    self.directory,
                    "sentinel staging entry is outside the durable restoration scope",
                ));
            }
            Some(scope)
        } else {
            return Err(tree_error(
                self.directory,
                "unexpected sentinel recovery staging entry",
            ));
        };
        let receipt = self.original.ok_or_else(|| {
            tree_error(
                self.directory,
                "sentinel staging cleanup lacks its original RETIRING receipt",
            )
        })?;
        let content_name = ContentName::new(format!("etc/{}", name.to_string_lossy()))
            .map_err(|error| tree_error(self.directory, error))?;
        let relative = std::path::Path::new(content_name.as_str());
        if receipt.staging_scope() != scope
            || !super::restoration::parent_is_eligible(&self.parents, relative)
            || receipt.contains_inventory_name(content_name.as_str())
            || self
                .store
                .content()
                .describe(&StateOwner::System, &content_name)
                .map_err(|error| tree_error(self.directory, error))?
                .is_some()
        {
            return Err(tree_error(
                self.directory,
                "sentinel staging entry lacks original inventory authority",
            ));
        }
        Ok(match scope {
            Some(scope) => AuthorizedSentinelTemporary::Scoped(content_name, scope),
            None => AuthorizedSentinelTemporary::Legacy(content_name),
        })
    }
}

impl AuthorizedSentinelTemporary {
    fn remove(
        self,
        writer: &astrid_core::platform_fs::PrivateFileProjection,
    ) -> std::io::Result<()> {
        match self {
            Self::Legacy(name) => {
                writer.remove_authorized_private_leaf(std::path::Path::new(name.as_str()))
            },
            Self::Scoped(name, scope) => {
                writer.remove_staging(std::path::Path::new(name.as_str()), scope)
            },
        }
    }
}
