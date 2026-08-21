//! The one boot gate for released (layout-one) native state.
//!
//! Layout migration used to be a collection of independent best-effort
//! imports.  That is not a safe cut-over: a successful layout sentinel could
//! then coexist with an unimported capsule, token, or environment source.  The
//! barrier in this module is deliberately boring.  It snapshots every source
//! before the first destructive operation, runs the component-owned importer,
//! verifies the destination receipt, retires only the exact source, and writes
//! one canonical completion ledger last.  A layout-two home without that
//! ledger is not served.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_audit::AuditLog;
use astrid_capsule_install::{
    legacy_capsule_authority_status, migrate_all_native_capsules_with_report,
    retire_unmatched_legacy_authority_receipts,
};
use astrid_core::dirs::{AstridHome, LAYOUT_VERSION, WorkspaceLayout};
use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;
use astrid_storage::{IdentityStore, KvStore, PrincipalDirectory, RuntimePrincipalStore};

mod env_import;
mod fs_hooks;
mod hooks;
mod host_fs;
mod ledger;
mod legacy_audit;
use legacy_audit::handle_non_default_audit_source;
mod legacy_tmp;
#[cfg(test)]
pub(super) use legacy_tmp::tighten_legacy_dedicated_directories;
mod proof;
mod secret;
mod source;
#[cfg(unix)]
use crate::{preflight_legacy_audit_sources, retire_legacy_audit_dir};
use env_import::import_env_and_secrets;
#[cfg(test)]
pub(crate) use hooks::inject_tmp_retirement_interruption_once;
pub(crate) use hooks::interrupt_after_tmp_retirement_if_requested;
use host_fs::retire_tree;
use host_fs::{
    add_principal_scope_sources, add_source, collect_workspace_targets,
    ensure_legacy_secret_aliases, path_exists, read_bounded_file, require_layout_provenance,
    retire_empty_directory, snapshot_owner_controlled_path, snapshot_path, storage_io, sync_parent,
    validate_source_path,
};
#[cfg(not(unix))]
use host_fs::{preflight_legacy_audit_sources, retire_legacy_audit_dir};
use ledger::{
    DestinationProof, MigrationLedger, SourceCount, SourceDigest, SourceIdentity,
    collect_destination_proofs, decode_canonical, reject_unsupported_sources,
    validate_existing_proofs, validate_ledger_shape, write_ledger,
};
#[cfg(test)]
use ledger::{MigrationComponent, canonical_json};

#[cfg(test)]
pub(crate) use secret::record_absent_legacy_secret_for_test;
pub(crate) use secret::{
    ensure_legacy_secret_deletion_allowed, legacy_secret_source_must_be_absent,
};

const LEDGER_NAME: &str = "layout-v2-components.complete";
const LEDGER_SCHEMA: u32 = 1;
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_BYTES: u64 = 1 << 30;
const MAX_REVOCATION_BYTES: u64 = 10 * 1024 * 1024;
const REVOCATION_NAMESPACE: &str = "system:gateway:revocations";
const REVOCATION_RECEIPT_KEY: &str = "migration/legacy-json-v1";
const REVOCATION_PRINCIPAL_PREFIX: &str = "principal/";
const HOST_SECRET_RECEIPT_NAME: &str = "system-host-secrets-v1.receipt";
const CAPSULE_AUTHORITY_RECEIPT_NAME: &str = "capsule-authority-v1.receipt";

/// Layout state captured before `AstridHome::ensure` can create a v2
/// sentinel.  A bool cannot distinguish a brand-new home from a cut-over
/// home that lost its completion ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) enum LayoutOrigin {
    Fresh,
    Legacy,
    ExistingV2,
}

#[cfg(any(unix, test))]
pub(crate) fn capture_layout_origin(home: &AstridHome) -> io::Result<LayoutOrigin> {
    match home.layout_version()?.as_deref() {
        None => Ok(LayoutOrigin::Fresh),
        Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) => Ok(LayoutOrigin::Legacy),
        Some(LAYOUT_VERSION) => Ok(LayoutOrigin::ExistingV2),
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported Astrid home layout version {other:?}"),
        )),
    }
}

/// Path of the global migration ledger.
#[must_use]
pub(crate) fn ledger_path(home: &AstridHome) -> PathBuf {
    home.migrations_dir().join(LEDGER_NAME)
}

/// Reject an existing layout-two home that was cut over without the complete
/// component ledger.  Fresh homes have no sentinel yet and are admitted by
/// the caller, which creates the ledger after the durable store is open.
pub(crate) fn reject_incomplete_layout_v2(home: &AstridHome) -> io::Result<()> {
    if home.layout_version()?.as_deref() != Some(LAYOUT_VERSION) {
        return Ok(());
    }
    let path = ledger_path(home);
    let bytes = read_bounded_file(&path, MAX_BYTES)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Astrid layout sentinel is v2 but the component migration ledger is missing: {}",
                path.display()
            ),
        )
    })?;
    let ledger: MigrationLedger = decode_canonical(&bytes, &path)?;
    if ledger.schema != LEDGER_SCHEMA || !ledger.complete || ledger.components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Astrid layout sentinel is v2 but the component migration ledger is incomplete: {}",
                path.display()
            ),
        ));
    }
    validate_ledger_shape(&ledger)?;
    let fresh_layout = ledger
        .components
        .iter()
        .any(|component| component.name == "system:fresh-layout");
    require_layout_provenance(&home.migrations_dir(), fresh_layout)?;
    Ok(())
}

/// Run every released-home migration while the daemon singleton is held.
///
/// The origin is captured before `AstridHome::ensure` changes a fresh home to
/// layout two. Fresh homes receive an explicit initialization ledger; released
/// homes perform the full import before the caller commits the layout receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "boot passes the singleton-owned cutover context explicitly"
)]
pub(crate) async fn run(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
    identity: &dyn IdentityStore,
    audit: &Arc<AuditLog>,
    layout_origin: LayoutOrigin,
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<()> {
    let ledger = ledger_path(home);
    match fs::read(&ledger) {
        Ok(bytes) => {
            resume_existing_layout(
                home,
                store,
                directory,
                &ledger,
                &bytes,
                workspace_root,
                workspace_layout,
            )
            .await?;
            retire_post_barrier_sources(home, store)?;
            return Ok(());
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }
    if !matches!(layout_origin, LayoutOrigin::Fresh | LayoutOrigin::Legacy) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "layout v2 has no complete component migration ledger; refusing to serve",
        ));
    }

    if matches!(layout_origin, LayoutOrigin::Legacy) {
        crate::principal_home_migration::admit_unbound_legacy_principal_homes(
            home, directory, identity,
        )
        .await?;
        legacy_tmp::tighten_legacy_dedicated_directories(home, directory)?;
    }

    let bindings = directory.bindings();
    let snapshots = preflight_sources(home, store, &bindings)?;

    if matches!(layout_origin, LayoutOrigin::Fresh) {
        initialize_fresh_layout(
            home,
            store,
            directory,
            snapshots,
            workspace_root,
            workspace_layout,
        )
        .await?;
        retire_post_barrier_sources(home, store)?;
        return Ok(());
    }

    migrate_legacy_layout(
        home,
        store,
        directory,
        audit,
        bindings,
        snapshots,
        workspace_root,
        workspace_layout,
    )
    .await?;
    retire_post_barrier_sources(home, store)
}

/// Retire sources whose deletion is authorized only by the complete global
/// component ledger. Re-reading the canonical ledger makes crash re-entry use
/// the same durable authorization as the first boot. `CoW` retirement is tied
/// to the exact preflight identity; the principal-store retirement is tied to
/// its immutable volume cutover receipt and independently verified roots.
fn retire_post_barrier_sources(home: &AstridHome, store: &RuntimePrincipalStore) -> io::Result<()> {
    let path = ledger_path(home);
    let bytes = fs::read(&path)?;
    let ledger: MigrationLedger = decode_canonical(&bytes, &path)?;
    validate_ledger_shape(&ledger)?;
    if !ledger.complete {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "component migration ledger is incomplete; retirement is not authorized",
        ));
    }
    let cow = ledger
        .components
        .iter()
        .find(|component| component.name == "system:cow")
        .ok_or_else(|| io::Error::other("migration ledger has no CoW source identity"))?;
    retire_tree(&home.cow_dir(), &cow.source, &[])?;
    store
        .retire_verified_legacy_directory_store(home)
        .map_err(storage_io)
}

async fn resume_existing_layout(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
    ledger: &Path,
    bytes: &[u8],
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<()> {
    let existing: MigrationLedger = decode_canonical(bytes, ledger)?;
    if !existing.complete {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "component migration ledger is incomplete: {}",
                ledger.display()
            ),
        ));
    }
    validate_ledger_shape(&existing)?;
    let source_inventory = existing
        .components
        .iter()
        .map(|component| (component.name.clone(), component.source.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut proofs =
        collect_destination_proofs(home, store, directory, &source_inventory, false).await?;
    if existing
        .components
        .iter()
        .any(|component| component.name == "system:fresh-layout")
    {
        proofs.insert(
            "system:fresh-layout".to_owned(),
            DestinationProof::fresh_layout(),
        );
    }
    validate_existing_proofs(home, &existing, &proofs, directory)?;
    ensure_no_unretired_authority_receipts(home, workspace_root, workspace_layout)?;
    ensure_no_unretired_component_sources(home, directory, false)?;
    crate::principal_home_migration::verify_migrated_legacy_principal_sources_retired(
        home, directory,
    )
}

async fn initialize_fresh_layout(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
    mut snapshots: BTreeMap<String, SourceIdentity>,
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<()> {
    // A home with no layout sentinel is allowed to be initialized only when
    // it contains no released component sources.  `state.db` and the CoW
    // directory are runtime-owned paths that may have been created while the
    // authoritative store opened; every other source would be an unadmitted
    // legacy input and must fail closed rather than being recorded as a fresh
    // empty-home receipt.
    for (name, source) in &snapshots {
        if source.present && !matches!(name.as_str(), "system:state-db" | "system:cow") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fresh Astrid home contains a legacy migration source {name}; refusing to initialize"
                ),
            ));
        }
    }
    snapshots.insert("system:fresh-layout".to_owned(), SourceIdentity::absent());
    ensure_no_unretired_authority_receipts(home, workspace_root, workspace_layout)?;
    let mut proofs = collect_destination_proofs(home, store, directory, &snapshots, true).await?;
    proofs.insert(
        "system:fresh-layout".to_owned(),
        DestinationProof::fresh_layout(),
    );
    write_ledger(home, snapshots, &proofs)
}

#[allow(
    clippy::too_many_arguments,
    reason = "boot passes the singleton-owned migration context explicitly"
)]
async fn migrate_legacy_layout(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
    audit: &Arc<AuditLog>,
    bindings: Vec<(PrincipalId, PrincipalUid)>,
    mut snapshots: BTreeMap<String, SourceIdentity>,
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<()> {
    let current = preflight_sources(home, store, &bindings)?;
    if current != snapshots {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "legacy migration source inventory changed before component import",
        ));
    }
    reject_unsupported_sources(home, directory, &snapshots)?;
    crate::principal_distro_migration::migrate_legacy_distro_locks(home, store, directory).await?;
    crate::principal_distro_migration::retire_legacy_distro_init_locks(home, directory)?;
    for (alias, _) in &bindings {
        crate::migrate_legacy_profile_path(home, alias)?;
    }
    crate::principal_home_migration::migrate_legacy_principal_homes(home, store, directory)?;
    let store_arc = Arc::new(store.clone());
    let workspace_targets = workspace_portal_targets(workspace_root, workspace_layout)?;
    let capsule_report =
        migrate_all_native_capsules_with_report(&store_arc, home, directory, &workspace_targets)
            .map_err(|error| {
                io::Error::other(format!("legacy capsule migration failed: {error}"))
            })?;
    retire_unmatched_legacy_authority_receipts(&store_arc, home, directory, &workspace_targets)
        .map_err(|error| {
            io::Error::other(format!(
                "legacy leftover capsule authority retirement failed: {error}"
            ))
        })?;
    for (alias, uid) in &bindings {
        let owner = astrid_storage::StateOwner::Principal(*uid);
        let capsule_ids = store
            .capsules()
            .list(&owner)
            .map_err(storage_io)?
            .into_iter()
            .map(|summary| summary.id().to_owned())
            .collect::<Vec<_>>();
        add_principal_scope_sources(&mut snapshots, home, alias, *uid, &capsule_ids)?;
    }
    let authority_source = snapshots.get("system:capsule-authority").ok_or_else(|| {
        io::Error::other("migration source inventory is missing capsule authority")
    })?;
    let authority_proof = capsule_report.canonical_proof(authority_source.digest.as_str());
    astrid_core::platform_fs::ensure_private_directory(&home.migrations_dir())?;
    astrid_core::platform_fs::atomic_write_private_file(
        &home.migrations_dir().join(CAPSULE_AUTHORITY_RECEIPT_NAME),
        authority_proof.as_bytes(),
    )?;
    ensure_no_unretired_authority_receipts(home, workspace_root, workspace_layout)?;
    crate::principal_log_migration::migrate_legacy_principal_logs(home, directory)?;
    let host_secret_source = snapshots
        .get("system:host-secrets")
        .ok_or_else(|| io::Error::other("migration source inventory is missing host secrets"))?;
    import_env_and_secrets(home, store, &bindings, &snapshots, host_secret_source).await?;
    import_legacy_control_state(home, store, directory).await?;
    migrate_legacy_audit(home, audit).await?;
    retire_disposable_tmp_sources(home, directory, &snapshots)?;
    interrupt_after_tmp_retirement_if_requested(home)?;
    ensure_no_unretired_component_sources(home, directory, true)?;
    crate::principal_home_migration::retire_migrated_legacy_principal_homes(home, directory)?;
    let proofs = collect_destination_proofs(home, store, directory, &snapshots, true).await?;
    write_ledger(home, snapshots, &proofs)
}

fn retire_disposable_tmp_sources(
    home: &AstridHome,
    directory: &PrincipalDirectory,
    sources: &BTreeMap<String, SourceIdentity>,
) -> io::Result<()> {
    for (alias, uid) in directory.bindings() {
        let name = format!("principal:{uid}:tmp");
        let Some(expected) = sources.get(&name) else {
            return Err(io::Error::other(format!(
                "missing migration source: {name}"
            )));
        };
        if !expected.present {
            continue;
        }
        let path = home.principal_home(&alias).tmp_dir();
        let actual = snapshot_path(&path)?;
        if actual != *expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy temporary source changed before retirement: {}",
                    path.display()
                ),
            ));
        }
        astrid_core::dirs::retire_legacy_source_tree(&path).map_err(|error| {
            io::Error::other(format!(
                "retire legacy temporary source {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

async fn import_legacy_control_state(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    let invites = crate::invite::DurableInviteStore::new(store.kv()).map_err(storage_io)?;
    invites
        .ensure_legacy_import(home)
        .await
        .map_err(storage_io)?;
    let pair_tokens =
        crate::pair_token::DurablePairTokenStore::new(store.kv()).map_err(storage_io)?;
    pair_tokens
        .ensure_legacy_import(home, directory)
        .await
        .map_err(storage_io)?;
    import_gateway_revocations(home, store.kv()).await
}

async fn migrate_legacy_audit(home: &AstridHome, audit: &Arc<AuditLog>) -> io::Result<()> {
    let default_audit = home.principal_home(&PrincipalId::default()).audit_dir();
    let source_present = preflight_legacy_audit_sources(home, &default_audit)?;
    if !source_present {
        return Ok(());
    }
    let import_report = audit
        .import_legacy_audit(&default_audit, "astrid-system-audit-v1")
        .await
        .map_err(|error| io::Error::other(format!("legacy audit migration failed: {error}")))?;
    match fs::symlink_metadata(&default_audit) {
        Ok(_) => {
            preflight_legacy_audit_sources(home, &default_audit)?;
            audit
                .verify_legacy_source_digest(
                    &default_audit,
                    "astrid-system-audit-v1",
                    &import_report.source_digest,
                )
                .await
                .map_err(|error| {
                    io::Error::other(format!(
                        "legacy audit source changed before digest-bound retirement: {error}"
                    ))
                })?;
            retire_legacy_audit_dir(home, &default_audit)?;
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound && source_present => {
            return Err(io::Error::other(
                "legacy audit source disappeared before digest-bound retirement",
            ));
        },
        Err(error) => return Err(error),
    }
    Ok(())
}

fn ensure_no_unretired_authority_receipts(
    home: &AstridHome,
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<()> {
    let workspace_targets = workspace_portal_targets(workspace_root, workspace_layout)?;
    let status = legacy_capsule_authority_status(home, &workspace_targets).map_err(|error| {
        io::Error::other(format!("legacy capsule authority status failed: {error}"))
    })?;
    if let Some(path) = status
        .pending
        .first()
        .or_else(|| status.previous.first())
        .or_else(|| status.unknown_active.first())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy capsule authority receipt remains after migration; refusing cutover: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn workspace_portal_targets(
    workspace_root: &Path,
    workspace_layout: &WorkspaceLayout,
) -> io::Result<Vec<PathBuf>> {
    let selection = workspace_layout.resolve(workspace_root)?;
    let capsules = match selection.capsules_dir() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    collect_workspace_targets(&capsules)
}

/// Agent deletion/rollback must not discard a released source that has not
/// crossed the global barrier.  This is synchronous by design: the admin
/// delete path already holds its write fence and must make the decision before
/// unlinking identity or purging durable state.
pub(crate) fn ensure_principal_delete_allowed(
    home: &AstridHome,
    principal: &PrincipalId,
) -> io::Result<()> {
    reject_incomplete_layout_v2(home)?;
    let principal_home = home.principal_home(principal);
    let root = principal_home.root();
    if path_exists(root)? && snapshot_path(root)?.entries != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "cannot delete principal {principal}: legacy native source is not retired: {}",
                root.display()
            ),
        ));
    }
    let profile = principal_home.config_dir().join("profile.toml");
    if path_exists(&profile)? {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "cannot delete principal {principal}: legacy profile is not retired: {}",
                profile.display()
            ),
        ));
    }
    Ok(())
}

async fn import_gateway_revocations(home: &AstridHome, store: Arc<dyn KvStore>) -> io::Result<()> {
    let path = home.etc_dir().join("gateway-revocations.json");
    let Some(bytes) = read_bounded_file(&path, MAX_REVOCATION_BYTES)? else {
        return Ok(());
    };
    let raw: BTreeMap<String, u64> = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse gateway revocations: {error}"),
        )
    })?;
    if raw.len() > 1_000_000 {
        return Err(io::Error::other(
            "gateway revocation source exceeds entry limit",
        ));
    }
    let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    let receipt =
        serde_json::json!({"schema": 1_u8, "digest": digest, "principal_count": raw.len()});
    let receipt_bytes = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
    if let Some(existing) = store
        .get(REVOCATION_NAMESPACE, REVOCATION_RECEIPT_KEY)
        .await
        .map_err(storage_io)?
    {
        if existing != receipt_bytes {
            return Err(io::Error::other(
                "gateway revocation migration receipt conflicts",
            ));
        }
    } else {
        for (alias, epoch) in &raw {
            PrincipalId::new(alias.clone()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid revoked principal {alias:?}: {error}"),
                )
            })?;
            let key = format!("{REVOCATION_PRINCIPAL_PREFIX}{alias}");
            let value = epoch.to_le_bytes().to_vec();
            let current = store
                .get(REVOCATION_NAMESPACE, &key)
                .await
                .map_err(storage_io)?;
            if let Some(current) = current {
                if current.len() != 8 || u64::from_le_bytes(current.try_into().unwrap()) < *epoch {
                    store
                        .set(REVOCATION_NAMESPACE, &key, value)
                        .await
                        .map_err(storage_io)?;
                }
            } else {
                store
                    .set(REVOCATION_NAMESPACE, &key, value)
                    .await
                    .map_err(storage_io)?;
            }
        }
        let inserted = store
            .compare_and_swap(
                REVOCATION_NAMESPACE,
                REVOCATION_RECEIPT_KEY,
                None,
                receipt_bytes,
            )
            .await
            .map_err(storage_io)?;
        if !inserted {
            return Err(io::Error::other(
                "gateway revocation migration receipt raced",
            ));
        }
    }
    let reread = fs::read(&path).map_err(io::Error::other)?;
    if reread != bytes {
        return Err(io::Error::other(
            "gateway revocation source changed during migration",
        ));
    }
    fs::remove_file(&path).map_err(io::Error::other)?;
    sync_parent(&path)
}

#[allow(
    clippy::too_many_lines,
    reason = "the preflight inventory is the single source manifest"
)]
fn preflight_sources(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    bindings: &[(PrincipalId, PrincipalUid)],
) -> io::Result<BTreeMap<String, SourceIdentity>> {
    let mut sources = BTreeMap::new();
    sources.insert(
        "system:state-db".to_owned(),
        snapshot_owner_controlled_path(&home.state_db_path())?,
    );
    add_source(&mut sources, "system:cow".to_owned(), home.cow_dir())?;
    add_source(
        &mut sources,
        "system:invites".to_owned(),
        crate::invite::InviteStore::path_for(home),
    )?;
    add_source(
        &mut sources,
        "system:pair-tokens".to_owned(),
        crate::pair_token::PairTokenStore::path_for(home),
    )?;
    add_source(
        &mut sources,
        "system:gateway-revocations".to_owned(),
        home.etc_dir().join("gateway-revocations.json"),
    )?;
    add_source(
        &mut sources,
        "system:capsule-authority".to_owned(),
        home.etc_dir().join("capsule-authority"),
    )?;
    add_source(
        &mut sources,
        "system:host-secrets".to_owned(),
        home.secrets_dir().join("__host__"),
    )?;
    for (alias, uid) in bindings {
        let home_name = format!("principal:{uid}:home");
        let ordinary =
            crate::principal_home_migration::legacy_ordinary_source_snapshot(home, alias)?;
        let distro = crate::principal_distro_migration::legacy_distro_source_snapshot(home, alias)?;
        let distro_init =
            crate::principal_distro_migration::legacy_distro_init_source_snapshot(home, alias)?;
        if distro.present {
            validate_source_path(&home.principal_home(alias).config_dir().join("distro.lock"))?;
        }
        if distro_init.present {
            validate_source_path(
                &home
                    .principal_home(alias)
                    .config_dir()
                    .join("distro.init.lock"),
            )?;
        }
        add_source(
            &mut sources,
            format!("principal:{uid}:secrets"),
            home.secrets_dir().join(alias.as_str()),
        )?;
        add_source(
            &mut sources,
            format!("principal:{uid}:profile"),
            home.principal_home(alias).config_dir().join("profile.toml"),
        )?;
        sources.insert(
            format!("principal:{uid}:distro-lock"),
            SourceIdentity::from_snapshot_fields(
                &distro.digest,
                distro.entries,
                distro.bytes,
                distro.present,
            )?,
        );
        sources.insert(
            format!("principal:{uid}:distro-init"),
            SourceIdentity::from_snapshot_fields(
                &distro_init.digest,
                distro_init.entries,
                distro_init.bytes,
                distro_init.present,
            )?,
        );
        sources.insert(
            format!("principal:{uid}:audit"),
            snapshot_owner_controlled_path(&home.principal_home(alias).audit_dir())?,
        );
        add_source(
            &mut sources,
            format!("principal:{uid}:logs"),
            home.principal_home(alias).log_dir(),
        )?;
        add_source(
            &mut sources,
            format!("principal:{uid}:tmp"),
            home.principal_home(alias).tmp_dir(),
        )?;
        sources.insert(
            format!("principal:{uid}:capsules"),
            snapshot_owner_controlled_path(&home.principal_home(alias).capsules_dir())?,
        );
        let owner = astrid_storage::StateOwner::Principal(*uid);
        let capsule_ids = store
            .capsules()
            .list(&owner)
            .map_err(storage_io)?
            .into_iter()
            .map(|summary| summary.id().to_owned())
            .collect::<Vec<_>>();
        add_principal_scope_sources(&mut sources, home, alias, *uid, &capsule_ids)?;
        sources.insert(
            home_name,
            SourceIdentity::from_snapshot_fields(
                &ordinary.digest,
                ordinary.entries,
                ordinary.bytes,
                ordinary.present,
            )?,
        );
    }
    Ok(sources)
}

#[allow(
    clippy::too_many_lines,
    reason = "all dedicated sources are checked before cut-over"
)]
fn ensure_no_unretired_component_sources(
    home: &AstridHome,
    directory: &PrincipalDirectory,
    allow_empty_cleanup: bool,
) -> io::Result<()> {
    let candidates = [
        ("invites", crate::invite::InviteStore::path_for(home)),
        (
            "pair-tokens",
            crate::pair_token::PairTokenStore::path_for(home),
        ),
        (
            "gateway-revocations",
            home.etc_dir().join("gateway-revocations.json"),
        ),
    ];
    for (name, path) in candidates {
        if path_exists(&path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy {name} source remains after migration: {}",
                    path.display()
                ),
            ));
        }
    }
    for (alias, uid) in directory.bindings() {
        let root = home.principal_home(&alias).root().to_path_buf();
        if !path_exists(&root)? {
            continue;
        }
        let unsupported = [
            ("kv", home.principal_home(&alias).kv_dir()),
            ("tokens", home.principal_home(&alias).tokens_dir()),
        ];
        for (name, path) in unsupported {
            if !path_exists(&path)? {
                continue;
            }
            if snapshot_path(&path)?.entries != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "legacy principal {alias} (uid {uid}) retains unsupported {name} state; no authoritative migration API exists: {}",
                        path.display()
                    ),
                ));
            }
            if allow_empty_cleanup {
                retire_empty_directory(&path)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy {name} source reappeared after cut-over: {}",
                        path.display()
                    ),
                ));
            }
        }
        for (name, path) in [
            ("capsules", home.principal_home(&alias).capsules_dir()),
            ("env", home.principal_home(&alias).env_dir()),
            ("audit", home.principal_home(&alias).audit_dir()),
            ("logs", home.principal_home(&alias).log_dir()),
            ("tmp", home.principal_home(&alias).tmp_dir()),
            (
                "distro-lock",
                home.principal_home(&alias).config_dir().join("distro.lock"),
            ),
            (
                "distro-init",
                home.principal_home(&alias)
                    .config_dir()
                    .join("distro.init.lock"),
            ),
            ("secrets", home.secrets_dir().join(alias.as_str())),
        ] {
            if path_exists(&path)? {
                let snapshot = snapshot_path(&path)?;
                if snapshot.entries != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "legacy principal {alias} (uid {uid}) retains {name} source after its importer: {}",
                            path.display()
                        ),
                    ));
                }
                if allow_empty_cleanup {
                    retire_empty_directory(&path)?;
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "legacy {name} source reappeared after cut-over: {}",
                            path.display()
                        ),
                    ));
                }
            }
        }
        let profile = home
            .principal_home(&alias)
            .config_dir()
            .join("profile.toml");
        if path_exists(&profile)? {
            return Err(io::Error::other(format!(
                "legacy profile remains: {}",
                profile.display()
            )));
        }
    }
    let secrets_root = home.secrets_dir();
    ensure_legacy_secret_aliases(&secrets_root, allow_empty_cleanup)?;
    let host_secrets = home.secrets_dir().join("__host__");
    if path_exists(&host_secrets)? {
        if snapshot_path(&host_secrets)?.entries != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy host secret scopes remain after their system importer: {}",
                    host_secrets.display()
                ),
            ));
        }
        if allow_empty_cleanup {
            retire_empty_directory(&host_secrets)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy host secret source reappeared after cut-over: {}",
                    host_secrets.display()
                ),
            ));
        }
    }
    if path_exists(&secrets_root)? {
        let remaining = snapshot_path(&secrets_root)?;
        if remaining.entries == 0 {
            if allow_empty_cleanup {
                retire_empty_directory(&secrets_root)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy secrets root reappeared after cut-over: {}",
                        secrets_root.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
