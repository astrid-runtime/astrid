//! Restore a volume-authoritative projection before ACTIVE publication.

use std::path::Path;

use astrid_core::platform_fs::{PrivateFileProjection, PrivateProjectionInspection, StagingScope};

use super::{
    AstridHome, ContentName, ReceiptPhase, RuntimePrincipalStore, StateOwner, StorageResult,
};
use super::{confined_projection_path, ingest_runtime_key, is_excluded};
use super::{is_retired_legacy_projection, is_staging_generation, seed_layout_version};
use super::{transition_retiring_projection, tree_error, tree_io_error};
use crate::content::ContentEntry;
use crate::principal_state::NativePrincipalContentStore;

/// Proof that this exact home/store pair has a durable restoration inventory.
/// Private fields prevent callers from manufacturing or rebinding the proof.
pub(super) struct PreparedRestoration<'a> {
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    staging_scope: Option<StagingScope>,
    projection: Option<PrivateFileProjection>,
}

impl PreparedRestoration<'_> {
    /// Root and parent privacy repairs are host mutations too: only open this
    /// writer after the complete recovery inventory has reached durable storage.
    pub(super) fn store(&self) -> &RuntimePrincipalStore {
        self.store
    }

    pub(super) fn staging_scope(&self) -> Option<StagingScope> {
        self.staging_scope
    }

    pub(super) fn writer(&mut self) -> StorageResult<&PrivateFileProjection> {
        if self.projection.is_none() {
            self.projection = Some(match self.staging_scope {
                Some(scope) => PrivateFileProjection::open_with_staging(self.home.root(), scope)
                    .map_err(|error| tree_error(self.home.root(), error))?,
                None => PrivateFileProjection::open(self.home.root())
                    .map_err(|error| tree_error(self.home.root(), error))?,
            });
            #[cfg(test)]
            tests::writer_opened(self.home.root());
            #[cfg(test)]
            tests::after_write(self.home.root(), "<private-root>");
        }
        self.projection
            .as_ref()
            .ok_or_else(|| tree_error(self.home.root(), "restoration writer was not prepared"))
    }

    /// After legacy unscoped cleanup, mint schema-2 scope before scoped temps.
    pub(super) fn ensure_scoped_intent(&mut self) -> StorageResult<()> {
        if self.staging_scope.is_some() {
            return Ok(());
        }
        let staging_scope = StagingScope::new();
        let entries = super::active_projection_entries(self.home, self.store)?;
        let intent = super::receipt_ingest(
            self.home,
            ReceiptPhase::Retiring,
            &entries,
            Some(staging_scope),
        )?;
        self.store.replace_contiguous_files_removing_exact(
            StateOwner::System,
            [intent],
            &[],
            None,
        )?;
        self.store.content().flush().map_err(|error| {
            tree_error(
                self.home.root(),
                format!("flush scoped restoration intent: {error}"),
            )
        })?;
        self.staging_scope = Some(staging_scope);
        // Drop any unscoped cleanup writer before ordinary materialization.
        self.projection = None;
        #[cfg(test)]
        tests::intent_committed(self.home.root());
        Ok(())
    }
}

/// Complete cleanup before handing a prepared writer to restoration, whose
/// early validation can fail before entering its normal fence/rollback loop.
pub(super) fn finish_cleanup(
    home: &AstridHome,
    writer: &PrivateFileProjection,
    cleanup: StorageResult<()>,
) -> StorageResult<()> {
    let fence = writer
        .sync()
        .map_err(|error| tree_error(home.root(), error));
    match (cleanup, fence) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(fence)) => Err(tree_error(
            home.root(),
            format!("staging cleanup failed: {error}; durability fence failed: {fence}"),
        )),
    }
}

pub(super) fn restore_after_recovery(prepared: PreparedRestoration<'_>) -> StorageResult<()> {
    let home = prepared.home;
    let store = prepared.store;
    restore(home, store, &store.content, Some(prepared), || Ok(()))
}

/// Replace durable host files with volume-backed running projections.
pub(in crate::principal_state) fn restore_projection(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
) -> StorageResult<()> {
    restore_with_sync(home, store, content, || Ok(()))
}

fn restore_with_sync(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
    after_sync: impl FnMut() -> StorageResult<()>,
) -> StorageResult<()> {
    restore(home, store, content, None, after_sync)
}

fn restore<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
    mut prepared: Option<PreparedRestoration<'a>>,
    mut after_sync: impl FnMut() -> StorageResult<()>,
) -> StorageResult<()> {
    let layout_version = home
        .layout_version()
        .map_err(|error| tree_io_error(&error))?;
    if layout_version.as_deref() == Some(astrid_core::dirs::LEGACY_LAYOUT_VERSION) {
        return Ok(());
    }
    ingest_runtime_key(home, store)?;
    seed_layout_version(home, store)?;
    let entries = projection_entries(home, content)?;
    let mut written = Vec::new();
    let mut spool = rollback::RollbackSpool::default();
    let result = restore_entries(
        home,
        store,
        content,
        entries,
        &mut prepared,
        &mut spool,
        &mut written,
    )
    .and_then(|()| sync_projection(home, prepared.as_ref(), &mut after_sync));
    if let Err(error) = result {
        let rollback_errors = rollback(
            home,
            prepared.as_ref(),
            &mut spool,
            written,
            &mut after_sync,
        );
        if !rollback_errors.is_empty() {
            let retirement = match transition_retiring_projection(home, store) {
                Ok(()) => "durable RETIRING receipt recorded".to_owned(),
                Err(retirement) => format!("failed to force RETIRING receipt: {retirement}"),
            };
            return Err(tree_error(
                home.root(),
                format!(
                    "restore failed: {error}; rollback failures: {rollback_errors:?}; {retirement}"
                ),
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn projection_entries(
    home: &AstridHome,
    content: &NativePrincipalContentStore,
) -> StorageResult<Vec<ContentEntry>> {
    let mut entries = content
        .list(&StateOwner::System)
        .map_err(|error| tree_error(home.root(), format!("list volume projection: {error}")))?;
    // Make subsequent interrupted restores structurally recognizable before
    // materializing other volume-owned directories or configuration files.
    entries.retain(|entry| {
        !is_excluded(entry.name().as_str())
            && !is_retired_legacy_projection(home, entry.name().as_str())
    });
    entries.sort_by_key(|entry| entry.name().as_str() != "etc/layout-version");
    for entry in &entries {
        let name = entry.name().as_str();
        confined_projection_path(home.root(), name.strip_suffix('/').unwrap_or(name))?;
    }
    names::validate(home, &entries)?;
    Ok(entries)
}

struct WrittenFile {
    name: ContentName,
    previous: rollback::PreviousGeneration,
    publication: astrid_core::platform_fs::PrivateFilePublication,
}

fn restore_entries<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    content: &NativePrincipalContentStore,
    entries: Vec<ContentEntry>,
    prepared: &mut Option<PreparedRestoration<'a>>,
    spool: &mut rollback::RollbackSpool,
    written: &mut Vec<WrittenFile>,
) -> StorageResult<()> {
    // Read-only matching never repairs. A non-private root (bootstrap 0755) yields
    // no inspection session, so entries fall through to intent + writer repair.
    let inspection = PrivateProjectionInspection::try_open(home.root()).ok();
    for entry in entries {
        let name = entry.name().as_str();
        if let Some(directory) = name.strip_suffix('/') {
            if entry.logical_bytes() != 0 {
                return Err(tree_error(
                    home.root(),
                    "directory marker contains file bytes",
                ));
            }
            let path = confined_projection_path(home.root(), directory)?;
            if inspection_matches_directory(inspection.as_ref(), Path::new(directory), &path)? {
                continue;
            }
            prepare(home, store, prepared)?
                .ensure_directory(Path::new(directory))
                .map_err(|error| tree_error(&path, error))?;
            continue;
        }
        let Some(handle) = content
            .open_read(&StateOwner::System, entry.name())
            .map_err(|error| tree_error(home.root(), format!("read projection {name}: {error}")))?
        else {
            continue;
        };
        let mut reader = read::AuthenticatedContentReader::new(&handle);
        let length = reader.logical_len();
        if length != entry.logical_bytes() {
            return Err(tree_error(
                home.root(),
                "projection changed during restoration admission",
            ));
        }
        let path = confined_projection_path(home.root(), name)?;
        // Matching payload bytes alone do not establish the private-file contract.
        // Skips must prove the root-bound mount/device boundary, not ambient paths.
        if !is_staging_generation(name)
            && inspection_matches_file(
                inspection.as_ref(),
                Path::new(name),
                length,
                &mut reader,
                &path,
            )?
        {
            continue;
        }
        reader.rewind();
        let writer = prepare(home, store, prepared)?;
        let (replacement, previous) = spool
            .capture(writer, Path::new(name))
            .map_err(|error| tree_error(&path, error))?;
        #[cfg(test)]
        tests::after_backup(home.root(), name);
        let (publication, result) = replacement.write_from(&mut reader, length).into_parts();
        if let Some(publication) = publication {
            // Rename may have succeeded before a later durability fence failed.
            // Enroll that exact installed identity before propagating the error.
            written.push(WrittenFile {
                name: entry.name().clone(),
                previous,
                publication,
            });
        }
        result.map_err(|error| tree_error(&path, error))?;
        #[cfg(test)]
        tests::after_write(home.root(), name);
        if is_staging_generation(name) {
            super::super::rebind_staging_generation(&path)?;
        }
    }
    if prepared.is_none()
        && let Some(inspection) = inspection.as_ref()
    {
        // All projected entries matched through the captured root. Confirm the
        // absolute binding before returning without opening the writer.
        inspection
            .confirm_absolute_root()
            .map_err(|error| tree_error(home.root(), error))?;
    }
    Ok(())
}

fn inspection_matches_directory(
    inspection: Option<&PrivateProjectionInspection>,
    relative: &Path,
    path: &Path,
) -> StorageResult<bool> {
    let Some(inspection) = inspection else {
        return Ok(false);
    };
    inspection
        .matches_private_directory(relative)
        .map_err(|error| tree_error(path, error))
}

fn inspection_matches_file(
    inspection: Option<&PrivateProjectionInspection>,
    relative: &Path,
    length: u64,
    expected: &mut dyn std::io::Read,
    path: &Path,
) -> StorageResult<bool> {
    let Some(inspection) = inspection else {
        return Ok(false);
    };
    inspection
        .matches_private_file_from(relative, length, expected)
        .map_err(|error| tree_error(path, error))
}

fn prepare<'a, 'b>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
    prepared: &'b mut Option<PreparedRestoration<'a>>,
) -> StorageResult<&'b PrivateFileProjection> {
    if prepared.is_none() {
        *prepared = Some(record_intent(home, store)?);
        #[cfg(test)]
        tests::after_intent(home.root());
    }
    let prepared = prepared
        .as_mut()
        .ok_or_else(|| tree_error(home.root(), "restoration intent was not prepared"))?;
    // Materialization may create scoped temps; never open that writer unscoped.
    prepared.ensure_scoped_intent()?;
    prepared.writer()
}

fn sync_projection(
    home: &AstridHome,
    prepared: Option<&PreparedRestoration<'_>>,
    after_sync: &mut impl FnMut() -> StorageResult<()>,
) -> StorageResult<()> {
    if let Some(writer) = prepared.and_then(|state| state.projection.as_ref()) {
        writer
            .sync()
            .map_err(|error| tree_error(home.root(), error))?;
        after_sync()?;
    }
    Ok(())
}

fn rollback(
    home: &AstridHome,
    prepared: Option<&PreparedRestoration<'_>>,
    spool: &mut rollback::RollbackSpool,
    written: Vec<WrittenFile>,
    after_sync: &mut impl FnMut() -> StorageResult<()>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(writer) = prepared.and_then(|state| state.projection.as_ref()) {
        for file in written.into_iter().rev() {
            let path = Path::new(file.name.as_str());
            if let Err(error) = spool.restore(writer, file.publication, file.previous) {
                errors.push(format!("{}: {error}", path.display()));
            }
        }
    }
    if let Err(error) = sync_projection(home, prepared, after_sync) {
        errors.push(format!("rollback durability fence: {error}"));
    }
    errors
}

/// Commit the existing volume inventory before materializing any host bytes.
pub(super) fn record_intent<'a>(
    home: &'a AstridHome,
    store: &'a RuntimePrincipalStore,
) -> StorageResult<PreparedRestoration<'a>> {
    let staging_scope = reuse_or_mint_staging_scope(home, store)?;
    let entries = super::active_projection_entries(home, store)?;
    let intent = super::receipt_ingest(home, ReceiptPhase::Retiring, &entries, staging_scope)?;
    store.replace_contiguous_files_removing_exact(StateOwner::System, [intent], &[], None)?;
    store
        .content()
        .flush()
        .map_err(|error| tree_error(home.root(), format!("flush restoration intent: {error}")))?;
    #[cfg(test)]
    tests::intent_committed(home.root());
    Ok(PreparedRestoration {
        home,
        store,
        staging_scope,
        projection: None,
    })
}

fn reuse_or_mint_staging_scope(
    home: &AstridHome,
    store: &RuntimePrincipalStore,
) -> StorageResult<Option<StagingScope>> {
    // Crash/retry must keep authorizing temps created under the prior scope.
    // Never drop a durable scope on intent refresh, and never invent one over
    // schema-1 Retiring before legacy temps are discharged.
    // Mint only when creating Retiring from Active / receiptless bootstrap.
    match super::active::read_relocatable(home, store)? {
        Some(receipt) if receipt.phase() == ReceiptPhase::Retiring => {
            if !receipt.root_matches(home)? {
                return Err(tree_error(
                    home.root(),
                    "retiring staging scope does not match this durable root",
                ));
            }
            Ok(receipt.staging_scope())
        },
        _ => Ok(Some(StagingScope::new())),
    }
}

pub(super) use staging::{discharge_scoped_staging, eligible_file_parents, parent_is_eligible};

#[cfg(all(test, unix))]
pub(super) fn begin_writer_count(root: &std::path::Path) {
    tests::begin_writer_count(root);
}

#[cfg(all(test, unix))]
pub(super) fn take_writer_opens(root: &std::path::Path) -> usize {
    tests::take_writer_opens(root)
}

mod names;
mod read;
#[cfg(test)]
mod read_tests;
mod rollback;
mod staging;

#[cfg(test)]
mod barrier_tests;
#[cfg(test)]
mod rollback_tests;
#[cfg(test)]
mod staging_tests;
#[cfg(test)]
mod tests;
