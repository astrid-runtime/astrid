//! Reuse a boot snapshot and its committed identities through receipt completion.

use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

use astrid_core::platform_fs::PrivateProjectionInspection;

use super::{
    ActiveProjectionEntry, ActiveReceiptDeriver, AstridHome, ContentName, ContiguousFileIngest,
    PackedProjectionIngest, RuntimePrincipalStore, RuntimeTreeEntry, StateOwner, active,
    active_projection_entries, confined_projection_path, is_excluded, is_retired_legacy_projection,
    projection, scan,
};
use crate::content::ContentBatchExpectation;
use crate::storage_model::ObjectId;

/// Pending completion of one home/store-bound boot snapshot admission.
///
/// Payloads and their matching ACTIVE inventory are already durable. Completion rechecks the original snapshot
/// after that publication, then publishes the caller's control receipt and
/// matching ACTIVE inventory together. The borrowed store, home and snapshot
/// cannot be rebound; dropping this value leaves admission incomplete and safe
/// to retry. No file payload or persistent cache is retained.
#[must_use = "complete the source check and receipt publication, or retry admission"]
pub struct RuntimeTreeAdmission<'a> {
    store: &'a RuntimePrincipalStore,
    home: &'a AstridHome,
    snapshot: &'a [RuntimeTreeEntry],
    root: PrivateProjectionInspection,
    source_root: PathBuf,
    entries: Vec<ActiveProjectionEntry>,
    control: ContentName,
    control_expected: Option<ObjectId>,
    active_expected: Option<ObjectId>,
}

impl RuntimePrincipalStore {
    /// Admit an already-scanned boot tree without walking it again.
    ///
    /// The snapshot must come from this home's `scan_runtime_tree`. Callers
    /// supply the control receipt name but retain its serialization policy.
    /// `finish` checks the source after the final payload CAS before writing
    /// that receipt. Existing unrestricted admission remains available through
    /// `admit_runtime_tree`.
    ///
    /// # Errors
    /// Rejects a foreign snapshot, unsafe root, or failed packed publication.
    pub fn admit_runtime_tree_snapshot<'a>(
        &'a self,
        home: &'a AstridHome,
        snapshot: &'a [RuntimeTreeEntry],
        control: ContentName,
    ) -> io::Result<RuntimeTreeAdmission<'a>> {
        let root = PrivateProjectionInspection::try_open(home.root())?;
        let source_root = std::fs::canonicalize(home.root())?;
        validate_snapshot(home, snapshot, &control)?;
        super::restoration::names::validate_admission(home, snapshot, &control)
            .map_err(io_error)?;
        let mut entries = active_projection_entries(home, self)
            .map_err(io_error)?
            .into_iter()
            .filter(|entry| entry.name.as_str().ends_with('/'))
            .collect::<Vec<_>>();
        let active_name = active::active_projection_name().map_err(io_error)?;
        let mut active_expected = catalog_file(self, &active_name)?;
        let mut control_expected = catalog_file(self, &control)?;
        let expectation = ContentBatchExpectation::exact(
            entries
                .iter()
                .map(|entry| (entry.name.clone(), Some(entry.file)))
                .chain([
                    (active_name.clone(), active_expected),
                    (control.clone(), control_expected),
                ]),
        );
        let files = snapshot.iter().map(|entry| {
            PackedProjectionIngest::File(ContiguousFileIngest::new(
                entry.name.clone(),
                entry.source_path.clone(),
                entry.logical_bytes,
            ))
        });
        root.confirm_absolute_root()?;
        if std::fs::canonicalize(home.root())? != source_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "admission home resolves to another root",
            ));
        }
        // An interrupted payload commit must retain a catalog-consistent
        // ACTIVE receipt, so reconciliation can import remaining host edits.
        let mut derived = ActiveReceiptDeriver {
            home: home.clone(),
            entries: snapshot
                .iter()
                .filter(|entry| !is_retired_legacy_projection(home, entry.name.as_str()))
                .map(|entry| (entry.name.clone(), entry.logical_bytes))
                .collect(),
            retained: &entries,
        };
        let outcome = self
            .replace_contiguous_files_with_expectation(
                StateOwner::System,
                files,
                &[],
                Some(&mut derived),
                Some(&expectation).into(),
            )
            .map_err(io_error)?;
        if let Some(outcome) = outcome {
            for entry in outcome.entries() {
                if entry.name() == &active_name {
                    active_expected = Some(entry.descriptor().file());
                }
                if entry.name() == &control {
                    control_expected = Some(entry.descriptor().file());
                }
                if !is_excluded(entry.name().as_str())
                    && !is_retired_legacy_projection(home, entry.name().as_str())
                {
                    entries.push(ActiveProjectionEntry {
                        name: entry.name().clone(),
                        file: entry.descriptor().file(),
                        logical_bytes: entry.descriptor().logical_bytes(),
                    });
                }
            }
        }
        Ok(RuntimeTreeAdmission {
            store: self,
            home,
            snapshot,
            root,
            source_root,
            entries,
            control,
            control_expected,
            active_expected,
        })
    }
}

impl RuntimeTreeAdmission<'_> {
    /// Verify the published source snapshot and complete its control receipt.
    ///
    /// Source mutation returns `WouldBlock` without writing a completed host
    /// receipt. Catalog identities are checked on every publication CAS retry.
    /// Failed receipt publication rolls back only this attempt's installed
    /// host identity, including failures after rename.
    ///
    /// # Errors
    /// Rejects changed sources, roots or catalog identities and propagates
    /// source, publication, durability and guarded rollback failures.
    pub fn finish(mut self, control_bytes: Vec<u8>) -> io::Result<()> {
        let after = scan(self.home.root()).map_err(io_error)?;
        self.confirm_root()?;
        if after.as_slice() != self.snapshot {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "runtime tree changed while packed admission was in progress",
            ));
        }
        self.entries.retain(|entry| {
            !entry.name.as_str().ends_with('/')
                || projection::surviving_directory(self.home.root(), entry.name.as_str())
        });
        #[cfg(all(test, unix))]
        tests::before_writer_creation(self.home.root())?;
        let writer = self.root.open_writer()?;
        let mut previous = Vec::new();
        let (replacement, prior_length) =
            writer.capture_replacement(Path::new(self.control.as_str()), &mut previous)?;
        let length = u64::try_from(control_bytes.len()).map_err(io_error)?;
        let (publication, write_result) = replacement
            .write_from(&mut Cursor::new(control_bytes.as_slice()), length)
            .into_parts();
        let result = write_result.and_then(|()| self.publish_control(length, control_bytes));
        if let Err(error) = result {
            if let Some(publication) = publication {
                let mut prior = Cursor::new(previous);
                let backup = prior_length.map(|length| (&mut prior as &mut dyn io::Read, length));
                writer
                    .rollback_publication(publication, backup)
                    .map_err(|rollback| {
                        io::Error::other(format!("{error}; rollback control receipt: {rollback}"))
                    })?;
            }
            return Err(error);
        }
        Ok(())
    }

    fn publish_control(&self, length: u64, control_bytes: Vec<u8>) -> io::Result<()> {
        self.confirm_root()?;
        let active_name = active::active_projection_name().map_err(io_error)?;
        let expectation = ContentBatchExpectation::exact(
            self.entries
                .iter()
                .map(|entry| (entry.name.clone(), Some(entry.file)))
                .chain([
                    (self.control.clone(), self.control_expected),
                    (active_name, self.active_expected),
                ]),
        );
        let mut derived = ActiveReceiptDeriver {
            home: self.home.clone(),
            entries: vec![(self.control.clone(), length)],
            retained: &self.entries,
        };
        self.store
            .replace_contiguous_files_with_expectation(
                StateOwner::System,
                [PackedProjectionIngest::bytes(
                    self.control.clone(),
                    control_bytes,
                )],
                &[],
                Some(&mut derived),
                Some(&expectation).into(),
            )
            .map_err(io_error)?;
        self.store.content().flush().map_err(io_error)?;
        self.confirm_root()
    }

    fn confirm_root(&self) -> io::Result<()> {
        self.root.confirm_absolute_root()?;
        if std::fs::canonicalize(self.home.root())? != self.source_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "admission home resolves to another root",
            ));
        }
        Ok(())
    }
}

fn validate_snapshot(
    home: &AstridHome,
    entries: &[RuntimeTreeEntry],
    control: &ContentName,
) -> io::Result<()> {
    confined_projection_path(home.root(), control.as_str())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if is_excluded(control.as_str())
        || control.as_str().ends_with('/')
        || is_retired_legacy_projection(home, control.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid admission control name",
        ));
    }
    for entry in entries {
        let expected =
            confined_projection_path(home.root(), entry.name.as_str()).map_err(io_error)?;
        if expected != entry.source_path || is_excluded(entry.name.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime snapshot belongs to another source",
            ));
        }
    }
    Ok(())
}

fn catalog_file(store: &RuntimePrincipalStore, name: &ContentName) -> io::Result<Option<ObjectId>> {
    store
        .content()
        .describe(&StateOwner::System, name)
        .map(|descriptor| descriptor.map(crate::content::ContentDescriptor::file))
        .map_err(io_error)
}

fn io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests;
