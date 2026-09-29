//! Operator retention controls for the system audit log, from the
//! `[audit.retention]` config table: whether pruning requires an anchored
//! watermark, and where pruned segments are archived before deletion.

use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_audit::{
    AuditArchiveWriter, AuditArchiver, AuditEntry, AuditError, AuditLog, AuditPruneReceipt,
    AuditResult,
};
use astrid_config::types::{AuditConfig, AuditRetentionConfig};
use astrid_core::PrincipalId;
use async_trait::async_trait;

/// Read `[audit]` from the daemon's config, or the defaults when it cannot
/// be loaded.
pub(crate) fn load_audit_config(
    workspace_root: &Path,
    workspace_layout: &astrid_core::dirs::WorkspaceLayout,
) -> AuditConfig {
    astrid_config::Config::load_with_layout(Some(workspace_root), workspace_layout).map_or_else(
        |error| {
            tracing::warn!(error = %error, "config unavailable; using default audit settings");
            AuditConfig::default()
        },
        |resolved| resolved.config.audit,
    )
}

/// Apply `[audit.retention]` to the kernel's audit log.
pub(crate) fn apply_retention_config(audit_log: &AuditLog, config: &AuditRetentionConfig) {
    audit_log.set_require_anchor_before_prune(config.require_anchor);
    let archiver = config.archive_dir.as_ref().map(|root| {
        Arc::new(FileArchiver {
            root: PathBuf::from(root),
        }) as Arc<dyn AuditArchiver>
    });
    if let Some(root) = &config.archive_dir {
        tracing::info!(archive_dir = %root, "Pruned audit segments are archived before deletion");
    }
    audit_log.set_prune_archiver(archiver);
}

/// Archives each pruned segment as one file,
/// `<root>/<session>/<chain>/<generation:020>.jsonl`, where `<chain>` is
/// `system` or `principal.<alias>`. The first line is the signed prune
/// receipt exactly as the log stores it; each further line is one removed
/// entry as stored, in chain order. The file is written under a temporary
/// name, synced, and renamed into place, and every directory is private to
/// the daemon's user. File operations run on the blocking thread pool, so a
/// large archive or a slow disk does not stall the async runtime.
pub(crate) struct FileArchiver {
    pub(crate) root: PathBuf,
}

#[async_trait]
impl AuditArchiver for FileArchiver {
    async fn begin(
        &self,
        receipt: &AuditPruneReceipt,
        receipt_bytes: &[u8],
    ) -> AuditResult<Box<dyn AuditArchiveWriter>> {
        // Receipts name the session in its display form, `session:<uuid>`.
        let session = receipt
            .session
            .strip_prefix("session:")
            .unwrap_or(&receipt.session);
        let session = uuid::Uuid::parse_str(session)
            .map_err(|error| archive_error("receipt session", &error))?;
        let chain = match &receipt.principal {
            Some(alias) => {
                let principal =
                    PrincipalId::new(alias).map_err(|error| archive_error("principal", &error))?;
                format!("principal.{principal}")
            },
            None => "system".to_owned(),
        };
        let root = self.root.clone();
        let name = format!("{:020}.jsonl", receipt.generation);
        let mut first_line = receipt_bytes.to_vec();
        first_line.push(b'\n');
        blocking(move || {
            let session_dir = root.join(session.to_string());
            let directory = session_dir.join(chain);
            for dir in [&root, &session_dir, &directory] {
                astrid_core::platform_fs::ensure_private_directory(dir)
                    .map_err(|error| archive_error("directory", &error))?;
            }
            let temporary =
                directory.join(format!(".{name}.{}.partial", uuid::Uuid::new_v4().simple()));
            let mut writer = FileArchiveWriter {
                file: Some(BufWriter::new(create_private(&temporary)?)),
                destination: directory.join(name),
                #[cfg(unix)]
                directory,
                temporary,
                committed: false,
            };
            writer.write_bytes(&first_line)?;
            Ok(Box::new(writer) as Box<dyn AuditArchiveWriter>)
        })
        .await
    }
}

struct FileArchiveWriter {
    file: Option<BufWriter<File>>,
    temporary: PathBuf,
    destination: PathBuf,
    #[cfg(unix)]
    directory: PathBuf,
    committed: bool,
}

impl FileArchiveWriter {
    fn write_bytes(&mut self, bytes: &[u8]) -> AuditResult<()> {
        self.file
            .as_mut()
            .ok_or_else(|| AuditError::StorageError("audit archive is closed".to_owned()))?
            .write_all(bytes)
            .map_err(|error| archive_error("write", &error))
    }

    /// Flush, sync and rename the archive into place, then sync its
    /// directory.
    fn commit_blocking(mut self) -> AuditResult<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| AuditError::StorageError("audit archive is closed".to_owned()))?
            .into_inner()
            .map_err(|error| archive_error("flush", error.error()))?;
        file.sync_all()
            .map_err(|error| archive_error("sync", &error))?;
        drop(file);
        // A retried prune of the same generation archives the same entries
        // under the same name. Windows does not replace on rename.
        #[cfg(windows)]
        if self.destination.exists() {
            std::fs::remove_file(&self.destination)
                .map_err(|error| archive_error("replace", &error))?;
        }
        astrid_core::platform_fs::rename_with_write_through(&self.temporary, &self.destination)
            .map_err(|error| archive_error("rename", &error))?;
        self.committed = true;
        #[cfg(unix)]
        sync_directory(&self.directory)?;
        Ok(())
    }
}

#[async_trait]
impl AuditArchiveWriter for FileArchiveWriter {
    async fn write(&mut self, entries: &[AuditEntry]) -> AuditResult<()> {
        let mut lines = Vec::new();
        for entry in entries {
            serde_json::to_writer(&mut lines, entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            lines.push(b'\n');
        }
        let mut file = self
            .file
            .take()
            .ok_or_else(|| AuditError::StorageError("audit archive is closed".to_owned()))?;
        let (file, written) = astrid_runtime::spawn_blocking(move || {
            let written = file.write_all(&lines);
            (file, written)
        })
        .await
        .map_err(|error| archive_error("write task", &error))?;
        self.file = Some(file);
        written.map_err(|error| archive_error("write", &error))
    }

    async fn commit(self: Box<Self>) -> AuditResult<()> {
        let writer = *self;
        blocking(move || writer.commit_blocking()).await
    }
}

impl Drop for FileArchiveWriter {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.temporary);
        }
    }
}

/// Run file work on the blocking thread pool.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> AuditResult<T> + Send + 'static,
) -> AuditResult<T> {
    astrid_runtime::spawn_blocking(work)
        .await
        .map_err(|error| archive_error("task", &error))?
}

fn create_private(path: &Path) -> AuditResult<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| archive_error("create", &error))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> AuditResult<()> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| archive_error("sync directory", &error))
}

fn archive_error(step: &str, error: &dyn std::fmt::Display) -> AuditError {
    AuditError::StorageError(format!("audit archive {step} failed: {error}"))
}

#[cfg(test)]
#[path = "audit_retention_tests.rs"]
mod tests;
