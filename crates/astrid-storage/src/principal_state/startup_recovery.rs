//! Read-only authentication before an interrupted host projection can resume.

use super::{AstridHome, NativePrincipalContentStore, StateOwner};
use super::{runtime_tree, runtime_tree_active as active};
use crate::content::ContentName;
use crate::error::{StorageError, StorageResult};

/// Borrowed read-only content covered by a complete same-root RETIRING receipt.
///
/// This view cannot mutate a catalogue or provision identities. Policy remains
/// with the caller: each read must name an inventoried object and state its
/// allocation bound. The exclusive recovered volume owner outlives the callback.
pub struct RuntimeProjectionRecovery<'a> {
    content: &'a NativePrincipalContentStore,
    receipt: active::ActiveProjectionReceipt,
}

impl RuntimeProjectionRecovery<'_> {
    /// Describe one immutable object covered by the recovery inventory.
    ///
    /// # Errors
    /// Rejects changed identities/lengths or an invalid content descriptor.
    pub fn describe(
        &self,
        name: &ContentName,
    ) -> StorageResult<Option<crate::content::ContentDescriptor>> {
        self.open(name)
            .map(|reader| reader.map(|reader| reader.descriptor()))
    }

    /// Read one immutable inventoried object within the caller's allocation cap.
    ///
    /// # Errors
    /// Rejects changed identities/lengths, oversized values, or invalid content DAGs.
    pub fn read(&self, name: &ContentName, maximum_bytes: u64) -> StorageResult<Option<Vec<u8>>> {
        let Some(reader) = self.open(name)? else {
            return Ok(None);
        };
        if reader.descriptor().logical_bytes() > maximum_bytes {
            return Err(guard_error(format!(
                "recovery content {name} exceeds its allocation bound"
            )));
        }
        reader
            .read()
            .map(Some)
            .map_err(|error| guard_error(format!("read recovery content {name}: {error}")))
    }

    fn open(
        &self,
        name: &ContentName,
    ) -> StorageResult<
        Option<crate::content::PrincipalContentReadHandle<StateOwner, super::RuntimeEngine>>,
    > {
        let Some((expected_file, expected_bytes)) = self.receipt.inventory_object(name.as_str())?
        else {
            return Ok(None);
        };
        let reader = self
            .content
            .open_read(&StateOwner::System, name)
            .map_err(|error| guard_error(format!("open recovery content {name}: {error}")))?
            .ok_or_else(|| guard_error(format!("recovery content {name} disappeared")))?;
        let descriptor = reader.descriptor();
        if descriptor.file() != expected_file || descriptor.logical_bytes() != expected_bytes {
            return Err(guard_error(format!(
                "recovery content {name} does not match RETIRING inventory"
            )));
        }
        Ok(Some(reader))
    }
}

pub(super) fn authenticate<'a>(
    home: &AstridHome,
    content: &'a NativePrincipalContentStore,
) -> StorageResult<RuntimeProjectionRecovery<'a>> {
    let receipt = active::read_from_content(home, content)?
        .ok_or_else(|| guard_error("interrupted projection has no recovery receipt"))?;
    if receipt.phase() != active::ReceiptPhase::Retiring {
        return Err(guard_error(
            "interrupted projection requires RETIRING authority",
        ));
    }
    // Ordinary historical ACTIVE receipts may cover a materialized subset.
    // Startup recovery instead requires every materializable durable entry.
    for entry in content
        .list(&StateOwner::System)
        .map_err(|error| guard_error(format!("list recovery inventory: {error}")))?
    {
        let name = entry.name();
        if runtime_tree::is_excluded(name.as_str())
            || runtime_tree::is_retired_legacy_projection(home, name.as_str())
        {
            continue;
        }
        if receipt.inventory_object(name.as_str())? != Some((entry.file(), entry.logical_bytes())) {
            return Err(guard_error(format!(
                "RETIRING inventory does not cover {name}"
            )));
        }
    }
    Ok(RuntimeProjectionRecovery { content, receipt })
}

pub(super) fn guard_error(message: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("runtime projection recovery: {message}"))
}

#[cfg(all(test, unix))]
mod tests;
