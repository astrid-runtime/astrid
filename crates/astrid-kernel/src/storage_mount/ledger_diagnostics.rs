//! Fixed cleanup operation evidence without printing paths or guest input.
use astrid_core::storage_provider::StorageMountId;
use std::io;

#[derive(Clone, Copy, Debug)]
pub(super) enum LedgerOperation {
    EnsureDirectory,
    AtomicWrite,
    RemoveFile,
}

pub(super) fn cleanup_ledger_io_error(
    mount_id: Option<StorageMountId>,
    operation: LedgerOperation,
    error: io::Error,
) -> io::Error {
    #[cfg(test)]
    eprintln!(
        "cleanup ledger IO: operation={operation:?} mount_id={mount_id:?} kind={:?} os_error={:?}",
        error.kind(),
        native_error_code(&error)
    );
    #[cfg(not(test))]
    let _ = (mount_id, operation);
    // Return the original error: formatting it into Other destroys native cause.
    error
}

#[cfg(test)]
fn native_error_code(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    if let Some(io) = error.downcast_ref::<io::Error>() {
        if let Some(code) = io.raw_os_error() {
            return Some(code);
        }
        if let Some(inner) = io.get_ref()
            && let Some(code) = native_error_code(inner)
        {
            return Some(code);
        }
    }
    error.source().and_then(native_error_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ledger_diagnostic_preserves_native_kind_and_code() {
        let original = io::Error::from_raw_os_error(2);
        let expected_kind = original.kind();
        let error = cleanup_ledger_io_error(None, LedgerOperation::AtomicWrite, original);
        assert_eq!(error.kind(), expected_kind);
        assert_eq!(error.raw_os_error(), Some(2));
    }
    #[test]
    fn ledger_diagnostic_traverses_nested_io_sources() {
        let original = io::Error::from_raw_os_error(5);
        let kind = original.kind();
        let wrapped = io::Error::new(kind, original);
        let error = cleanup_ledger_io_error(None, LedgerOperation::EnsureDirectory, wrapped);
        assert_eq!(error.kind(), kind);
        assert_eq!(native_error_code(&error), Some(5));
    }
}
