//! `astrid:kv@1.0.0` host implementation.
//!
//! Per-(principal, capsule) namespaced key-value store. Reads and writes
//! are routed to the invoking principal's `ScopedKvStore`, falling back
//! to the capsule owner's store when no invocation is in scope.

use crate::engine::wasm::bindings::astrid::kv::host::{self as kv, ErrorCode, KeyPage};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;

/// Map an `astrid-storage` error string into the typed `kv::ErrorCode`.
///
/// The store doesn't yet expose a structured error type, so we
/// best-effort classify by substring and fall through to `unknown`.
fn store_err(op: &str, msg: impl std::fmt::Display) -> ErrorCode {
    let s = msg.to_string();
    if s.contains("invalid key") || s.contains("validation") {
        ErrorCode::InvalidKey
    } else if s.contains("quota") {
        ErrorCode::Quota
    } else if s.contains("too large") {
        ErrorCode::TooLarge
    } else {
        ErrorCode::Unknown(format!("{op}: {s}"))
    }
}

impl kv::Host for HostState {
    fn kv_get(&mut self, key: String) -> Result<Option<Vec<u8>>, ErrorCode> {
        self.with_kv_operation("kv_get", async |kv| kv.get(&key).await)
    }

    fn kv_set(&mut self, key: String, value: Vec<u8>) -> Result<(), ErrorCode> {
        self.with_kv_operation("kv_set", async |kv| kv.set(&key, value).await)
    }

    fn kv_delete(&mut self, key: String) -> Result<(), ErrorCode> {
        self.with_kv_operation("kv_delete", async |kv| kv.delete(&key).await)
            .map(|_| ())
    }

    fn kv_list_keys(&mut self, prefix: String) -> Result<Vec<String>, ErrorCode> {
        let keys = self.with_kv_operation("kv_list_keys", async |kv| {
            kv.list_keys_with_prefix(&prefix).await
        })?;
        if keys.len() > 1024 {
            return Err(ErrorCode::TooLarge);
        }
        Ok(keys)
    }

    fn kv_list_keys_page(
        &mut self,
        prefix: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<KeyPage, ErrorCode> {
        // Underlying ScopedKvStore doesn't expose paging yet — emulate by
        // listing-with-prefix then slicing. Acceptable for 1.0 because
        // the store backend has a 1024-key cap; revisit if a capsule
        // legitimately needs unbounded paging.
        let mut keys = self.with_kv_operation("kv_list_keys_page", async |kv| {
            kv.list_keys_with_prefix(&prefix).await
        })?;
        keys.sort();
        let limit = if limit == 0 { 1024 } else { limit.min(1024) } as usize;
        let start = cursor
            .as_deref()
            .map(|c| keys.partition_point(|k| k.as_str() <= c))
            .unwrap_or(0);
        let end = (start + limit).min(keys.len());
        let page_keys = keys[start..end].to_vec();
        let next_cursor = if end < keys.len() {
            page_keys.last().cloned()
        } else {
            None
        };
        Ok(KeyPage {
            keys: page_keys,
            next_cursor,
        })
    }

    fn kv_clear_prefix(&mut self, prefix: String) -> Result<u64, ErrorCode> {
        self.with_kv_operation("kv_clear_prefix", async |kv| kv.clear_prefix(&prefix).await)
    }

    fn kv_cas(
        &mut self,
        key: String,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<(), ErrorCode> {
        // Atomic compare-and-swap is delegated to the storage layer. Every
        // `KvStore` implementation must make the comparison and mutation one
        // linearizable operation. A concurrent capsule's winning commit
        // invalidates this caller's `expected` rather than being overwritten.
        //
        // The storage layer reports mismatch via `Ok(false)`; the WIT
        // contract surfaces mismatch via `Err(ErrorCode::CasMismatch)`.
        // Translate at the boundary so capsule code can pattern-match
        // `Err(CasMismatch)` for the routine lost-race retry and use
        // `?` for everything else.
        let swapped = self.with_kv_operation("kv_cas", async |kv| {
            kv.compare_and_swap(&key, expected.as_deref(), new).await
        })?;
        if swapped {
            Ok(())
        } else {
            Err(ErrorCode::CasMismatch)
        }
    }
}

impl HostState {
    /// Hold lifecycle admission until the backend future returns. The
    /// callback receives the store selected for this invocation.
    fn with_kv_operation<T>(
        &self,
        name: &str,
        operation: impl AsyncFnOnce(&astrid_storage::ScopedKvStore) -> astrid_storage::StorageResult<T>,
    ) -> Result<T, ErrorCode> {
        let _guard = self.begin_host_operation().map_err(|()| {
            ErrorCode::Unknown("principal capsule view is retired or unauthorized".to_string())
        })?;
        util::bounded_block_on(&self.runtime_handle, &self.blocking_semaphore, async {
            // Admit after the host capacity wait and keep the registration
            // live across the backend future, including a blocking mutation.
            let _device = self
                .begin_device_operation()
                .map_err(|()| ErrorCode::Unknown("device registration unavailable".into()))?;
            operation(self.effective_kv())
                .await
                .map_err(|error| store_err(name, error))
        })
    }
}
