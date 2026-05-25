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
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.get(&key).await
        })
        .map_err(|e| store_err("kv_get", e))
    }

    fn kv_set(&mut self, key: String, value: Vec<u8>) -> Result<(), ErrorCode> {
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.set(&key, value).await
        })
        .map_err(|e| store_err("kv_set", e))
    }

    fn kv_delete(&mut self, key: String) -> Result<(), ErrorCode> {
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.delete(&key).await
        })
        .map(|_| ())
        .map_err(|e| store_err("kv_delete", e))
    }

    fn kv_list_keys(&mut self, prefix: String) -> Result<Vec<String>, ErrorCode> {
        let kv = self.effective_kv().clone();
        let keys = util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.list_keys_with_prefix(&prefix).await
        })
        .map_err(|e| store_err("kv_list_keys", e))?;
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
        let kv = self.effective_kv().clone();
        let mut keys = util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.list_keys_with_prefix(&prefix).await
        })
        .map_err(|e| store_err("kv_list_keys_page", e))?;
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
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.clear_prefix(&prefix).await
        })
        .map_err(|e| store_err("kv_clear_prefix", e))
    }

    fn kv_cas(
        &mut self,
        key: String,
        expected: Option<Vec<u8>>,
        new: Vec<u8>,
    ) -> Result<bool, ErrorCode> {
        // Atomic compare-and-swap is delegated to the storage layer.
        // `MemoryKvStore` serializes the read+conditional-write under a
        // single write lock; `SurrealKvStore` issues one MVCC
        // transaction and treats commit conflicts as `Ok(false)` so a
        // concurrent capsule's commit invalidates this caller's
        // `expected` rather than overwriting the new value.
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            kv.compare_and_swap(&key, expected.as_deref(), new)
                .await
                .map_err(|e| store_err("kv_cas", e))
        })
    }
}
