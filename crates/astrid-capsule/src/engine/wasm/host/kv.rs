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
        // ScopedKvStore doesn't yet expose an atomic CAS primitive — emulate
        // by get-then-set under the runtime's single-threaded executor. This
        // is NOT race-free across capsules; the WIT contract requires real
        // atomicity, so this is a placeholder until storage exposes a CAS.
        // TODO(astrid-storage): plumb through a true atomic CAS.
        let kv = self.effective_kv().clone();
        util::bounded_block_on(&self.runtime_handle, &self.host_semaphore, async {
            let current = kv.get(&key).await.map_err(|e| store_err("kv_cas/get", e))?;
            if current.as_deref() != expected.as_deref() {
                return Ok(false);
            }
            kv.set(&key, new)
                .await
                .map_err(|e| store_err("kv_cas/set", e))?;
            Ok(true)
        })
    }
}
