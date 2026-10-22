//! Immutable verified code sharing without retired compilation tombstones.

use super::{
    EpochTickerGuard, HostState, build_wasmtime_engine, configure_kernel_linker, spawn_epoch_ticker,
};
use crate::error::{CapsuleError, CapsuleResult};
use std::sync::Arc;
use wasmtime::component::{Component, Linker};

pub(super) struct CompiledWasmArtifact {
    pub(super) engine: wasmtime::Engine,
    pub(super) instance_pre: wasmtime::component::InstancePre<HostState>,
    _epoch_ticker: EpochTickerGuard,
    _registration: Registration,
}

/// Identity of the wasmtime engine configuration and linked host ABI that
/// compiled capsule code is built for. Part of the compiled-code cache key,
/// and recorded as the engine profile of loaded capsules.
pub const COMPILED_ENGINE_ABI: &str = "astrid-wasmtime48-component-abi-v1";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CompiledArtifactKey(String);

impl CompiledArtifactKey {
    fn new(verified_hash: &str) -> Self {
        Self(format!("{COMPILED_ENGINE_ABI}:{verified_hash}"))
    }
}

/// Deduplicates immutable verified compiled code across authority-scoped
/// runtimes. It never stores a mutable `Store`, `Instance`, guest memory,
/// resource table, run task, or principal host state.
#[derive(Clone, Default)]
pub struct CompiledWasmCache {
    entries: Arc<std::sync::Mutex<Entries>>,
}

impl CompiledWasmCache {
    pub(super) fn compile(
        &self,
        verified_hash: &str,
        wasm_bytes: &[u8],
    ) -> CapsuleResult<Arc<CompiledWasmArtifact>> {
        // This domain is part of the cache identity. Bump it whenever the
        // engine configuration or linked host ABI changes incompatibly.
        let key = CompiledArtifactKey::new(verified_hash);
        self.compile_with_key(key, wasm_bytes)
    }

    fn compile_with_key(
        &self,
        key: CompiledArtifactKey,
        wasm_bytes: &[u8],
    ) -> CapsuleResult<Arc<CompiledWasmArtifact>> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(compiled) = entries.get(&key).and_then(std::sync::Weak::upgrade) {
            return Ok(compiled);
        }

        let engine = build_wasmtime_engine()?;
        let mut linker: Linker<HostState> = Linker::new(&engine);
        configure_kernel_linker(&mut linker).map_err(|error| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "Failed to add Astrid host to linker: {error}"
            ))
        })?;
        let component = Component::from_binary(&engine, wasm_bytes).map_err(|error| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "Failed to compile WASM component: {error}"
            ))
        })?;
        let instance_pre = linker.instantiate_pre(&component).map_err(|error| {
            CapsuleError::UnsupportedEntryPoint(format!(
                "Failed to pre-instantiate WASM component: {error}"
            ))
        })?;
        let artifact = Arc::new_cyclic(|identity| CompiledWasmArtifact {
            _epoch_ticker: spawn_epoch_ticker(&engine),
            engine,
            instance_pre,
            _registration: Registration {
                cache: Arc::downgrade(&self.entries),
                key: key.clone(),
                artifact: identity.clone(),
            },
        });
        entries.insert(key, Arc::downgrade(&artifact));
        Ok(artifact)
    }
}

type Entries =
    std::collections::HashMap<CompiledArtifactKey, std::sync::Weak<CompiledWasmArtifact>>;

/// Remove exactly this compilation generation after its last runtime releases
/// it. A concurrent recompile may already have replaced the weak index entry.
struct Registration {
    cache: std::sync::Weak<std::sync::Mutex<Entries>>,
    key: CompiledArtifactKey,
    artifact: std::sync::Weak<CompiledWasmArtifact>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let Some(cache) = self.cache.upgrade() else {
            return;
        };
        let mut entries = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries
            .get(&self.key)
            .is_some_and(|current| current.ptr_eq(&self.artifact))
        {
            entries.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests;
