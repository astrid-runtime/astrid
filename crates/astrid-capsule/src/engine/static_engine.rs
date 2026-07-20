use std::path::PathBuf;

use async_trait::async_trait;

use super::ExecutionEngine;
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::CapsuleManifest;

/// The simplest engine. Handles universal, non-executable data injected into
/// the OS memory (e.g., context files and declarative commands).
///
/// Every CompositeCapsule contains a `StaticEngine` by default.
pub(crate) struct StaticEngine {
    _manifest: CapsuleManifest,
    _capsule_dir: PathBuf,
}

impl StaticEngine {
    /// Create a new StaticEngine from a capsule manifest.
    #[must_use]
    pub(crate) fn new(manifest: CapsuleManifest, capsule_dir: PathBuf) -> Self {
        Self {
            _manifest: manifest,
            _capsule_dir: capsule_dir,
        }
    }
}

#[async_trait]
impl ExecutionEngine for StaticEngine {
    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        // TODO: Read `self.manifest.context_files` from `self.capsule_dir` and
        // publish them to the OS Event Bus or another user-space consumer.

        // For now, loading static files is instantaneous and infallible.
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        // Purge the static context from OS memory.
        Ok(())
    }
}
