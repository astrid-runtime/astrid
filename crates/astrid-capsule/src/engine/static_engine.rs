use async_trait::async_trait;

use super::ExecutionEngine;
use crate::context::CapsuleContext;
use crate::error::CapsuleResult;

/// The simplest engine. Handles universal, non-executable data injected into
/// the OS memory (e.g., context files and declarative commands).
///
/// Every CompositeCapsule contains a `StaticEngine` by default.
pub(crate) struct StaticEngine;

#[async_trait]
impl ExecutionEngine for StaticEngine {
    async fn load(&mut self, _ctx: &CapsuleContext) -> CapsuleResult<()> {
        // Static context publication is not implemented yet; this engine
        // retains no manifest or path while its lifecycle remains a no-op.
        // For now, loading static files is instantaneous and infallible.
        Ok(())
    }

    async fn unload(&mut self) -> CapsuleResult<()> {
        // Purge the static context from OS memory.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_engine_retains_no_per_capsule_payload() {
        assert_eq!(std::mem::size_of::<StaticEngine>(), 0);
    }
}
