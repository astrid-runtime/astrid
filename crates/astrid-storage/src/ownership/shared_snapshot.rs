//! One decoded ownership graph, coupled to fresh bytes and directory identity.
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{GRAPH_KEY, OwnershipError, OwnershipSnapshot, OwnershipStore};
use crate::principal_directory::PrincipalDirectoryRevision;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredGraph {
    Missing,
    Present(blake3::Hash),
}

#[derive(Debug)]
struct ValidatedSnapshot {
    stored: StoredGraph,
    directory: PrincipalDirectoryRevision,
    graph: Arc<OwnershipSnapshot>,
}

#[derive(Debug, Default)]
pub(super) struct SharedSnapshots(Mutex<Option<ValidatedSnapshot>>);

impl OwnershipStore {
    /// Load the current validated graph without cloning its decoded allocations.
    ///
    /// Every call reads the current stored value. An immutable decoded graph
    /// is reused only for the same bytes and an unchanged principal directory.
    /// Directory changes require validation again. The store retains at most
    /// one snapshot; callers holding older snapshots do not confer authority
    /// over later mutations.
    ///
    /// # Errors
    ///
    /// Fails closed on storage, decoding or validation errors, including a
    /// directory change that invalidates otherwise unchanged graph bytes.
    pub async fn load_shared(&self) -> Result<Arc<OwnershipSnapshot>, OwnershipError> {
        // Admit before fetching bytes: concurrent readers must not each hold
        // a full raw graph while awaiting the same decoded allocation.
        let mut slot = self.snapshots.0.lock().await;
        let previous = slot.take();
        let raw = self.storage.get(GRAPH_KEY).await?;
        let stored = raw.as_deref().map_or(StoredGraph::Missing, |bytes| {
            StoredGraph::Present(blake3::hash(bytes))
        });
        let directory = self.principals.revision();
        let graph = if let Some(previous) = previous.filter(|entry| entry.stored == stored) {
            if previous.directory != directory {
                previous.graph.validate(&self.principals)?;
            }
            previous.graph
        } else {
            Arc::new(self.decode(raw.as_deref())?)
        };
        let directory = self.confirm_directory(&graph, directory).await?;
        *slot = Some(ValidatedSnapshot {
            stored,
            directory,
            graph: Arc::clone(&graph),
        });
        Ok(graph)
    }

    async fn confirm_directory(
        &self,
        graph: &OwnershipSnapshot,
        mut validated: PrincipalDirectoryRevision,
    ) -> Result<PrincipalDirectoryRevision, OwnershipError> {
        loop {
            let current = self.principals.revision();
            if current == validated {
                return Ok(validated);
            }
            // A cached graph cannot escape on a revision mismatch. Validate
            // under the new identity, then require a stable identity across
            // that walk. Yield under churn instead of monopolizing a worker.
            graph.validate(&self.principals)?;
            validated = current;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests;
