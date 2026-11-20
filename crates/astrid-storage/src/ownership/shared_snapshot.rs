//! One decoded graph per store lineage; storage and validation remain authoritative.

use std::sync::Arc;

use parking_lot::Mutex;

use super::{GRAPH_KEY, OwnershipError, OwnershipSnapshot, OwnershipStore};

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq)]
enum StoredGraph {
    Missing,
    Present(Vec<u8>),
}

#[derive(Debug)]
struct DecodedSnapshot {
    source: StoredGraph,
    graph: Arc<OwnershipSnapshot>,
}

#[derive(Debug, Default)]
pub(super) struct SharedSnapshots {
    current: Mutex<Option<Arc<DecodedSnapshot>>>,
}

impl OwnershipStore {
    /// Fetch current storage and share its decoded, fully validated graph.
    ///
    /// Every call reads storage and validates against the live principal
    /// directory. Exact stored bytes identify the one retained decoded graph;
    /// no hash collision can substitute an older graph. Only decoding is reused. Mutations independently read,
    /// decode and validate their CAS input through the owned path.
    ///
    /// # Errors
    /// Fails closed on storage errors, malformed bytes, or broken invariants.
    pub async fn load_shared(&self) -> Result<Arc<OwnershipSnapshot>, OwnershipError> {
        let raw = self.storage.get(GRAPH_KEY).await?;
        let source = raw.map_or(StoredGraph::Missing, StoredGraph::Present);
        let cached = self.snapshots.current.lock().clone();
        if let Some(entry) = cached.filter(|entry| entry.source == source) {
            drop(source);
            entry.graph.validate(&self.principals)?;
            return Ok(Arc::clone(&entry.graph));
        }
        // Never hold the slot lock over I/O, decoding, validation or graph drop.
        // Concurrent cold readers may decode independently, as on the owned path.
        let graph = Arc::new(self.decode(match &source {
            StoredGraph::Missing => None,
            StoredGraph::Present(bytes) => Some(bytes),
        })?);
        let entry = Arc::new(DecodedSnapshot {
            source,
            graph: Arc::clone(&graph),
        });
        let previous = self.snapshots.current.lock().replace(entry);
        drop(previous);
        Ok(graph)
    }
}
