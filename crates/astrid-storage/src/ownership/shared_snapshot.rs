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

impl StoredGraph {
    fn matches(&self, raw: Option<&[u8]>) -> bool {
        match (self, raw) {
            (Self::Missing, None) => true,
            (Self::Present(cached), Some(current)) => cached == current,
            _ => false,
        }
    }
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

/// Identity of a read-cache entry observed during one fresh CAS attempt.
#[derive(Debug)]
pub(super) struct ReadCacheEntry(Arc<DecodedSnapshot>);

impl ReadCacheEntry {
    /// Select an obsolete entry before the encoded bytes move into CAS.
    /// Discard it only if that CAS commits successfully.
    pub(super) fn invalidated_by(self, encoded: &[u8]) -> Option<Self> {
        (!self.0.source.matches(Some(encoded))).then_some(self)
    }
}

impl SharedSnapshots {
    /// Never evict a newer entry published while the write was committing.
    pub(super) fn discard(&self, observed: ReadCacheEntry) {
        let retired = {
            let mut current = self.current.lock();
            if current
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry, &observed.0))
            {
                current.take()
            } else {
                None
            }
        };
        drop(retired);
        drop(observed);
    }
}

impl OwnershipStore {
    /// Reuse parsing only for the exact bytes fetched for this CAS attempt.
    /// Repeat full live validation before returning an owned, editable clone.
    pub(super) fn decode_mutation_input(
        &self,
        raw: Option<&[u8]>,
    ) -> Result<(OwnershipSnapshot, Option<ReadCacheEntry>), OwnershipError> {
        let cached = self.snapshots.current.lock().clone();
        let graph = if let Some(entry) = cached.as_ref().filter(|entry| entry.source.matches(raw)) {
            entry.graph.validate(&self.principals)?;
            (*entry.graph).clone()
        } else {
            self.decode(raw)?
        };
        Ok((graph, cached.map(ReadCacheEntry)))
    }

    /// Fetch current storage and share its decoded, fully validated graph.
    ///
    /// Every call reads storage and validates against the live principal
    /// directory. Exact stored bytes identify the one retained decoded graph;
    /// no hash collision can substitute an older graph. Only decoding is reused.
    /// Mutations independently read and fully
    /// validate the exact fetched CAS input before editing an owned graph.
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
