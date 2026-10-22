//! Reject circular publication waits while keeping unrelated lanes independent.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{PrincipalKey, RuntimeId};

pub(super) type ConsumerKey = (RuntimeId, PrincipalKey);
tokio::task_local! {
    /// Actual executing queue, including the shared fallback. It must not be
    /// reconstructed from a principal that may have acquired a new queue since
    /// this invocation began.
    pub(super) static ACTIVE_CONSUMER: ConsumerKey;
}
type Edges = HashMap<(ConsumerKey, ConsumerKey), usize>;

#[derive(Clone, Default)]
pub(super) struct WaitGraph(Arc<parking_lot::Mutex<Edges>>);

pub(super) struct WaitGuard {
    graph: WaitGraph,
    edge: (ConsumerKey, ConsumerKey),
}

impl WaitGraph {
    pub(super) fn enter(&self, source: ConsumerKey, target: ConsumerKey) -> Option<WaitGuard> {
        let mut edges = self.0.lock();
        let mut pending = vec![target.clone()];
        let mut seen = HashSet::new();
        while let Some(node) = pending.pop() {
            if node == source {
                return None;
            }
            if !seen.insert(node.clone()) {
                continue;
            }
            pending.extend(
                edges
                    .keys()
                    .filter(|(from, _)| from == &node)
                    .map(|(_, to)| to.clone()),
            );
        }
        let edge = (source, target);
        *edges.entry(edge.clone()).or_default() += 1;
        Some(WaitGuard {
            graph: self.clone(),
            edge,
        })
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        let mut edges = self.graph.0.lock();
        if let Some(count) = edges.get_mut(&self.edge) {
            *count -= 1;
            if *count == 0 {
                edges.remove(&self.edge);
            }
        }
    }
}
