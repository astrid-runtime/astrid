//! Principal-scoped MCP tool snapshots.
//!
//! The kernel owns the authoritative list surface.  A snapshot is built from
//! the live registry view intersected with the authenticated principal's
//! capsule grants, then replaced as one immutable value with a private
//! per-principal epoch.  The epoch is deliberately separate from the global
//! IPC delivery sequence: transport ordering is not authority.

use std::collections::HashMap;
use std::sync::Arc;

use astrid_capsule::ToolDescriptor;
use astrid_core::PrincipalId;

/// Private epoch for one principal's MCP namespace.
///
/// This is not [`astrid_types::ipc::IpcMessage::seq`], which orders events on
/// the global bus, and it is not an `AuthorityEpoch`, which represents a
/// different policy domain.  The value advances only when this principal's
/// complete MCP snapshot is atomically replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct McpNamespaceEpoch(u64);

impl McpNamespaceEpoch {
    /// Return the wire value.  The newtype stays crate-private while the wire
    /// representation remains a bounded JSON integer for the CLI consumer.
    #[must_use]
    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    /// Construct an epoch received from a trusted in-tree snapshot store.
    #[must_use]
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// One complete principal-visible MCP surface.
#[derive(Debug, Clone)]
pub(crate) struct McpToolSnapshot {
    /// Epoch that names this exact immutable surface.
    pub(crate) epoch: McpNamespaceEpoch,
    /// Descriptors captured from loaded capsule runtimes.
    pub(crate) tools: Vec<ToolDescriptor>,
}

/// In-memory snapshot coordinator.  It is guarded by the kernel's async mutex
/// so replacing an epoch and its descriptors is one atomic publication edge.
#[derive(Debug, Default)]
pub(crate) struct McpSnapshotStore {
    snapshots: HashMap<PrincipalId, Arc<McpToolSnapshot>>,
    next_epochs: HashMap<PrincipalId, McpNamespaceEpoch>,
}

impl McpSnapshotStore {
    /// Replace a principal's complete surface and advance its private epoch.
    ///
    /// Epoch exhaustion is fail-closed: no replacement is published because a
    /// wrapped value could make a stale snapshot appear current.
    pub(crate) fn replace(
        &mut self,
        principal: PrincipalId,
        tools: Vec<ToolDescriptor>,
    ) -> Option<Arc<McpToolSnapshot>> {
        let previous = self
            .next_epochs
            .get(&principal)
            .copied()
            .unwrap_or(McpNamespaceEpoch::new(0));
        let epoch = McpNamespaceEpoch::new(previous.get().checked_add(1)?);
        let snapshot = Arc::new(McpToolSnapshot { epoch, tools });
        self.next_epochs.insert(principal.clone(), epoch);
        self.snapshots.insert(principal, Arc::clone(&snapshot));
        Some(snapshot)
    }

    /// Read the last successfully produced snapshot for `principal`.
    #[must_use]
    pub(crate) fn get(&self, principal: &PrincipalId) -> Option<Arc<McpToolSnapshot>> {
        self.snapshots.get(principal).cloned()
    }

    /// Return every principal that has had a snapshot epoch allocated.
    ///
    /// Retaining this small index lets a global lifecycle publication emit an
    /// empty replacement for a principal whose last visible capsule was just
    /// unloaded.  The caller clones the keys while holding the store lock and
    /// performs the potentially blocking refreshes afterwards.
    pub(crate) fn principals(&self) -> impl Iterator<Item = PrincipalId> + '_ {
        self.next_epochs.keys().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid principal")
    }

    #[test]
    fn epochs_are_private_and_monotonic_per_principal() {
        let mut store = McpSnapshotStore::default();
        let alice = principal("alice");
        let bob = principal("bob");

        let a1 = store.replace(alice.clone(), Vec::new()).expect("epoch");
        let b1 = store.replace(bob.clone(), Vec::new()).expect("epoch");
        let a2 = store.replace(alice.clone(), Vec::new()).expect("epoch");

        assert_eq!(a1.epoch.get(), 1);
        assert_eq!(b1.epoch.get(), 1);
        assert_eq!(a2.epoch.get(), 2);
        assert_eq!(store.get(&alice).expect("alice snapshot").epoch, a2.epoch);
        assert_eq!(store.get(&bob).expect("bob snapshot").epoch, b1.epoch);
    }

    #[test]
    fn lifecycle_replacements_advance_without_cross_principal_aliasing() {
        let mut store = McpSnapshotStore::default();
        let alice = principal("alice");
        let bob = principal("bob");
        let lifecycle = ["load", "grant-on-use", "revoke", "replacement", "unload"];

        for (index, _operation) in lifecycle.iter().enumerate() {
            let snapshot = store
                .replace(
                    alice.clone(),
                    vec![ToolDescriptor {
                        name: format!("alice-{index}"),
                        description: String::new(),
                        input_schema: serde_json::json!({}),
                    }],
                )
                .expect("epoch must advance");
            assert_eq!(snapshot.epoch.get(), (index + 1) as u64);
        }
        let bob_snapshot = store
            .replace(
                bob.clone(),
                vec![ToolDescriptor {
                    name: "bob-only".to_string(),
                    description: String::new(),
                    input_schema: serde_json::json!({}),
                }],
            )
            .expect("bob epoch");
        assert_eq!(bob_snapshot.epoch.get(), 1);
        assert_eq!(
            store
                .get(&alice)
                .expect("alice snapshot")
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alice-4"]
        );
        assert_eq!(
            store
                .get(&bob)
                .expect("bob snapshot")
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            vec!["bob-only"]
        );
    }

    #[test]
    fn epoch_exhaustion_does_not_publish_wrapped_snapshot() {
        let mut store = McpSnapshotStore::default();
        let principal = principal("alice");
        store
            .next_epochs
            .insert(principal.clone(), McpNamespaceEpoch::new(u64::MAX));
        assert!(store.replace(principal.clone(), Vec::new()).is_none());
        assert!(store.get(&principal).is_none());
    }
}
