//! Principal-scoped MCP tool snapshots.
//!
//! The kernel owns the authoritative list surface.  A snapshot is built from
//! the live registry view intersected with the authenticated principal's
//! capsule grants, then replaced as one immutable value with a private
//! per-principal epoch.  The epoch is deliberately separate from the global
//! IPC delivery sequence: transport ordering is not authority.

use std::collections::{BTreeMap, HashMap};
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

/// Monotonic capture generation for one principal's in-flight refreshes.
///
/// A generation is reserved before any runtime handles or descriptors are
/// captured.  Publication checks that the reservation is still current, so a
/// delayed probe cannot replace a snapshot produced by a newer refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct McpSnapshotGeneration(u64);

impl McpSnapshotGeneration {
    #[must_use]
    const fn new(value: u64) -> Self {
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
    refresh_generations: HashMap<PrincipalId, McpSnapshotGeneration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpSnapshotPublishError {
    StaleGeneration,
    EpochExhausted,
}

impl McpSnapshotStore {
    /// Reserve the next capture generation for `principal`.
    fn begin_refresh(&mut self, principal: &PrincipalId) -> Option<McpSnapshotGeneration> {
        let previous = self
            .refresh_generations
            .get(principal)
            .copied()
            .unwrap_or(McpSnapshotGeneration::new(0));
        let generation = McpSnapshotGeneration::new(previous.0.checked_add(1)?);
        self.refresh_generations
            .insert(principal.clone(), generation);
        Some(generation)
    }

    /// Replace a principal's complete surface and advance its private epoch.
    ///
    /// Epoch exhaustion is fail-closed: no replacement is published because a
    /// wrapped value could make a stale snapshot appear current.
    fn replace(
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

    /// Publish only when `generation` is still the latest capture reservation.
    ///
    /// A stale completion is rejected without allocating an epoch or changing
    /// the current snapshot.
    fn replace_if_current(
        &mut self,
        principal: PrincipalId,
        generation: McpSnapshotGeneration,
        tools: Vec<ToolDescriptor>,
    ) -> Result<Arc<McpToolSnapshot>, McpSnapshotPublishError> {
        if self.refresh_generations.get(&principal).copied() != Some(generation) {
            return Err(McpSnapshotPublishError::StaleGeneration);
        }
        self.replace(principal, tools)
            .ok_or(McpSnapshotPublishError::EpochExhausted)
    }

    /// Read the last successfully produced snapshot for `principal`.
    #[must_use]
    fn get(&self, principal: &PrincipalId) -> Option<Arc<McpToolSnapshot>> {
        self.snapshots.get(principal).cloned()
    }

    /// Return every principal that has had a snapshot epoch allocated.
    ///
    /// Retaining this small index lets a global lifecycle publication emit an
    /// empty replacement for a principal whose last visible capsule was just
    /// unloaded.  The caller clones the keys while holding the store lock and
    /// performs the potentially blocking refreshes afterwards.
    fn principals(&self) -> impl Iterator<Item = PrincipalId> + '_ {
        self.next_epochs.keys().cloned()
    }
}

impl crate::Kernel {
    async fn begin_mcp_snapshot_refresh(
        &self,
        principal: &PrincipalId,
    ) -> anyhow::Result<McpSnapshotGeneration> {
        self.mcp_snapshots
            .lock()
            .await
            .begin_refresh(principal)
            .ok_or_else(|| {
                anyhow::anyhow!("MCP snapshot refresh generation exhausted for '{principal}'")
            })
    }

    async fn refresh_mcp_snapshot_with_generation(
        &self,
        principal: &PrincipalId,
        runtimes: Vec<(
            astrid_capsule::registry::RuntimeId,
            Arc<dyn astrid_capsule::capsule::Capsule>,
        )>,
        generation: McpSnapshotGeneration,
    ) -> anyhow::Result<McpNamespaceEpoch> {
        let resolver = astrid_capsule::CapsuleAccessResolver::new(
            Arc::clone(&self.profile_cache),
            Arc::clone(&self.groups),
        );
        let anonymous = *principal == PrincipalId::anonymous();
        if !anonymous {
            let profile = self.profile_cache.resolve(principal).map_err(|error| {
                anyhow::anyhow!(
                    "principal '{principal}' has no resolvable enabled profile: {error}"
                )
            })?;
            if !profile.enabled {
                anyhow::bail!("principal '{principal}' has no resolvable enabled profile");
            }
        }

        let mut tools = Vec::new();
        for (runtime_id, capsule) in runtimes {
            let capsule_id = runtime_id.key().capsule_id();
            if !resolver.is_capsule_allowed(Some(principal.as_str()), capsule_id) {
                continue;
            }
            let Some(mut described) =
                astrid_capsule::describe_loaded_capsule_status_for(capsule.as_ref(), principal)
                    .await?
            else {
                anyhow::bail!(
                    "tool surface for capsule '{capsule_id}' is unavailable for principal '{principal}'"
                );
            };
            tools.append(&mut described);
        }

        // Keep the wire surface deterministic across registry map iteration and
        // capsule reloads. Tool names are the MCP dispatch key, so ambiguity is
        // a closed failure rather than an arbitrary first-descriptor choice.
        tools.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.description.cmp(&right.description))
                .then_with(|| {
                    left.input_schema
                        .to_string()
                        .cmp(&right.input_schema.to_string())
                })
        });
        for pair in tools.windows(2) {
            if pair[0].name == pair[1].name {
                anyhow::bail!(
                    "duplicate MCP tool name '{}' across allowed capsules for principal '{principal}'",
                    pair[0].name
                );
            }
        }

        let mut store = self.mcp_snapshots.lock().await;
        let snapshot = match store.replace_if_current(principal.clone(), generation, tools) {
            Ok(snapshot) => snapshot,
            Err(McpSnapshotPublishError::StaleGeneration) => {
                anyhow::bail!("MCP snapshot refresh superseded for principal '{principal}'")
            },
            Err(McpSnapshotPublishError::EpochExhausted) => {
                anyhow::bail!("MCP namespace epoch exhausted for '{principal}'")
            },
        };
        Ok(snapshot.epoch)
    }

    /// Build and atomically publish one principal's complete MCP tool surface.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) async fn refresh_mcp_snapshot(
        &self,
        principal: &PrincipalId,
    ) -> anyhow::Result<McpNamespaceEpoch> {
        let generation = self.begin_mcp_snapshot_refresh(principal).await?;
        let runtimes = if *principal == PrincipalId::anonymous() {
            Vec::new()
        } else {
            let registry = self.capsules.read().await;
            registry.cloned_runtimes_for(principal)
        };
        self.refresh_mcp_snapshot_with_generation(principal, runtimes, generation)
            .await
    }

    /// Return the latest principal snapshot, producing one on first request.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) async fn mcp_snapshot_for(
        &self,
        principal: &PrincipalId,
    ) -> anyhow::Result<Arc<McpToolSnapshot>> {
        if let Some(snapshot) = self.mcp_snapshots.lock().await.get(principal) {
            return Ok(snapshot);
        }
        self.refresh_mcp_snapshot(principal).await?;
        self.mcp_snapshots
            .lock()
            .await
            .get(principal)
            .ok_or_else(|| anyhow::anyhow!("MCP snapshot disappeared for '{principal}'"))
    }

    /// Answer the existing MCP `tools/list` request topic from the kernel's
    /// authenticated snapshot store.
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn spawn_mcp_tools_list_responder(
        kernel: Arc<Self>,
    ) -> astrid_runtime::JoinHandle<()> {
        let mut receiver = kernel
            .event_bus
            .subscribe_topic_as(crate::MCP_TOOLS_LIST_TOPIC, "mcp_snapshot");
        astrid_runtime::spawn(async move {
            while let Some(event) = receiver.recv().await {
                let astrid_events::AstridEvent::Ipc { message, .. } = &*event else {
                    continue;
                };
                let astrid_events::ipc::IpcPayload::RawJson(body) = &message.payload else {
                    continue;
                };
                // Native uplink ingress rebuilds client messages with a nil
                // source id after authenticating the socket. A capsule publish
                // carries its own runtime UUID and cannot read another
                // principal's snapshot through the shared request topic.
                if message.source_id != uuid::Uuid::nil() {
                    continue;
                }
                let Some(req_id) = body.get("req_id").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if req_id.is_empty() || req_id.contains('.') {
                    continue;
                }
                let Some(raw_principal) = message.principal.as_deref() else {
                    continue;
                };
                let Ok(principal) = PrincipalId::new(raw_principal) else {
                    continue;
                };
                let response = match kernel.mcp_snapshot_for(&principal).await {
                    Ok(snapshot) => serde_json::json!({
                        "kind": "tools.list",
                        "req_id": req_id,
                        "epoch": snapshot.epoch.get(),
                        "tools": snapshot.tools.iter().map(|tool| serde_json::json!({
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.input_schema,
                        })).collect::<Vec<_>>(),
                    }),
                    Err(error) => serde_json::json!({
                        "kind": "tools.list",
                        "req_id": req_id,
                        "error": error.to_string(),
                    }),
                };
                crate::kernel_router::publish_response_value(
                    &kernel,
                    astrid_events::ipc::Topic::kernel_response(req_id),
                    principal.as_str(),
                    message.device_key_id.as_deref(),
                    response,
                );
            }
        })
    }

    /// Publish `astrid.v1.capsules_loaded` for every principal with a live or
    /// previously-published view.
    pub(crate) async fn publish_capsules_loaded(&self) {
        let mut principals = {
            let registry = self.capsules.read().await;
            registry
                .cloned_values_with_principal()
                .into_iter()
                .map(|(principal, _)| principal)
                .collect::<std::collections::HashSet<_>>()
        };
        principals.extend(self.mcp_snapshots.lock().await.principals());
        if principals.is_empty() {
            principals.insert(PrincipalId::default());
        }
        let mut principals: Vec<_> = principals.into_iter().collect();
        principals.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for principal in principals {
            self.publish_capsules_loaded_for(&principal).await;
        }
    }

    /// Publish the current capsule inventory for exactly one principal view.
    pub(crate) async fn publish_capsules_loaded_for(&self, principal: &PrincipalId) {
        let generation = match self.begin_mcp_snapshot_refresh(principal).await {
            Ok(generation) => Some(generation),
            Err(error) => {
                tracing::warn!(%principal, %error, "MCP snapshot refresh generation failed");
                None
            },
        };
        let runtimes = if *principal == PrincipalId::anonymous() {
            Vec::new()
        } else {
            let reg = self.capsules.read().await;
            reg.cloned_runtimes_for(principal)
        };
        let capsules: Vec<(PrincipalId, Arc<dyn astrid_capsule::capsule::Capsule>)> = runtimes
            .iter()
            .map(|(_, capsule)| (principal.clone(), Arc::clone(capsule)))
            .collect();
        let epoch = match generation {
            Some(generation) => match self
                .refresh_mcp_snapshot_with_generation(principal, runtimes, generation)
                .await
            {
                Ok(epoch) => Some(epoch),
                Err(error) => {
                    tracing::warn!(%principal, %error, "MCP snapshot refresh failed; publishing non-authoritative hint");
                    // Keep the legacy inventory signal useful to diagnostics
                    // even when policy or descriptor inputs are unavailable.
                    for (entry_principal, capsule) in &capsules {
                        let _ = astrid_capsule::describe_loaded_capsule_status_for(
                            capsule.as_ref(),
                            entry_principal,
                        )
                        .await;
                    }
                    None
                },
            },
            None => None,
        };

        self.publish_capsules_loaded_snapshot(&capsules, principal, epoch);
    }

    fn publish_capsules_loaded_snapshot(
        &self,
        capsules: &[(PrincipalId, Arc<dyn astrid_capsule::capsule::Capsule>)],
        empty_principal: &PrincipalId,
        epoch: Option<McpNamespaceEpoch>,
    ) {
        let mut by_principal =
            BTreeMap::<String, Vec<(String, String, Option<serde_json::Value>)>>::new();
        for (principal, capsule) in capsules {
            let name = capsule.id().to_string();
            let mut meta = capsule.source_dir().and_then(|source_dir| {
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                let meta = crate::capsules_loaded::read_capsule_meta_opaque(source_dir);
                self.verify_workspace_capsule_tree(source_dir).ok()?;
                meta
            });
            // `tools` is live-owned data. Strip surfaces persisted by older
            // Astrid releases before probing so an unavailable/failed probe
            // leaves the field genuinely absent and consumer fan-out can run.
            meta = crate::capsules_loaded::without_tools(meta);

            by_principal
                .entry(principal.to_string())
                .or_default()
                .push((principal.to_string(), name, meta));
        }
        if by_principal.is_empty() {
            by_principal.insert(empty_principal.to_string(), Vec::new());
        }

        for (principal, entries) in by_principal {
            let payload = match epoch {
                Some(epoch) => crate::capsules_loaded::build_capsules_loaded_payload_with_epoch(
                    entries,
                    epoch.get(),
                ),
                None => crate::capsules_loaded::build_capsules_loaded_payload(entries),
            };

            let msg = astrid_events::ipc::IpcMessage::new(
                astrid_events::ipc::Topic::from_raw("astrid.v1.capsules_loaded"),
                astrid_events::ipc::IpcPayload::RawJson(payload),
                self.session_id.0,
            )
            .with_principal(principal);
            let _ = self.event_bus.publish(astrid_events::AstridEvent::Ipc {
                metadata: astrid_events::EventMetadata::new("kernel"),
                message: msg,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid principal")
    }

    fn descriptor(name: &str) -> ToolDescriptor {
        ToolDescriptor {
            name: name.to_string(),
            description: String::new(),
            input_schema: serde_json::json!({}),
        }
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

    #[test]
    fn replace_if_current_rejects_a_superseded_capture() {
        let mut store = McpSnapshotStore::default();
        let principal = principal("alice");
        let first_capture = store.begin_refresh(&principal).expect("first capture");
        let second_capture = store.begin_refresh(&principal).expect("second capture");

        let newer = store
            .replace_if_current(
                principal.clone(),
                second_capture,
                vec![descriptor("current")],
            )
            .expect("current refresh publishes");
        let stale =
            store.replace_if_current(principal.clone(), first_capture, vec![descriptor("stale")]);
        assert!(stale.is_err());
        assert_eq!(
            store.get(&principal).map(|snapshot| snapshot.epoch),
            Some(newer.epoch)
        );

        let third_capture = store.begin_refresh(&principal).expect("third capture");
        let replaced = store
            .replace_if_current(principal, third_capture, vec![descriptor("replacement")])
            .expect("latest capture publishes");
        assert_eq!(replaced.epoch.get(), 2);
    }
}
