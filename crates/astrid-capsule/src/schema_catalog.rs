//! Topic schema catalog for A2UI integration.
//!
//! Maps IPC topics to the typed WIT payload reference declared on the capsule's
//! `[publish]` / `[subscribe]` entries. Populated at capsule load time. The
//! A2UI bridge (Track 2) reads this catalog and resolves each `wit` ref to a
//! JSON Schema + description via the WIT registry, to generate schema context
//! for the LLM system prompt.
//!
//! Schemas come from WIT — the typed payload contract on the `[publish]` /
//! `[subscribe]` entry — rather than capsule-self-described inline schemas, so
//! the description is authoritative and not dependent on bus-time self-report.

use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::capsule::CapsuleId;
use crate::manifest::CapsuleManifest;

/// Schema metadata for a single IPC topic.
#[derive(Debug, Clone)]
pub struct TopicSchema {
    /// ID of the capsule that owns this topic.
    pub capsule_id: CapsuleId,
    /// The typed WIT payload reference from the `[publish]` / `[subscribe]`
    /// entry (e.g. `@unicity-astrid/wit/types/tool-call`, or `"opaque"` for an
    /// untyped proxy topic). The A2UI bridge resolves this to a schema +
    /// description via the WIT registry.
    pub wit_ref: String,
    /// Human-readable description, resolved from the WIT record's doc comments.
    /// `None` until the WIT registry resolver populates it (Phase 3).
    pub description: Option<String>,
    /// JSON Schema for the payload, resolved from the WIT record. `None` until
    /// the WIT registry resolver populates it (Phase 3).
    pub schema: Option<serde_json::Value>,
}

/// Runtime catalog mapping IPC topics to their schemas.
///
/// Thread-safe (uses `RwLock`) and shared across the runtime via `Arc`.
/// Updated on capsule load/unload.
#[derive(Debug, Default)]
pub struct SchemaCatalog {
    schemas: RwLock<HashMap<String, TopicSchema>>,
}

impl SchemaCatalog {
    /// Create an empty schema catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a capsule's topics from its `[publish]` / `[subscribe]` tables.
    ///
    /// Called during `WasmEngine::load()`. Each topic is recorded with the
    /// `wit` ref declared on its table entry; the A2UI bridge resolves that ref
    /// to a schema + description, so `description` / `schema` start `None`.
    pub async fn register_topics(&self, capsule_id: &CapsuleId, manifest: &CapsuleManifest) {
        let mut schemas = self.schemas.write().await;
        let entries = manifest
            .publishes
            .iter()
            .map(|(topic, def)| (topic, &def.wit))
            .chain(
                manifest
                    .subscribes
                    .iter()
                    .map(|(topic, def)| (topic, &def.wit)),
            );
        for (topic, wit_ref) in entries {
            schemas.insert(
                topic.clone(),
                TopicSchema {
                    capsule_id: capsule_id.clone(),
                    wit_ref: wit_ref.clone(),
                    description: None,
                    schema: None,
                },
            );
        }
    }

    /// Unregister all topics owned by a capsule (on unload).
    pub async fn unregister_capsule(&self, capsule_id: &CapsuleId) {
        let mut schemas = self.schemas.write().await;
        schemas.retain(|_, v| &v.capsule_id != capsule_id);
    }

    /// Look up the schema for a specific topic.
    pub async fn get(&self, topic: &str) -> Option<TopicSchema> {
        self.schemas.read().await.get(topic).cloned()
    }

    /// Get all registered topic schemas.
    ///
    /// Used by the A2UI bridge to generate the full schema context
    /// for the LLM system prompt.
    pub async fn all(&self) -> HashMap<String, TopicSchema> {
        self.schemas.read().await.clone()
    }

    /// Number of registered topics.
    pub async fn len(&self) -> usize {
        self.schemas.read().await.len()
    }

    /// Whether the catalog is empty.
    pub async fn is_empty(&self) -> bool {
        self.schemas.read().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{PublishDef, SubscribeDef};

    fn test_capsule_id() -> CapsuleId {
        CapsuleId::from_static("test-capsule")
    }

    fn publish(wit: &str) -> PublishDef {
        PublishDef {
            wit: wit.into(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            fanout: false,
        }
    }

    fn subscribe(wit: &str) -> SubscribeDef {
        SubscribeDef {
            wit: wit.into(),
            version: None,
            tag: None,
            rev: None,
            branch: None,
            path: None,
            handler: None,
            priority: None,
        }
    }

    fn manifest_with(publishes: &[(&str, &str)], subscribes: &[(&str, &str)]) -> CapsuleManifest {
        CapsuleManifest {
            publishes: publishes
                .iter()
                .map(|(t, w)| ((*t).to_string(), publish(w)))
                .collect(),
            subscribes: subscribes
                .iter()
                .map(|(t, w)| ((*t).to_string(), subscribe(w)))
                .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn register_records_wit_ref_from_publish_table() {
        let catalog = SchemaCatalog::new();
        let manifest = manifest_with(
            &[(
                "registry.v1.active_model_changed",
                "@unicity-astrid/wit/registry/active-model",
            )],
            &[],
        );

        catalog.register_topics(&test_capsule_id(), &manifest).await;

        let schema = catalog
            .get("registry.v1.active_model_changed")
            .await
            .expect("topic registered");
        assert_eq!(schema.capsule_id, test_capsule_id());
        assert_eq!(schema.wit_ref, "@unicity-astrid/wit/registry/active-model");
        // description + schema are resolved from the WIT ref by A2UI later.
        assert!(schema.description.is_none());
        assert!(schema.schema.is_none());
    }

    #[tokio::test]
    async fn register_covers_publish_and_subscribe() {
        let catalog = SchemaCatalog::new();
        let manifest = manifest_with(
            &[("a.v1.foo", "@scope/wit/a/foo")],
            &[("a.v1.bar", "opaque")],
        );

        catalog.register_topics(&test_capsule_id(), &manifest).await;
        assert_eq!(catalog.len().await, 2);
        assert_eq!(catalog.get("a.v1.bar").await.unwrap().wit_ref, "opaque");
    }

    #[tokio::test]
    async fn unregister_capsule_removes_its_topics() {
        let catalog = SchemaCatalog::new();
        let id = test_capsule_id();
        let manifest = manifest_with(
            &[("a.v1.foo", "@scope/wit/a/foo")],
            &[("a.v1.bar", "@scope/wit/a/bar")],
        );

        catalog.register_topics(&id, &manifest).await;
        assert_eq!(catalog.len().await, 2);

        catalog.unregister_capsule(&id).await;
        assert!(catalog.is_empty().await);
    }

    #[tokio::test]
    async fn multiple_capsules_independent() {
        let catalog = SchemaCatalog::new();
        let id_a = CapsuleId::from_static("capsule-a");
        let id_b = CapsuleId::from_static("capsule-b");

        catalog
            .register_topics(
                &id_a,
                &manifest_with(&[("a.v1.event", "@scope/wit/a/e")], &[]),
            )
            .await;
        catalog
            .register_topics(
                &id_b,
                &manifest_with(&[("b.v1.event", "@scope/wit/b/e")], &[]),
            )
            .await;

        assert_eq!(catalog.len().await, 2);

        catalog.unregister_capsule(&id_a).await;
        assert_eq!(catalog.len().await, 1);
        assert!(catalog.get("b.v1.event").await.is_some());
        assert!(catalog.get("a.v1.event").await.is_none());
    }
}
