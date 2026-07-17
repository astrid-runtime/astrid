//! Agent-loop readiness DTOs carried over the kernel management API.
//!
//! These describe whether the loaded capsule set can actually serve an agent
//! chat turn. They are *mirror* definitions: the readiness computation lives in
//! `astrid_capsule::readiness`, but the DTOs are defined here (in `astrid-core`)
//! because the `KernelRequest`/`KernelResponse` API surface lives here and
//! `astrid-core` cannot depend on `astrid-capsule` without a dependency cycle
//! (`astrid-capsule` already depends on `astrid-core`). `astrid_capsule`
//! constructs these types directly, so the computation stays single-source —
//! only the wire shape is defined here.

use serde::{Deserialize, Serialize};

/// Whether the loaded capsule set can serve an agent chat turn. Name-agnostic
/// (no capsule name hardcoded): the prompt topic needs a subscriber, the reply
/// topic a publisher, and every required import an exporter. A socket-only
/// daemon reports `ready == false` instead of silently dropping prompts.
/// Populated by `astrid_capsule::readiness::agent_loop_readiness`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLoopReadiness {
    /// `true` iff there is a prompt subscriber, a response publisher, and no
    /// unsatisfied required import.
    pub ready: bool,
    /// Loaded capsules whose `[subscribe]` matches the prompt topic.
    pub prompt_subscribers: Vec<String>,
    /// Loaded capsules whose `[publish]` matches the reply topic.
    pub response_publishers: Vec<String>,
    /// Required imports no loaded capsule exports — each breaks its importer.
    pub unsatisfied_required_imports: Vec<MissingImport>,
    /// All loaded capsule names, for context in diagnostics.
    pub loaded_capsules: Vec<String>,
}

/// In-process agent-loop readiness probe.
///
/// Agent-loop serviceability ("can this daemon serve a chat turn?") is global
/// daemon health, not per-principal authorization — so the co-located gateway's
/// prompt fail-fast reads it directly instead of issuing the capability-gated
/// [`crate::kernel_api::KernelRequest::GetAgentReadiness`] as the caller (which
/// only admins/`capsule:list` holders could answer). The closure is built in
/// `astrid-kernel` (which owns the live registry) and merely invoked by the
/// gateway, so neither the capability model nor the gateway's dependency on the
/// WASM engine is touched. Defined here so both crates can name it without a
/// dependency cycle, and spelled with `std` types so `astrid-core` needs no
/// `futures` dependency.
#[derive(Clone)]
pub struct AgentReadinessProbe(
    #[allow(clippy::type_complexity)]
    std::sync::Arc<
        dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = AgentLoopReadiness> + Send>>
            + Send
            + Sync,
    >,
);

impl AgentReadinessProbe {
    /// Wrap a readiness-computing closure. The closure must be cheap and
    /// self-contained (it captures whatever state it reads) so each call
    /// reflects the current loaded set.
    pub fn new(
        f: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = AgentLoopReadiness> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Compute current readiness.
    pub async fn probe(&self) -> AgentLoopReadiness {
        (self.0)().await
    }
}

impl std::fmt::Debug for AgentReadinessProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentReadinessProbe(..)")
    }
}

/// In-process probe answering "does a loaded capsule subscribe to this
/// topic?", computed from the live registry without a capability check.
///
/// The cap-free counterpart to the capability-gated
/// [`crate::kernel_api::KernelRequest::GetCapsuleMetadata`], built the same
/// way as [`AgentReadinessProbe`] and for the same reason: whether a verb is
/// served is global daemon health, not per-principal authorization, so a
/// gateway route can probe it for **every** authenticated caller without a
/// capability check or leaking the capsule inventory. Lets a route degrade
/// gracefully — e.g. answer `501 Not Implemented` when no loaded capsule
/// handles a newer verb — instead of waiting out a bus timeout. The closure
/// is built in `astrid-kernel` (which owns the registry) and merely invoked
/// here; spelled with `std` types so `astrid-core` needs no `futures` dep.
#[derive(Clone)]
pub struct CapsuleTopicProbe(std::sync::Arc<CapsuleTopicProbeFns>);

struct CapsuleTopicProbeFns {
    is_subscribed: CapsuleTopicProbeFn,
    ensure_subscribed: CapsuleTopicProbeFn,
    subscriber_source_ids: CapsuleTopicSourceProbeFn,
}

#[allow(clippy::type_complexity)]
type CapsuleTopicProbeFn = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

#[allow(clippy::type_complexity)]
type CapsuleTopicSourceProbeFn = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<uuid::Uuid>> + Send>>
        + Send
        + Sync,
>;

impl CapsuleTopicProbe {
    /// Wrap a closure that answers whether `topic` has a loaded-capsule
    /// subscriber. The closure captures the registry it reads, so each call
    /// reflects the current loaded set (correct across live reloads).
    pub fn new(
        f: impl Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        let f = std::sync::Arc::new(f);
        let is_subscribed = {
            let f = std::sync::Arc::clone(&f);
            std::sync::Arc::new(move |topic: String| f(topic))
        };
        let ensure_subscribed = std::sync::Arc::new(move |topic: String| f(topic));
        Self(std::sync::Arc::new(CapsuleTopicProbeFns {
            is_subscribed,
            ensure_subscribed,
            subscriber_source_ids: std::sync::Arc::new(|_| Box::pin(async { Vec::new() })),
        }))
    }

    /// Wrap a closure pair: one passive readiness read, and one active
    /// best-effort warm/read for routes that must not publish into an unloaded
    /// caller view after restart.
    pub fn new_with_ensure(
        is_subscribed: impl Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync
        + 'static,
        ensure_subscribed: impl Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(CapsuleTopicProbeFns {
            is_subscribed: std::sync::Arc::new(is_subscribed),
            ensure_subscribed: std::sync::Arc::new(ensure_subscribed),
            subscriber_source_ids: std::sync::Arc::new(|_| Box::pin(async { Vec::new() })),
        }))
    }

    /// Wrap readiness, warm-up, and trusted-source probes from the same live
    /// capsule registry.
    pub fn new_with_ensure_and_sources(
        is_subscribed: impl Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync
        + 'static,
        ensure_subscribed: impl Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync
        + 'static,
        subscriber_source_ids: impl Fn(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<uuid::Uuid>> + Send>,
        > + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(CapsuleTopicProbeFns {
            is_subscribed: std::sync::Arc::new(is_subscribed),
            ensure_subscribed: std::sync::Arc::new(ensure_subscribed),
            subscriber_source_ids: std::sync::Arc::new(subscriber_source_ids),
        }))
    }

    /// True if some loaded capsule's `[subscribe]` matches `topic`.
    pub async fn is_subscribed(&self, topic: &str) -> bool {
        (self.0.is_subscribed)(topic.to_string()).await
    }

    /// Best-effort warm-up for `topic`, then answer whether a subscriber is
    /// present. Probes built with [`Self::new`] are passive and simply mirror
    /// [`Self::is_subscribed`].
    pub async fn ensure_subscribed(&self, topic: &str) -> bool {
        (self.0.ensure_subscribed)(topic.to_string()).await
    }

    /// Kernel-stamped IPC source IDs of loaded subscribers matching `topic`.
    pub async fn subscriber_source_ids(&self, topic: &str) -> Vec<uuid::Uuid> {
        (self.0.subscriber_source_ids)(topic.to_string()).await
    }
}

impl std::fmt::Debug for CapsuleTopicProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapsuleTopicProbe(..)")
    }
}

/// A required interface import with no matching export among loaded capsules.
///
/// `Ord` (by capsule, namespace, interface, requirement in declaration order)
/// so readiness reports can present a stable, sorted list — the loaded set is
/// iterated from a `HashMap`, which has no inherent order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MissingImport {
    /// The capsule whose import is unsatisfied.
    pub capsule: String,
    /// Interface namespace (e.g. `astrid`).
    pub namespace: String,
    /// Interface name (e.g. `llm`).
    pub interface: String,
    /// The semver requirement string the import declared.
    pub requirement: String,
}
