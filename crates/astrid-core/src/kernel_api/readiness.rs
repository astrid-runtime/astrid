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
use uuid::Uuid;

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
pub struct CapsuleTopicProbe(
    #[allow(clippy::type_complexity)]
    std::sync::Arc<
        dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
            + Send
            + Sync,
    >,
);

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
        Self(std::sync::Arc::new(f))
    }

    /// True if some loaded capsule's `[subscribe]` matches `topic`.
    pub async fn is_subscribed(&self, topic: &str) -> bool {
        (self.0)(topic.to_string()).await
    }
}

impl std::fmt::Debug for CapsuleTopicProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapsuleTopicProbe(..)")
    }
}

/// In-process probe returning the kernel-stamped IPC source UUIDs for a loaded
/// capsule package.
///
/// Source UUIDs are runtime-instance identifiers, not package-name constants:
/// per-principal/content-addressed loading includes the owning principal and
/// artifact hash in the UUID seed. Gateway routes that trust capsule replies
/// use this probe to follow the live registry across reloads while still
/// rejecting same-topic responses from unrelated capsules.
#[derive(Clone)]
pub struct CapsuleSourceProbe(
    #[allow(clippy::type_complexity)]
    std::sync::Arc<
        dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Uuid>> + Send>>
            + Send
            + Sync,
    >,
);

impl CapsuleSourceProbe {
    /// Wrap a closure that returns the currently loaded source UUIDs for
    /// `capsule_id`.
    pub fn new(
        f: impl Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Uuid>> + Send>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Return every loaded runtime source UUID for `capsule_id`.
    pub async fn source_ids(&self, capsule_id: &str) -> Vec<Uuid> {
        (self.0)(capsule_id.to_string()).await
    }
}

impl std::fmt::Debug for CapsuleSourceProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapsuleSourceProbe(..)")
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
