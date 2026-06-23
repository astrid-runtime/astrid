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

/// A required interface import with no matching export among loaded capsules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
