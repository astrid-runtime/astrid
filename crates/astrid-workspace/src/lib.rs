//! Astrid Workspace - Operational boundaries for agent actions.
//!
//! This crate provides workspace boundaries that define where the agent
//! can operate. Unlike the WASM sandbox (which is inescapable), the
//! operational workspace can be escaped with user approval.
//!
//! # Key Concepts
//!
//! - **Workspace**: A directory tree where the agent can freely operate
//! - **Escape**: Operations outside the workspace require approval
//! - **Modes**: Safe (always ask), Guided (smart defaults), Autonomous (no restrictions)
//!
//! # Example
//!
//! ```rust,ignore
//! use astrid_workspace::{WorkspaceBoundary, WorkspaceConfig, WorkspaceMode};
//!
//! let config = WorkspaceConfig::new("/home/user/project")
//!     .with_mode(WorkspaceMode::Guided);
//!
//! let boundary = WorkspaceBoundary::new(config);
//!
//! // Check if a path is allowed
//! match boundary.check("/home/user/project/src/main.rs") {
//!     PathCheck::Allowed => println!("Path is in workspace"),
//!     PathCheck::RequiresApproval => println!("Needs user approval"),
//!     _ => {}
//! }
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

#[allow(dead_code)]
pub(crate) mod boundaries;
#[allow(dead_code)]
pub(crate) mod config;
#[allow(dead_code)]
pub(crate) mod escape;
#[allow(dead_code)]
pub(crate) mod profiles;
/// Host-level sandbox generation for shell processes.
pub mod sandbox;
/// Git worktree management for agent sessions.
#[allow(dead_code)]
pub(crate) mod worktree;

pub use sandbox::{ProcessSandboxConfig, SandboxCommand, SandboxPolicy, SandboxPrefix};
