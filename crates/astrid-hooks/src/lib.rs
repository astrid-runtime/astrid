//! Astrid Hooks - User-defined extension points for the Astrid runtime.
//!
//! This crate provides a flexible hook system that allows users to extend
//! the behavior of the Astrid runtime at key points in the execution flow.
//!
//! # Hook Events
//!
//! Hooks can be triggered on various events:
//! - Session lifecycle (start, end)
//! - User prompts
//! - Tool calls (before, after, on error)
//! - Approval flows
//! - Subagent operations
//!
//! # Hook Handlers
//!
//! Hooks can be implemented using different handlers:
//! - **Command**: Execute shell commands
//! - **HTTP**: Call webhooks
//! - **WASM**: Run WebAssembly modules
//!
//! # Example
//!
//! ```rust,ignore
//! use astrid_hooks::{Hook, HookEvent, HookHandler, HookManager};
//!
//! let mut manager = HookManager::new();
//!
//! let hook = Hook::new(HookEvent::PreToolCall)
//!     .with_handler(HookHandler::Command {
//!         command: "echo".to_string(),
//!         args: vec!["Tool called: $TOOL_NAME".to_string()],
//!         env: Default::default(),
//!     });
//!
//! manager.register(hook);
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

#[allow(dead_code)]
pub(crate) mod config;
#[allow(dead_code)]
pub(crate) mod discovery;
#[allow(dead_code)]
pub(crate) mod executor;
#[allow(dead_code)]
pub(crate) mod handler;
pub mod hook;
pub mod hook_event;
#[allow(dead_code)]
pub(crate) mod manager;
#[allow(dead_code)]
pub(crate) mod profiles;
#[allow(dead_code)]
pub(crate) mod result;

pub use hook::{Hook, HookHandler};
pub use hook_event::HookEvent;
pub use result::HookResult;
