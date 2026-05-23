//! Astrid Events - Event bus and types for the Astrid secure agent runtime.
//!
//! This crate provides:
//! - IPC payload types and LLM message schemas (re-exported from `astrid-types`)
//! - Broadcast-based event bus for async subscribers
//! - Subscriber registry for synchronous handlers

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

mod bus;
mod event;
pub mod ipc;
pub mod rate_limiter;
mod subscriber;

// Re-export shared types for backward compatibility. `kernel_api` lives in
// `astrid-core` (it references `PrincipalId`/`Quotas`); `llm` is in
// `astrid-types` (the WASM-compatible side, zero `astrid-core` dep).
pub use astrid_core::kernel_api;
pub use astrid_types::llm;

pub use bus::{EventBus, EventReceiver};
pub use event::{AstridEvent, EventMetadata};
pub use ipc::IpcMessage;
pub use ipc::IpcPayload;
pub use ipc::IpcRateLimiter;
