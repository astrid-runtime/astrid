//! Shared data types for the Astrid secure agent runtime.
//!
//! This crate provides the canonical definitions for:
//! - IPC payload schemas (cross-boundary messaging between WASM guests and host)
//! - LLM message, tool, and streaming types
//!
//! It has zero dependency on `astrid-core` and minimal dependencies overall
//! (serde, uuid, chrono with serde-only features), so it compiles on
//! `wasm32-unknown-unknown` for capsule SDK consumption without dragging
//! in the kernel.
//!
//! Kernel-management RPC types (CLI ↔ daemon: `KernelRequest`,
//! `KernelResponse`, etc.) live in `astrid_core::kernel_api`. They depend
//! on `PrincipalId` and `Quotas` and therefore cannot live here.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod ipc;
pub mod llm;

pub use ipc::{IpcMessage, IpcPayload, OnboardingField, OnboardingFieldType, SelectionOption};
pub use llm::{
    ContentPart, LlmResponse, LlmToolDefinition, Message, MessageContent, MessageRole, StopReason,
    StreamEvent, ToolCall, ToolCallResult, Usage,
};
