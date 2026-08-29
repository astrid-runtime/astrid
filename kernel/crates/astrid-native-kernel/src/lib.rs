#![no_std]

//! Shared native-kernel state machines and their narrow machine adapter.

// The freestanding binary is the production caller of these portable modules.
pub mod ipc;
pub mod platform;
