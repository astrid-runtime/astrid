#![no_std]

//! Shared native-kernel state machines and their narrow machine adapter.

// The freestanding binary is the production caller of these portable modules.

// Architecture-owned boot and domain-runtime code is excluded from host test
// compilation; its pure state machines remain in `ipc` and `domains`.
#[cfg(not(test))]
pub mod apic;
#[cfg(not(test))]
pub mod closure;
pub mod domains;
#[cfg(not(test))]
pub mod entropy;
#[cfg(not(test))]
pub mod gdt;
#[cfg(not(test))]
pub mod interrupts;
pub mod ipc;
#[cfg(not(test))]
pub mod memory;
pub mod platform;
// Production-compiled ahead of its first consumer so the native target keeps
// typechecking the frozen relation semantics.
#[allow(dead_code)]
mod relations;
// Production-compiled ahead of its first consumer so the native target keeps
// typechecking the frozen audit-chain semantics.
#[allow(dead_code)]
mod audit;
#[cfg(not(test))]
pub mod serial;
#[cfg(not(test))]
pub mod tests;
#[cfg(not(test))]
pub mod trap;
