#![deny(unreachable_pub)]

//! Target-selected facade over the kernel's task-spawning and time surface.
//!
//! The kernel spawns background tasks and reads the clock at ~50 call sites via
//! `tokio::spawn`, `tokio::time::{sleep, interval, timeout, Instant,
//! MissedTickBehavior}`, and `std::time::SystemTime`. None of those exist on
//! `wasm32-unknown-unknown` (no tokio runtime, no OS threads, no `std::time`
//! clock), so routing them all through this one crate gives a portable host
//! profile a single seam where the runtime surface is selected per target:
//!
//! - **Native** (everything except `wasm32-unknown-unknown`): pure `tokio`/`std`
//!   re-exports. Every item resolves to the exact same tokio/std type it
//!   replaced, so the facade is zero-cost and changes no behaviour.
//! - **Browser wasm** (`wasm32-unknown-unknown` only — WASI targets take the
//!   native arm, since these deps are browser-specific): the task surface maps to the JS
//!   microtask queue (`wasm-bindgen-futures`), the timer surface to JS timers
//!   (`wasmtimer`), and the wall clock to the browser time bridge
//!   (`web-time`). See each item's docs for the accepted semantic differences
//!   (task panics, monotonic-clock source).
//!
//! ## Why no trait
//!
//! This is deliberately a compile-time `cfg` selection, not a runtime-dispatch
//! trait. The implementation never varies *within* a single platform build: a
//! native binary is always pure tokio, a wasm binary is always the JS-timer
//! mapping. There is no point at which both live behind one interface and a
//! value picks between them at run time, so a trait (or `dyn`/generic
//! parameter) would add an indirection layer that models a polymorphism the
//! system does not have. A `cfg`-gated re-export expresses exactly the real
//! shape — "pick the surface at build time, then it's fixed" — and keeps the
//! native arm a literal alias with no wrapper cost. Traits were considered and
//! rejected for that reason.
//!
//! ## Module layout
//!
//! - [`spawn`], [`JoinHandle`], [`JoinError`] — task surface.
//! - [`time`] — `sleep`, `interval`, `timeout`, `Instant`,
//!   `MissedTickBehavior`.
//! - [`clock`] — wall-clock reads ([`clock::now_epoch_secs`]).

// ===========================================================================
// Native arm — pure tokio/std re-exports. Byte-for-byte the surface the kernel
// used before the facade existed; no wrappers, no behaviour change.
// ===========================================================================

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tokio::spawn;
/// Run a blocking closure off the async runtime. Native = `tokio`'s dedicated
/// blocking thread pool; wasm = inline on the current task (see the wasm arm).
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tokio::task::spawn_blocking;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use tokio::task::{JoinError, JoinHandle};

/// Timer surface. Native = `tokio::time`; wasm = `wasmtimer`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod time {
    pub use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};
}

/// Wall-clock reads.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod clock {
    /// Current wall-clock as whole seconds since the Unix epoch, saturating to
    /// `0` on the (impossible) pre-1970 case so the returned `u64` never wraps.
    ///
    /// Native reads `std::time::SystemTime`; wasm reads `web_time::SystemTime`.
    #[must_use]
    pub fn now_epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

// ===========================================================================
// Wasm arm — JS-timer / microtask equivalents. Compile-checked in core CI
// (`cargo check --target wasm32-unknown-unknown`); no runtime path exercises
// it here, that lives in the browser host build.
// ===========================================================================

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm_task;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use wasm_task::{JoinError, JoinHandle, spawn, spawn_blocking};

/// Timer surface. Native = `tokio::time`; wasm = `wasmtimer`.
///
/// `wasmtimer` is a drop-in for `tokio::time` on wasm: `sleep`/`interval`/
/// `timeout` and `MissedTickBehavior` mirror tokio's API and semantics. The
/// one source difference is [`Instant`](wasmtimer::std::Instant): native's is
/// `tokio::time::Instant` (the runtime clock, pausable in tokio tests), wasm's
/// is `wasmtimer::std::Instant` (a real monotonic clock over the JS
/// `Performance` timer). Every kernel use reads `Instant::now`, adds/subtracts
/// `Duration`, and compares — arithmetic both types share — so the swap is
/// behaviour-preserving on either target.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod time {
    pub use wasmtimer::std::Instant;
    pub use wasmtimer::tokio::{MissedTickBehavior, interval, sleep, timeout};
}

/// Wall-clock reads.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod clock {
    /// Current wall-clock as whole seconds since the Unix epoch, saturating to
    /// `0` on the (impossible) pre-1970 case so the returned `u64` never wraps.
    ///
    /// Native reads `std::time::SystemTime`; wasm reads `web_time::SystemTime`.
    #[must_use]
    pub fn now_epoch_secs() -> u64 {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}
