//! IPC types — re-exported from `astrid-types` with runtime additions.

// Re-export everything from astrid-types::ipc
pub use astrid_types::ipc::*;
// `Topic` lives in `astrid_types::topic`, not `::ipc`, so re-export it here so
// kernel-side consumers can reach it through the familiar `ipc` namespace.
pub use astrid_types::topic::Topic;

pub use crate::rate_limiter::IpcRateLimiter;
