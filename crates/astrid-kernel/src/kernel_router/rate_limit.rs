//! Per-request rate-limit metadata for the kernel management API.
//!
//! Split out of `kernel_router/mod.rs` to keep that file under the 1000-line CI
//! threshold. Pure functions mapping a [`KernelRequest`] to its rate-limit label
//! and per-minute cap; the dispatcher in `mod.rs` calls
//! [`rate_limit_for_request`] before admitting a management request.

use astrid_events::kernel_api::KernelRequest;

use super::kernel_request_method;

/// Return the rate limit label and max-per-minute for a request type.
/// Returns `None` for the limit if the request type is not rate-limited.
pub(crate) fn rate_limit_for_request(req: &KernelRequest) -> (&'static str, Option<u32>) {
    (kernel_request_method(req), rate_limit_max(req))
}

/// Return the max-per-minute rate limit for a request type, if any.
fn rate_limit_max(req: &KernelRequest) -> Option<u32> {
    match req {
        KernelRequest::ReloadCapsules
        | KernelRequest::ReloadCapsule { .. }
        | KernelRequest::UnloadCapsule { .. }
        | KernelRequest::PromoteWorkspace { .. }
        | KernelRequest::RollbackWorkspace { .. } => Some(5),
        KernelRequest::InstallCapsule { .. } | KernelRequest::ApproveCapability { .. } => Some(10),
        KernelRequest::Shutdown { .. } => Some(1),
        KernelRequest::ListCapsules
        | KernelRequest::GetCommands
        | KernelRequest::GetCapsuleMetadata
        | KernelRequest::GetAgentReadiness
        | KernelRequest::GetStatus => None,
    }
}
