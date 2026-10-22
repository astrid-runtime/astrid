//! Shared admin response construction and error logging.

use astrid_core::{PrincipalId, profile::ProfileError};
use astrid_events::kernel_api::AdminResponseBody;
use tracing::warn;

pub(in crate::kernel_router::admin) fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request rejected: bad input");
    AdminResponseBody::Error(msg)
}

pub(in crate::kernel_router::admin) fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request failed: internal error");
    AdminResponseBody::Error(msg)
}

pub(in crate::kernel_router::admin) fn err_profile(
    principal: &PrincipalId,
    e: &ProfileError,
) -> AdminResponseBody {
    err_internal(format!("profile error for {principal}: {e}"))
}

pub(in crate::kernel_router::admin) fn success_json(val: serde_json::Value) -> AdminResponseBody {
    AdminResponseBody::Success(val)
}
