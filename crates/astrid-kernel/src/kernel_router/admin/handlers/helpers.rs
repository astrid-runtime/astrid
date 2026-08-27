//! Shared validation and response helpers for admin handlers.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::{PrincipalProfile, ProfileError};
use astrid_events::kernel_api::AdminResponseBody;
use tracing::warn;

pub(crate) fn principal_profile_path(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> PathBuf {
    PrincipalProfile::path_for(&kernel.astrid_home, principal)
}

/// Reject mutating-handler calls that target a principal with no
/// `profile.toml` on disk. Required because
/// [`PrincipalProfile::load_from_path`] returns `Default` on `NotFound`.
pub(crate) fn require_principal_exists(principal: &PrincipalId, path: &Path) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!(
            "principal {principal} does not exist (no profile.toml at {})",
            path.display()
        ))
    }
}

pub(crate) fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request rejected: bad input");
    AdminResponseBody::Error(msg)
}

pub(crate) fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request failed: internal error");
    AdminResponseBody::Error(msg)
}

pub(crate) fn err_profile(principal: &PrincipalId, e: &ProfileError) -> AdminResponseBody {
    err_internal(format!("profile error for {principal}: {e}"))
}

pub(crate) fn success_json(val: serde_json::Value) -> AdminResponseBody {
    AdminResponseBody::Success(val)
}
