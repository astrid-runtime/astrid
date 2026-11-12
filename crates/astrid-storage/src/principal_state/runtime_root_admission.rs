//! Windows runtime-root admission for public store open.
//!
//! Captures one `ExactPrivate` [`RetainedPrivateRoot`] before any volume or
//! legacy mutation and keeps that `Arc` alive through cutover and the returned
//! hosted volume. The retained final-boundary file fences ancestor rename for
//! the open lifetime.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::platform_fs::directory_capability::RetainedPrivateRoot;

use crate::error::StorageError;

use super::StorageResult;

pub(super) type AdmittedRuntimeRoot = Arc<RetainedPrivateRoot>;

/// Absolutize `home` once and admit its `ExactPrivate` runtime root.
///
/// # Errors
/// Broad, redirected, or non-directory roots fail closed without ACL repair.
pub(super) fn normalize_and_admit(
    home: &AstridHome,
) -> StorageResult<(AstridHome, AdmittedRuntimeRoot)> {
    let absolute = std::path::absolute(home.root()).map_err(|error| {
        StorageError::Connection(format!(
            "absolutize Astrid runtime root {}: {error}",
            home.root().display()
        ))
    })?;
    let home = AstridHome::from_path(absolute);
    let retained = RetainedPrivateRoot::admit(home.root()).map_err(|error| {
        StorageError::Connection(format!(
            "admit Astrid runtime root {}: {error}",
            home.root().display()
        ))
    })?;
    Ok((home, retained))
}

#[cfg(test)]
thread_local! {
    static CUTOVER_GAP_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: run after temporary cutover volume drop and before publish rename.
#[cfg(test)]
pub(super) fn arm_cutover_gap_hook(hook: impl FnOnce() + 'static) {
    CUTOVER_GAP_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
pub(super) fn run_cutover_gap_hook() {
    if let Some(hook) = CUTOVER_GAP_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
pub(super) fn run_cutover_gap_hook() {}
