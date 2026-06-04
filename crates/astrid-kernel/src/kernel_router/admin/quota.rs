//! Layer 6 quota / usage admin handlers (issue #672).
//!
//! Split out of [`super::handlers`] to keep that file under the
//! repo's per-file line cap. These handlers share the same
//! enforcement-preamble contract and helper surface as the rest of
//! the admin handlers — the shared helpers live in
//! [`super::handlers`] and are re-used here via `pub(super)`.

use std::sync::Arc;

use astrid_core::principal::PrincipalId;
use astrid_core::profile::PrincipalProfile;
use astrid_events::kernel_api::{AdminResponseBody, ResourceUsage};

use super::handlers::{
    err_bad_input, err_profile, principal_profile_path, require_principal_exists, success_json,
};

pub(super) async fn quota_set(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    quotas: astrid_core::profile::Quotas,
) -> AdminResponseBody {
    // Validate before taking the write lock — quick reject on bad input.
    if let Err(e) = quotas.validate() {
        return err_bad_input(format!("quotas rejected: {e}"));
    }

    let _guard = kernel.admin_write_lock.lock().await;
    let path = principal_profile_path(kernel, &principal);
    if let Err(msg) = require_principal_exists(&principal, &path) {
        return err_bad_input(msg);
    }
    let mut profile = match PrincipalProfile::load_from_path(&path) {
        Ok(p) => p,
        Err(e) => return err_profile(&principal, &e),
    };
    profile.quotas = quotas;
    if let Err(e) = profile.save_to_path(&path) {
        return err_profile(&principal, &e);
    }
    kernel.profile_cache.invalidate(&principal);
    success_json(serde_json::json!({ "principal": principal.as_str() }))
}

pub(super) fn quota_get(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) -> AdminResponseBody {
    // quota.get reads through the cache. The cache.resolve path
    // returns Default on missing profile.toml, so a typo'd name would
    // silently return Default-shaped quotas without revealing the
    // mistake. Surface "no such principal" as a hard error.
    let path = principal_profile_path(kernel, principal);
    if let Err(msg) = require_principal_exists(principal, &path) {
        return err_bad_input(msg);
    }
    match kernel.profile_cache.resolve(principal) {
        Ok(profile) => AdminResponseBody::Quotas(profile.quotas.clone()),
        Err(e) => err_profile(principal, &e),
    }
}

/// Read a principal's resource usage vs budget.
///
/// CONTRACT STUB (PR3 fills the live fields). Today it resolves the principal's
/// configured ceilings and returns them with `cpu_fuel_consumed_total = 0`,
/// `exempt = false`, and no current memory — placeholders the read-path PR
/// replaces with the shared fuel-ledger total and a capability-based exempt
/// check. The request routing, scope (`self:quota:get` / `quota:get`), and
/// response shape are real now so the gateway + CLI surfaces can build against
/// them in parallel.
pub(super) fn usage_get(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) -> AdminResponseBody {
    // Same "no such principal" guard as quota_get — a typo'd name must not
    // silently report Default-shaped ceilings.
    let path = principal_profile_path(kernel, principal);
    if let Err(msg) = require_principal_exists(principal, &path) {
        return err_bad_input(msg);
    }
    match kernel.profile_cache.resolve(principal) {
        Ok(profile) => AdminResponseBody::Usage(ResourceUsage {
            principal: principal.clone(),
            // TODO(PR3 feat/resource-usage-readpath): read the cross-capsule
            // total from kernel.fuel_ledger.
            cpu_fuel_consumed_total: 0,
            cpu_fuel_per_sec_limit: profile.quotas.max_cpu_fuel_per_sec,
            // TODO(PR3): resolve via the capability check
            // (system:resources:unbounded / net_bind / uplink).
            exempt: false,
            memory_bytes_limit_per_instance: profile.quotas.max_memory_bytes,
            // Per-principal aggregate RAM is not implemented.
            memory_bytes_current_total: None,
        }),
        Err(e) => err_profile(principal, &e),
    }
}
