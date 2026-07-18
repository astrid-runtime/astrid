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
/// Returns the principal's live cross-capsule CPU total (summed by the shared
/// [`FuelLedger`](astrid_capsule::FuelLedger)), its configured ceilings, and
/// whether it is exempt from the per-principal CPU+memory bound.
///
/// **Displayed-exempt MUST equal enforced-exempt.** The enforcement side
/// (PR2, `astrid_capsule::engine::wasm::resolve_exemption`) decides exemption
/// with `CapabilityCheck::has` over the shared
/// [`EXEMPT_CAPABILITIES`](astrid_core::EXEMPT_CAPABILITIES) list. This read
/// path recomputes the *same* predicate over the *same* list with the kernel's
/// own profile + group snapshot — decoupled from the enforcement branch but
/// guaranteed to yield the identical answer because both iterate one source of
/// truth. admin holds all of them via the `*` grant, so an admin principal
/// reports `exempt = true`.
pub(super) fn usage_get(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) -> AdminResponseBody {
    // Same "no such principal" guard as quota_get — a typo'd name must not
    // silently report Default-shaped ceilings.
    let path = principal_profile_path(kernel, principal);
    if let Err(msg) = require_principal_exists(principal, &path) {
        return err_bad_input(msg);
    }
    match kernel.profile_cache.resolve(principal) {
        Ok(profile) => {
            let exempt = principal_is_exempt(kernel, principal, &profile);
            AdminResponseBody::Usage(ResourceUsage {
                principal: principal.clone(),
                cpu_fuel_consumed_total: kernel.fuel_ledger.total(principal),
                cpu_fuel_per_sec_limit: profile.quotas.max_cpu_fuel_per_sec,
                exempt,
                memory_bytes_limit_per_instance: profile.quotas.max_memory_bytes,
                // Exact aggregate for principal-affine resident Stores. Free
                // checkout Stores remain unattributable and contribute no
                // current value; zero therefore stays `None`.
                memory_bytes_current_total: match kernel.memory_ledger.current(principal) {
                    0 => None,
                    bytes => Some(bytes),
                },
                memory_bytes_peak_total: match kernel.memory_ledger.peak(principal) {
                    0 => None,
                    bytes => Some(bytes),
                },
            })
        },
        Err(e) => err_profile(principal, &e),
    }
}

/// Does `principal` hold any capability that exempts it from the per-principal
/// CPU+memory bound?
///
/// This is the *read-path* mirror of the enforcement predicate
/// `astrid_capsule::engine::wasm::resolve_exemption`: it must return the same
/// answer so displayed-exempt == enforced-exempt. Both iterate the single
/// shared [`EXEMPT_CAPABILITIES`](astrid_core::EXEMPT_CAPABILITIES) list and ask
/// [`CapabilityCheck::has`] with the capability grammar's precedence (revokes >
/// grants > group-inherited) and wildcard semantics, so an admin holder of `*`
/// matches all of them and the two sides cannot drift.
fn principal_is_exempt(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    profile: &PrincipalProfile,
) -> bool {
    let groups = kernel.groups.load_full();
    let check =
        astrid_capabilities::CapabilityCheck::new(profile, groups.as_ref(), principal.clone());
    astrid_core::EXEMPT_CAPABILITIES
        .iter()
        .any(|&cap| check.has(cap))
}
