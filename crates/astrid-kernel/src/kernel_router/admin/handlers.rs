//! Layer 6 admin handler implementations (issue #672).
//!
//! Each handler assumes the caller has already passed the
//! [`super::handle_admin_request`] enforcement preamble; mutating
//! handlers acquire [`crate::Kernel::admin_write_lock`] before touching
//! disk state and invalidate the matching profile-cache entry after a
//! successful write.
//!
//! # Pre-condition: principal must already exist
//!
//! `quota.set`, `caps.grant`, `caps.revoke`, `agent.enable`, and
//! `agent.disable` all require the target principal's `profile.toml` to
//! already exist on disk. Without this gate a typo'd principal name
//! (`alic` instead of `alice`) would silently materialize a phantom
//! principal — `PrincipalProfile::load_from_path` returns `Default` on
//! `NotFound`, the handler would then save the mutated default back to
//! disk, and any future traffic claiming that principal would inherit
//! the phantom permissions. See [`require_principal_exists`].
//!
//! # `default` principal protection
//!
//! The `default` principal is the single-tenant bootstrap anchor.
//! `agent.delete`, `agent.disable`, and `caps.revoke` against it are
//! rejected up front so an admin cannot accidentally lock themselves
//! out of the management API. `caps.grant` and `quota.set` are still
//! allowed (they only add permissions / adjust resource bounds).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_core::capability_grammar::validate_capability;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{PrincipalProfile, ProfileError};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary};
use tracing::{info, warn};

/// Platform label used by the identity store for agent principals
/// created via [`AdminRequestKind::AgentCreate`]. The per-principal
/// `platform_user_id` equals the `PrincipalId` string.
pub(super) const AGENT_IDENTITY_PLATFORM: &str = "cli";

/// Dispatch an already-authorized [`AdminRequestKind`] to the matching
/// handler.
///
/// `caller` is the verified principal from the IPC handshake. Most
/// handlers ignore it (the target principal comes from the request
/// body for variants like [`AdminRequestKind::CapsGrant`]), but
/// handlers that intrinsically bind a result to the caller
/// (notably [`AdminRequestKind::PairDeviceIssue`], which mints a
/// token tied to the caller's own principal regardless of any
/// wire-level hint) need it.
///
/// Thin wrapper over [`dispatch_with_device`] for callers (tests, any
/// non-device path) that have no authenticating device key id. The
/// production admin path uses [`dispatch_with_device`] so a paired issuer's
/// own device scope is threaded into `PairDeviceIssue`'s no-escalation checks.
pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    req: AdminRequestKind,
) -> AdminResponseBody {
    dispatch_with_device(kernel, caller, None, req).await
}

/// Dispatch carrying the issuer's authenticating device key id.
///
/// `issuer_device_key_id` is the device key that authenticated this request,
/// when one did. Only [`AdminRequestKind::PairDeviceIssue`] consumes it: it
/// resolves the issuer's OWN device scope so the no-escalation subset check
/// and the full-mint gate run against the issuer's *attenuated* effective set
/// (a scoped device cannot mint a child broader than itself). Every other
/// handler ignores it.
pub(super) async fn dispatch_with_device(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    issuer_device_key_id: Option<&str>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    match req {
        req @ AdminRequestKind::AgentCreate { .. } => agent_create_from_req(kernel, req).await,
        AdminRequestKind::AgentDelete { principal } => agent_delete(kernel, principal).await,
        AdminRequestKind::AgentEnable { principal } => {
            agent_set_enabled(kernel, principal, true).await
        },
        AdminRequestKind::AgentDisable { principal } => {
            agent_set_enabled(kernel, principal, false).await
        },
        AdminRequestKind::AgentList => agent_list(kernel, caller),
        req @ AdminRequestKind::AgentModify { .. } => agent_modify_from_req(kernel, req).await,
        AdminRequestKind::QuotaSet { principal, quotas } => {
            super::quota::quota_set(kernel, principal, quotas).await
        },
        AdminRequestKind::QuotaGet { principal } => super::quota::quota_get(kernel, &principal),
        AdminRequestKind::UsageGet { principal } => super::quota::usage_get(kernel, &principal),
        AdminRequestKind::GroupCreate {
            name,
            capabilities,
            description,
            unsafe_admin,
        } => {
            super::group::group_create(kernel, name, capabilities, description, unsafe_admin).await
        },
        AdminRequestKind::GroupDelete { name } => super::group::group_delete(kernel, name).await,
        AdminRequestKind::GroupModify {
            name,
            capabilities,
            description,
            unsafe_admin,
        } => {
            super::group::group_modify(kernel, name, capabilities, description, unsafe_admin).await
        },
        AdminRequestKind::GroupList => super::group::group_list(kernel),
        AdminRequestKind::CapsGrant {
            principal,
            capabilities,
            unsafe_admin,
        } => {
            mutate_caps(
                kernel,
                &principal,
                capabilities,
                CapsMutation::Grant { unsafe_admin },
            )
            .await
        },
        AdminRequestKind::CapsRevoke {
            principal,
            capabilities,
        } => mutate_caps(kernel, &principal, capabilities, CapsMutation::Revoke).await,
        req @ (AdminRequestKind::CapsTokenMint { .. }
        | AdminRequestKind::CapsTokenRevoke { .. }
        | AdminRequestKind::CapsTokenList { .. }) => {
            super::caps_tokens::dispatch(kernel, req).await
        },
        AdminRequestKind::InviteIssue {
            group,
            expires_secs,
            max_uses,
            metadata,
        } => {
            super::invite_handlers::invite_issue(kernel, group, expires_secs, max_uses, metadata)
                .await
        },
        AdminRequestKind::InviteRedeem {
            token,
            public_key,
            display_name,
        } => super::invite_handlers::invite_redeem(kernel, token, public_key, display_name).await,
        AdminRequestKind::InviteList => super::invite_handlers::invite_list(kernel).await,
        AdminRequestKind::InviteRevoke { token } => {
            super::invite_handlers::invite_revoke(kernel, token).await
        },
        req @ (AdminRequestKind::PairDeviceIssue { .. }
        | AdminRequestKind::PairDeviceRedeem { .. }
        | AdminRequestKind::PairDeviceList { .. }
        | AdminRequestKind::PairDeviceRevoke { .. }) => {
            pair_device_dispatch(kernel, caller, issuer_device_key_id, req).await
        },
    }
}

/// Dispatch the four pair-device variants. Split from the main `dispatch`
/// router to keep that function under the per-function line cap; the caller
/// guarantees the variant, so the fallback is unreachable in practice.
async fn pair_device_dispatch(
    kernel: &Arc<crate::Kernel>,
    caller: &PrincipalId,
    issuer_device_key_id: Option<&str>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    match req {
        AdminRequestKind::PairDeviceIssue {
            expires_secs,
            label,
            scope,
        } => {
            super::pair_device_handlers::pair_device_issue(
                kernel,
                caller,
                issuer_device_key_id,
                expires_secs,
                label,
                scope,
            )
            .await
        },
        AdminRequestKind::PairDeviceRedeem { token, public_key } => {
            super::pair_device_handlers::pair_device_redeem(kernel, token, public_key).await
        },
        AdminRequestKind::PairDeviceList { principal } => {
            super::pair_device_handlers::pair_device_list(kernel, &principal)
        },
        AdminRequestKind::PairDeviceRevoke { principal, key_id } => {
            super::pair_device_handlers::pair_device_revoke(kernel, &principal, &key_id).await
        },
        _ => AdminResponseBody::Error("not a pair-device request".to_string()),
    }
}

// ── Agent lifecycle ────────────────────────────────────────────────────

/// Destructure an [`AdminRequestKind::AgentCreate`] and forward to
/// [`agent_create`]. Split from the `dispatch` match arm to keep that
/// router under the per-function line cap; the caller guarantees the
/// variant, so the fallback is unreachable in practice.
async fn agent_create_from_req(
    kernel: &Arc<crate::Kernel>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    let AdminRequestKind::AgentCreate {
        name,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    } = req
    else {
        return err_internal(
            "agent_create_from_req received a non-AgentCreate variant".to_string(),
        );
    };
    agent_create(
        kernel,
        name,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    )
    .await
}

async fn agent_create(
    kernel: &Arc<crate::Kernel>,
    name: String,
    groups: Vec<String>,
    grants: Vec<String>,
    inherit_from: Option<PrincipalId>,
    clone_from: Option<PrincipalId>,
    allow_admin_clone: bool,
) -> AdminResponseBody {
    let principal = match PrincipalId::new(name.clone()) {
        Ok(p) => p,
        Err(e) => return err_bad_input(format!("invalid principal name: {e}")),
    };

    // `default` (the bootstrap anchor) and `anonymous` (the no-capability
    // identity stamped on unauthenticated connections, #45/#852) are reserved.
    if let Some(reason) = principal.reserved_reason() {
        return err_bad_input(format!("principal {name:?} is {reason}"));
    }

    // `clone_from` is a full replica: the source supplies groups, grants,
    // revokes, network, process, quotas, AND the state copy. Mixing it with
    // the profile-shaping inputs is ambiguous, so reject rather than silently
    // pick a winner. The CLI also enforces this via clap `conflicts_with`; the
    // kernel enforces it too — defense in depth against a hand-built request.
    if clone_from.is_some() && (inherit_from.is_some() || !groups.is_empty() || !grants.is_empty())
    {
        return err_bad_input(
            "clone_from is mutually exclusive with inherit_from, groups, and grants".to_string(),
        );
    }

    // Acquire the admin write lock BEFORE validating the inheritance source.
    // The source's existence is state this lock protects: every admin mutator
    // (create/delete/...) takes it, so checking the source outside the lock
    // would let a concurrent delete remove it between the existence check and
    // the inheritance copy below (TOCTOU) — the creation would then silently
    // produce an empty agent instead of inheriting. Holding the lock pins the
    // source in place across the check-then-copy.
    let _guard = kernel.admin_write_lock.lock().await;

    // Self-inherit is meaningless (the source home tree does not exist yet),
    // and a non-existent source must fail loudly rather than silently
    // producing an empty agent the operator believes was provisioned.
    if let Some(ref source) = inherit_from {
        if *source == principal {
            return err_bad_input(format!(
                "inherit_from source {source} is the same as the new principal"
            ));
        }
        let source_path = principal_profile_path(kernel, source);
        if let Err(e) = require_principal_exists(source, &source_path) {
            return err_bad_input(format!("inherit_from source rejected: {e}"));
        }
    }

    let profile_path = principal_profile_path(kernel, &principal);

    // Collision: a profile on disk means this principal already exists. Rather
    // than unconditionally reject, defer to the keypair-backfill heal — a bare
    // re-create of an existing KEYLESS (pre-#45/#852) principal surgically adds
    // its missing keypair so `astrid-up`'s per-boot re-run auto-heals upgraders;
    // an already-keyed principal (or any shaping input) still errors. See
    // `agent_create_helpers::backfill_keypair` for the full rationale + invariants.
    if profile_path.exists() {
        // A backfill is not a re-create: any profile-shaping input (last arg)
        // keeps the hard "already exists" error rather than being silently
        // dropped.
        return super::agent_create_helpers::backfill_keypair(
            kernel,
            &principal,
            &profile_path,
            clone_from.is_some()
                || inherit_from.is_some()
                || !groups.is_empty()
                || !grants.is_empty(),
        );
    }

    // A genuinely new principal: build its profile, mint its keypair, register
    // its identity, and provision its home tree + state.
    super::agent_create_helpers::provision_new_principal(
        kernel,
        principal,
        profile_path,
        groups,
        grants,
        inherit_from,
        clone_from,
        allow_admin_clone,
    )
    .await
}

async fn agent_delete(kernel: &Arc<crate::Kernel>, principal: PrincipalId) -> AdminResponseBody {
    if principal == PrincipalId::default() {
        return err_bad_input(
            "cannot delete the `default` principal — it is the single-tenant bootstrap anchor"
                .to_string(),
        );
    }

    let _guard = kernel.admin_write_lock.lock().await;

    // Resolve the link first so we know which user-record to delete.
    let resolved = match kernel
        .identity_store
        .resolve(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
    {
        Ok(user) => user,
        Err(e) => return err_internal(format!("identity store resolve failed: {e}")),
    };
    // Unlink before delete_user so a concurrent `resolve` can't return
    // a dangling user id in the narrow window between the two calls.
    if let Err(e) = kernel
        .identity_store
        .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
        .await
    {
        return err_internal(format!("identity store unlink failed: {e}"));
    }
    if let Some(user) = resolved
        && let Err(e) = kernel.identity_store.delete_user(user.id).await
    {
        return err_internal(format!("identity store delete_user failed: {e}"));
    }

    // Remove the policy file. Without this, traffic claiming this
    // principal would re-load the old profile from disk via the
    // cache and continue to satisfy authz checks against the old
    // grants/groups. The home directory itself (capsule data, KV
    // namespace, audit chain) is NOT scrubbed — reclamation is an
    // ops concern. Best-effort delete: if the file is already gone
    // (concurrent admin or never existed) we proceed.
    let path = principal_profile_path(kernel, &principal);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return err_internal(format!(
            "failed to remove profile.toml at {}: {e}",
            path.display()
        ));
    }

    // Invalidate cache so subsequent authz checks for this principal
    // re-resolve from disk and observe the deletion (next resolve
    // returns Default, which under the Layer 5 enforcement preamble
    // grants no capabilities).
    kernel.profile_cache.invalidate(&principal);

    info!(%principal, "Layer 6 agent.delete");
    success_json(serde_json::json!({ "principal": principal.as_str() }))
}

async fn agent_set_enabled(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    enabled: bool,
) -> AdminResponseBody {
    // Refuse to disable `default` — it is the bootstrap admin anchor and
    // disabling it would lock the operator out of the management API
    // (the Layer 5 preamble denies every request from a disabled
    // principal). Re-enabling `default` is fine and idempotent.
    if !enabled && principal == PrincipalId::default() {
        return err_bad_input(
            "cannot disable the `default` principal — it is the single-tenant bootstrap anchor"
                .to_string(),
        );
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
    if profile.enabled == enabled {
        // No-op but still invalidate cache so the invariant "post-write
        // reads see current disk state" holds unconditionally.
        kernel.profile_cache.invalidate(&principal);
        return success_json(serde_json::json!({
            "principal": principal.as_str(),
            "enabled": enabled,
            "changed": false,
        }));
    }
    profile.enabled = enabled;
    if let Err(e) = profile.save_to_path(&path) {
        return err_profile(&principal, &e);
    }
    kernel.profile_cache.invalidate(&principal);
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "enabled": enabled,
        "changed": true,
    }))
}

async fn agent_modify_from_req(
    kernel: &Arc<crate::Kernel>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    let AdminRequestKind::AgentModify {
        principal,
        add_groups,
        remove_groups,
        add_capsules,
        remove_capsules,
    } = req
    else {
        return err_internal(
            "agent_modify_from_req received a non-AgentModify variant".to_string(),
        );
    };
    if add_groups.is_empty()
        && remove_groups.is_empty()
        && add_capsules.is_empty()
        && remove_capsules.is_empty()
    {
        return err_bad_input(
            "agent.modify: at least one of `add_groups`, `remove_groups`, `add_capsules`, or \
             `remove_capsules` must be non-empty"
                .to_string(),
        );
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

    // Capsule grants mirror the group mechanism EXACTLY via the shared
    // `apply_set_delta`: idempotent remove-then-add, set-based change
    // detection. The capsule grant set is what the kernel gates the
    // user-invocable tool surface against at dispatch (#992).
    let groups_changed = apply_set_delta(&mut profile.groups, &add_groups, &remove_groups);
    let capsules_changed = apply_set_delta(&mut profile.capsules, &add_capsules, &remove_capsules);
    if !groups_changed && !capsules_changed {
        kernel.profile_cache.invalidate(&principal);
        return modify_response(&principal, &profile, false);
    }

    // Validate before saving: re-runs the profile invariants (group
    // names match groups.toml, grants/revokes still well-formed, capsule
    // grants well-formed, etc.). Without this an operator could
    // `agent modify --add-group typo` and the Layer 5 cap lookup would
    // silently miss the typo'd group at every authz check.
    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }
    if let Err(e) = profile.save_to_path(&path) {
        return err_profile(&principal, &e);
    }
    kernel.profile_cache.invalidate(&principal);

    info!(
        %principal,
        added_groups = ?add_groups,
        removed_groups = ?remove_groups,
        added_capsules = ?add_capsules,
        removed_capsules = ?remove_capsules,
        groups = ?profile.groups,
        capsules = ?profile.capsules,
        "Layer 6 agent.modify"
    );
    modify_response(&principal, &profile, true)
}

/// Build the `agent.modify` success body reporting the principal's
/// resulting groups + capsule grants and whether the call changed state.
fn modify_response(
    principal: &PrincipalId,
    profile: &PrincipalProfile,
    changed: bool,
) -> AdminResponseBody {
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "groups": profile.groups,
        "capsules": profile.capsules,
        "changed": changed,
    }))
}

/// Apply an idempotent set delta to `target`: remove every entry in
/// `remove`, then append every entry in `add` not already present.
///
/// Returns `true` if the resulting set differs from the original
/// (order-insensitive). Removes are applied first so a (remove, add) of
/// the same entry is an idempotent rename rather than a duplicate; adding
/// a present entry or removing an absent one is a no-op. Shared by the
/// group and capsule mechanisms so they behave identically.
///
/// On a no-op (the resulting set equals the original) `target` is left
/// byte-for-byte unchanged — including its element order. The delta is
/// computed on a scratch copy and written back only when the set actually
/// changed, so an order-only churn (e.g. removing then re-adding a present
/// entry) is never reflected back to the caller as a mutated profile that
/// then goes unpersisted (`changed=false`).
pub(crate) fn apply_set_delta(target: &mut Vec<String>, add: &[String], remove: &[String]) -> bool {
    // Build the resulting order on a scratch copy WITHOUT touching `target`:
    // surviving entries keep their order, then new additions append.
    let mut next: Vec<String> = target
        .iter()
        .filter(|e| !remove.contains(e))
        .cloned()
        .collect();
    for entry in add {
        if !next.contains(entry) {
            next.push(entry.clone());
        }
    }
    // Order-insensitive set comparison; the borrows end with the block so the
    // write-back below can take `&mut *target`.
    let changed = {
        let before: std::collections::HashSet<&String> = target.iter().collect();
        let after: std::collections::HashSet<&String> = next.iter().collect();
        before != after
    };
    if changed {
        *target = next;
    }
    changed
}

/// Does `caller` hold the admin-tier global `agent:list` capability
/// (directly, via `agent:*`, or `*`)?
///
/// Self-scoped agents hold only `self:agent:list` (the `agent` builtin
/// grants it via `self:*`), and `self:*` does not match `agent:list`
/// (segment 1 `self` ≠ `agent`), so this returns `false` for them — they
/// are filtered to their own row. Fail-closed: an unresolvable caller
/// profile yields `false` (most restrictive, self-only).
fn caller_has_global_agent_list(kernel: &Arc<crate::Kernel>, caller: &PrincipalId) -> bool {
    let Ok(profile) = kernel.profile_cache.resolve(caller) else {
        return false;
    };
    let groups = kernel.groups.load_full();
    astrid_capabilities::CapabilityCheck::new(profile.as_ref(), groups.as_ref(), caller.clone())
        .has("agent:list")
}

fn agent_list(kernel: &Arc<crate::Kernel>, caller: &PrincipalId) -> AdminResponseBody {
    // Source of truth: `etc/profiles/{principal}.toml`. Iterating the
    // home directory was the pre-#672 approach but stopped working
    // when profiles moved out — and was always wrong in spirit since
    // a principal's home dir can outlive its policy file (e.g. after
    // `agent.delete`, where home stays as an ops concern but the
    // profile is removed).
    let profiles_dir = kernel.astrid_home.profiles_dir();
    let entries = match std::fs::read_dir(&profiles_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return AdminResponseBody::AgentList(Vec::new());
        },
        Err(e) => {
            return err_internal(format!("failed to read {}: {e}", profiles_dir.display()));
        },
    };

    let mut summaries = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".toml") else {
            continue;
        };
        let Ok(principal) = PrincipalId::new(stem) else {
            continue;
        };
        let profile = match kernel.profile_cache.resolve(&principal) {
            Ok(p) => p,
            Err(e) => {
                warn!(%principal, error = %e, "skipping agent.list entry with unreadable profile");
                continue;
            },
        };
        summaries.push(AgentSummary {
            principal,
            enabled: profile.enabled,
            groups: profile.groups.clone(),
            grants: profile.grants.clone(),
            revokes: profile.revokes.clone(),
        });
    }
    summaries.sort_by(|a, b| a.principal.as_str().cmp(b.principal.as_str()));

    // Authority-scope filter (fail-secure). `AgentList` always resolves
    // to `AuthorityScope::Self_`, so the preamble already requires
    // `self:agent:list` to reach this handler at all — which the `agent`
    // builtin holds via `self:*`. That lowering lets an agent resolve its
    // own group-inherited capabilities (e.g. `caps check <self>`) WITHOUT
    // being handed the admin-tier `agent:list`, but it must NOT leak the
    // full roster (every other principal's groups / grants / revokes). So
    // a caller is narrowed to its own row unless it ALSO holds the global
    // `agent:list` capability. Both are required for the full roster: a
    // bare `agent:list` grant does not satisfy the `self:agent:list`
    // preamble (the grammar does not make a global cap imply its
    // self-scoped form), so in practice only the `admin` group's `*`
    // (which matches both) sees everyone. This realises the gateway's
    // documented "the kernel filters server-side" contract.
    if !caller_has_global_agent_list(kernel, caller) {
        summaries.retain(|s| s.principal == *caller);
    }

    AdminResponseBody::AgentList(summaries)
}

// ── Per-principal grants / revokes ─────────────────────────────────────

enum CapsMutation {
    /// Add capabilities to `profile.grants`. `unsafe_admin` is required
    /// when the patterns include the universal `*` pattern — mirrors the
    /// group-level rail so an individual grant cannot silently escalate
    /// a principal to universal admin.
    Grant {
        unsafe_admin: bool,
    },
    Revoke,
}

async fn mutate_caps(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    capabilities: Vec<String>,
    which: CapsMutation,
) -> AdminResponseBody {
    if capabilities.is_empty() {
        return err_bad_input("capabilities must not be empty".to_string());
    }
    for cap in &capabilities {
        if let Err(e) = validate_capability(cap) {
            return err_bad_input(format!("capability {cap:?} rejected: {e}"));
        }
    }

    // `caps.grant <agent> "*"` must be acknowledged via `unsafe_admin =
    // true`. Mirrors `group_create`'s rail (see groups/mod.rs:UNIVERSAL_
    // WITHOUT_UNSAFE_ADMIN_ERROR) — without this, an individual grant
    // bypasses the group-level safety check and silently promotes a
    // principal to universal admin. The check is scoped to a literal
    // bare `*` cap; multi-segment wildcards (`network:egress:*`) are
    // inherently scoped and not affected.
    if let CapsMutation::Grant { unsafe_admin } = &which
        && !*unsafe_admin
        && capabilities.iter().any(|c| c == "*")
    {
        return err_bad_input(format!(
            "caps.grant rejected: granting `*` to {principal} confers universal admin; \
             pass `unsafe_admin = true` (CLI: `--unsafe-admin`) to confirm this elevation"
        ));
    }

    // Refuse to revoke from `default` — it is the bootstrap admin
    // anchor and any revoke risks locking the operator out
    // (`self:*`, `*`, or `system:shutdown`-shaped revokes all bite).
    // Grants on `default` are still allowed; they only add power.
    if matches!(which, CapsMutation::Revoke) && principal == &PrincipalId::default() {
        return err_bad_input(
            "cannot revoke capabilities from the `default` principal — it is the \
             single-tenant bootstrap anchor"
                .to_string(),
        );
    }

    let _guard = kernel.admin_write_lock.lock().await;
    let path = principal_profile_path(kernel, principal);
    if let Err(msg) = require_principal_exists(principal, &path) {
        return err_bad_input(msg);
    }
    let mut profile = match PrincipalProfile::load_from_path(&path) {
        Ok(p) => p,
        Err(e) => return err_profile(principal, &e),
    };

    // Grant-after-revoke must NOT clear the matching revoke — Layer 5
    // precedence is revoke > grant, so we just append. Revoke-after-grant
    // leaves the grant in place; the revoke wins at check time.
    //
    // Dedup against the target vec: repeated `caps.grant`/`caps.revoke`
    // of the same string is idempotent. Without this, scripts that
    // re-apply the same grant on each run would unboundedly grow
    // `profile.toml` and slow `CapabilityCheck::has` on the linear
    // grant/revoke scan.
    let target = match which {
        CapsMutation::Grant { .. } => &mut profile.grants,
        CapsMutation::Revoke => &mut profile.revokes,
    };
    for cap in &capabilities {
        if !target.iter().any(|existing| existing == cap) {
            target.push(cap.clone());
        }
    }

    if let Err(e) = profile.save_to_path(&path) {
        return err_profile(principal, &e);
    }
    kernel.profile_cache.invalidate(principal);
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "capabilities": capabilities,
    }))
}

// ── Helpers ────────────────────────────────────────────────────────────

pub(crate) fn principal_profile_path(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
) -> PathBuf {
    PrincipalProfile::path_for(&kernel.astrid_home, principal)
}

/// Reject mutating-handler calls that target a principal with no
/// `profile.toml` on disk. Required because
/// [`PrincipalProfile::load_from_path`] returns `Default` on `NotFound`,
/// which would let a typo'd name silently materialize a phantom
/// principal with grants on disk.
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

/// Mirror the read-only introspection furniture (installed-capsule registry
/// plus the `home://wit/` interface mirror) from the install principal's home
/// into a freshly-created principal's home, so its `system_status` /
/// `list_interfaces` reflect the globally-loaded capsule set, not an empty home.
///
/// Best-effort: callers invoke this AFTER the principal's home tree is
/// provisioned, so a sync failure must not fail the create/redeem — it only
/// degrades introspection visibility, and the boot sweep retries on next
/// daemon start. Env config (`.config/env/`) is deliberately excluded inside
/// [`astrid_capsule_install::materialize_principal_furniture`] for secret
/// isolation.
pub(super) async fn sync_principal_furniture(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) {
    // `materialize_principal_furniture` does synchronous recursive directory
    // copies. Run it on the blocking pool so it never pins a tokio worker, but
    // `.await` the handle so the furniture is materialized before this handler
    // returns — a freshly-created principal must have its introspection mirror
    // ready by the time `agent.create`/`invite.redeem` completes.
    let home = kernel.astrid_home.clone();
    let principal = principal.clone();
    let result = tokio::task::spawn_blocking(move || {
        astrid_capsule_install::materialize_principal_furniture(&home, &principal)
            .map_err(|e| (principal, e))
    })
    .await;
    match result {
        Ok(Ok(())) => {},
        Ok(Err((principal, e))) => {
            warn!(
                %principal,
                error = %format!("{e:#}"),
                "failed to materialize per-principal home furniture; \
                 introspection tools may not see the loaded capsule set"
            );
        },
        Err(join_err) => {
            warn!(
                error = %join_err,
                "per-principal home-furniture task panicked; \
                 introspection tools may not see the loaded capsule set"
            );
        },
    }
}

pub(super) fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request rejected: bad input");
    AdminResponseBody::Error(msg)
}

pub(super) fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request failed: internal error");
    AdminResponseBody::Error(msg)
}

pub(super) fn err_profile(principal: &PrincipalId, e: &ProfileError) -> AdminResponseBody {
    err_internal(format!("profile error for {principal}: {e}"))
}

pub(super) fn success_json(val: serde_json::Value) -> AdminResponseBody {
    AdminResponseBody::Success(val)
}
