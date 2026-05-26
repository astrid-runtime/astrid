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
use astrid_core::groups::{Group, GroupConfig};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{PrincipalProfile, ProfileError};
use astrid_events::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary, GroupSummary};
use tracing::{info, warn};

/// Platform label used by the identity store for agent principals
/// created via [`AdminRequestKind::AgentCreate`]. The per-principal
/// `platform_user_id` equals the `PrincipalId` string.
const AGENT_IDENTITY_PLATFORM: &str = "cli";

/// Dispatch an already-authorized [`AdminRequestKind`] to the matching
/// handler.
pub(super) async fn dispatch(
    kernel: &Arc<crate::Kernel>,
    req: AdminRequestKind,
) -> AdminResponseBody {
    match req {
        AdminRequestKind::AgentCreate {
            name,
            groups,
            grants,
        } => agent_create(kernel, name, groups, grants).await,
        AdminRequestKind::AgentDelete { principal } => agent_delete(kernel, principal).await,
        AdminRequestKind::AgentEnable { principal } => {
            agent_set_enabled(kernel, principal, true).await
        },
        AdminRequestKind::AgentDisable { principal } => {
            agent_set_enabled(kernel, principal, false).await
        },
        AdminRequestKind::AgentList => agent_list(kernel),
        AdminRequestKind::AgentModify {
            principal,
            add_groups,
            remove_groups,
        } => agent_modify(kernel, principal, add_groups, remove_groups).await,
        AdminRequestKind::QuotaSet { principal, quotas } => {
            quota_set(kernel, principal, quotas).await
        },
        AdminRequestKind::QuotaGet { principal } => quota_get(kernel, &principal),
        AdminRequestKind::GroupCreate {
            name,
            capabilities,
            description,
            unsafe_admin,
        } => group_create(kernel, name, capabilities, description, unsafe_admin).await,
        AdminRequestKind::GroupDelete { name } => group_delete(kernel, name).await,
        AdminRequestKind::GroupModify {
            name,
            capabilities,
            description,
            unsafe_admin,
        } => group_modify(kernel, name, capabilities, description, unsafe_admin).await,
        AdminRequestKind::GroupList => group_list(kernel),
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
    }
}

// ── Agent lifecycle ────────────────────────────────────────────────────

async fn agent_create(
    kernel: &Arc<crate::Kernel>,
    name: String,
    groups: Vec<String>,
    grants: Vec<String>,
) -> AdminResponseBody {
    let principal = match PrincipalId::new(name.clone()) {
        Ok(p) => p,
        Err(e) => return err_bad_input(format!("invalid principal name: {e}")),
    };

    // Reject bootstrap name: the `default` principal is seeded by
    // bootstrap_cli_root_user and must not be re-created through the
    // admin surface.
    if principal == PrincipalId::default() {
        return err_bad_input(format!(
            "principal {name:?} is reserved for single-tenant bootstrap"
        ));
    }

    let _guard = kernel.admin_write_lock.lock().await;
    let profile_path = principal_profile_path(kernel, &principal);

    // Collision: a profile on disk means this principal already exists.
    if profile_path.exists() {
        return err_bad_input(format!("principal {principal} already exists"));
    }

    let resolved_groups = if groups.is_empty() {
        vec![astrid_core::groups::BUILTIN_AGENT.to_string()]
    } else {
        groups
    };
    let profile = PrincipalProfile {
        groups: resolved_groups,
        grants,
        ..PrincipalProfile::default()
    };

    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }

    let user = match kernel
        .identity_store
        .create_user(Some(principal.as_str()))
        .await
    {
        Ok(u) => u,
        Err(e) => return err_internal(format!("identity store create_user failed: {e}")),
    };
    if let Err(e) = kernel
        .identity_store
        .link(
            AGENT_IDENTITY_PLATFORM,
            principal.as_str(),
            user.id,
            "system",
        )
        .await
    {
        // Best-effort rollback so partial state doesn't persist.
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("identity store link failed: {e}"));
    }

    if let Err(e) = profile.save_to_path(&profile_path) {
        let _ = kernel
            .identity_store
            .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        return err_internal(format!("profile save failed: {e}"));
    }

    // Provision the per-principal home tree so per-invocation KV, log,
    // tmp, secrets, audit, and capability tokens have a place to land.
    // Capsule WASM stays shared (loaded once from the system/default
    // location); only the principal-scoped data namespaces live here.
    //
    // Fail-closed: if the home tree cannot be created, downstream
    // per-invocation lookups silently fall back to the `default`
    // principal's namespace — a confidentiality break across tenants.
    // Roll back identity + profile so the agent isn't left in a state
    // where future invocations would leak into someone else's data.
    if let Err(e) = kernel.astrid_home.principal_home(&principal).ensure() {
        let _ = kernel
            .identity_store
            .unlink(AGENT_IDENTITY_PLATFORM, principal.as_str())
            .await;
        let _ = kernel.identity_store.delete_user(user.id).await;
        let _ = std::fs::remove_file(&profile_path);
        return err_internal(format!(
            "principal home tree provisioning failed (rolled back): {e}"
        ));
    }

    // Inherit `default`'s per-principal state so the new agent works
    // out of the box: env JSON (non-secret config like base URL /
    // model name), per-capsule KV namespaces, and per-capsule secret
    // files. Best-effort — a copy failure logs a warn and leaves the
    // agent in a "needs manual setup" state but doesn't roll back the
    // profile or the home tree (those already succeeded; the
    // confidentiality boundary is intact regardless).
    inherit_from_default(kernel, &principal).await;

    info!(%principal, user_id = %user.id, "Layer 6 agent.create");
    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "astrid_user_id": user.id,
    }))
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

async fn agent_modify(
    kernel: &Arc<crate::Kernel>,
    principal: PrincipalId,
    add_groups: Vec<String>,
    remove_groups: Vec<String>,
) -> AdminResponseBody {
    if add_groups.is_empty() && remove_groups.is_empty() {
        return err_bad_input(
            "agent.modify: at least one of `add_groups` or `remove_groups` must be non-empty"
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

    // Apply removes first so a (remove, add) of the same group is an
    // idempotent rename rather than a duplicate. Both ops are per-group
    // idempotent: adding present groups and removing absent ones are
    // no-ops.
    let before = profile.groups.clone();
    profile.groups.retain(|g| !remove_groups.contains(g));
    for g in &add_groups {
        if !profile.groups.iter().any(|existing| existing == g) {
            profile.groups.push(g.clone());
        }
    }

    // Set-based comparison: group membership is a set semantically, so
    // a no-op modify (adding present, removing absent, or add+remove
    // of the same group) should report `changed = false` regardless
    // of the underlying Vec's order. `retain` + `push` happens to
    // preserve the order of pre-existing groups today, but the
    // correctness of `changed` shouldn't depend on that implementation
    // detail.
    let before_set: std::collections::HashSet<&String> = before.iter().collect();
    let after_set: std::collections::HashSet<&String> = profile.groups.iter().collect();
    if before_set == after_set {
        kernel.profile_cache.invalidate(&principal);
        return success_json(serde_json::json!({
            "principal": principal.as_str(),
            "groups": profile.groups,
            "changed": false,
        }));
    }

    // Validate before saving: re-runs the profile invariants (group
    // names match groups.toml, grants/revokes still well-formed, etc.).
    // Without this an operator could `agent modify --add-group typo`
    // and the Layer 5 cap lookup would silently miss the typo'd group
    // at every authz check.
    if let Err(e) = profile.validate() {
        return err_bad_input(format!("profile rejected: {e}"));
    }

    if let Err(e) = profile.save_to_path(&path) {
        return err_profile(&principal, &e);
    }
    kernel.profile_cache.invalidate(&principal);

    info!(
        %principal,
        added = ?add_groups,
        removed = ?remove_groups,
        groups = ?profile.groups,
        "Layer 6 agent.modify"
    );

    success_json(serde_json::json!({
        "principal": principal.as_str(),
        "groups": profile.groups,
        "changed": true,
    }))
}

fn agent_list(kernel: &Arc<crate::Kernel>) -> AdminResponseBody {
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
    AdminResponseBody::AgentList(summaries)
}

// ── Quotas ─────────────────────────────────────────────────────────────

async fn quota_set(
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

fn quota_get(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) -> AdminResponseBody {
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

// ── Groups ─────────────────────────────────────────────────────────────

async fn group_create(
    kernel: &Arc<crate::Kernel>,
    name: String,
    capabilities: Vec<String>,
    description: Option<String>,
    unsafe_admin: bool,
) -> AdminResponseBody {
    let group = Group {
        capabilities,
        description,
        unsafe_admin,
    };
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.insert_custom_group(name, group) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.create rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

async fn group_delete(kernel: &Arc<crate::Kernel>, name: String) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.remove_group(&name) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.delete rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

// `Option<Option<String>>` intentionally encodes three states: `None` =
// keep existing description, `Some(None)` = clear it, `Some(Some(v))` =
// replace with `v`. Collapsing to a single `Option` would conflate "no
// change" with "clear" at the wire format. Clippy's `option_option` lint
// is overly cautious for partial-update APIs.
#[allow(clippy::option_option)]
async fn group_modify(
    kernel: &Arc<crate::Kernel>,
    name: String,
    capabilities: Option<Vec<String>>,
    description: Option<Option<String>>,
    unsafe_admin: Option<bool>,
) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    let current = kernel.groups.load_full();
    let next = match current.modify_custom_group(&name, capabilities, description, unsafe_admin) {
        Ok(n) => n,
        Err(e) => return err_bad_input(format!("group.modify rejected: {e}")),
    };
    commit_group_config(kernel, next)
}

fn group_list(kernel: &Arc<crate::Kernel>) -> AdminResponseBody {
    let cfg = kernel.groups.load_full();
    let mut summaries: Vec<GroupSummary> = cfg
        .iter()
        .map(|(name, group)| GroupSummary {
            name: name.clone(),
            capabilities: group.capabilities.clone(),
            description: group.description.clone(),
            unsafe_admin: group.unsafe_admin,
            builtin: GroupConfig::is_builtin_name(name),
        })
        .collect();
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    AdminResponseBody::GroupList(summaries)
}

/// Commit a new [`GroupConfig`] to disk and the
/// [`ArcSwap`](arc_swap::ArcSwap). Caller must hold the admin write lock.
fn commit_group_config(kernel: &Arc<crate::Kernel>, next: GroupConfig) -> AdminResponseBody {
    let path = GroupConfig::path_for(&kernel.astrid_home);
    if let Err(e) = next.save_to_path(&path) {
        return err_internal(format!("groups.toml save failed: {e}"));
    }
    kernel.groups.store(Arc::new(next));
    success_json(serde_json::json!({ "status": "ok" }))
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

fn principal_profile_path(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) -> PathBuf {
    PrincipalProfile::path_for(&kernel.astrid_home, principal)
}

/// Reject mutating-handler calls that target a principal with no
/// `profile.toml` on disk. Required because
/// [`PrincipalProfile::load_from_path`] returns `Default` on `NotFound`,
/// which would let a typo'd name silently materialize a phantom
/// principal with grants on disk.
fn require_principal_exists(principal: &PrincipalId, path: &Path) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!(
            "principal {principal} does not exist (no profile.toml at {})",
            path.display()
        ))
    }
}

fn err_bad_input(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request rejected: bad input");
    AdminResponseBody::Error(msg)
}

fn err_internal(msg: String) -> AdminResponseBody {
    warn!(error = %msg, "admin request failed: internal error");
    AdminResponseBody::Error(msg)
}

fn err_profile(principal: &PrincipalId, e: &ProfileError) -> AdminResponseBody {
    err_internal(format!("profile error for {principal}: {e}"))
}

fn success_json(val: serde_json::Value) -> AdminResponseBody {
    AdminResponseBody::Success(val)
}

// ── agent.create: inherit `default`'s per-principal state ──────────────

/// Copy `default`'s env JSON, per-capsule KV namespaces, and
/// per-capsule secret files into the new principal's slots so the
/// agent works out of the box.
///
/// Best-effort: any single failure logs at `warn` and the rest of the
/// inheritance proceeds. The home tree already exists by the time
/// this is called (its absence is what makes the parent fail-closed
/// rollback necessary, not this).
async fn inherit_from_default(kernel: &Arc<crate::Kernel>, principal: &PrincipalId) {
    if principal == &PrincipalId::default() {
        return;
    }
    let default = PrincipalId::default();

    copy_env_dir(kernel, &default, principal);

    // Snapshot manifest data under the registry lock, then drop it
    // before any async / blocking I/O. Holding the read lock across
    // `copy_kv_namespaces` (async KV) and `copy_secret_files`
    // (blocking fs) would serialise every concurrent install / update
    // / remove against the inherit path for as long as the copy ran.
    let (capsule_ids, secret_keys_by_capsule): (
        Vec<astrid_capsule::capsule::CapsuleId>,
        Vec<(astrid_capsule::capsule::CapsuleId, Vec<String>)>,
    ) = {
        let registry = kernel.capsules.read().await;
        let ids: Vec<_> = registry.list().into_iter().cloned().collect();
        let mut secrets: Vec<(astrid_capsule::capsule::CapsuleId, Vec<String>)> = Vec::new();
        for id in &ids {
            if let Some(capsule) = registry.get(id) {
                let keys: Vec<String> = capsule
                    .manifest()
                    .env
                    .iter()
                    .filter(|(_, def)| def.env_type == "secret")
                    .map(|(k, _)| k.clone())
                    .collect();
                if !keys.is_empty() {
                    secrets.push((id.clone(), keys));
                }
            }
        }
        (ids, secrets)
    };

    let total_keys = copy_kv_namespaces(kernel, &default, principal, &capsule_ids).await;
    let (probed_secrets, copied_secrets) =
        copy_secret_files(kernel, &default, principal, &secret_keys_by_capsule);

    info!(
        %principal,
        total_keys,
        copied_secrets,
        probed_secrets,
        "agent.create: inherited default's env JSON + KV namespaces + secrets"
    );
}

fn copy_env_dir(kernel: &Arc<crate::Kernel>, default: &PrincipalId, principal: &PrincipalId) {
    let default_env = kernel.astrid_home.principal_home(default).env_dir();
    let agent_env = kernel.astrid_home.principal_home(principal).env_dir();
    if !default_env.is_dir() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&agent_env) {
        tracing::warn!(%principal, error = %e, "agent.create: env_dir mkdir failed");
        return;
    }
    let Ok(entries) = std::fs::read_dir(&default_env) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let src = entry.path();
        let dst = agent_env.join(&name);
        if let Err(e) = std::fs::copy(&src, &dst) {
            tracing::warn!(
                %principal,
                file = %name.to_string_lossy(),
                error = %e,
                "agent.create: env JSON copy failed"
            );
        }
    }
}

async fn copy_kv_namespaces(
    kernel: &Arc<crate::Kernel>,
    default: &PrincipalId,
    principal: &PrincipalId,
    capsule_ids: &[astrid_capsule::capsule::CapsuleId],
) -> usize {
    use astrid_storage::KvStore;
    let mut total_keys = 0usize;
    for capsule_id in capsule_ids {
        let src_ns = format!("{default}:capsule:{capsule_id}");
        let dst_ns = format!("{principal}:capsule:{capsule_id}");
        let keys = match kernel.kv.list_keys(&src_ns).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    error = %e,
                    "agent.create: KV list_keys failed for capsule namespace"
                );
                continue;
            },
        };
        if !keys.is_empty() {
            info!(
                %principal,
                capsule_id = %capsule_id,
                key_count = keys.len(),
                src_ns = %src_ns,
                "agent.create: copying KV namespace"
            );
            total_keys = total_keys.saturating_add(keys.len());
        }
        for key in keys {
            match kernel.kv.get(&src_ns, &key).await {
                Ok(Some(value)) => {
                    if let Err(e) = kernel.kv.set(&dst_ns, &key, value).await {
                        tracing::warn!(
                            %principal,
                            capsule_id = %capsule_id,
                            key = %key,
                            error = %e,
                            "agent.create: KV copy write failed"
                        );
                    }
                },
                Ok(None) => { /* benign race: key disappeared between list and get */ },
                Err(e) => {
                    tracing::warn!(
                        %principal,
                        capsule_id = %capsule_id,
                        key = %key,
                        error = %e,
                        "agent.create: KV copy read failed"
                    );
                },
            }
        }
    }
    total_keys
}

fn copy_secret_files(
    kernel: &Arc<crate::Kernel>,
    default: &PrincipalId,
    principal: &PrincipalId,
    secret_keys_by_capsule: &[(astrid_capsule::capsule::CapsuleId, Vec<String>)],
) -> (usize, usize) {
    use astrid_storage::{FileSecretStore, SecretStore};
    let mut probed = 0usize;
    let mut copied = 0usize;
    let secrets_root = kernel.astrid_home.secrets_dir();
    for (capsule_id, secret_keys) in secret_keys_by_capsule {
        let src = FileSecretStore::new(
            secrets_root
                .join(default.as_str())
                .join(capsule_id.as_str()),
        );
        let dst = FileSecretStore::new(
            secrets_root
                .join(principal.as_str())
                .join(capsule_id.as_str()),
        );
        for key in secret_keys {
            probed = probed.saturating_add(1);
            let value = match src.get(key) {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        %principal,
                        capsule_id = %capsule_id,
                        key = %key,
                        error = %e,
                        security_event = true,
                        "agent.create: secret read failed for default's slot"
                    );
                    continue;
                },
            };
            if let Err(e) = dst.set(key, &value) {
                tracing::warn!(
                    %principal,
                    capsule_id = %capsule_id,
                    key = %key,
                    error = %e,
                    security_event = true,
                    "agent.create: secret write failed for new principal"
                );
            } else {
                copied = copied.saturating_add(1);
            }
        }
    }
    (probed, copied)
}
