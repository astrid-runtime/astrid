//! Per-principal capsule-access resolution for the dispatch hot path.
//!
//! Closes the security gap where the capsule **tool surface was global**:
//! any principal could invoke any installed capsule's tools because
//! dispatch matched on topic alone. Access is now **per-principal**, gated
//! by the kernel at dispatch on the user-invocable surface only
//! (`tool.v1.execute.*`, `cli.v1.command.execute`); see
//! [`crate::dispatcher`].
//!
//! # The grant set
//!
//! A principal may invoke a capsule only if the capsule's
//! [`CapsuleId`](crate::capsule::CapsuleId) is in that principal's
//! [`PrincipalProfile::capsules`](astrid_core::profile::PrincipalProfile)
//! grant set, **or** the principal is an admin (holds the `*` capability),
//! which bypasses the filter entirely. New principals get no capsule access
//! by default; the bootstrap `default`/admin principal is unaffected via the
//! `*` bypass (we never special-case by name).
//!
//! # Hot-path discipline
//!
//! Dispatch is the per-event hot path (cf. the #813 worker-starvation
//! cliffs). Resolution must be cheap and lock-free under steady state:
//! - The grant set + admin status come from the in-memory
//!   [`PrincipalProfileCache`], whose [`resolve`](PrincipalProfileCache::resolve)
//!   takes only an `RwLock` **read** after the first miss per principal —
//!   the same machinery `authorize_request` uses kernel-side, and the same
//!   no-hot-path-write rule the fuel/memory ledgers follow.
//! - The group config is read through an [`ArcSwap`] load (lock-free), so a
//!   runtime group mutation (e.g. adding a principal to `admin`) is observed
//!   on the next event without a daemon restart, matching the kernel's own
//!   `kernel.groups.load_full()` per-check read.
//!
//! Mirroring the ledger pattern, one resolver is built kernel-side and
//! cloned (cheap `Arc` clones) into the dispatcher.
//!
//! # Fail-closed
//!
//! An unknown / `None` / `anonymous` caller, or any profile-resolution
//! error, yields **no** capsule access — never default-allow.

use std::sync::Arc;

use arc_swap::ArcSwap;
use astrid_capabilities::CapabilityCheck;
use astrid_core::GroupConfig;
use astrid_core::principal::PrincipalId;
use tracing::warn;

use crate::capsule::CapsuleId;
use crate::profile_cache::PrincipalProfileCache;

/// Topic prefix for the user-invocable **tool execute** surface. A tool
/// invocation is `tool.v1.execute.<name>` — a single segment after this
/// prefix. Result-delivery sub-topics (`...<name>.result`, `...result`) are
/// deliberately NOT gated; see [`is_user_invocable_surface`].
const TOOL_EXECUTE_PREFIX: &str = "tool.v1.execute.";

/// The user-invocable **CLI command execute** topic. Matched exactly.
const CLI_COMMAND_EXECUTE_TOPIC: &str = "cli.v1.command.execute";

/// Is `topic` part of the **user-invocable surface** that the per-principal
/// capsule-access filter gates? Co-located with the resolver because it
/// defines *which* topics the grant set applies to.
///
/// CRITICAL SCOPING: only `tool.v1.execute.<name>` and
/// `cli.v1.command.execute` are gated. Every other topic — the internal
/// orchestration mesh (`session.*`, `spark.*`, `registry.*`,
/// `prompt_builder.*`, `context_engine.*`, lifecycle/hooks, llm streams) AND
/// tool-result delivery (`tool.v1.execute.<name>.result`, react's bare
/// `tool.v1.execute.result`) — dispatches UNCHANGED, or the runtime wedges. A
/// dual-role capsule (e.g. `identity` handling both
/// `tool.v1.execute.save_identity` and `spark.v1.request.build`) has its tool
/// gated while its orchestration role stays open: the gate is keyed on the
/// **topic**, not the capsule.
#[must_use]
pub(crate) fn is_user_invocable_surface(topic: &str) -> bool {
    if topic == CLI_COMMAND_EXECUTE_TOPIC {
        return true;
    }
    // A tool INVOCATION is exactly `tool.v1.execute.<name>` — a single
    // segment after the prefix. Result-delivery topics must NOT be gated:
    // `tool.v1.execute.<name>.result` (router `handle_execute_result`) and
    // react's bare `tool.v1.execute.result` (`handle_tool_result`) are handled
    // by orchestration capsules that are never in a principal's grant set, so
    // gating them would drop every tool result and hang the turn. Match only a
    // single, non-`result` segment after the prefix.
    match topic.strip_prefix(TOOL_EXECUTE_PREFIX) {
        Some(name) => !name.is_empty() && !name.contains('.') && name != "result",
        None => false,
    }
}

/// Publish a grant-on-first-use [`astrid_events::ipc::IpcPayload::GrantRequired`]
/// signal on `astrid.v1.approval` for an access-gate miss (#998), so a
/// broker/shim can elicit consent and, on approve, the kernel grants the
/// capsule. Co-located with the access gate it serves.
///
/// Synchronous fire-and-forget: `event_bus.publish` never blocks, so the
/// dispatch hot path takes no new lock or `.await`. The `request_id` is a fresh
/// unguessable UUID the broker keys the response on. The message carries a nil
/// `source_id` (kernel-originated): the kernel's grant handler only honours
/// nil-sourced `GrantRequired`, so this must stay kernel-published.
pub(crate) fn emit_grant_required(
    event_bus: &astrid_events::EventBus,
    principal: &str,
    capsule_id: String,
) {
    let request_id = uuid::Uuid::new_v4().to_string();
    let payload = astrid_events::ipc::IpcPayload::GrantRequired {
        request_id,
        principal: principal.to_string(),
        capsule_id,
    };
    let message = astrid_events::ipc::IpcMessage::new(
        astrid_events::ipc::Topic::approval_request(),
        payload,
        uuid::Uuid::nil(), // Kernel-originated; the grant handler requires nil source.
    )
    .with_principal(principal.to_string());
    event_bus.publish(astrid_events::AstridEvent::Ipc {
        message,
        metadata: astrid_events::EventMetadata::new("dispatcher"),
    });
}

/// Resolves whether a principal may invoke a given capsule, for the
/// dispatcher's user-invocable-surface filter.
///
/// Bundles the kernel-owned [`PrincipalProfileCache`] (grant set + admin
/// status) and the live [`GroupConfig`] (admin via group-inherited `*`).
/// Cloning is cheap — both fields are `Arc`.
#[derive(Clone)]
pub struct CapsuleAccessResolver {
    /// Per-principal profile cache. First resolve for a principal reads
    /// disk; subsequent resolves are an `RwLock`-read `Arc` clone.
    profile_cache: Arc<PrincipalProfileCache>,
    /// Live group config. Read via a lock-free [`ArcSwap`] load so admin
    /// status reflects runtime group mutations without a restart.
    groups: Arc<ArcSwap<GroupConfig>>,
}

impl std::fmt::Debug for CapsuleAccessResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The cache and group config are large and not useful here; only
        // identify the type so `#[derive(Debug)]` consumers compile.
        f.debug_struct("CapsuleAccessResolver")
            .finish_non_exhaustive()
    }
}

impl CapsuleAccessResolver {
    /// Build a resolver from the kernel-owned profile cache and live group
    /// config.
    #[must_use]
    pub fn new(
        profile_cache: Arc<PrincipalProfileCache>,
        groups: Arc<ArcSwap<GroupConfig>>,
    ) -> Self {
        Self {
            profile_cache,
            groups,
        }
    }

    /// Return `true` if `principal` may invoke `capsule`.
    ///
    /// Resolution order:
    /// 1. **Fail-closed identity gate** — a `None`, empty, `anonymous`, or
    ///    syntactically invalid principal yields `false` (no grant set).
    /// 2. **Profile resolve** — a resolution error (malformed TOML, IO
    ///    error) yields `false`. Never default-allow on error.
    /// 3. **Admin bypass** — a caller holding `*` (directly, via a grant,
    ///    or via an `admin`-group `*`) returns `true` for any capsule.
    /// 4. **Grant-set membership** — otherwise, `true` iff the capsule id
    ///    appears in the principal's `capsules` grant set.
    ///
    /// `principal` is the kernel-stamped value carried on the originating
    /// IPC message — never a capsule- or caller-supplied claim — so a
    /// principal cannot forge its way past the filter.
    #[must_use]
    pub fn is_capsule_allowed(&self, principal: Option<&str>, capsule: &CapsuleId) -> bool {
        // (1) Identity gate. `anonymous` is the explicit unauthenticated
        // sentinel; treat it like an absent principal — no grant set.
        let Some(principal_str) = principal else {
            return false;
        };
        if principal_str.is_empty() || principal_str == "anonymous" {
            return false;
        }
        let Ok(pid) = PrincipalId::new(principal_str) else {
            warn!(
                security_event = true,
                principal = %principal_str,
                "Capsule-access check: invalid principal string — deny (fail-closed)"
            );
            return false;
        };

        // (2) Profile resolve. Fail-closed on any error.
        let profile = match self.profile_cache.resolve(&pid) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    security_event = true,
                    principal = %pid,
                    error = %e,
                    "Capsule-access check: profile resolution failed — deny (fail-closed)"
                );
                return false;
            },
        };

        // (3) Admin bypass — reuse the SAME machinery `authorize_request`
        // uses. A `*` holder (admin) bypasses the per-principal filter.
        let groups = self.groups.load();
        let check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid);
        if check.has("*") {
            return true;
        }

        // (4) Grant-set membership.
        profile
            .capsules
            .iter()
            .any(|granted| granted == capsule.as_str())
    }

    /// Return true when the caller may bypass principal-view narrowing.
    #[must_use]
    pub fn is_admin(&self, principal: Option<&str>) -> bool {
        let Some(principal_str) = principal else {
            return false;
        };
        if principal_str.is_empty() || principal_str == "anonymous" {
            return false;
        }
        let Ok(pid) = PrincipalId::new(principal_str) else {
            return false;
        };
        let Ok(profile) = self.profile_cache.resolve(&pid) else {
            return false;
        };
        let groups = self.groups.load();
        CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid).has("*")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_core::dirs::AstridHome;
    use astrid_core::groups::{BUILTIN_ADMIN, GroupConfig};
    use astrid_core::profile::PrincipalProfile;

    fn fixture() -> (tempfile::TempDir, AstridHome, CapsuleAccessResolver) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
        (dir, home, CapsuleAccessResolver::new(cache, groups))
    }

    fn write(home: &AstridHome, principal: &str, profile: &PrincipalProfile) {
        let pid = PrincipalId::new(principal).unwrap();
        profile.save(home, &pid).expect("save");
    }

    fn cap(id: &str) -> CapsuleId {
        CapsuleId::from_static(id)
    }

    #[test]
    fn none_principal_denied() {
        let (_d, _h, r) = fixture();
        assert!(!r.is_capsule_allowed(None, &cap("identity")));
    }

    #[test]
    fn empty_and_anonymous_denied() {
        let (_d, _h, r) = fixture();
        assert!(!r.is_capsule_allowed(Some(""), &cap("identity")));
        assert!(!r.is_capsule_allowed(Some("anonymous"), &cap("identity")));
    }

    #[test]
    fn invalid_principal_string_denied() {
        let (_d, _h, r) = fixture();
        // Contains characters a PrincipalId rejects.
        assert!(!r.is_capsule_allowed(Some("bad/principal"), &cap("identity")));
    }

    #[test]
    fn ungranted_denied_granted_allowed() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "alice",
            &PrincipalProfile {
                capsules: vec!["identity".into()],
                ..PrincipalProfile::default()
            },
        );
        assert!(r.is_capsule_allowed(Some("alice"), &cap("identity")));
        assert!(!r.is_capsule_allowed(Some("alice"), &cap("registry")));
    }

    #[test]
    fn admin_bypasses() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "root",
            &PrincipalProfile {
                groups: vec![BUILTIN_ADMIN.to_string()],
                ..PrincipalProfile::default()
            },
        );
        // Admin holds `*`, so any capsule is allowed without an explicit grant.
        assert!(r.is_capsule_allowed(Some("root"), &cap("identity")));
        assert!(r.is_capsule_allowed(Some("root"), &cap("anything-else")));
    }

    #[test]
    fn unknown_principal_denied_no_profile() {
        let (_d, _h, r) = fixture();
        // No profile on disk → default profile → empty grant set → deny.
        assert!(!r.is_capsule_allowed(Some("ghost"), &cap("identity")));
    }

    #[test]
    fn resolve_error_denies() {
        let (_d, home, r) = fixture();
        let pid = PrincipalId::new("broken").unwrap();
        let path = home.profile_path(&pid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Future profile_version fails validation → resolve returns Err.
        std::fs::write(&path, "profile_version = 9999\n").unwrap();
        assert!(!r.is_capsule_allowed(Some("broken"), &cap("identity")));
    }
}
