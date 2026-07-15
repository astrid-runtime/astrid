//! Per-principal capsule-access resolution for the dispatch hot path.
//!
//! Closes the security gap where the capsule **tool surface was global**:
//! any principal could invoke any installed capsule's tools because
//! dispatch matched on topic alone. Access is now **per-principal**, gated
//! by the kernel at dispatch on the user-invocable surface only
//! (`tool.v1.execute.*`, `cli.v1.command.run.*`); see
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
use astrid_core::profile::{DeviceKeyId, PrincipalProfile};
use tracing::warn;

use crate::capsule::CapsuleId;
use crate::profile_cache::PrincipalProfileCache;

/// Topic prefix for the user-invocable **tool execute** surface. A tool
/// invocation is `tool.v1.execute.<name>` — a single segment after this
/// prefix. Result-delivery sub-topics (`...<name>.result`, `...result`) are
/// deliberately NOT gated; see [`is_user_invocable_surface`]. Shared with the
/// load-time route check via [`crate::topic`].
use crate::topic::TOOL_EXECUTE_PREFIX;

/// Topic prefix for the user-invocable **CLI command run** surface.
/// A capsule command invocation is `cli.v1.command.run.<provider>`.
const CLI_COMMAND_RUN_PREFIX: &str = "cli.v1.command.run.";

/// Exact internal capability for unrestricted capsule execution.
const CAPSULE_ACCESS_ANY: &str = "capsule:access:any";

/// Is `topic` part of the **user-invocable surface** that the per-principal
/// capsule-access filter gates? Co-located with the resolver because it
/// defines *which* topics the grant set applies to.
///
/// CRITICAL SCOPING: only `tool.v1.execute.<name>` and
/// `cli.v1.command.run.<provider>` are gated. Every other topic — the internal
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
    if topic
        .strip_prefix(CLI_COMMAND_RUN_PREFIX)
        .is_some_and(|provider| !provider.is_empty() && !provider.contains('.'))
    {
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

/// Immutable authority inputs for one dispatched event.
pub(crate) struct ResolvedCapsuleAccess {
    principal: PrincipalId,
    profile: Arc<PrincipalProfile>,
    groups: Arc<GroupConfig>,
    has_global_capsule_view: bool,
    has_unrestricted_capsule_access: bool,
}

impl ResolvedCapsuleAccess {
    #[must_use]
    pub(crate) fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub(crate) fn has_global_capsule_view(&self) -> bool {
        self.has_global_capsule_view
    }

    #[must_use]
    pub(crate) fn has_unrestricted_capsule_access(&self) -> bool {
        self.has_unrestricted_capsule_access
    }

    #[must_use]
    pub(crate) fn is_capsule_allowed(&self, capsule: &CapsuleId) -> bool {
        if self.has_unrestricted_capsule_access() {
            return true;
        }
        self.profile
            .capsules
            .iter()
            .any(|granted| granted == capsule.as_str())
    }
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

    /// Resolve one immutable authority snapshot for a dispatched event.
    #[must_use]
    pub(crate) fn resolve_access(
        &self,
        principal: Option<&str>,
        device_key_id: Option<&str>,
    ) -> Option<ResolvedCapsuleAccess> {
        let principal_str = principal?;
        if principal_str.is_empty() || principal_str == "anonymous" {
            return None;
        }
        let pid = match PrincipalId::new(principal_str) {
            Ok(pid) => pid,
            Err(error) => {
                warn!(
                    security_event = true,
                    principal = %principal_str,
                    %error,
                    "Capsule-access check: invalid principal string — deny (fail-closed)"
                );
                return None;
            },
        };
        let profile = match self.profile_cache.resolve(&pid) {
            Ok(profile) => profile,
            Err(error) => {
                warn!(
                    security_event = true,
                    principal = %pid,
                    %error,
                    "Capsule-access check: profile resolution failed — deny (fail-closed)"
                );
                return None;
            },
        };
        if !profile.enabled {
            warn!(
                security_event = true,
                principal = %pid,
                "Capsule-access check: disabled principal — deny (fail-closed)"
            );
            return None;
        }
        let device_scope = match device_key_id {
            None => None,
            Some(raw_key_id) => {
                let key_id = match DeviceKeyId::new(raw_key_id) {
                    Ok(key_id) => key_id,
                    Err(error) => {
                        warn!(
                            security_event = true,
                            principal = %pid,
                            key_id = %raw_key_id,
                            %error,
                            "Capsule-access check: invalid device key id — deny (fail-closed)"
                        );
                        return None;
                    },
                };
                let Some(device) = profile.auth.device_by_typed_key_id(&key_id) else {
                    warn!(
                        security_event = true,
                        principal = %pid,
                        key_id = %raw_key_id,
                        "Capsule-access check: device key id is not registered — deny (fail-closed)"
                    );
                    return None;
                };
                Some(device.scope.clone())
            },
        };

        let groups = self.groups.load_full();
        let mut device_check = CapabilityCheck::new(profile.as_ref(), groups.as_ref(), pid.clone());
        if let Some(scope) = &device_scope {
            device_check = device_check.with_device_scope(scope);
        }
        let has_global_capsule_view = device_check.has("capsule:list");
        let has_unrestricted_capsule_access = device_check.has(CAPSULE_ACCESS_ANY);

        Some(ResolvedCapsuleAccess {
            principal: pid,
            profile,
            groups,
            has_global_capsule_view,
            has_unrestricted_capsule_access,
        })
    }

    /// Return whether `principal` may invoke `capsule`.
    /// Invalid identities fail closed; exact `capsule:access:any` bypasses the
    /// principal's exact capsule grant set.
    #[must_use]
    pub fn is_capsule_allowed(&self, principal: Option<&str>, capsule: &CapsuleId) -> bool {
        self.resolve_access(principal, None)
            .is_some_and(|access| access.is_capsule_allowed(capsule))
    }

    /// Return true when the caller may bypass principal-view narrowing.
    #[must_use]
    pub fn is_admin(&self, principal: Option<&str>) -> bool {
        self.resolve_access(principal, None).is_some_and(|access| {
            CapabilityCheck::new(
                access.profile.as_ref(),
                access.groups.as_ref(),
                access.principal.clone(),
            )
            .has("*")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_core::dirs::AstridHome;
    use astrid_core::groups::{BUILTIN_ADMIN, Group, GroupConfig};
    use astrid_core::profile::{AuthConfig, AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};

    fn fixture() -> (tempfile::TempDir, AstridHome, CapsuleAccessResolver) {
        let (dir, home, _cache, resolver) = fixture_with_cache();
        (dir, home, resolver)
    }

    fn fixture_with_cache() -> (
        tempfile::TempDir,
        AstridHome,
        Arc<PrincipalProfileCache>,
        CapsuleAccessResolver,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
        let resolver = CapsuleAccessResolver::new(Arc::clone(&cache), groups);
        (dir, home, cache, resolver)
    }

    fn write(home: &AstridHome, principal: &str, profile: &PrincipalProfile) {
        let pid = PrincipalId::new(principal).unwrap();
        profile.save(home, &pid).expect("save");
    }

    fn cap(id: &str) -> CapsuleId {
        CapsuleId::from_static(id)
    }

    fn device(seed: char, scope: DeviceScope) -> DeviceKey {
        DeviceKey::new(seed.to_string().repeat(64), scope, None, 0)
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

    #[test]
    fn device_scope_attenuates_admin_bypass() {
        let (_d, home, r) = fixture();
        let full = device('a', DeviceScope::Full);
        let list_only = device(
            'b',
            DeviceScope::Scoped {
                allow: vec!["capsule:list".into()],
                deny: Vec::new(),
            },
        );
        let access_any = device(
            'c',
            DeviceScope::Scoped {
                allow: vec!["capsule:access:any".into()],
                deny: Vec::new(),
            },
        );
        let access_denied = device(
            'd',
            DeviceScope::Scoped {
                allow: vec!["*".into()],
                deny: vec!["capsule:access:any".into()],
            },
        );
        let ids = [
            full.key_id.clone(),
            list_only.key_id.clone(),
            access_any.key_id.clone(),
            access_denied.key_id.clone(),
        ];
        write(
            &home,
            "root",
            &PrincipalProfile {
                groups: vec![BUILTIN_ADMIN.to_string()],
                capsules: vec!["identity".into()],
                auth: AuthConfig {
                    methods: vec![AuthMethod::Keypair],
                    public_keys: vec![full, list_only, access_any, access_denied],
                },
                ..PrincipalProfile::default()
            },
        );

        let no_device = r.resolve_access(Some("root"), None).unwrap();
        let full = r.resolve_access(Some("root"), Some(&ids[0])).unwrap();
        let list_only = r.resolve_access(Some("root"), Some(&ids[1])).unwrap();
        let access_any = r.resolve_access(Some("root"), Some(&ids[2])).unwrap();
        let denied = r.resolve_access(Some("root"), Some(&ids[3])).unwrap();
        assert!(no_device.is_capsule_allowed(&cap("registry")));
        assert!(full.is_capsule_allowed(&cap("registry")));
        assert!(list_only.has_global_capsule_view());
        assert!(!list_only.is_capsule_allowed(&cap("registry")));
        assert!(access_any.has_unrestricted_capsule_access());
        assert!(access_any.is_capsule_allowed(&cap("registry")));
        assert!(!denied.is_capsule_allowed(&cap("registry")));
        assert!(list_only.is_capsule_allowed(&cap("identity")));
        assert!(denied.is_capsule_allowed(&cap("identity")));
    }

    #[test]
    fn global_capsule_view_does_not_bypass_capsule_grants() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "operator",
            &PrincipalProfile {
                grants: vec!["capsule:list".into()],
                capsules: vec!["identity".into()],
                ..PrincipalProfile::default()
            },
        );

        let access = r.resolve_access(Some("operator"), None).unwrap();
        assert!(access.has_global_capsule_view());
        assert!(access.is_capsule_allowed(&cap("identity")));
        assert!(!access.is_capsule_allowed(&cap("registry")));
    }

    #[test]
    fn disabled_principal_has_no_access_snapshot() {
        let (_d, home, r) = fixture();
        write(
            &home,
            "disabled",
            &PrincipalProfile {
                enabled: false,
                groups: vec![BUILTIN_ADMIN.to_string()],
                capsules: vec!["identity".into()],
                ..PrincipalProfile::default()
            },
        );
        assert!(r.resolve_access(Some("disabled"), None).is_none());
    }

    #[test]
    fn group_changes_apply_to_the_next_access_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = Arc::new(PrincipalProfileCache::with_home(home.clone()));
        let groups = Arc::new(ArcSwap::from_pointee(GroupConfig::builtin_only()));
        let resolver = CapsuleAccessResolver::new(cache, Arc::clone(&groups));
        write(
            &home,
            "operator",
            &PrincipalProfile {
                groups: vec!["ops".into()],
                ..PrincipalProfile::default()
            },
        );

        let before = resolver.resolve_access(Some("operator"), None).unwrap();
        assert!(!before.has_global_capsule_view());
        assert!(!before.has_unrestricted_capsule_access());

        let promoted = GroupConfig::builtin_only()
            .insert_custom_group(
                "ops".into(),
                Group {
                    capabilities: vec!["*".into()],
                    description: None,
                    unsafe_admin: true,
                },
            )
            .unwrap();
        groups.store(Arc::new(promoted));
        let promoted = resolver.resolve_access(Some("operator"), None).unwrap();
        assert!(promoted.has_global_capsule_view());
        assert!(promoted.has_unrestricted_capsule_access());

        groups.store(Arc::new(GroupConfig::builtin_only()));
        let demoted = resolver.resolve_access(Some("operator"), None).unwrap();
        assert!(!demoted.has_global_capsule_view());
        assert!(!demoted.has_unrestricted_capsule_access());
    }

    #[test]
    fn malformed_unknown_and_revoked_device_ids_fail_closed() {
        let (_d, home, cache, r) = fixture_with_cache();
        let full = device('d', DeviceScope::Full);
        let full_id = full.key_id.clone();
        let mut profile = PrincipalProfile {
            groups: vec![BUILTIN_ADMIN.to_string()],
            auth: AuthConfig {
                methods: vec![AuthMethod::Keypair],
                public_keys: vec![full],
            },
            ..PrincipalProfile::default()
        };
        write(&home, "root", &profile);

        assert!(r.resolve_access(Some("root"), Some(&full_id)).is_some());
        assert!(
            r.resolve_access(Some("root"), Some("not-a-key-id"))
                .is_none()
        );
        assert!(
            r.resolve_access(Some("root"), Some("0000000000000000"))
                .is_none()
        );

        profile.auth.public_keys.clear();
        write(&home, "root", &profile);
        cache.invalidate(&PrincipalId::new("root").unwrap());
        assert!(r.resolve_access(Some("root"), Some(&full_id)).is_none());
    }

    #[test]
    fn one_dispatch_snapshot_cannot_fall_back_after_revocation() {
        let (_d, home, cache, r) = fixture_with_cache();
        let full = device('e', DeviceScope::Full);
        let full_id = full.key_id.clone();
        let mut profile = PrincipalProfile {
            groups: vec![BUILTIN_ADMIN.to_string()],
            auth: AuthConfig {
                methods: vec![AuthMethod::Keypair],
                public_keys: vec![full],
            },
            ..PrincipalProfile::default()
        };
        write(&home, "root", &profile);
        let in_flight = r.resolve_access(Some("root"), Some(&full_id)).unwrap();

        profile.auth.public_keys.clear();
        write(&home, "root", &profile);
        cache.invalidate(&PrincipalId::new("root").unwrap());

        assert!(in_flight.has_global_capsule_view());
        assert!(in_flight.is_capsule_allowed(&cap("registry")));
        assert!(r.resolve_access(Some("root"), Some(&full_id)).is_none());
    }
}
