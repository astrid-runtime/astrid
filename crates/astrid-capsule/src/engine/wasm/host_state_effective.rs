//! Per-principal `effective_*` overlay accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Admit one principal-scoped host operation and hold its lifecycle count
    /// until the returned guard drops.
    pub(crate) fn begin_host_operation(
        &self,
    ) -> Result<Option<crate::engine::wasm::PrincipalInvocationGuard>, ()> {
        if !self.invocation_authority_active() {
            return Err(());
        }
        self.principal_invocations
            .as_ref()
            .map(|tracker| tracker.begin(&self.effective_principal()).ok_or(()))
            .transpose()
    }
    /// Return the effective KV store for the current invocation.
    ///
    /// Per-principal isolation lives HERE, not in capsule keys. Every real store
    /// is namespaced `{principal}:capsule:{capsule_id}`, so two principals
    /// writing the *same* logical key — e.g. capsule-session's principal-less
    /// `session.data.{id}` — resolve to different backing namespaces and never
    /// collide. A capsule therefore must not (and need not) fold the principal
    /// into its own keys.
    ///
    /// Resolution: `invocation_kv` (installed for the current caller when an
    /// explicit system runtime multiplexes views) wins; otherwise the runtime's
    /// load-time [`kv`](HostState::kv). Principal runtimes are constructed with
    /// their owner's real namespace and are never reachable by a peer. System
    /// runtimes are constructed with a neutral namespace, so a principal-less
    /// system event cannot fall through into a human principal's state.
    #[must_use]
    pub fn effective_kv(&self) -> &ScopedKvStore {
        #[cfg(debug_assertions)]
        self.debug_assert_invocation_field_set(self.invocation_kv.is_some(), "invocation_kv");
        self.invocation_kv.as_ref().unwrap_or(&self.kv)
    }

    /// The current invocation's capsule KV namespace,
    /// `{effective_principal}:capsule:{capsule_id}`.
    ///
    /// Retained only for backward compatibility; superseded by
    /// [`effective_kv`](Self::effective_kv). This returns just a namespace
    /// STRING, so — unlike `effective_kv` — it cannot express the fail-closed,
    /// physically-isolated neutral placeholder that an explicit system runtime
    /// falls back to for a principal-less context; it can only ever name a
    /// `{principal}:capsule:{id}` namespace.
    ///
    /// The body anchors [`effective_principal`](Self::effective_principal) (the
    /// INVOKING principal, falling back to the load owner only when no caller is
    /// in scope), NOT the raw load owner, so a stray caller gets the current
    /// principal's namespace rather than the misleading owner-only value the
    /// shared-runtime model made incorrect. Prefer `effective_kv()`, which builds
    /// the correctly-scoped, fail-closed store directly.
    #[deprecated(
        since = "0.8.0",
        note = "use `effective_kv()` for the current invocation's per-principal store; this returns only a namespace string and cannot express the fail-closed/neutral fallback"
    )]
    #[must_use]
    pub fn principal_kv_namespace(&self) -> String {
        format!("{}:capsule:{}", self.effective_principal(), self.capsule_id)
    }

    /// Return the effective home mount for the current invocation.
    ///
    /// Prefers `invocation_home` (installed for the invoking principal) over the
    /// load-time `home`. Principal runtimes own that mount exclusively; an
    /// explicit system runtime has no load-time home and therefore fails closed
    /// for principal-less work.
    #[must_use]
    pub fn effective_home(&self) -> Option<&PrincipalMount> {
        self.invocation_home.as_ref().or(self.home.as_ref())
    }

    /// Return the effective tmp mount for the current invocation. Same
    /// precedence and same neutral-`None`-on-shared-runtime safety as
    /// [`effective_home`](Self::effective_home).
    #[must_use]
    pub fn effective_tmp(&self) -> Option<&PrincipalMount> {
        self.invocation_tmp.as_ref().or(self.tmp.as_ref())
    }

    /// Return the effective authoritative workspace branch for this call.
    ///
    /// Shared runtimes install `invocation_workspace` from the authenticated
    /// caller; principal runtimes use their load-time branch.
    #[must_use]
    pub fn effective_workspace(&self) -> Option<&PrincipalMount> {
        self.invocation_workspace
            .as_ref()
            .or(self.workspace.as_ref())
    }

    /// Return an owned native home root when the effective mount has one.
    ///
    /// Durable AstridFilesystem home mounts are logical and deliberately return
    /// `None`; this helper exists only for native scratch/lifecycle and process
    /// compatibility paths.
    #[must_use]
    pub fn effective_home_root_buf(&self) -> Option<PathBuf> {
        self.effective_home()
            .and_then(|mount| match &mount.location {
                PrincipalMountLocation::Native(root) => Some(root.clone()),
                PrincipalMountLocation::AstridFilesystem => None,
            })
    }

    /// Return the effective secret store for the current invocation.
    ///
    /// Prefers `invocation_secret_store` (set when serving a different
    /// principal) over the load-time `secret_store`.
    #[must_use]
    pub fn effective_secret_store(&self) -> &Arc<dyn SecretStore> {
        #[cfg(debug_assertions)]
        self.debug_assert_invocation_field_set(
            self.invocation_secret_store.is_some(),
            "invocation_secret_store",
        );
        self.invocation_secret_store
            .as_ref()
            .unwrap_or(&self.secret_store)
    }

    /// Return the effective capsule log file for the current invocation.
    ///
    /// Same precedence as [`effective_secret_store`](Self::effective_secret_store).
    /// Returns `None` if neither the invocation nor load-time log is open.
    #[must_use]
    pub fn effective_capsule_log(&self) -> Option<&Arc<std::sync::Mutex<std::fs::File>>> {
        self.invocation_capsule_log
            .as_ref()
            .or(self.capsule_log.as_ref())
    }

    /// Return the principal whose budget should be charged for host-fn
    /// side-effects in the current invocation.
    ///
    /// Prefers the invoking principal from [`caller_context`](Self::caller_context)
    /// (set per-invocation by [`WasmEngine::invoke_interceptor`](crate::engine::wasm::WasmEngine::invoke_interceptor))
    /// and falls back to the capsule owner's [`principal`](Self::principal) when
    /// no caller is in scope — load-time host calls, tests, and daemons'
    /// self-triggered paths run on the owner's budget, matching the VFS/KV
    /// `effective_*` accessors.
    #[must_use]
    pub fn effective_principal(&self) -> astrid_core::principal::PrincipalId {
        self.caller_context
            .as_ref()
            .and_then(|m| m.principal.as_deref())
            .and_then(|p| astrid_core::principal::PrincipalId::new(p).ok())
            .unwrap_or_else(|| self.principal.clone())
    }

    /// Return the host-stamped transport [`MessageOrigin`] of the request
    /// currently being served, for the local-egress consent decision.
    ///
    /// Read from the in-flight [`caller_context`](Self::caller_context) (set
    /// per-invocation by the dispatcher), falling back to
    /// [`System`](astrid_events::ipc::MessageOrigin::System) — the fail-closed,
    /// **non-local** floor — when no caller is in scope (load-time host calls,
    /// tests, a run-loop's self-triggered work). A non-`LocalSocket` origin
    /// never earns runtime local-egress consent, so an absent caller context can
    /// never accidentally grant a local exemption. Mirrors
    /// [`effective_principal`](Self::effective_principal): the same
    /// host-populated, never-guest-supplied caller context drives both.
    #[must_use]
    pub fn effective_origin(&self) -> astrid_events::ipc::MessageOrigin {
        self.caller_context
            .as_ref()
            .map(|m| m.origin)
            .unwrap_or(astrid_events::ipc::MessageOrigin::System)
    }

    /// Return the effective cancellation token for the current invocation's
    /// blocking host calls: the per-principal
    /// [`invocation_cancel_token`](Self::invocation_cancel_token) overlay when
    /// installed, else the instance [`cancel_token`](Self::cancel_token).
    ///
    /// DELIBERATELY unlike the KV/secret overlays, the fallback here is the
    /// INSTANCE token, not a neutral deny: cancellation is a liveness concern,
    /// not data isolation. A principal-less context (load-time work, a
    /// run-loop's self-triggered work, lifecycle hooks, tests) should have its
    /// waits interrupted only by a full-instance cancel (unload/replace/
    /// shutdown) — exactly today's behaviour. There is nothing fail-open about
    /// the fallback: it grants no data access, it only decides which teardown
    /// signal a wait listens to.
    ///
    /// Returns an owned clone — every wait site immediately cloned the token
    /// anyway to move it into the blocking future.
    #[must_use]
    pub fn effective_cancel_token(&self) -> CancellationToken {
        self.invocation_cancel_token
            .clone()
            .unwrap_or_else(|| self.cancel_token.clone())
    }

    /// Whether the current principal-scoped host authority is still live.
    ///
    /// Authority-sensitive hosts use this common decision. Profile failure and
    /// view retirement are revocations, not merely quota/liveness signals; a
    /// guest that was already running must not retain principal-scoped access.
    #[must_use]
    pub(crate) fn invocation_authority_active(&self) -> bool {
        self.invocation_profile_authorized && !self.effective_cancel_token().is_cancelled()
    }

    /// Return the effective quota profile for the current invocation.
    ///
    /// Prefers `invocation_profile` (set by
    /// [`WasmEngine::invoke_interceptor`](crate::engine::wasm::WasmEngine::invoke_interceptor)
    /// for the calling principal) and falls back to the process-global
    /// [`PrincipalProfile::default_ref`](astrid_core::profile::PrincipalProfile::default_ref)
    /// when no invocation profile is in scope — load-time host calls, tests,
    /// and single-tenant deployments all legitimately run without one.
    ///
    /// The fallback path intentionally does **not** substitute the capsule
    /// owner's profile: that would leak the owner's quotas to every
    /// unauthenticated call path. Using `Default` preserves single-tenant
    /// parity while keeping the security invariant honest.
    #[must_use]
    pub fn effective_profile(&self) -> &astrid_core::profile::PrincipalProfile {
        match self.invocation_profile.as_deref() {
            Some(p) => p,
            None => astrid_core::profile::PrincipalProfile::default_ref(),
        }
    }

    /// Enforce the derived-principal network boundary while preserving legacy
    /// profiles that predate principal-level host enforcement. Membership in
    /// the built-in `restricted` group opts into fail-closed egress: only the
    /// profile's explicit `network.egress` patterns may resolve/connect.
    pub(crate) fn principal_egress_allows(&self, host: &str, port: Option<u16>) -> bool {
        if !self.invocation_authority_active() {
            return false;
        }
        let profile = self.effective_profile();
        if !profile
            .groups
            .iter()
            .any(|group| group == astrid_core::groups::BUILTIN_RESTRICTED)
        {
            return true;
        }
        profile.network.egress.iter().any(|pattern| {
            let Some((pattern_host, pattern_port)) = pattern.rsplit_once(':') else {
                return false;
            };
            if !pattern_host.eq_ignore_ascii_case(host) {
                return false;
            }
            match port {
                Some(port) => {
                    pattern_port == "*"
                        || pattern_port.parse::<u16>().is_ok_and(|value| value == port)
                },
                None => pattern_port == "*" || pattern_port.parse::<u16>().is_ok(),
            }
        })
    }

    /// Restricted principals may spawn only executables explicitly named in
    /// their profile. Derived principals currently provision an empty list, so
    /// a child process cannot bypass the host's network boundary.
    pub(crate) fn principal_process_allows(&self, command: &str) -> bool {
        if !self.invocation_authority_active() {
            return false;
        }
        let profile = self.effective_profile();
        if !profile
            .groups
            .iter()
            .any(|group| group == astrid_core::groups::BUILTIN_RESTRICTED)
        {
            return true;
        }
        profile.process.allow.iter().any(|allowed| {
            allowed == command
                || (!allowed.contains('/')
                    && std::path::Path::new(command)
                        .file_name()
                        .is_some_and(|name| name == std::ffi::OsStr::new(allowed)))
        })
    }
}
