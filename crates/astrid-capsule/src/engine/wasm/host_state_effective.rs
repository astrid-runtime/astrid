//! Per-principal `effective_*` overlay accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Return the effective KV store for the current invocation.
    ///
    /// Per-principal isolation lives HERE, not in capsule keys. Every real store
    /// is namespaced `{principal}:capsule:{capsule_id}`, so two principals
    /// writing the *same* logical key — e.g. capsule-session's principal-less
    /// `session.data.{id}` — resolve to different backing namespaces and never
    /// collide. A capsule therefore must not (and need not) fold the principal
    /// into its own keys.
    ///
    /// Resolution: `invocation_kv` (the per-call store installed for the invoking
    /// principal) wins; otherwise the NEUTRAL fail-closed
    /// [`kv`](HostState::kv) placeholder.
    ///
    /// Runtimes are SHARED by content hash across principals (issue #1069) and
    /// the kernel loads them under [`PrincipalId::default()`](astrid_core::PrincipalId::default),
    /// but `default` is an ORDINARY principal — reading its namespace from
    /// another principal would be a cross-principal bleed. So the load-time `kv`
    /// fallback is NOT `default`'s namespace: it is a neutral, physically-
    /// isolated placeholder holding no real principal's data (see the field doc).
    /// EVERY caller carrying a principal — the owner/`default` included — gets an
    /// `invocation_kv` overlay scoped to its own principal (installed by
    /// `invoke_interceptor` / `install_recv_invocation_context`), so the fallback
    /// is reached ONLY by principal-less contexts:
    ///
    /// - no caller in scope (load-time, a run-loop's own work, tests), or
    /// - a principal-less system/lifecycle event (watchdog tick,
    ///   `capsules_loaded`).
    ///
    /// In every one of those the fallback is the neutral placeholder, so no
    /// invocation can EVER reach another principal's KV — nor `default`'s — via
    /// the fallback. The degrade path (invocation-KV construction failing and
    /// leaving `invocation_kv = None`) also falls back to the neutral placeholder.
    /// Pinned by the `effective_kv_*` / `scoped_kv_*` tests. Relates to #977, #1069.
    #[must_use]
    pub fn effective_kv(&self) -> &ScopedKvStore {
        #[cfg(debug_assertions)]
        self.debug_assert_invocation_field_set(self.invocation_kv.is_some(), "invocation_kv");
        self.invocation_kv.as_ref().unwrap_or(&self.kv)
    }

    /// Return the effective home mount for the current invocation.
    ///
    /// Prefers `invocation_home` (installed for the invoking principal) over the
    /// load-time `home`. On a SHARED runtime (issue #1069) `home` is `None`, so
    /// this fallback is neutral/fail-closed — it can NEVER be another principal's
    /// (nor `default`'s) home. `home` is set to a real principal's mount only on
    /// the single-principal lifecycle/hook paths, which no other principal can
    /// reach, so there is no cross-principal home fallback anywhere.
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

    /// Owned copy of the effective home root path.
    ///
    /// Convenience for host fs functions that need to pass the principal
    /// home into a security-gate check running inside an `async move` block.
    #[must_use]
    pub fn effective_home_root_buf(&self) -> Option<PathBuf> {
        self.effective_home().map(|m| m.root.clone())
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
}
