//! Per-principal `effective_*` overlay accessors for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Return the KV namespace for this capsule scoped to its principal.
    ///
    /// Format: `{principal}:capsule:{capsule_id}`. This is the same namespace
    /// used when the `ScopedKvStore` was created, but exposed here for cases
    /// where host functions need to construct the namespace dynamically.
    #[must_use]
    pub fn principal_kv_namespace(&self) -> String {
        format!("{}:capsule:{}", self.principal, self.capsule_id)
    }

    /// Return the effective KV store for the current invocation.
    ///
    /// Uses `invocation_kv` if set (different principal), falls back to
    /// the capsule's default `kv` store.
    #[must_use]
    pub fn effective_kv(&self) -> &ScopedKvStore {
        #[cfg(debug_assertions)]
        self.debug_assert_invocation_field_set(self.invocation_kv.is_some(), "invocation_kv");
        self.invocation_kv.as_ref().unwrap_or(&self.kv)
    }

    /// Return the effective home mount for the current invocation.
    ///
    /// Prefers `invocation_home` (set when serving a different principal)
    /// over `home` (set at capsule load for the owning principal).
    #[must_use]
    pub fn effective_home(&self) -> Option<&PrincipalMount> {
        self.invocation_home.as_ref().or(self.home.as_ref())
    }

    /// Return the effective tmp mount for the current invocation. Same
    /// precedence as [`effective_home`](Self::effective_home).
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
