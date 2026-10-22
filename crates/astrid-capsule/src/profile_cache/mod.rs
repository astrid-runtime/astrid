//! Process-lifetime cache of [`PrincipalProfile`] values, keyed by
//! [`PrincipalId`].
//!
//! `invoke_interceptor` runs on every interceptor dispatch and tool call; a
//! bare [`PrincipalProfile::load`] per call would re-read TOML from disk each
//! time. The cache is lazy (load-on-first-use) and flat, with explicit
//! invalidation for principal/profile management. There is no TTL or file watcher.
//! In-flight load identities prevent a pre-invalidation disk read from restoring
//! a revoked profile, and are released when their final loader exits.
//!
//! # Fail-closed
//!
//! The bootstrap `default` principal retains missing-file single-tenant parity.
//! A missing profile for every non-default identity is a hard error, as are
//! malformed TOML, unknown fields, invalid values,
//! or a future `profile_version`. Those errors propagate out
//! of [`PrincipalProfileCache::resolve`] so callers can deny the invocation
//! with a clear audit trail, rather than silently falling back to permissive
//! defaults or the capsule owner's limits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

mod load;
use load::{ProfileLoad, ProfileLoadToken};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{CommandAlwaysGrant, PrincipalProfile, ProfileError, ProfileResult};

/// Lazy, process-lifetime cache of resolved [`PrincipalProfile`] values.
///
/// One instance is created per kernel boot and shared (via `Arc`) through
/// the capsule load context into every [`WasmEngine`](crate::engine::wasm::WasmEngine).
/// Reads vastly outnumber writes (entries are populated on first use and
/// changed only by invalidation), so profiles and in-flight load identities
/// share one `RwLock`. Invalidated aliases do not leave permanent tombstones.
#[derive(Debug)]
pub struct PrincipalProfileCache {
    /// Root against which principal profile paths are resolved.
    ///
    /// Set at construction so tests can point at a tempdir without mutating
    /// the process-global `$ASTRID_HOME`. Production callers use
    /// [`PrincipalProfileCache::new`], which captures
    /// [`AstridHome::resolve`] once — matching the rest of the kernel's
    /// one-shot home resolution at boot.
    astrid_home: AstridHome,
    state: RwLock<ProfileCacheState>,
}

#[derive(Debug, Default)]
struct ProfileCacheState {
    profiles: HashMap<PrincipalId, Arc<PrincipalProfile>>,
    loads: HashMap<PrincipalId, Weak<ProfileLoadToken>>,
}

impl ProfileCacheState {
    fn invalidate(&mut self, principal: &PrincipalId) {
        self.profiles.remove(principal);
        self.loads.remove(principal);
    }
}

impl PrincipalProfileCache {
    /// Create a cache rooted at [`AstridHome::resolve`]'s current result.
    ///
    /// # Errors
    ///
    /// Returns an IO error if neither `$ASTRID_HOME` nor `$HOME` is set.
    /// The kernel already requires a resolvable Astrid home at boot, so this
    /// failing would be a programmer error — callers may `.expect()` the
    /// result during kernel startup.
    pub fn new() -> ProfileResult<Self> {
        let astrid_home = AstridHome::resolve().map_err(|e| {
            ProfileError::Io(std::io::Error::other(format!(
                "failed to resolve AstridHome: {e}"
            )))
        })?;
        Ok(Self::with_home(astrid_home))
    }

    /// Create a cache rooted at the supplied [`AstridHome`].
    ///
    /// Primary use cases: tests that want a tempdir-rooted cache, and
    /// integration tests that explicitly inject a pre-resolved home rather
    /// than read the process environment.
    #[must_use]
    pub fn with_home(astrid_home: AstridHome) -> Self {
        Self {
            astrid_home,
            state: RwLock::new(ProfileCacheState::default()),
        }
    }

    /// Resolve the profile for `principal`, populating the cache on first use.
    ///
    /// The first call for a given principal reads
    /// `{AstridHome}/etc/profiles/{principal}.toml` from disk.
    /// Subsequent calls return the cached `Arc` clone with no filesystem
    /// access.
    ///
    /// # Errors
    ///
    /// - [`ProfileError::Io`] if reading the profile file fails with an IO
    ///   error other than `NotFound`.
    /// - [`ProfileError::Parse`] if the profile TOML is malformed, contains
    ///   unknown fields, or has an unknown enum variant.
    /// - [`ProfileError::Invalid`] if the profile fails semantic validation,
    ///   including a `profile_version` above `CURRENT_PROFILE_VERSION`.
    ///
    /// The caller is expected to deny the invocation on any of these errors
    /// (see Layer 3 design doc, issue #666).
    pub fn resolve(&self, principal: &PrincipalId) -> ProfileResult<Arc<PrincipalProfile>> {
        // `default` is the explicit single-tenant compatibility identity and
        // may use the built-in profile when no file exists. Every other
        // principal is an isolation boundary: silently manufacturing the
        // permissive default profile for a deleted or half-provisioned alias
        // would restore authority after its profile fence was removed.
        loop {
            let state = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(profile) = state.profiles.get(principal) {
                return Ok(Arc::clone(profile));
            }
            drop(state);
            let load = self.begin_load(principal);
            let profile = Arc::new(if *principal == PrincipalId::default() {
                PrincipalProfile::load(&self.astrid_home, principal)?
            } else {
                PrincipalProfile::load_required(&self.astrid_home, principal)?
            });
            if let Some(profile) = self.publish_loaded(profile, &load) {
                return Ok(profile);
            }
        }
    }

    fn publish_loaded(
        &self,
        profile: Arc<PrincipalProfile>,
        load: &ProfileLoad<'_>,
    ) -> Option<Arc<PrincipalProfile>> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !load.is_current(&state) {
            return None;
        }
        let entry = state
            .profiles
            .entry(load.principal().clone())
            .or_insert(profile);
        Some(Arc::clone(entry))
    }

    /// Drop the cached entry for `principal`, forcing a reload on the next
    /// [`resolve`](Self::resolve) call.
    ///
    /// A concurrent pre-invalidation load cannot repopulate the cache.
    pub fn invalidate(&self, principal: &PrincipalId) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.invalidate(principal);
    }

    /// Persist an operator-consented local-egress endpoint to `principal`'s
    /// profile on disk under `capsule_id` (`network.capsule_egress[capsule_id]`),
    /// then invalidate the cache so the next resolve reloads it.
    ///
    /// This is the `approve_always` path of the runtime local-egress consent
    /// flow: a `host:port` the local operator chose to remember across daemon
    /// restarts, **for that capsule specifically**. The grant is keyed by
    /// `capsule_id` so a persisted grant for capsule A reaching an endpoint
    /// never exempts capsule B reaching the same endpoint for the same
    /// principal — mirroring the operator `[security.capsule_local_egress]`
    /// shape and the in-memory `AllowanceStore` grant's per-capsule scope.
    ///
    /// The load-modify-save runs under the cache's own write lock so two
    /// concurrent consents on the same principal cannot lose an entry, and
    /// mirrors the kernel's `grant_on_use` discipline (load → mutate → validate
    /// → save → invalidate). It is fail-closed and **idempotent**: an endpoint
    /// already present under that capsule is a no-op success.
    ///
    /// # Security
    ///
    /// The caller (the egress consent gate) guarantees the request was a
    /// host-attributed `LocalSocket`-origin operator action that the operator
    /// explicitly approved-always. This method does not itself re-check origin;
    /// it is the persistence primitive, not the policy gate.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] on load/validate/save failure. The caller treats
    /// any error as a fail-closed no-op (the in-flight session grant still
    /// stands; only the disk persistence is skipped).
    pub fn persist_egress(
        &self,
        principal: &PrincipalId,
        capsule_id: &str,
        endpoint: &str,
    ) -> ProfileResult<()> {
        // Serialize the load-modify-save against any other writer on this cache
        // (and against a concurrent `resolve` populating the same key) by
        // holding the write lock for the whole operation.
        //
        // TRADEOFF (deliberate): the write lock is held across blocking disk
        // I/O (load + validate + fsync + rename), so a concurrent `resolve()`
        // on this cache waits for the whole persist. Accepted because this path
        // runs only on an `approve_always` consent — a rare, operator-driven
        // event — not on the hot read path. Revisit (e.g. drop the lock around
        // the disk write, or snapshot-then-swap) only if this becomes a
        // measurable `resolve()` latency source.
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let path = self.astrid_home.profile_path(principal);
        let mut profile = PrincipalProfile::load_from_path(&path)?;

        let entries = profile
            .network
            .capsule_egress
            .entry(capsule_id.to_string())
            .or_default();

        if entries.iter().any(|e| e.eq_ignore_ascii_case(endpoint)) {
            // Already persisted for this capsule — idempotent. The profile was
            // just loaded from disk while holding the cache write lock, so it
            // is the current system-of-record value and can refresh the cache
            // directly without invalidating in-flight loads or another disk read.
            guard.profiles.insert(principal.clone(), Arc::new(profile));
            return Ok(());
        }

        entries.push(endpoint.to_string());
        // `save_to_path` re-runs `validate()` before writing, so a malformed
        // profile never reaches disk.
        profile.save_to_path(&path)?;
        guard.invalidate(principal);
        Ok(())
    }

    /// Persist an operator-consented command-family grant to `principal`'s
    /// profile (`approvals.command_always`), then invalidate the cache so the
    /// next resolve reloads it.
    ///
    /// This is the capability `approve_always` path: a command family the
    /// operator chose to remember across daemon restarts. Matching stays
    /// principal + workspace + the existing host glob `{escaped_command} *`
    /// against `target_resource`. It is **not** capsule-keyed, not
    /// exact-resource-only, and does not widen that prefix contract.
    ///
    /// Command equality is exact (unlike egress endpoints, which are
    /// case-insensitive). `command` is trimmed before compare/store;
    /// workspace bytes are preserved because whitespace can be part of a path.
    ///
    /// The load-modify-save runs under the same cache write lock as
    /// [`Self::persist_egress`]. Both methods load the current profile from
    /// disk while holding that lock, so these two methods cannot drop each
    /// other's writes. Other profile writers do not share this lock.
    ///
    /// Host persist always supplies `Some(pristine hosted portal path)`, not
    /// the process-local `CoW` merged path. This method does not invent a
    /// `None`. `None` on the grant type is only the existing in-memory
    /// unscoped [`astrid_approval::Allowance::workspace_root`] semantics
    /// (matches any workspace); it is not a historical on-disk migration.
    ///
    /// Fail-closed and idempotent: the same trimmed command + workspace pair
    /// is a no-op success. Empty command or empty present workspace returns
    /// [`ProfileError::Invalid`] **before** taking the lock.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Invalid`] if `command` is empty or a present
    /// `workspace_root` is empty. Other [`ProfileError`] variants come from
    /// load/validate/save. The caller must not report `ApprovedAlways` unless
    /// this returns `Ok`.
    pub fn persist_command_always(
        &self,
        principal: &PrincipalId,
        command: &str,
        workspace_root: Option<&str>,
    ) -> ProfileResult<()> {
        self.persist_command_at(
            principal,
            command,
            workspace_root,
            astrid_core::profile::CommandApprovalLocation::Hosted,
        )
    }

    /// Remember a command in the principal's path-free workspace, not all workspaces.
    ///
    /// # Errors
    /// Returns profile validation, load, or persistence failures.
    pub fn persist_astrid_command_always(
        &self,
        principal: &PrincipalId,
        command: &str,
    ) -> ProfileResult<()> {
        self.persist_command_at(
            principal,
            command,
            None,
            astrid_core::profile::CommandApprovalLocation::AstridWorkspace,
        )
    }

    fn persist_command_at(
        &self,
        principal: &PrincipalId,
        command: &str,
        workspace_root: Option<&str>,
        location: astrid_core::profile::CommandApprovalLocation,
    ) -> ProfileResult<()> {
        let command = command.trim();
        if command.is_empty() {
            return Err(ProfileError::Invalid(
                "approvals.command_always.command must be non-empty".into(),
            ));
        }
        let workspace_root = match workspace_root {
            Some(workspace) => {
                // Filesystem names may end in spaces. Do not change the scope.
                if workspace.trim().is_empty() {
                    return Err(ProfileError::Invalid(
                        "approvals.command_always.workspace_root must be non-empty when set".into(),
                    ));
                }
                Some(workspace)
            },
            None => None,
        };

        // Same lock tradeoff as `persist_egress`: hold the write lock across
        // load + validate + fsync + rename. Accepted because approve_always is
        // a rare operator-driven event, not the hot read path. Loading from
        // disk under this lock is what keeps a concurrent persist_egress from
        // being dropped by a stale full-profile save.
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let path = self.astrid_home.profile_path(principal);
        // Approval cannot resurrect a principal removed while the prompt was open.
        let mut profile = if principal == &PrincipalId::default() {
            PrincipalProfile::load_from_path(&path)?
        } else {
            PrincipalProfile::load_required(&self.astrid_home, principal)?
        };
        if !profile.enabled {
            return Err(ProfileError::Invalid("principal is disabled".into()));
        }

        let already = profile.approvals.command_always.iter().any(|grant| {
            grant.command == command
                && grant.location == location
                && grant.workspace_root.as_deref() == workspace_root
        });
        if already {
            guard.profiles.insert(principal.clone(), Arc::new(profile));
            return Ok(());
        }

        profile.approvals.command_always.push(CommandAlwaysGrant {
            command: command.to_string(),
            location,
            workspace_root: workspace_root.map(str::to_string),
        });
        profile.save_to_path(&path)?;
        guard.invalidate(principal);
        Ok(())
    }

    /// Number of principals currently cached. Test-only introspection.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .profiles
            .len()
    }
}

#[cfg(test)]
mod tests;
