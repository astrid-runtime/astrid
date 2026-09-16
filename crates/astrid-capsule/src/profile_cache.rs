//! Process-lifetime cache of [`PrincipalProfile`] values, keyed by
//! [`PrincipalId`].
//!
//! `invoke_interceptor` runs on every interceptor dispatch and tool call; a
//! bare [`PrincipalProfile::load`] per call would re-read TOML from disk each
//! time. The cache is lazy (load-on-first-use) and flat — there is no TTL or
//! file watcher. The intended invalidation model is **kernel restart**, which
//! matches how capsule manifests, identity entries, and allowance rules are
//! reloaded today.
//!
//! Layer 6 (management IPC) will add explicit invalidation entry points
//! (`astrid.v1.admin.quota.set`); this cache deliberately exposes an
//! [`invalidate`](PrincipalProfileCache::invalidate) hook for that future
//! work but does not otherwise touch the entries once populated.
//!
//! # Fail-closed
//!
//! The bootstrap `default` principal retains missing-file single-tenant parity.
//! A missing profile for every non-default identity is a hard error, as are
//! malformed TOML, unknown fields, invalid values,
//! or a future `profile_version` are hard errors. Those errors propagate out
//! of [`PrincipalProfileCache::resolve`] so callers can deny the invocation
//! with a clear audit trail, rather than silently falling back to permissive
//! defaults or the capsule owner's limits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{CommandAlwaysGrant, PrincipalProfile, ProfileError, ProfileResult};

/// Lazy, process-lifetime cache of resolved [`PrincipalProfile`] values.
///
/// One instance is created per kernel boot and shared (via `Arc`) through
/// the capsule load context into every [`WasmEngine`](crate::engine::wasm::WasmEngine).
/// Reads vastly outnumber writes (entries are populated on first use and
/// never mutated afterward), so profiles and their per-principal invalidation
/// generations share one `RwLock`.
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
    generations: HashMap<PrincipalId, u64>,
}

impl ProfileCacheState {
    fn invalidate(&mut self, principal: &PrincipalId) {
        self.profiles.remove(principal);
        let generation = self.generations.entry(principal.clone()).or_default();
        *generation = generation.wrapping_add(1);
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
            let generation = state.generations.get(principal).copied().unwrap_or(0);
            drop(state);
            let profile = Arc::new(if *principal == PrincipalId::default() {
                PrincipalProfile::load(&self.astrid_home, principal)?
            } else {
                PrincipalProfile::load_required(&self.astrid_home, principal)?
            });
            if let Some(profile) = self.publish_loaded(principal, profile, generation) {
                return Ok(profile);
            }
        }
    }

    fn publish_loaded(
        &self,
        principal: &PrincipalId,
        profile: Arc<PrincipalProfile>,
        generation: u64,
    ) -> Option<Arc<PrincipalProfile>> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(principal).copied().unwrap_or(0) != generation {
            return None;
        }
        let entry = state.profiles.entry(principal.clone()).or_insert(profile);
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
            // directly without a generation bump or another disk read.
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
    /// Host persist always supplies `Some(current workspace root)`. This
    /// method does not invent a `None`. `None` on the grant type is only the
    /// existing in-memory unscoped [`astrid_approval::Allowance::workspace_root`]
    /// semantics (matches any workspace); it is not a historical on-disk
    /// migration.
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

    #[cfg(test)]
    fn generation_for(&self, principal: &PrincipalId) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generations
            .get(principal)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::Arc;

    use astrid_core::principal::PrincipalId;
    use astrid_core::profile::{
        CURRENT_PROFILE_VERSION, DEFAULT_MAX_BACKGROUND_PROCESSES,
        DEFAULT_MAX_IPC_THROUGHPUT_BYTES, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_TIMEOUT_SECS,
        PrincipalProfile,
    };

    /// Fixture: tempdir-rooted cache. No process env mutation — avoids the
    /// `unsafe { std::env::set_var(..) }` dance that conflicts with this
    /// crate's `#![deny(unsafe_code)]`.
    fn fixture() -> (tempfile::TempDir, PrincipalProfileCache) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(dir.path());
        let cache = PrincipalProfileCache::with_home(home);
        (dir, cache)
    }

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid principal")
    }

    fn command_fixture() -> (tempfile::TempDir, PrincipalProfileCache) {
        let (dir, cache) = fixture();
        for name in ["alice", "bob"] {
            PrincipalProfile::default()
                .save_to_path(&cache.astrid_home.profile_path(&principal(name)))
                .expect("create test principal");
        }
        (dir, cache)
    }

    #[test]
    fn command_approval_does_not_recreate_deleted_principal() {
        let (_dir, cache) = command_fixture();
        let p = principal("alice");
        cache.resolve(&p).expect("prime cache");
        let path = cache.astrid_home.profile_path(&p);
        fs::remove_file(&path).expect("delete test profile");
        assert!(
            cache
                .persist_command_always(&p, "git push", Some("/tmp"))
                .is_err()
        );
        assert!(!path.exists(), "approval must not recreate the principal");
    }

    #[test]
    fn command_approval_does_not_modify_disabled_principal() {
        let (_dir, cache) = command_fixture();
        let p = principal("alice");
        let path = cache.astrid_home.profile_path(&p);
        let profile = PrincipalProfile {
            enabled: false,
            ..PrincipalProfile::default()
        };
        profile.save_to_path(&path).expect("disable test principal");
        let before = fs::read(&path).expect("profile bytes");
        assert!(
            cache
                .persist_command_always(&p, "git push", Some("/tmp"))
                .is_err()
        );
        assert_eq!(fs::read(&path).expect("unchanged profile"), before);
    }

    fn write_profile(dir: &tempfile::TempDir, p: &PrincipalId, contents: &str) {
        let home = AstridHome::from_path(dir.path());
        let profiles_dir = home.profiles_dir();
        fs::create_dir_all(&profiles_dir).expect("mkdir etc/profiles");
        fs::write(home.profile_path(p), contents).expect("write profile");
    }

    #[test]
    fn only_default_principal_may_use_missing_file_compatibility_profile() {
        let (_dir, cache) = fixture();
        let p = PrincipalId::default();

        let profile = cache.resolve(&p).expect("resolve missing");
        assert_eq!(*profile, PrincipalProfile::default());
        assert_eq!(cache.len(), 1, "missing-file path must still cache");

        // Second call: same Arc, no second disk read.
        let profile2 = cache.resolve(&p).expect("resolve cached");
        assert!(Arc::ptr_eq(&profile, &profile2));

        let alice = principal("alice");
        assert!(matches!(
            cache.resolve(&alice),
            Err(ProfileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(cache.len(), 1, "failed identities must not be cached");
    }

    #[test]
    fn populated_profile_loaded_once() {
        let (dir, cache) = fixture();
        let p = principal("bob");
        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 [quotas]\n\
                 max_memory_bytes = 16777216\n\
                 max_timeout_secs = 42\n\
                 max_ipc_throughput_bytes = 524288\n\
                 max_background_processes = 2\n\
                 max_storage_bytes = 1048576\n"
            ),
        );

        let profile = cache.resolve(&p).expect("resolve populated");
        assert_eq!(profile.quotas.max_memory_bytes, 16_777_216);
        assert_eq!(profile.quotas.max_timeout_secs, 42);
        assert_eq!(profile.quotas.max_ipc_throughput_bytes, 524_288);
        assert_eq!(profile.quotas.max_background_processes, 2);
        assert_eq!(profile.quotas.max_storage_bytes, 1_048_576);
    }

    #[test]
    fn malformed_profile_is_hard_error_no_fallback() {
        let (dir, cache) = fixture();
        let p = principal("mallory");
        write_profile(&dir, &p, "this is = = not [ valid toml");

        let err = cache
            .resolve(&p)
            .expect_err("malformed TOML must not silently fall back");
        assert!(matches!(err, ProfileError::Parse(_)), "got: {err:?}");
        // And crucially, it must NOT be cached as Default — the next call
        // still fails (fail-closed, no operator surprise).
        assert_eq!(cache.len(), 0);
        let err2 = cache.resolve(&p).expect_err("still fails on retry");
        assert!(matches!(err2, ProfileError::Parse(_)));
    }

    #[test]
    fn invalid_profile_version_is_hard_error() {
        let (dir, cache) = fixture();
        let p = principal("future");
        write_profile(
            &dir,
            &p,
            &format!("profile_version = {}\n", CURRENT_PROFILE_VERSION + 1),
        );

        let err = cache.resolve(&p).expect_err("future version rejected");
        assert!(matches!(err, ProfileError::Invalid(_)), "got: {err:?}");
    }

    #[test]
    fn two_principals_have_independent_entries() {
        let (dir, cache) = fixture();
        let a = principal("alice2");
        let b = principal("bob2");
        write_profile(
            &dir,
            &a,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 [quotas]\n\
                 max_memory_bytes = 16777216\n"
            ),
        );
        write_profile(
            &dir,
            &b,
            &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
        );

        let pa = cache.resolve(&a).expect("alice");
        let pb = cache.resolve(&b).expect("bob");
        assert_eq!(pa.quotas.max_memory_bytes, 16_777_216);
        assert_eq!(pb.quotas.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);
        assert_eq!(pb.quotas.max_timeout_secs, DEFAULT_MAX_TIMEOUT_SECS);
        assert_eq!(
            pb.quotas.max_ipc_throughput_bytes,
            DEFAULT_MAX_IPC_THROUGHPUT_BYTES
        );
        assert_eq!(
            pb.quotas.max_background_processes,
            DEFAULT_MAX_BACKGROUND_PROCESSES
        );
    }

    #[test]
    fn invalidate_forces_reload() {
        let (dir, cache) = fixture();
        let p = principal("reloader");

        write_profile(
            &dir,
            &p,
            &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
        );
        let first = cache.resolve(&p).expect("first resolve");
        assert_eq!(first.quotas.max_memory_bytes, DEFAULT_MAX_MEMORY_BYTES);

        // Write a populated profile, invalidate, resolve again.
        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 [quotas]\n\
                 max_memory_bytes = 8388608\n"
            ),
        );
        cache.invalidate(&p);
        let second = cache.resolve(&p).expect("second resolve");
        assert_eq!(second.quotas.max_memory_bytes, 8_388_608);
    }

    #[test]
    fn invalidation_prevents_stale_load_publication() {
        let (dir, cache) = fixture();
        let p = principal("generation-race");
        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 enabled = true\n"
            ),
        );
        let generation = cache.generation_for(&p);
        let stale = Arc::new(
            PrincipalProfile::load(&cache.astrid_home, &p).expect("load pre-invalidation profile"),
        );

        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 enabled = false\n"
            ),
        );
        cache.invalidate(&p);

        assert!(cache.publish_loaded(&p, stale, generation).is_none());
        assert_eq!(cache.len(), 0);
        assert!(!cache.resolve(&p).expect("resolve current profile").enabled);
    }

    #[test]
    fn invalidating_one_principal_does_not_reject_another_principal_load() {
        let (_dir, cache) = fixture();
        let alice = principal("alice-invalidation");
        let bob = principal("bob-load");
        let bob_generation = 0;
        let bob_profile = Arc::new(PrincipalProfile::default());

        cache.invalidate(&alice);

        assert!(
            cache
                .publish_loaded(&bob, bob_profile, bob_generation)
                .is_some()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn concurrent_readers_do_not_race() {
        // Lightweight contention check — not a loom model, just a sanity
        // check that multiple threads can `resolve()` the same principal
        // without deadlocks or panics.
        let (dir, cache) = fixture();
        let cache = Arc::new(cache);
        let p = principal("racer");
        write_profile(
            &dir,
            &p,
            &format!("profile_version = {CURRENT_PROFILE_VERSION}\n"),
        );

        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&cache);
            let pid = p.clone();
            handles.push(std::thread::spawn(move || {
                let _ = c.resolve(&pid).expect("resolve");
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        assert_eq!(cache.len(), 1, "only one entry expected");
    }

    #[test]
    fn persist_egress_appends_under_capsule_key_and_invalidates() {
        let (dir, cache) = fixture();
        let p = principal("alice");
        // Start from a profile with a pre-existing consented endpoint under a
        // DIFFERENT capsule to prove we append per-capsule, not overwrite, and
        // that the flat `egress` allowlist is left untouched.
        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 [network]\n\
                 egress = [\"api.example.com:443\"]\n\
                 [network.capsule_egress]\n\
                 openai-compat = [\"127.0.0.1:5678\"]\n"
            ),
        );
        // Populate the cache so we can prove persist invalidates it.
        let _ = cache.resolve(&p).expect("prime cache");
        assert_eq!(cache.len(), 1);

        cache
            .persist_egress(&p, "react", "127.0.0.1:1234")
            .expect("persist egress");

        // Cache was invalidated by the persist.
        assert_eq!(cache.len(), 0, "persist_egress must invalidate the cache");

        let reloaded = cache.resolve(&p).expect("reload");
        // The flat general egress allowlist is untouched.
        assert_eq!(reloaded.network.egress, vec!["api.example.com:443"]);
        // The new grant lands ONLY under "react".
        assert_eq!(
            reloaded.network.capsule_egress.get("react"),
            Some(&vec!["127.0.0.1:1234".to_string()])
        );
        // The pre-existing "openai-compat" grant is preserved and the react
        // grant did NOT widen to it.
        assert_eq!(
            reloaded.network.capsule_egress.get("openai-compat"),
            Some(&vec!["127.0.0.1:5678".to_string()])
        );
        assert!(
            !reloaded
                .network
                .capsule_egress
                .get("openai-compat")
                .unwrap()
                .contains(&"127.0.0.1:1234".to_string()),
            "a react grant must not appear under openai-compat"
        );
    }

    #[test]
    fn persist_egress_is_per_capsule_isolated() {
        // Spec (FIX 1b): a persisted grant for capsule "react" reaching
        // 127.0.0.1:1234 must NOT exempt capsule "openai-compat" reaching the
        // same endpoint for the same principal.
        let (_dir, cache) = fixture();
        let p = principal("alice");
        cache
            .persist_egress(&p, "react", "127.0.0.1:1234")
            .expect("persist react grant");

        let profile = cache.resolve(&p).expect("reload");
        assert_eq!(
            profile.network.capsule_egress.get("react"),
            Some(&vec!["127.0.0.1:1234".to_string()]),
            "react holds its own grant"
        );
        assert!(
            !profile.network.capsule_egress.contains_key("openai-compat"),
            "openai-compat must NOT inherit react's persisted grant"
        );
    }

    #[test]
    fn persist_egress_is_idempotent() {
        let (_dir, cache) = fixture();
        let p = principal("bob");
        let initial_generation = cache.generation_for(&p);
        // No file on disk → starts from default (empty capsule_egress).
        cache
            .persist_egress(&p, "react", "10.0.0.5:8080")
            .expect("first persist");
        let persisted_generation = cache.generation_for(&p);
        assert_eq!(persisted_generation, initial_generation + 1);
        // A second persist of the SAME endpoint under the SAME capsule
        // (case-insensitive) is a no-op success, not a duplicate.
        cache
            .persist_egress(&p, "react", "10.0.0.5:8080")
            .expect("idempotent persist");
        assert_eq!(cache.generation_for(&p), persisted_generation);
        assert_eq!(cache.len(), 1, "idempotent persist refreshes the cache");

        let profile = cache.resolve(&p).expect("resolve refreshed profile");
        assert_eq!(
            profile.network.capsule_egress.get("react"),
            Some(&vec!["10.0.0.5:8080".to_string()]),
            "idempotent persist must not duplicate the entry"
        );
    }

    #[test]
    fn persist_command_always_appends_and_invalidates() {
        let (dir, cache) = fixture();
        let p = principal("alice");
        write_profile(
            &dir,
            &p,
            &format!(
                "profile_version = {CURRENT_PROFILE_VERSION}\n\
                 [network]\n\
                 egress = [\"api.example.com:443\"]\n"
            ),
        );
        let _ = cache.resolve(&p).expect("prime cache");
        assert_eq!(cache.len(), 1);

        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .expect("persist command always");

        assert_eq!(
            cache.len(),
            0,
            "persist_command_always must invalidate the cache"
        );

        let reloaded = cache.resolve(&p).expect("reload");
        assert_eq!(reloaded.network.egress, vec!["api.example.com:443"]);
        assert_eq!(reloaded.approvals.command_always.len(), 1);
        assert_eq!(reloaded.approvals.command_always[0].command, "git push");
        assert_eq!(
            reloaded.approvals.command_always[0]
                .workspace_root
                .as_deref(),
            Some("/tmp")
        );
        assert!(
            reloaded.network.capsule_egress.is_empty(),
            "command-always persist must not touch capsule_egress"
        );
    }

    #[test]
    fn persist_command_always_is_idempotent_for_same_command_and_workspace() {
        let (_dir, cache) = command_fixture();
        let p = principal("bob");
        let initial_generation = cache.generation_for(&p);
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .expect("first persist");
        let persisted_generation = cache.generation_for(&p);
        assert_eq!(persisted_generation, initial_generation + 1);
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .expect("idempotent persist");
        assert_eq!(cache.generation_for(&p), persisted_generation);
        assert_eq!(cache.len(), 1, "idempotent persist refreshes the cache");

        let profile = cache.resolve(&p).expect("resolve refreshed profile");
        assert_eq!(profile.approvals.command_always.len(), 1);
        assert_eq!(profile.approvals.command_always[0].command, "git push");
    }

    #[test]
    fn persist_command_always_isolates_workspace_and_principal() {
        let (_dir, cache) = command_fixture();
        let alice = principal("alice");
        let bob = principal("bob");
        cache
            .persist_command_always(&alice, "git push", Some("/tmp"))
            .expect("alice /tmp");
        cache
            .persist_command_always(&alice, "git push", Some("/other"))
            .expect("alice /other");
        cache
            .persist_command_always(&bob, "git push", Some("/tmp"))
            .expect("bob /tmp");

        let alice_profile = cache.resolve(&alice).expect("alice");
        let alice_workspaces: Vec<_> = alice_profile
            .approvals
            .command_always
            .iter()
            .map(|g| g.workspace_root.as_deref())
            .collect();
        assert_eq!(alice_workspaces, vec![Some("/tmp"), Some("/other")]);
        assert!(
            alice_profile
                .approvals
                .command_always
                .iter()
                .all(|g| g.command == "git push")
        );

        let bob_profile = cache.resolve(&bob).expect("bob");
        assert_eq!(bob_profile.approvals.command_always.len(), 1);
        assert_eq!(
            bob_profile.approvals.command_always[0]
                .workspace_root
                .as_deref(),
            Some("/tmp")
        );
    }

    #[test]
    fn persist_command_always_rejects_empty_command() {
        let (_dir, cache) = fixture();
        let p = principal("alice");
        let err = cache
            .persist_command_always(&p, "   ", Some("/tmp"))
            .expect_err("empty command");
        assert!(
            matches!(&err, ProfileError::Invalid(msg) if msg.contains("command")),
            "got {err:?}"
        );
        assert_eq!(cache.len(), 0, "invalid persist must not cache");
    }

    #[test]
    fn persist_command_always_rejects_empty_workspace() {
        let (_dir, cache) = fixture();
        let p = principal("alice");
        let err = cache
            .persist_command_always(&p, "git push", Some("   "))
            .expect_err("empty workspace");
        assert!(
            matches!(&err, ProfileError::Invalid(msg) if msg.contains("workspace_root")),
            "got {err:?}"
        );
        assert_eq!(cache.len(), 0, "invalid persist must not cache");
    }

    #[test]
    fn persist_command_always_preserves_workspace_bytes() {
        let (_dir, cache) = command_fixture();
        let p = principal("alice");
        cache
            .persist_command_always(&p, "  git push  ", Some(" /tmp "))
            .expect("persist spaced workspace");
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .expect("persist distinct workspace");
        let profile = cache.resolve(&p).expect("resolve");
        assert_eq!(profile.approvals.command_always.len(), 2);
        assert_eq!(profile.approvals.command_always[0].command, "git push");
        assert_eq!(
            profile.approvals.command_always[0]
                .workspace_root
                .as_deref(),
            Some(" /tmp ")
        );
    }

    #[test]
    fn persist_egress_then_command_always_keeps_both() {
        let (_dir, cache) = fixture();
        let p = principal("alice");
        cache
            .persist_egress(&p, "react", "127.0.0.1:1234")
            .expect("persist egress");
        cache
            .persist_command_always(&p, "git push", Some("/tmp"))
            .expect("persist command");
        let profile = cache.resolve(&p).expect("resolve");
        assert_eq!(
            profile.network.capsule_egress.get("react"),
            Some(&vec!["127.0.0.1:1234".to_string()])
        );
        assert_eq!(profile.approvals.command_always.len(), 1);
        assert_eq!(profile.approvals.command_always[0].command, "git push");
        assert_eq!(
            profile.approvals.command_always[0]
                .workspace_root
                .as_deref(),
            Some("/tmp")
        );
    }
}
