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
//! [`PrincipalProfile::load`] treats a missing file as [`PrincipalProfile::default`]
//! (single-tenant parity), but malformed TOML, unknown fields, invalid values,
//! or a future `profile_version` are hard errors. Those errors propagate out
//! of [`PrincipalProfileCache::resolve`] so callers can deny the invocation
//! with a clear audit trail, rather than silently falling back to permissive
//! defaults or the capsule owner's limits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{PrincipalProfile, ProfileError, ProfileResult};

/// Lazy, process-lifetime cache of resolved [`PrincipalProfile`] values.
///
/// One instance is created per kernel boot and shared (via `Arc`) through
/// the capsule load context into every [`WasmEngine`](crate::engine::wasm::WasmEngine).
/// Reads vastly outnumber writes (entries are populated on first use and
/// never mutated afterward), so the inner map sits behind a `RwLock`.
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
    cache: RwLock<HashMap<PrincipalId, Arc<PrincipalProfile>>>,
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
            cache: RwLock::new(HashMap::new()),
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
        // Fast path: a concurrent reader should never take the write lock.
        // RwLock poisoning can happen only if a writer panicked mid-insert;
        // recover and continue — the map is a simple key → Arc mapping
        // with no partial-write window.
        if let Some(profile) = self
            .cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(principal)
        {
            return Ok(Arc::clone(profile));
        }

        let profile = Arc::new(PrincipalProfile::load(&self.astrid_home, principal)?);

        let mut w = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Two threads may race to resolve the same principal; the first
        // writer wins and the second returns the already-inserted value.
        let entry = w.entry(principal.clone()).or_insert(profile);
        Ok(Arc::clone(entry))
    }

    /// Drop the cached entry for `principal`, forcing a reload on the next
    /// [`resolve`](Self::resolve) call.
    ///
    /// Reserved for Layer 6 management IPC (`astrid.v1.admin.quota.set`).
    /// Unused today — the invalidation model is kernel restart.
    pub fn invalidate(&self, principal: &PrincipalId) {
        self.cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(principal);
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
            .cache
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
            // Already persisted for this capsule — idempotent. Drop the stale
            // cache entry so a reload reflects on-disk state, then return
            // success.
            guard.remove(principal);
            return Ok(());
        }

        entries.push(endpoint.to_string());
        // `save_to_path` re-runs `validate()` before writing, so a malformed
        // profile never reaches disk.
        profile.save_to_path(&path)?;
        guard.remove(principal);
        Ok(())
    }

    /// Number of principals currently cached. Test-only introspection.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
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

    fn write_profile(dir: &tempfile::TempDir, p: &PrincipalId, contents: &str) {
        let home = AstridHome::from_path(dir.path());
        let profiles_dir = home.profiles_dir();
        fs::create_dir_all(&profiles_dir).expect("mkdir etc/profiles");
        fs::write(home.profile_path(p), contents).expect("write profile");
    }

    #[test]
    fn missing_file_returns_default_and_caches_it() {
        let (_dir, cache) = fixture();
        let p = principal("alice");

        let profile = cache.resolve(&p).expect("resolve missing");
        assert_eq!(*profile, PrincipalProfile::default());
        assert_eq!(cache.len(), 1, "missing-file path must still cache");

        // Second call: same Arc, no second disk read.
        let profile2 = cache.resolve(&p).expect("resolve cached");
        assert!(Arc::ptr_eq(&profile, &profile2));
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
        // Bob has no file on disk → Default.

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

        // First load: no file → Default.
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
    fn concurrent_readers_do_not_race() {
        // Lightweight contention check — not a loom model, just a sanity
        // check that multiple threads can `resolve()` the same principal
        // without deadlocks or panics.
        let (_dir, cache) = fixture();
        let cache = Arc::new(cache);
        let p = principal("racer");

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
        // No file on disk → starts from default (empty capsule_egress).
        cache
            .persist_egress(&p, "react", "10.0.0.5:8080")
            .expect("first persist");
        // A second persist of the SAME endpoint under the SAME capsule
        // (case-insensitive) is a no-op success, not a duplicate.
        cache
            .persist_egress(&p, "react", "10.0.0.5:8080")
            .expect("idempotent persist");

        let profile = cache.resolve(&p).expect("reload");
        assert_eq!(
            profile.network.capsule_egress.get("react"),
            Some(&vec!["10.0.0.5:8080".to_string()]),
            "idempotent persist must not duplicate the entry"
        );
    }
}
