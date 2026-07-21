//! Recv-path per-invocation context installer for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
    /// Build a fresh, empty per-principal cancellation-token map.
    ///
    /// Out-of-pool constructors (lifecycle hooks, the hook handler, tests) use
    /// this so they do not have to name the map type. The pooled path instead
    /// clones one shared map into every instance, exactly like
    /// [`new_connection_principals`](Self::new_connection_principals).
    #[must_use]
    pub fn new_principal_cancel_tokens() -> PrincipalCancelTokens {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    /// Install (or clear) the per-invocation cancellation token, mirroring the
    /// lifecycle of the other `invocation_*` overlays.
    ///
    /// `Some(p)` looks up `p`'s entry in the shared
    /// [`principal_cancel_tokens`](Self::principal_cancel_tokens) map, lazily
    /// minting a fresh [`child_token`](CancellationToken::child_token) of the
    /// instance [`cancel_token`](Self::cancel_token) if absent — so a
    /// full-instance cancel still cascades, and a principal whose token was
    /// cancelled + removed on view release gets a FRESH, uncancelled token when
    /// it re-registers and invokes again. `None` (principal-less context)
    /// clears the overlay so waits fall back to the instance token.
    ///
    /// The map mutex is only ever held for this entry-or-clone, so a poisoned
    /// lock (a panic while holding it) is recovered rather than propagated —
    /// wedging every principal's cancellation over a torn map would trade a
    /// liveness mechanism for a liveness bug.
    pub(crate) fn install_invocation_cancel_token(
        &mut self,
        principal: Option<&astrid_core::PrincipalId>,
    ) {
        match principal {
            Some(p) => {
                let token = {
                    let mut map = self
                        .principal_cancel_tokens
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    map.entry(p.clone())
                        .or_insert_with(|| self.cancel_token.child_token())
                        .clone()
                };
                self.invocation_cancel_token = Some(token);
            },
            None => self.invocation_cancel_token = None,
        }
    }

    /// Re-arm the wait context when a DEPARTED principal's cancelled token is
    /// still installed: clear the stale overlay so the next wait falls back to
    /// the (alive) instance token.
    ///
    /// The dedicated run-loop Store keeps its `invocation_*` overlays between
    /// messages (deliberately, for publish stamping), so after a per-principal
    /// cancel fires, that principal's cancelled token would otherwise poison
    /// the shared event pump forever: `ipc::recv` short-circuits before
    /// draining, starving every OTHER principal's messages — re-creating the
    /// cross-principal wedge the per-principal tokens exist to prevent. Called
    /// at the top of `ipc::recv` only — the pump anchor, where the
    /// cancellation has already delivered its wake. Pooled instances never
    /// need it (overlays clear on lease return), and it must NOT be called
    /// from mid-invocation wait sites (approval/elicit/io), where a cancelled
    /// invocation token is exactly the signal being delivered.
    ///
    /// When the INSTANCE token is cancelled too (full unload), the overlay is
    /// left in place: everything is being torn down and the short-circuit is
    /// the desired behaviour.
    pub(crate) fn clear_stale_invocation_cancel_token(&mut self) {
        if !self.cancel_token.is_cancelled()
            && self
                .invocation_cancel_token
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
        {
            self.invocation_cancel_token = None;
        }
    }

    /// Install per-invocation context from an inbound IPC message picked
    /// up via [`ipc::Host::ipc_recv`](crate::engine::wasm::host::ipc) /
    /// [`ipc::Host::ipc_poll`].
    ///
    /// Mirrors the principal-isolation setup done in
    /// [`WasmEngine::invoke_interceptor`](crate::engine::wasm::WasmEngine::invoke_interceptor)
    /// for the dispatcher path, but driven by `recv`/`poll` so that
    /// `run + ipc::recv` capsules (prompt-builder, registry,
    /// context-engine) also stamp publishes with the publisher's
    /// principal and route reads/writes to the invoking principal's
    /// namespaces. Without this hook these capsules silently fall back
    /// to the owner principal (`default` for the standard distro),
    /// breaking chat for any non-default agent: the publish goes out
    /// stamped `default`, downstream interceptors load the wrong KV
    /// namespace, the turn-state phase doesn't match, and the chain
    /// stalls.
    ///
    /// Sets up the context relevant to publish stamping and per-principal
    /// state routing:
    /// - [`caller_context`](Self::caller_context) — drives both
    ///   [`effective_principal`](Self::effective_principal) and the
    ///   `principal_str` chosen by `publish_inner`.
    /// - [`invocation_kv`](Self::invocation_kv) — per-principal KV
    ///   namespace; falls back to load-time `kv` on failure.
    /// - [`invocation_capsule_log`](Self::invocation_capsule_log) —
    ///   per-principal log file; falls back to load-time `capsule_log`
    ///   when the principal has no home directory yet.
    /// - [`invocation_profile`](Self::invocation_profile) — the publishing
    ///   principal's quota profile (owner included), resolved through
    ///   [`profile_cache`](Self::profile_cache) so per-principal ceilings
    ///   (background-process count, IPC throughput, HTTP streams) apply on
    ///   this path too; falls back to the process-global default on a missing
    ///   cache or failed load.
    ///
    /// - [`invocation_secret_store`](Self::invocation_secret_store) — installed
    ///   for the publisher (owner included) via the shared
    ///   [`install_principal_overlays_sync`](crate::engine::wasm::install_principal_overlays_sync),
    ///   so a non-owner publisher's `has_secret` / secret writes resolve to ITS
    ///   OWN store, never the neutral load-time fallback and never `default`'s.
    /// - `invocation_home` / `invocation_tmp` — mounted for the publisher so a
    ///   recv-driven capsule can use principal-scoped VFS paths and can spawn a
    ///   native process rooted in that same principal's home.
    ///
    /// Remaining difference from the interceptor path:
    /// - `store_meter` — the per-invocation linear-memory ceiling stays the
    ///   capsule owner's; the recv path does not re-target it per publisher
    ///   the way `invoke_interceptor` does. Acceptable because the run+recv
    ///   capsules are shared singletons whose per-call allocation is bounded
    ///   by the bus message-size limits. Re-target when a recv-driven capsule
    ///   needs per-principal memory enforcement.
    pub(crate) fn install_recv_invocation_context(&mut self, msg: &astrid_events::ipc::IpcMessage) {
        // Fast path: if the new message's principal matches whatever
        // we already have installed, keep the existing
        // `invocation_kv` / `invocation_capsule_log` rather than
        // re-opening the namespace and log file. The chat-stack run
        // loop calls this on every recv tick — re-init each time
        // burns I/O and allocations for no behavioural change.
        // An interceptor's caller is owned by the dispatch path
        // (`WasmEngine::invoke_interceptor`), not by recv. Nested
        // `ipc::recv` calls inside an interceptor must NOT overwrite
        // it — otherwise a recv'd message from a different publisher
        // (or the empty-batch clear path below) would silently flip
        // every subsequent `publish_json` away from the principal the
        // interceptor was dispatched under.
        if self.interceptor_active {
            return;
        }

        let publisher: Option<astrid_core::PrincipalId> = msg
            .principal
            .as_deref()
            .and_then(|p| astrid_core::PrincipalId::new(p).ok());
        let new_principal = msg.principal.clone();
        let existing_principal = self
            .caller_context
            .as_ref()
            .and_then(|c| c.principal.clone());
        if new_principal == existing_principal {
            // Refresh the caller context so e.g. topic name / payload
            // tracking stays current. Also refresh the env overlay: dashboard
            // onboarding can write config after a capsule is already loaded,
            // and a same-principal recv loop must observe the new file on the
            // next message without requiring a capsule reload.
            self.caller_context = Some(msg.clone());
            let env_principal = publisher.as_ref().unwrap_or(&self.principal);
            self.invocation_env_overlay = crate::engine::wasm::load_invocation_env_overlay(
                env_principal,
                self.capsule_id.as_str(),
            );
            if self.invocation_home.is_none() {
                self.install_recv_invocation_vfs(publisher.as_ref());
            }
            // Refresh the cancellation token from the shared map too (the map
            // is the source of truth; this field is a cache). Without this, a
            // publisher whose token was cancelled + removed on view release —
            // and who then re-registered — would keep the STALE cancelled
            // token on this persistent run-loop context, so its approval/
            // elicit waits during message processing would short-circuit
            // instead of waiting under a fresh per-principal token.
            self.install_invocation_cancel_token(publisher.as_ref());
            return;
        }

        self.caller_context = Some(msg.clone());

        // The publishing principal, parsed once. Used two different ways
        // below, matching the split in the interceptor path
        // (`invoke_interceptor`):
        //
        //   • QUOTA profile — resolved for EVERY publisher, the owner
        //     included. `effective_profile()`'s fallback is the process-global
        //     *default*, never the owner's profile, so an owner-published
        //     message must still resolve the owner's profile or its on-disk
        //     quotas are silently ignored. (For an owner with no profile file
        //     the cache returns the default, so this is a no-op in the common
        //     single-tenant case and only bites once an operator configures
        //     the owner principal.)
        //
        //   • KV / secret-store / log overlays — installed for EVERY publisher
        //     that carries a present, parseable principal, the load-owner
        //     (`default`) INCLUDED, via the shared
        //     [`install_principal_overlays_sync`]. A shared content-addressed
        //     runtime (issue #1069) is loaded under no real principal, so the
        //     load-time `kv` / `secret_store` / `capsule_log` are NEUTRAL
        //     fail-closed placeholders; every real publisher must get its OWN
        //     scope explicitly. A principal-less system/lifecycle event (no
        //     parseable principal) clears the overlays and resolves to the
        //     neutral floor — never another principal's data.
        //
        //   • Env overrides — refreshed for the effective publisher, owner
        //     included. Env files can be written after capsule load via the
        //     gateway onboarding route, so load-time `config` is only a
        //     fallback, not the whole source of truth.

        // Resolve the publisher's quota profile (owner included) so
        // per-principal ceilings (background-process count, IPC throughput,
        // HTTP streams) apply on the guest-pulled `recv` path too — not only
        // the dispatcher-driven interceptor path. When `msg.principal` is
        // absent/unparseable the owner's own profile is resolved, mirroring
        // `invoke_interceptor`'s `owner_principal` fallback. Best-effort: a
        // failed load logs and leaves `invocation_profile = None` (the same
        // process-global default fall-back as a missing cache), never denying
        // the message — the recv path has no error channel.
        let profile_principal = publisher.clone().unwrap_or_else(|| self.principal.clone());
        self.invocation_profile = self.profile_cache.as_ref().and_then(|cache| {
            match cache.resolve(&profile_principal) {
                Ok(profile) => Some(profile),
                Err(e) => {
                    tracing::warn!(
                        principal = %profile_principal,
                        error = %e,
                        "recv-path profile resolve failed; per-principal quotas fall back to the default profile"
                    );
                    None
                },
            }
        });
        // The recv path does not carry the engine's live group-policy snapshot,
        // so it cannot prove an exemption. Keep compute admission fail-closed.
        self.invocation_resource_exempt = false;

        self.invocation_env_overlay = crate::engine::wasm::load_invocation_env_overlay(
            &profile_principal,
            self.capsule_id.as_str(),
        );

        // Install every principal-scoped overlay for the publisher (owner
        // included), or clear to the neutral floor for a principal-less event.
        if crate::engine::wasm::install_principal_overlays_sync(self, publisher.as_ref()) {
            self.install_recv_invocation_vfs(publisher.as_ref());
        } else {
            self.invocation_home = None;
            self.invocation_tmp = None;
        }
    }

    /// Build the recv message's home/tmp VFS bundle synchronously. Principal
    /// switches are already deduplicated above, making this a per-switch cost
    /// rather than a per-message mount.
    fn install_recv_invocation_vfs(&mut self, principal: Option<&astrid_core::PrincipalId>) {
        let Some(principal) = principal else {
            self.invocation_home = None;
            self.invocation_tmp = None;
            return;
        };
        let Ok(astrid_home) = astrid_core::dirs::AstridHome::resolve() else {
            self.invocation_home = None;
            self.invocation_tmp = None;
            return;
        };
        self.install_recv_invocation_vfs_at(principal, &astrid_home);
    }

    fn install_recv_invocation_vfs_at(
        &mut self,
        principal: &astrid_core::PrincipalId,
        astrid_home: &astrid_core::dirs::AstridHome,
    ) {
        let bundle = build_recv_vfs_bundle_at(&astrid_home.principal_home(principal));
        self.invocation_home = bundle.home;
        self.invocation_tmp = bundle.tmp;
    }
}

fn build_recv_vfs_bundle_at(
    principal_home: &astrid_core::dirs::PrincipalHome,
) -> crate::engine::wasm::PrincipalVfsBundle {
    let home = mount_recv_dir(principal_home.root());
    let tmp = if home.is_some() {
        let path = principal_home.tmp_dir();
        if path.exists() || std::fs::create_dir_all(&path).is_ok() {
            mount_recv_dir(&path)
        } else {
            None
        }
    } else {
        None
    };
    crate::engine::wasm::PrincipalVfsBundle { home, tmp }
}

fn mount_recv_dir(root: &std::path::Path) -> Option<crate::engine::wasm::PrincipalMount> {
    if !root.exists() {
        return None;
    }
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let handle = astrid_capabilities::DirHandle::new();
    match astrid_vfs::HostVfs::with_registered_dir(handle.clone(), &root) {
        Ok(vfs) => Some(crate::engine::wasm::PrincipalMount {
            root,
            vfs: std::sync::Arc::new(vfs),
            handle,
        }),
        Err(error) => {
            tracing::warn!(%error, "failed to mount recv-path principal VFS");
            None
        },
    }
}

#[cfg(test)]
mod recv_vfs_tests {
    #[tokio::test]
    async fn recv_vfs_switches_principals_and_clears_without_one() {
        let root = tempfile::tempdir().expect("runtime home");
        let astrid_home = astrid_core::dirs::AstridHome::from_path(root.path());
        astrid_home.ensure().expect("runtime layout");
        let alice = astrid_core::PrincipalId::new("alice").expect("alice");
        let bob = astrid_core::PrincipalId::new("bob").expect("bob");
        astrid_home
            .principal_home(&alice)
            .ensure()
            .expect("Alice home");
        astrid_home.principal_home(&bob).ensure().expect("Bob home");

        let mut state = crate::engine::wasm::test_fixtures::minimal_host_state(
            tokio::runtime::Handle::current(),
        );
        state.install_recv_invocation_vfs_at(&alice, &astrid_home);
        let alice_root = state
            .invocation_home
            .as_ref()
            .expect("Alice mount")
            .root
            .clone();
        assert_eq!(
            alice_root,
            astrid_home
                .principal_home(&alice)
                .root()
                .canonicalize()
                .expect("canonical Alice home")
        );

        state.install_recv_invocation_vfs_at(&bob, &astrid_home);
        let bob_root = state
            .invocation_home
            .as_ref()
            .expect("Bob mount")
            .root
            .clone();
        assert_ne!(alice_root, bob_root);
        assert_eq!(
            bob_root,
            astrid_home
                .principal_home(&bob)
                .root()
                .canonicalize()
                .expect("canonical Bob home")
        );

        state.install_recv_invocation_vfs(None);
        assert!(state.invocation_home.is_none());
        assert!(state.invocation_tmp.is_none());
    }
}
