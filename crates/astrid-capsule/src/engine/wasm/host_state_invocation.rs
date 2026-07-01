//! Recv-path per-invocation context installer for `HostState`.
//! Split out of `host_state.rs` to stay under the 1000-line CI cap; included via `#[path]`.

use super::*;

impl HostState {
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
    /// Sets up the subset relevant to publish stamping and per-principal
    /// KV / log routing:
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
    ///
    /// Skipped vs the interceptor path (each is independently
    /// recoverable; documenting the gaps so the omissions are
    /// auditable):
    /// - `invocation_home` / `invocation_tmp` — these MOUNT a VFS (async), but
    ///   `ipc::poll` is a synchronous bindgen fn, so they are not installed on
    ///   this path. Run+recv capsules do not touch `home://` / `/tmp` paths, and
    ///   the load-time `home` / `tmp` fields are NEUTRAL (`None`) fail-closed
    ///   placeholders — so leaving them unset denies rather than exposing the
    ///   load-owner's mount. Install them (via the async
    ///   [`install_principal_overlays`](crate::engine::wasm::install_principal_overlays))
    ///   if a recv-driven capsule ever needs per-principal `home://`.
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

        self.invocation_env_overlay = crate::engine::wasm::load_invocation_env_overlay(
            &profile_principal,
            self.capsule_id.as_str(),
        );

        // Install the KV / secret-store / capsule-log overlays for the publisher
        // (owner included), or clear them to the neutral floor for a
        // principal-less event. `home` / `tmp` are NOT installed here: they mount
        // a VFS (async) and `ipc::poll` is a sync bindgen fn; run+recv capsules
        // do not touch `home://` / `/tmp`, and the neutral `None` fallback is
        // fail-closed (never the load-owner), so leaving them unset is correct.
        // This closes the recv-path secret bleed: a non-owner publisher now
        // resolves `effective_secret_store` to ITS OWN store, not `default`'s.
        crate::engine::wasm::install_principal_overlays_sync(self, publisher.as_ref());
    }
}
