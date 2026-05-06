# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changelog tracking starts with 0.2.0. Prior versions were not tracked.

## [Unreleased]

### Fixed

- **`IpcMessage` now tolerates wire frames that omit `timestamp` and `signature`.** Both fields are serde-defaulted (`timestamp` falls back to `Utc::now()` on deserialize, `signature` to `None`). The CLI proxy capsule (`astrid-capsule-cli`) forwards bus messages to socket clients using only the fields exposed by the SDK's `ipc::Message`: `{topic, payload, source_id}`. The SDK does not surface the original timestamp or signature, so every CLI proxy frame previously omitted them and the headless client's strict `from_slice::<IpcMessage>` silently failed on every frame — `astrid -p` and the chat REPL never received `agent.v1.response` and either timed out at 120s or hung indefinitely. Defaulting at the deserialization boundary preserves semantics for in-process publishers (which always set the fields via `IpcMessage::new`) while letting forwarding capsules pass partial frames through. Round-trip behaviour for already-complete frames is unchanged.
- **Interceptor dispatch restored for capsules without a `#[astrid::run]` loop.** After the wasmtime Component Model migration, the kernel's run-loop pre-scan misclassified every Component Model capsule as a live run-loop daemon, zeroed out the store/instance, and returned `NotSupported("plugin handles interceptors internally via IPC auto-subscribe")` for every direct interceptor invocation. End-to-end chat REPL was non-functional. The `wasm32-wasip2` toolchain auto-synthesizes a single shared nop function for every mandatory WIT `func()` export the source crate doesn't implement (`run`, `astrid-install`, `astrid-upgrade`) and aliases all unimplemented exports to that one function. The pre-scan now treats a `run` export aliased to `astrid-install` or `astrid-upgrade` as a stub and routes the capsule through the direct-invoke path. The same fix applies to lifecycle pre-scans, so capsules without real `#[astrid::install]` / `#[astrid::upgrade]` no longer compile a transient component just to run a nop. Real `#[astrid::run]` daemons (`prompt-builder`, `context-engine`, `cli`) keep using the auto-subscribe path introduced in #343.
- **`[[topic]]` declarations now accept trailing-suffix wildcards (e.g. `llm.v1.request.generate.*`).** The previous validator rejected every wildcard in topic names, which broke fan-out topic families where the trailing segment names a provider, source, or recipient that can't be enumerated at manifest-author time (multiple LLM providers, multiple session callbacks, hook fan-out targets). Every member of the family shares the same envelope, so a pattern is the genuine schema declaration. Mid-segment (`a.*.b`) and leading (`*.b`) wildcards are still rejected — the bus matcher only supports trailing-suffix wildcards, so those would silently never fire. Bare `*` is rejected as too broad. Mirrors `ipc_subscribe`'s host-side check.

### Breaking

- **`PrincipalProfile` files moved out of the principal home directory.** Per-principal `profile.toml` now lives at `~/.astrid/etc/profiles/{principal}.toml` instead of `~/.astrid/home/{principal}/.config/profile.toml`. Profile contents are 100% system policy (enabled, groups, grants, revokes, quotas, auth public keys, egress, process allowlist) — keeping them inside the principal's home directory let any capsule with `fs_read = ["home://"]` read its own policy file (and `fs_write` would have let it self-elevate). The new location sits outside the `home://` VFS scheme entirely. `PrincipalProfile::path_for(&PrincipalHome)` is now `PrincipalProfile::path_for(&AstridHome, &PrincipalId)`; same for `load`/`save`. A one-shot migration in `seed_default_principal_admin_profile` moves any legacy `home/{principal}/.config/profile.toml` to the new location on next boot. (#672)
- **`AdminKernelRequest` and `AdminKernelResponse` are now wrapper structs** with the typed body on a `kind`/`body` field, plus an optional `request_id` for client-side correlation. Pre-existing test fixtures using `AdminKernelRequest::AgentCreate { ... }` should construct the variant on `AdminRequestKind` and convert (`AdminRequestKind::AgentCreate { ... }.into()` or `AdminKernelRequest::new(...)`). The wire format is forward-compatible: `request_id` is omitted when `None`. (#672)
- **`AuditAction::AdminRequest` gained a `params: Option<serde_json::Value>` field.** Forward-compatible (`#[serde(default)]` + `skip_serializing_if`), but external consumers parsing audit entries with strict schemas may need to add the field. Capture is for forensic replay (issue #672). (#672)
- **`PermissionError` gained a `PrincipalDisabled` variant** thrown by the Layer 5 enforcement preamble when the caller's profile has `enabled = false`. Existing `match` blocks against the enum need a new arm. (#672)
- **`Kernel.groups` field type changed from `Arc<GroupConfig>` to `Arc<ArcSwap<GroupConfig>>`** (issue #672 — Layer 6). The boot-loaded group config is now hot-reloadable through the admin IPC topics (`astrid.v1.admin.group.*`); every authorization check clones the current `Arc` via `load_full()` on each request. Enforcement preambles hold their own `Arc` snapshot per check, so in-flight checks observe a consistent config even during a swap. Any direct consumer matching on `Arc<GroupConfig>` must migrate to `kernel.groups.load_full()`.
- **Built-in `agent` group gains `self:quota:get` and `self:agent:list` capabilities** (issue #672). `self:*` already subsumed both, but operators inspecting or matching on the exact capability vector see a minor widening. This makes agent self-service visibility into their own row and quotas an explicit contract rather than an incidental consequence of `self:*`.
- **Default principal's profile now carries `groups = ["admin"]` after boot (issue #670).** `bootstrap_cli_root_user` writes `groups = ["admin"]` to `~/.astrid/home/default/.config/profile.toml` on any boot where the profile is absent or has `groups=[] && grants=[] && revokes=[]`. Operators who previously ran with an explicitly empty `groups` list — and no grants/revokes — will see the default principal gain full management-API capabilities on the next boot. Either edit the profile to add a non-admin group (e.g. `restricted`), or add an explicit `grants`/`revokes` entry, to block the auto-seed. Profiles that already name any group, grant, or revoke are left untouched. (#670)
- **`CapabilityToken` signing format bumped v1 → v2** with `principal` signed into the payload (Layer 4 multi-tenancy, issue #668). Existing v1 persistent tokens on disk fail `verify_signature()` after upgrade and get rejected with `InvalidSignature` plus a `tracing::error!` pointing operators at re-mint. There is no silent migration path — changing the signing payload is a cryptographic break, not a data migration. `CapabilityToken::create` and `create_with_options` now take a required `principal: PrincipalId` argument. (#668)
- **`Allowance.principal: PrincipalId`** is now required at construction. `AllowanceStore` keys on `(principal, id)`; `find_matching`, `find_matching_and_consume`, `consume_use`, `export_session_allowances`, `export_workspace_allowances`, and `clear_session_allowances` now take `&PrincipalId`. A new `clear_all_session_allowances` retains the global sweep for kernel-initiated shutdown. (#668)
- **`CapabilityStore::has_capability` / `find_capability` now take `&PrincipalId`.** Tokens whose `principal` does not match the caller are rejected up front, even if the resource pattern matches — fail-closed cross-principal check. Revocation and single-use consumption stay global (they are about the token's identity, not the caller). Persistent KV keys changed from `caps:tokens/{token_id}` to `caps:tokens/{principal}/{token_id}`. `CapabilityValidator::check` and `validate_by_id` also thread `&PrincipalId`. (#668)
- **`Kernel.active_connections` is now per-principal** (`DashMap<PrincipalId, AtomicUsize>`). `connection_opened(&PrincipalId)` / `connection_closed(&PrincipalId)` take the connecting principal; only that principal's session allowances are cleared on last-disconnect. New `total_connection_count()` sums across principals for ephemeral-shutdown. (#668)
- **`Kernel.overlay_vfs` replaced by `Kernel.overlay_registry: Arc<OverlayVfsRegistry>`.** Each invoking principal resolves their own `OverlayVfs` on first use; Agent A's workspace writes never reach Agent B's view of the same tree. The registry is bounded (default 1024 principals, tunable via `ASTRID_OVERLAY_REGISTRY_MAX_PRINCIPALS`) with idle-eviction. `Kernel.vfs` now points at a plain workspace `HostVfs` — kernel-internal paths that do not know a principal keep using that field. (#668)
- **`SecurityInterceptor::intercept` and `ApprovalManager::check_approval` take `&PrincipalId`.** Single-tenant callers pass `PrincipalId::default()`. (#668)
- **`ApprovalDecision::ApproveWithAllowance` now boxes `Allowance`** (`Box<Allowance>`) — the added `principal` field pushed the enum past clippy's `large_enum_variant` threshold. (#668)
- **WASM engine migrated from Extism to wasmtime Component Model.** The kernel now loads Component Model binaries via `Component::from_binary`, not Extism modules. Existing capsules compiled with `extism-pdk` will not load — they must be rebuilt with the migrated SDK targeting `wasm32-wasip2`. This is a coordinated multi-repo migration (SDK + 16 capsule repos). (#632)
- **WIT host function signatures retyped.** All 49 functions now use proper typed params/returns (`result<T, string>`, WIT records, `u64` handles) instead of `string`-based JSON blobs. The `HostResult` 0x00/0x01 prefix encoding is removed — errors are returned via WIT `result` types. (#632)
- **Guest export `astrid-hook-trigger` signature changed.** Was `func(input: list<u8>) -> list<u8>`. Now `func(action: string, payload: list<u8>) -> capsule-result`. The action name and payload are separate typed parameters; the return is the typed `capsule-result` record. (#632)
- **`capsule_abi` module removed from `astrid-core`.** Types (`CapsuleAbiContext`, `CapsuleAbiResult`, `LogLevel`, etc.) are replaced by `wasmtime::component::bindgen!` generated types. (#632)
- **Approval API simplified.** `risk-level` removed from `approval-request` WIT record. `decision` removed from `approval-response`. Capsules declare action + resource, get back approved/denied. Risk classification was speculative complexity — the kernel manages allowance-based approval without risk levels. (#641)

### Fixed

- **bwrap mount ordering hides capsule directory on Linux.** Hidden `--tmpfs` overlays (e.g. `~/.astrid`) were applied before writable `--bind` mounts, erasing capsule directories inside the hidden path. Reordered so bind-mounts come after tmpfs and punch through. Mirrors the ancestor check already present in the macOS Seatbelt path (PR #534). (#648)
- **bwrap silently fails on Ubuntu 24.04+ (AppArmor).** `kernel.apparmor_restrict_unprivileged_userns=1` blocks user namespaces required by bwrap. Added a cached probe at startup that detects this and falls back to unsandboxed execution with a clear warning and distro-specific install instructions. (#648)
- **`capsule remove` no longer deletes env config by default.** User configuration (API keys, secrets) in `env.json` is preserved across uninstall/reinstall cycles. Use `--purge` to explicitly delete saved configuration. (#647)
- **`astrid-build` targets `wasm32-wasip2`** for Component Model capsules. Was still targeting `wasm32-wasip1`, producing plain WASM modules. (#649)
- **`astrid-build` bundles SDK shared WIT** (`astrid-contracts.wit`) into capsule archives as a WIT dep, so `wit_type` references in `Capsule.toml` resolve at install time without manual WIT duplication. (#649)
- **JSON Schema field names converted to snake_case** in `wit_schema` to match `serde(rename_all = "snake_case")` wire convention. (#649)
- **`reqwest::blocking` inside `#[tokio::main]` panics on first run.** All HTTP call sites in `self_update.rs`, `init.rs`, and `capsule/install.rs` used `reqwest::blocking::Client`, which creates an internal tokio runtime that panics on drop inside the outer async context. Converted to async `reqwest`. Only manifested on fresh installs (no cache/lock files to short-circuit). (#645)
- **`INTERNAL_SUBSCRIBER_COUNT` debug_assert race.** `EventDispatcher` subscribed to the event bus inside `tokio::spawn(dispatcher.run())`, so the assert could fire before the spawned task started. Moved subscription into `EventDispatcher::new()`. (#645)

### Added

- **CLI redesign — modern noun-verb structure with multi-tenancy admin surface (issue #657).**
  - The CLI is now modelled after `gh` and `fly`: `astrid agent <verb>`, `astrid capsule <verb>`, `astrid quota <verb>`, etc.
  - System-level operations (`status`, `start`, `stop`, `restart`, `ps`, `top`, `who`, `logs`) stay as bare verbs for speed.
  - `astrid` with no subcommand still drops the operator into an interactive agent session — the unchanged self-hosting path.
  - Phase 1 covers the admin-surface bulk unblocked by Layer 6 (#672); sub-agent delegation, vouchers, audit, trust, budget, and remote A2A surfaces are registered in the clap tree but stubbed with tracking-issue references (`#656`, `#658`, `#675`, `#653`) and exit code 2 so CI scripts can pattern-match.
  - New verbs implemented end-to-end against the Layer 6 admin IPC: `agent create / list / show / delete / enable / disable / switch / current`, `group create / list / show / delete / modify`, `caps show / grant / revoke / check`, `quota show / set`, `secret set / list / delete`, `capsule install / update / list / remove / tree / build / config / show`, `distro apply`, `gc`, `restart`, `logs`, `doctor`, `version`, `completions`, `update`, `ps`, `top`, `who`.
  - Every list/show command supports `--format pretty|json|yaml|toml`.
  - Per-agent commands accept `--agent <name>`/`-a` to override the active context; without the flag they fall back to `~/.astrid/run/cli-context.toml` written by `astrid agent switch`.
  - Migration aliases retained: `session info` → `session show`, `self-update` → `update`, `wit gc` → `gc`, top-level `build` → `capsule build`.
  - New `admin_client` module wraps `SocketClient` with `request_id` correlation (UUID v4 per call, echoed on `astrid.v1.admin.response.<topic>`) so multiple in-flight admin commands can disambiguate responses, and tolerates broadcast frames (`astrid.v1.capsules_loaded`) whose payloads do not round-trip through `IpcPayload::RawJson`'s tag.
  - New `read_until_topic` helper on `SocketClient` propagates the same skip-and-retry pattern to the bare verbs. (#657)

- **`PrincipalProfile.enabled` is now enforced by the Layer 5 management-API preamble.** Pre-Layer-6 the flag was set on disk by `agent.disable` but never consulted by `authorize_request` — operators who disabled an agent saw the flag persist while the agent kept passing authz checks. The preamble now resolves the caller's profile, and if `enabled = false` returns the new `PermissionError::PrincipalDisabled` variant before the capability check. (#672)
- **`PrincipalProfile.enabled` is also now enforced at Layer 3 (`WasmEngine::invoke_interceptor`).** Pre-fix, only the management API honored the flag; capsule invocations bypassed it entirely. The Layer 3 gate runs right after profile cache resolution and returns `CapsuleError::WasmError("principal '{p}' is disabled")` with a `security_event = true` log. In-flight invocations finish under the old value (we only check at entry); new invocations after `agent.disable` are refused. Together with the Layer 5 gate, `agent.disable` now denies *every* surface a principal can drive. (#672)
- **Phantom-principal pre-condition** on every mutating admin handler. `caps.grant`, `caps.revoke`, `quota.set`, `agent.enable`, and `agent.disable` now require the target's `profile.toml` to already exist on disk. Without this gate, a typo'd principal name (`alic` vs `alice`) silently materialized a phantom principal — `PrincipalProfile::load_from_path` returns `Default` on `NotFound`, the handler then saved the mutated default to disk, and any future traffic claiming that principal inherited the phantom permissions. `quota.get` got the same gate so a typo doesn't return Default-shaped quotas without revealing the mistake. (#672)
- **`agent.delete` removes `profile.toml`.** Pre-fix the handler unlinked the identity and invalidated the cache but left the policy file on disk; subsequent traffic claiming that principal would re-load the old policy. Home-directory data (capsule KV, audit chain) is still left intact — that's an ops-managed concern. (#672)
- **`agent.disable` and `caps.revoke` against the `default` principal are rejected.** The `default` principal is the bootstrap admin anchor; either operation could lock the operator out of the management API entirely (the new `enabled` gate denies every request from a disabled principal, and `caps.revoke self:*` would clear the operator's grants). `caps.grant` and `quota.set` on `default` remain allowed — they only add/adjust, never remove. (#672)
- **`AdminKernelRequest` now carries an optional `request_id`** echoed back on `AdminKernelResponse`. Lets clients with multiple in-flight requests on the shared `astrid.v1.admin.response.<topic>` channel disambiguate responses. The wire shape is `{ "request_id": "...", "method": "...", "params": {...} }` — `request_id` is `skip_serializing_if = Option::is_none`, so single-client deployments emit no extra field. The typed body lives on `AdminKernelRequest.kind: AdminRequestKind` (the previous enum, renamed). (#672)
- **`AuditAction::AdminRequest.params: Option<serde_json::Value>`** captures the request payload (capabilities granted, quotas set, group definition, etc.) so forensic replay doesn't require diffing `profile.toml`/`groups.toml` snapshots. `None` for legacy `KernelRequest` entries with no params struct. Forward-compatible add (`#[serde(default)]` + `skip_serializing_if`). (#672)
- **Layer 6 management IPC for agent lifecycle, quotas, groups, and capability grants (issue #672).** New `astrid.v1.admin.*` IPC surface with 13 topics covering agent (`create`, `delete`, `enable`, `disable`, `list`), quotas (`set`, `get`), groups (`create`, `delete`, `modify`, `list`), and per-principal capabilities (`grant`, `revoke`). Every topic runs through the existing Layer 5 `CapabilityCheck::require` preamble — there is no new authz mechanism. Capability mappings:
  - `admin.agent.create|delete|enable|disable` → `agent:create|delete|enable|disable`
  - `admin.agent.list` → `self:agent:list` (self) / `agent:list` (cross-tenant)
  - `admin.quota.set|get` → `self:quota:set|get` / `quota:set|get`
  - `admin.group.create|delete|modify|list` → `group:create|delete|modify|list`
  - `admin.caps.grant|revoke` → `caps:grant|caps:revoke`

  Mutating topics acquire a new `tokio::sync::Mutex<()>` (`Kernel.admin_write_lock`) so concurrent writers never interleave on `profile.toml` / `groups.toml`. Every profile-mutating handler (`quota.set`, `caps.grant`, `caps.revoke`, `agent.enable`, `agent.disable`) calls `profile_cache.invalidate(&target)` after the atomic write so subsequent authz checks reflect the new state without waiting on kernel restart. Group admin topics rewrite `groups.toml` atomically (tempfile + rename + `0o600` on Unix) and then `kernel.groups.store(Arc::new(new_config))` the `ArcSwap` — in-flight checks holding the old `Arc` finish under the old config, the next `load_full` sees the new one. Built-in groups (`admin`, `agent`, `restricted`) cannot be deleted or modified; `default` principal cannot be deleted. `caps.grant` never clears a matching revoke — Layer 5 precedence (revoke > grant > group) is preserved. Every allow and deny writes `AuditAction::AdminRequest` with `method` set to the topic wire name (`admin.agent.create`, etc.) and `target_principal` set when operating on another principal. `agent.delete` removes the `AstridUserId` and CLI identity link but does not scrub the home directory — reclamation is an ops concern. (#672)
- **`AdminKernelRequest` / `AdminKernelResponse` wire types** in `astrid-types::kernel` with tagged serde (`#[serde(tag = "method", content = "params")]`), mirroring the shape of `KernelRequest` / `KernelResponse`. Response variants include `Success(Value)`, `AgentList(Vec<AgentSummary>)`, `GroupList(Vec<GroupSummary>)`, `Quotas`, and `Error`. (#672)
- **Atomic `GroupConfig::save_to_path` + `save`** in `astrid-core::groups::io_impl` — tempfile + rename + `0o600` on Unix, mirroring `PrincipalProfile::save_to_path`. On rename failure the tempfile is removed so no secret-adjacent stale state is left on disk. (#672)
- **`GroupConfig::insert_custom_group`, `modify_custom_group`, `remove_group`, `is_builtin_name`** — immutable-value mutators that return a new `GroupConfig` with the requested change applied. Built-in names are rejected; modify/remove of unknown custom groups returns the new `GroupConfigError::UnknownGroup` variant (vs `DuplicateName` for insert collisions). (#672)
- **`IdentityStore::delete_user` and `list_users`** on the trait and `KvIdentityStore` — required by `admin.agent.delete` (delete user record + all links pointing at it, idempotent for unknown UUIDs) and `admin.agent.list` (enumerate user records). The name-index entry is cleared only when it still points at the deleted UUID (last-writer-wins survives). (#672)
- **`arc-swap` workspace dependency** for lock-free hot-reloadable `GroupConfig`. (#672)
- **Capability/group enforcement on the management API (issue #670).** Every arm of `kernel_router::handle_request` now runs through a `CapabilityCheck` enforcement preamble before reaching the handler body. Each `KernelRequest` variant maps to a required capability (`Shutdown → system:shutdown`, `ReloadCapsules → self:capsule:reload`, `InstallCapsule → self:capsule:install`, `ListCapsules`/`GetCommands`/`GetCapsuleMetadata → self:capsule:list`, `GetStatus → system:status`, `ApproveCapability → self:approval:respond`); no default-allow branch. The caller's principal is resolved from `IpcMessage.principal` (falling back to `PrincipalId::default()` for pre-#658 single-token socket traffic), their `PrincipalProfile` comes from the profile cache, and the new `GroupConfig` is boot-loaded from `$ASTRID_HOME/etc/groups.toml` (missing file → built-ins only). Precedence follows revoke > grant > group-inherited, so operators can revoke specific capabilities from admins without dropping the admin membership. Built-in groups (`admin`, `agent`, `restricted`) cannot be redefined at load time; custom groups must opt-in via `unsafe_admin = true` to grant the universal `*`. Every allow and deny outcome writes a new `AuditAction::AdminRequest { method, required_capability, target_principal }` audit entry (chain-linked, signed). The `default` principal is seeded with `groups = ["admin"]` on first boot so single-tenant deployments keep full access with no config. `CapabilityCheck` is a pure function — no I/O, no locking — and is a distinct namespace from the runtime `CapabilityToken` system (which continues to gate capsule-level sensitive actions). (#670)
- **`GroupConfig` + `Group` in `astrid-core::groups`** with a TOML loader at `$ASTRID_HOME/etc/groups.toml`, baked-in `admin`/`agent`/`restricted` built-ins, fail-closed handling for missing/malformed files, rejection of built-in redefinition, rejection of capability strings containing `**` or shell metacharacters, and a `Group::unsafe_admin` opt-in for custom groups that need the universal `*` capability. (#670)
- **`PrincipalProfile.grants` and `PrincipalProfile.revokes`** (per-principal capability overrides) validated at load/save time via the new `astrid_core::capability_grammar::validate_capability` helper. Revokes have strict precedence over grants and group-inherited capabilities. (#670)
- **`CapabilityCheck` + `PermissionError` in `astrid-capabilities`** — the policy-evaluation primitive. Borrowed evaluator over `(&PrincipalProfile, &GroupConfig)` with `has(&str) -> bool` and `require(&str) -> Result<(), PermissionError>`. Pure, thread-safe, zero-alloc on the hot path. (#670)
- **`AuditAction::AdminRequest { method, required_capability, target_principal }`** — new audit action for management-API requests, written with `AuthorizationProof::System` on allow and `AuthorizationProof::Denied` on deny. (#670)
- **Principal-scoped `AllowanceStore`, `CapabilityStore`, `OverlayVfs`, and connection counter (Layer 4).** `Allowance.principal` and `CapabilityToken.principal` are now required construction-time fields. All store lookups are principal-filtered up front; Agent A's approvals and capabilities never match Agent B. A new `astrid_vfs::OverlayVfsRegistry` gives each invoking principal a fresh `OverlayVfs` on first use, with a bounded (default 1024) LRU-evicting cache keyed by `PrincipalId`. `Kernel.active_connections` became a per-principal `DashMap`; only the disconnecting principal's session allowances are cleared, while ephemeral shutdown still waits on the global `total_connection_count()`. `WasmEngine::invoke_interceptor` resolves the invoking principal's overlay on every call and installs it on `HostState.invocation_overlay_vfs`. Single-tenant deployments pass `PrincipalId::default()` and see no behavior change. Extends invariants #6 and #7 from issue #653 (Agent A cannot use Agent B's approvals or capabilities). (#668)
- **Per-invocation quota enforcement from `PrincipalProfile` (Layer 3).** `WasmEngine::invoke_interceptor` now resolves the invoking principal's `PrincipalProfile` through a new kernel-scoped `PrincipalProfileCache` (`astrid_capsule::profile_cache`) and applies per-invocation: `max_memory_bytes` via a rebuilt `StoreLimits`, `max_timeout_secs` via the epoch deadline (non-daemon capsules only), and `max_ipc_throughput_bytes` via the rate limiter. `IpcRateLimiter` is rekeyed from `Uuid` to `(Uuid, PrincipalId)` so two principals sharing a single capsule instance never starve each other's throughput. `ManagedProcess` and active HTTP streams are tagged with the creator principal and counted per-principal against the existing per-capsule hard ceilings (`MAX_BACKGROUND_PROCESSES = 8`, `MAX_ACTIVE_HTTP_STREAMS = 4`) — the effective cap is always `min(profile, hard_cap)`. Profile load failures (malformed TOML, unknown fields, invalid values, future `profile_version`) fail the invocation closed; there is no fallback to the capsule owner's limits. `max_storage_bytes` is read but not enforced (no storage accountant yet; deferred). Single-tenant deployments without a `profile.toml` get Layer 2's `Default` profile and see no behavior change. (#666)
- **Per-principal `PrincipalProfile` + `profile.toml`.** New `astrid_core::profile` module with the per-principal policy struct (enablement, groups, auth methods, network egress, process spawn, resource quotas) plus loader and atomic writer at `~/.astrid/home/{principal}/.config/profile.toml`. Missing file falls back to `Default`; malformed TOML, unknown fields, failed validation, or a future `profile_version` are hard errors. Save is atomic on Unix (temp write at `0o600`, then `rename`). Validation fires on both load and save. Pure data plumbing — Layer 3 enforcement in `invoke_interceptor`, hot-reload, management IPC, and CLI are separate follow-ups. (#663)
- **Content-addressed WIT store** at `~/.astrid/wit/{blake3}.wit`. Install-time WIT files (including `deps/`) are recursively hashed, deduped, and stored with atomic writes. Per-capsule `wit/` is removed after addressing; `meta.json.wit_files` is the authoritative manifest. Append-only by design for replay preservation. (#649)
- **`astrid wit gc`** — admin-only mark-sweep GC for the WIT content store. Dry-run by default, `--force` to delete. Scans all principal homes + workspace. (#649)
- **Per-invocation `home://` and `/tmp/` VFS scoping.** A shared capsule serving multiple agents now resolves `home://` and `/tmp/` against the *invoking* agent's home directory (`~/.astrid/home/{principal}/`) instead of the capsule owner's. The security gate accepts a `principal_home` parameter and `WasmEngine::invoke_interceptor` builds a per-principal VFS bundle when the invocation principal differs from the capsule's. Unregistered principals (no home directory on disk) receive a clean denial — the kernel does not auto-create principal homes. Single-tenant installs (all traffic under `default`) see no behavior change. Precursor to multi-tenancy (#653). (#549)
- **Per-invocation `SecretStore` and capsule log re-scoping.** `has_secret` now reads secrets from the *invoking* agent's KV namespace (and OS keychain scope), and `astrid_log` writes to the invoking agent's `~/.astrid/home/{principal}/.local/log/{capsule}/{date}.log`. `HostState` gains `invocation_secret_store` / `invocation_capsule_log` fields plus `effective_secret_store()` / `effective_capsule_log()` accessors; `WasmEngine::invoke_interceptor` installs per-principal resources alongside the existing invocation VFS bundle and clears them on exit. Unregistered principals receive `None` — no attacker home is auto-created. Finishes #653 Layer 1's side-channel isolation started in #659. (#661)

### Removed

- **Raw `.wasm` release asset install paths.** Capsule distribution is now `.capsule` archive or clone+build. Raw WASM assets can't carry WIT dependencies. (#649)
- **`install_standard_wit()` from init.** Fetched stale per-interface WIT from upstream repo; shared contracts are now bundled by `astrid-build` into each capsule archive. (#649)

### Added (prior)

- **WIT-driven IPC topic schemas.** Capsules declare `wit_type = "record-name"` on `[[topic]]` entries in `Capsule.toml`. At install time, `wit-parser` reads the record from the capsule's `wit/` directory, extracts field names, types, and `///` doc comments into JSON Schema, and bakes it into `meta.json`. At runtime, `WasmEngine::load()` populates the `SchemaCatalog` from baked schemas. The LLM sees typed field descriptions without capsule authors writing JSON Schema by hand. (#643)
- `astrid-build::wit_schema` module — converts WIT records to JSON Schema. Handles primitives, `option<T>`, `list<T>`, tuple, enum, flags, variant, result, nested records, and type aliases. (#643)
- `wit_type: Option<String>` field on `TopicDef` in `Capsule.toml` — references a WIT record by kebab-case name. (#643)
- Schema catalog (`SchemaCatalog`) for A2UI Track 2 — maps IPC topics to schema definitions. Populated at capsule load time from baked `meta.json` schemas. (#632, #643)
- Epoch-based WASM timeout with `EpochTickerGuard` RAII type — replaces Extism wall-clock timeout. 5-minute deadline for interceptors, u64::MAX for daemons/run-loops, 10-minute safety net for lifecycle hooks. (#632)
- 64MB per-capsule WASM memory limit via `StoreLimitsBuilder` (matches old Extism setting). Global budget for multi-tenant hosting is a follow-up (#639). (#632)
- New WIT record types: `spawn-request`, `interceptor-handle`, `net-read-status` (variant), `capability-check-request/response`, `identity-*-request`, `elicit-request`. (#632)

### Removed

- `extism` dependency — replaced by direct `wasmtime` 43 + `wasmtime-wasi` 43. (#632)
- `capsule_abi.rs` (252 lines) — hand-written WIT type mirrors. (#632)
- `host/shim.rs` (430 lines) — Extism dispatch shim, `WasmHostFunction` enum, `register_host_functions()`, manual memory helpers. (#632)
- `RiskLevel` enum and all references — removed from WIT, IPC payloads, approval engine, audit entries, CLI renderers, policy engine, and test fixtures. Approval prompts now render with a single style. The allowance store handles "don't ask again" patterns without risk classification. (#641)

## [0.5.1] - 2026-03-25

### Added

- `cargo install astrid` now also installs `astrid-build` (capsule compiler) alongside `astrid` and `astrid-daemon`. Previously required a separate `cargo install astrid-build`.

### Fixed

- `astrid capsule install` no longer blocks when a new capsule exports an interface already exported by an installed capsule. Multiple providers (e.g. two LLM providers) can now coexist — prints an informational note instead of prompting for replacement.

## [0.5.0] - 2026-03-24

### Changed

- `workspace://` VFS scheme renamed to `cwd://` — the scheme maps to the daemon's CWD at boot; the old name implied a structured project workspace concept that was never implemented.

- **Tools are now a pure IPC convention.** Removed kernel-side tool dispatch (`WasmCapsuleTool`, `CapsuleTool` trait, `inject_tool_schemas`, `CapsuleToolContext`), `ToolDef` and `[[tool]]` from manifest, `inject_tool_schemas` from `astrid-build`. The kernel no longer parses or manages tool schemas. Tool capsules use IPC interceptors on `tool.v1.execute.<name>` and `tool.v1.request.describe`. The router capsule handles discovery and dispatch.
- **LLM providers are now a pure IPC convention.** Removed `LlmProviderDef` and `[[llm_provider]]` from manifest, `LlmProviderInfo` and `llm_providers` from `CapsuleMetadataEntry`. The kernel no longer parses or manages provider metadata. LLM capsules self-describe via `llm.v1.request.describe` interceptors; the registry capsule discovers them via `hooks::trigger`.
- **Removed dead cron host functions.** `astrid_cron_schedule` and `astrid_cron_cancel` were never implemented (stubs only). `CronDef` and `[[cron]]` removed from manifest. WIT spec updated: 49 host functions across 10 domain interfaces.
- Append-only artifact store — `bin/` and `wit/` are never deleted on capsule remove. Content-addressed artifacts are the audit trail; deleting them breaks provability. Future `astrid gc` for explicit cleanup.
- Replace `[dependencies]` provides/requires string arrays with `[imports]`/`[exports]` namespaced TOML tables — semver version requirements on imports (`^1.0`), exact versions on exports (`1.0.0`), optional imports, namespace/interface name validation
- **WIT spec:** Rewrite `wit/astrid-capsule.wit` to document all 51 host ABI functions (was 7). Split monolithic `host` interface into 11 domain-specific interfaces (fs, ipc, uplink, kv, net, http, sys, cron, process, elicit, approval, identity). Updated guest exports to reflect actual entry points (`astrid_hook_trigger`, `astrid_tool_call`, `run`, `astrid_install`, `astrid_upgrade`). Bumped package version to `0.2.0`.

### Added

- `cargo install astrid` installs both `astrid` (CLI) and `astrid-daemon` binaries from a single crate. The CLI crate now includes the daemon as a second `[[bin]]` entry point.
- `astrid self-update` command — checks GitHub releases for newer versions, downloads platform-specific binary to `~/.astrid/bin/`, no sudo required. Startup update banner (cached 24h) notifies on interactive commands.
- `astrid init` PATH setup — detects shell (zsh/bash/fish), offers to append `~/.astrid/bin` to the appropriate RC file
- Standard WIT interface installation during `astrid init` — fetches 9 WIT files (llm, session, spark, context, prompt, tool, hook, registry, types) from the canonical WIT repo and installs to `~/.astrid/home/{principal}/wit/` for capsule and LLM access via `home://wit/`
- Short-circuit interceptor chain — interceptors return `Continue`, `Final`, or `Deny` to control the middleware chain. A guard at priority 10 can veto an event before the core handler at priority 100 ever sees it. Wire format: discriminant byte (0x00/0x01/0x02) + payload, backward compatible with existing capsules.
- Export conflict detection on `capsule install` — detects when a new capsule exports interfaces already provided by an installed capsule, prompts user to replace. Nix-aligned approach: conflicts derived from exports data, no name-based `supersedes` field needed.
- Interceptor priority — `priority` field on `[[interceptor]]` in Capsule.toml (lower fires first, default 100). Enables layered interception (e.g. input guard before react loop).
- Distro.lock regeneration on `astrid capsule update` — keeps the lockfile in sync after capsule updates
- Content-addressed WIT storage — capsule install hashes `.wit` files into `~/.astrid/wit/`, capsule remove cleans up unreferenced WIT files, `wit_files` field in `meta.json`
- `astrid capsule tree` command — renders the imports/exports dependency graph of all installed capsules, showing which capsule exports satisfy each import, with unsatisfied imports highlighted in red (`astrid capsule deps` retained as hidden alias)
- `astrid init` with distro-based capsule installation — fetches Distro.toml, multi-select provider groups, shared variable prompts with `{{ var }}` template resolution, progress bars, writes Distro.lock for reproducibility. Supports `--distro` flag for custom distros.
- Distro.toml parser and Distro.lock generator — parse distro manifests with full os-release style metadata, shared variables with `{{ var }}` templates, provider groups, uplink roles, and semver validation. Atomic lockfile writes with BLAKE3 hashes for reproducible installs.
- Kernel boot validation — validates every capsule's required `[imports]` has a matching `[exports]` from another loaded capsule, logs errors for unsatisfied required imports and info for optional ones
- `astrid capsule remove` command with dependency safety checks — blocks removal if the capsule is the sole exporter of an interface that another capsule imports (`--force` to override), cleans up content-addressed WASM binaries from `bin/` when no other capsule references the same hash
- Install capsules from GitHub release WASM assets — `astrid capsule install @org/repo` now downloads pre-built `.wasm` binaries from release assets before falling back to clone + build from source
- Per-principal audit chain splitting — each principal maintains its own independent chain per session, independently verifiable via `verify_principal_chain()` and `get_principal_entries()`
- `AuditLog::append_with_principal()` for principal-tagged audit entries
- Auto-provisioning gated on identity store — only `"default"` principal is auto-provisioned when identity store is configured
- Linux FHS-aligned directory layout (`etc/`, `var/`, `run/`, `log/`, `keys/`, `bin/`, `home/`) replacing the flat `~/.astrid/` structure
- `PrincipalId` type for multi-principal (multi-user) deployments — each principal gets isolated capsules, KV, audit, tokens, and config under `home/{principal}/`
- Content-addressed WASM binaries in `bin/` using BLAKE3 hashing — integrity verified on every capsule load (no hash = no load, wrong hash = no load)
- Per-capsule daily log rotation at `home/{principal}/.local/log/{capsule}/{YYYY-MM-DD}.log` with 7-day retention
- `/tmp` VFS mount backed by `home/{principal}/.local/tmp/` for per-principal temp isolation
- Multi-source capsule discovery with precedence: principal > workspace (dedup by name)
- `PrincipalHome` struct with `.local/` and `.config/` following XDG conventions
- Per-invocation principal resolution — KV, audit, logging, and capability checks scope to the calling user per IPC message, not per capsule load
- `IpcMessage.principal` field for carrying the acting principal through event chains (transparent to capsules)
- `AstridUserId.principal` field mapping platform identities to `PrincipalId` with auto-derivation from display name
- Dynamic KV scoping via `invocation_kv` on `HostState` — capsules call `kv::get("key")` and the kernel returns the right value for the current principal
- Principal auto-propagation on `ipc_publish` — capsules never touch the principal, it flows through event chains automatically
- Auto-provisioning of principal home directories on first encounter
- `astrid_get_caller` host function now returns `{ principal, source_id, timestamp }` instead of empty object
- Dynamic per-principal log routing — cross-principal invocations write to the target principal's log directory
- `AuditEntry.principal` field with length-delimited signing data encoding
- `ScopedKvStore::with_namespace()` for creating scoped views sharing the same underlying store
- `AuditEntry::create_with_principal()` builder for principal-tagged audit entries
- `layout-version` sentinel in `etc/` for future migration support
- `lib/` directory reserved for future WIT shared WASM component libraries
- End-to-end Tier 2 OpenClaw plugin support: TypeScript plugins with npm dependencies install, transpile, sandbox, and run as MCP capsules with full tool integration
- OXC `strip_types()` transpiler for Tier 2 TS→JS (preserves ESM, unlike Tier 1's CJS conversion)
- Node.js binary resolution at build time: prefers versioned Homebrew installs (node@22+), validates each candidate
- MCP-discovered tools are now merged into the LLM tool schema injection alongside WASM capsule tools
- `astrid_net_read` now uses a self-describing `NetReadStatus` wire format: every response is prefixed with a discriminant byte (`0x00` = data, `0x01` = closed, `0x02` = pending), replacing the previous single-byte sentinel hack
- Headless mode: `astrid -p "prompt"` for non-interactive single-prompt execution with stdin piping support
- Post-install onboarding: `astrid capsule install` now prompts for `[env]` fields immediately after install
- Shared `astrid_telemetry::log_config_from()` behind `config` feature flag — replaces duplicate config bridge code
- `--snapshot-tui` mode — renders the full TUI to stdout as ANSI-colored text frames using ratatui's `TestBackend`. Each significant event (ready, input, tool call, approval, response) produces a frame dump. Configurable with `--tui-width` and `--tui-height`. Enables automated smoke testing without an interactive terminal.

### Fixed

- `cwd://` VFS scheme was handled in the security gate (capability checks) but not in the runtime path resolver — capsules using `cwd://` paths at runtime received a security denial because the path resolved to `<cwd>/cwd:/path` instead of `<cwd>/path`
- `sandbox-exec` (Seatbelt) crashes with SIGABRT on macOS 15+ (Darwin >= 24) — skip sandboxing on affected versions
- Headless approval response published to wrong IPC topic (`astrid.v1.approval.response` instead of `astrid.v1.approval.response.{request_id}`) and used wrong decision string (`allow` instead of `approve`)
- `[[component]].capabilities` (fs_read, fs_write, host_process) not merged into root capabilities — security gate couldn't see them
- Lifecycle hooks (`on_install`) couldn't access `home://` VFS — added `home_root` to `LifecycleConfig`
- `astrid init` standard WIT files were installed to `~/.astrid/wit/astrid/` (root-level, no VFS scheme). Capsules access the VFS via `home://` which maps to `~/.astrid/home/{principal}/` — the files were unreachable. Now installed to `~/.astrid/home/{principal}/wit/`, accessible as `home://wit/` (fixes #598)
- Dispatcher `known_principals` HashSet capped at 10K entries to prevent unbounded memory growth
- Dispatcher only caches principal after successful home provisioning — transient failures allow retry on next event
- `AstridUserId.principal` now has `#[serde(default)]` — existing identity records without the field deserialize with `"default"` instead of failing
- `transpile_and_install` now correctly unpacks `.capsule` archives from `astrid-build` output
- `copy_capsule_dir` only skips `dist/` at the top level; npm packages inside `node_modules` retain their `dist/` directories
- MCP host engine: absolute system binaries (e.g. `/opt/homebrew/opt/node@22/bin/node`) skip path traversal check when declared in `host_process` capability
- MCP host engine: `allow_network` derived from capsule capabilities (uplink/net) instead of defaulting to `false`
- Capsule env resolution no longer blocks loading on missing optional fields; fills with empty defaults so uplink capsules can boot before clients connect
- macOS Seatbelt sandbox: added `mach*` permission and unrestricted `file-read*` for Node.js compatibility
- macOS Seatbelt sandbox: hidden path deny rules skip paths that are ancestors of the writable root
- MCP tool schemas now include `properties` field for LLM API compatibility
- `net_write` no longer causes a WASM trap on broken pipe / connection reset when a headless client disconnects; write errors are logged at debug level and the dead stream is cleaned up on the next read
- `net_read` returns a `NET_STREAM_CLOSED` sentinel byte instead of trapping on peer EOF/disconnect, allowing the CLI capsule run loop to remove dead streams gracefully
- Also fixes a variable name mismatch (`capsule` vs `plugin`) in `approval.rs` that caused a compile error
- `~/.astrid/shared/` directory now created on boot, eliminating `global:// VFS not mounted` warning on fresh installs
- Capsule reinstall now preserves existing `.env.json` rather than overwriting it with an empty file
- WASM execution timeout bumped from 30s to 5 minutes to prevent premature cancellation on slow operations
- IPC event dispatcher now delivers events to each capsule in publish order via per-capsule mpsc queues, fixing out-of-order stream text assembly in the ReAct capsule
- `IpcMessage` gains a monotonic `seq` field assigned at publish time for ordering and diagnostics
- KV host function double-encoding: `kv_get_impl` returned `serde_json::to_vec` of raw bytes instead of raw bytes directly
- Config host function double-encoding: `get_config_impl` wrapped string values in JSON quotes, breaking URLs and other string config
- React capsule LLM topic validation: `active_llm_topic()` could produce topics with empty segments causing IPC publish failures
- `astrid_read_file` host function trapped (WASM abort) on recoverable errors (file-not-found, permission denied) — now returns status-prefix wire format (`0x00`+content / `0x01`+error), paired with SDK-side decoding. Eliminates crashes in memory, agents, identity, and fs capsules when reading optional files.

### Changed

- `global://` VFS scheme renamed to `home://`
- `Capsule::invoke_interceptor` now accepts `Option<&IpcMessage>` for per-invocation principal context
- `CapsuleContext.global_root` renamed to `home_root`; `HostState.global_vfs` renamed to `home_vfs`
- `AstridUserId` now requires `principal: PrincipalId` field (existing KV records incompatible — nuke `~/.astrid/`)
- Capsule install target moved from `~/.astrid/capsules/` to `home/{principal}/.local/capsules/` (capsule dir now holds only manifest + meta.json)
- KV namespace format changed from `capsule:{name}` to `{principal}:capsule:{name}`
- Socket/token/ready paths moved from `sessions/` to `run/`
- Env config moved from capsule dir `.env.json` to `home/{principal}/.config/env/{capsule}.env.json`
- System logs now use `.log` extension, no ANSI escape codes in file output, 7-day retention
- `user_key_path()` renamed to `runtime_key_path()` (now at `keys/runtime.key`), `logs_dir()` renamed to `log_dir()`
- Ephemeral daemon now shuts down immediately when the last client disconnects (idle timeout 0, 1s check interval) instead of waiting 5 minutes
- Renamed `plugin` → `capsule` in the WASM host layer and audit log fields for consistency with project terminology
- Split `astrid-build` 1166-line `build.rs` into focused modules: `rust.rs`, `openclaw.rs`, `mcp.rs`

### Removed

- `~/.astrid/capsules/` system capsules directory (user installs go to principal home)
- `sessions/`, `shared/`, `audit.db`, `capabilities.db`, `state/`, `spark.toml`, `cache/capsules/` — replaced by FHS equivalents or moved to principal home

### Breaking

- Existing `~/.astrid/` must be deleted — no migration path. Reinstall all capsules after upgrading.

## [0.4.0] - 2026-03-17

### Added

- `astrid-daemon` crate — standalone kernel daemon binary with `--ephemeral` flag for CLI-spawned instances vs persistent multi-frontend mode
- `astrid-build` crate — standalone capsule compiler and packager (Rust, OpenClaw, MCP). Invoked by CLI via subprocess.
- `astrid start` command — spawn a persistent daemon (detached, no TUI)
- `astrid status` command — query daemon PID, uptime, connected clients, loaded capsules
- `astrid stop` command — graceful daemon shutdown via management API
- `KernelRequest::Shutdown`, `KernelRequest::GetStatus`, and `DaemonStatus` types in `astrid-types`
- `Kernel::boot_time` field for uptime tracking
- Streaming HTTP airlock: `astrid_http_stream_start`, `astrid_http_stream_read`, `astrid_http_stream_close` host functions for real-time SSE consumption (`astrid-capsule`)

### Changed

- CLI no longer embeds the kernel — spawns `astrid-daemon` as a companion binary
- CLI no longer compiles capsules — delegates to `astrid-build` as a companion binary
- CLI reads `IpcMessage` directly from socket instead of wrapping in `AstridEvent::Ipc`
- IPC type imports in CLI now use `astrid-types` directly instead of going through `astrid-events` re-exports
- Package renamed from `astrid-cli` to `astrid` (`cargo install astrid`)

### Removed

- `astrid-kernel` dependency from CLI
- `astrid-openclaw`, `extism`, `cargo_metadata`, `toml_edit` dependencies from CLI
- `Commands::Daemon` and `Commands::WizerInternal` from CLI (moved to `astrid-daemon` and `astrid-build`)

## [0.3.0] - 2026-03-17

### Added

- `astrid-types` crate — shared IPC payload, LLM, and kernel API types with minimal deps (serde, uuid, chrono). WASM-compatible. Both `astrid-events` and the user-space SDK depend on this.
- `yolo` as an alias for `autonomous` workspace mode (`astrid-config`, `astrid-workspace`)

### Changed

- `astrid-events` now re-exports types from `astrid-types` instead of defining them inline. All existing import paths remain valid.
- `astrid-events` `runtime` feature removed — all functionality is now always available. Consumers no longer need `features = ["runtime"]`.

### Removed

- `astrid-sdk`, `astrid-sdk-macros`, `astrid-sys` extracted to standalone repo ([sdk-rust](https://github.com/unicity-astrid/sdk-rust))

## [0.2.0] - 2026-03-15

Initial tracked release. See the [repository history](https://github.com/unicity-astrid/astrid/commits/v0.2.0)
for changes included in this version.

[Unreleased]: https://github.com/unicity-astrid/astrid/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/unicity-astrid/astrid/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/unicity-astrid/astrid/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/unicity-astrid/astrid/releases/tag/v0.2.0
