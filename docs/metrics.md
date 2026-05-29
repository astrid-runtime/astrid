# Astrid OS — Host-Internal Operational Metrics

> Status: design doc for the **host-internal operational metrics** layer (tracking issue [#791](https://github.com/unicity-astrid/astrid/issues/791)). Target: full RED/USE coverage of the runtime *itself*, built on the `metrics` facade + `metrics-exporter-prometheus` recorder already shipped in `crates/astrid-gateway/src/metrics.rs`.
> Security posture: `/metrics` and `/healthz` are **unauthenticated** (operators restrict via the network layer). The scrape body is treated as **public output**. No principal identifiers, token material, file paths, prompt/response content, secrets, or audit content may appear in any metric name, label key, label value, or **numeric value** — anywhere, ever.

---

## 0. Scope — two metrics layers, two endpoints

Astrid's metrics split cleanly along the kernel/user-space boundary. **This document covers only the host-internal layer.** The capsule-telemetry layer is owned by [#705](https://github.com/unicity-astrid/astrid/issues/705).

| | **Host-internal operational metrics** *(this doc, #791)* | **Capsule telemetry rollup** *(#705 `astrid-capsule-metrics`)* |
|---|---|---|
| Question answered | How is the *runtime itself* behaving? | What is the *workload* doing / costing? |
| Examples | HTTP RED, event-bus saturation, WASM sandbox traps/fuel, daemon connections, process CPU/memory | LLM tokens & cost, tool calls, capability/approval decisions per principal |
| Where it lives | Kernel-side code → the gateway's process-wide recorder → gateway `/metrics` | A capsule that subscribes to the bus → its own capability-gated `/metrics`, off by default |
| Data source | Direct `counter!/gauge!/histogram!` from daemon-process code | Existing bus event contracts (tool.v1, llm.v1, capability, approval) |
| Contract surface | **None** — kernel-internal, out of RFC scope per [RFC-0001](https://github.com/unicity-astrid/rfcs/pull/22) | Rides existing event contracts; no new transport |
| Why not merged | Per-capsule resource accounting (#639) feeds it | Aggregation belongs in a capsule, not the kernel ("kernel is dumb") |

**Why the split is load-bearing:** a WASM capsule *structurally cannot* observe host-internal signals — bus queue depth, socket accepts, sandbox fuel, and per-subscriber lag are not on the event bus. Equally, per-principal cost/usage rollups are workload intelligence that does **not** belong in the kernel. The two layers are complementary, not competing. An earlier draft of this doc proposed a new `astrid.v1.metrics.emit` IPC *push* transport so capsules could emit into the host recorder; that was **withdrawn** — #705 already chose the more kernel-is-dumb-compliant design (the capsule *subscribes* to bus events it already receives), so no new contract is needed. See §3.

Related: #639 (per-capsule resource telemetry on `HostState`), #687 (`astrid usage report` CLI rollup), #653 (per-principal quotas — depends on the #705 layer). In-flight contract RFCs the capsule layer sits on: rfcs#20 (capsule interface system), #22 (host ABI), #23 (interceptor chain), #26 (manifest schema).

---

## 1. Executive summary

**Current state.** The daemon exposes exactly **5 metric series**, all in `core/crates/astrid-gateway/src/metrics.rs`:

| Series | Type | State today |
|---|---|---|
| `astrid_gateway_requests_total` (method/route/status) | counter | **Emitted** via `observe_request` from `metrics_middleware` (`routes/mod.rs:284`). |
| `astrid_gateway_request_duration_seconds` (method/route/status) | histogram | **Emitted** (same call site). |
| `astrid_gateway_auth_failures_total` | counter | **Dead.** Registered at zero in `install_recorder()`; no increment site exists. |
| `astrid_gateway_redeem_attempts_total` | counter | **Dead.** Registered at zero; never incremented. |
| `astrid_gateway_redeem_rate_limited_total` | counter | **Dead.** Registered at zero; never incremented. |

Everything else in the runtime — the kernel event bus, the WASM sandbox, capability/approval gates, audit/KV/VFS, the MCP server pool, the daemon's own connection/idle machinery, and all capsule domain logic — emits **only tracing logs**. There is no saturation signal anywhere, which is why the documented **idle 200–300% CPU + no-shutdown incidents** can only be inferred from `top`, never graphed.

The `metrics` facade (`0.24`) + `metrics-exporter-prometheus` (`0.17`, `default-features = false`) recorder is **process-wide**. Any kernel-side daemon code can emit through `counter!()`/`gauge!()`/`histogram!()` and it lands in the single `/metrics` scrape with **no new export plumbing** (one recorder, one scrape). **However, "no plumbing" is not "no work":** the `metrics` facade is today a dependency of **only `astrid-gateway`**. Every kernel-side crate that emits must add `metrics = { workspace = true }` first — a real, reviewable fan-out across ~11 crates (§6.0). Only `wasm32-unknown-unknown` capsules are excluded — they have no host path to the facade and must route signals over IPC (§3).

**Target.** Comprehensive RED/USE coverage across every subsystem, anchored on the shipped cardinality-collapse pattern (`http_method_static` / `status_to_static`).

**Headline count.** This document specifies **~64 host-internal metric families**, all emitting through the shared recorder with **no contract change**:

- **2** existing (wired correctly today).
- **3** existing-but-dead, revived and given a bounded `reason`/`outcome` label.
- **7** standard process/build series (`process_*` + `astrid_build_info`).
- **~52** new kernel-side families (gateway, kernel router/event bus, WASM sandbox, capabilities/approval, audit/KV/VFS, crypto, MCP, daemon/uplink/IPC), including hooks (host-side — §4.8) and the host-side HTTP-egress RED family and per-subscriber bus-lag attribution surfaced by review.

The earlier draft's **14 capsule-domain families** (LLM tokens/cost, tool calls, react loop, session, memory, plus `astrid_daemon_active_connections_by_kind`) are **out of scope here** — they belong to the capsule-telemetry layer (#705) and ride existing bus contracts. They are contributed to #705 as design input, not specified here.

Priority distribution after review re-scoping: **P0 = 30**, P1 = 17, P2 = 11, P3 = 4. All of it is shippable through the existing recorder with no contract change. **Review re-scoped P0 to satisfy true per-stage RED** (the Duration histogram for each subsystem whose Rate/Error counter is P0) and to make the idle-CPU/no-shutdown incident *actually diagnosable* (per-subscriber bus-lag attribution, per-namespace publish counter, host-side HTTP egress RED, net-stream saturation). See §6.

**Shipped so far.** The Phase-0 foundation slice — the `metrics-process` collector (`process_*`) + `astrid_build_info` — landed with this doc (issue #791). The `process_cpu_seconds_total` series is the direct, graphable answer to the idle 200–300% CPU class of bug.

---

## 2. Design principles & conventions

### 2.1 One recorder, one scrape

The `PrometheusRecorder` is process-wide. There is exactly **one** `install_recorder()` (today gateway-owned, idempotent behind a `Mutex<Option<PrometheusHandle>>`) and exactly **one** `/metrics`. Every subsystem emits through the global facade macros — none stands up its own builder. Lifting `install_recorder()` into a dedicated `astrid-metrics` crate is the recommended packaging step once the third non-gateway subsystem emits (§7.3); **note that lifting the *recorder* does not remove the per-crate `metrics`-facade dependency** — each emitting crate still depends on the facade to call the macros. **"One recorder, one scrape" is non-negotiable.**

### 2.2 Naming / unit rules (firm)

- **N1 — Name shape.** `astrid_<subsystem>_<thing>_<unit>`. `astrid_` prefix mandatory. `<subsystem>` ∈ {`gateway`, `router`, `bus`, `capsule`, `kv`, `vfs`, `audit`, `crypto`, `capabilities`, `approval`, `mcp`, `hooks`, `daemon`, `ipc`, `http`}. Lowercase snake_case only. (`bus`/`http` added by review — see §4.2 naming-collision note and the host HTTP-egress family in §4.6.)
- **N2 — Counters end in `_total`** and are monotonic. If it can decrease, it is a gauge.
- **N3 — Base units always.** Durations → `_seconds` (float). Sizes → `_bytes`. Discrete counts → bare `_total`. Dimensionless fuel/gas → `_units`. Never `_ms`, `_kb`, `_micros`.
- **N4 — Type matches the question.** Counter (rate), gauge (level), histogram (distribution). Never fake a histogram with N gauges; never hand-roll `_sum`/`_count`. Where a `histogram (count)` is used over a small integer range, a one-line rationale must state *why the distribution, not just a rate/level, is the operational need* (§4 entries comply).
- **N5 — Help text mandatory.** Every series registered with `describe_counter!`/`describe_gauge!`/`describe_histogram!` + a `Unit`. No `# HELP` line ⇒ review rejects.
- **N6 — Register at zero.** Counters that may not fire before first scrape are touched (`.absolute(0)`/`.increment(0)`) in the install path, exactly as the gateway does for the three dead counters. Absent-vs-zero is a real signal; do not make dashboards guess. Labelled series guaranteed to hit every request may materialise lazily.
- **N7 — Values are aggregate operational quantities only.** Every metric value is a count, level, byte size, or duration. **No metric value may ever encode an identity** — e.g. a `token_id`-as-number, a principal id cast to float, or any id-bearing integer. (Added by review: the deny-list covers names/keys/string-values; this closes the numeric-value channel. Note that an aggregate count of `1` *can* itself be disclosive — see §2.5.1 minimum-aggregation.)

### 2.3 Label rules

- **L1 — A label is a bounded operational dimension, never an identity.** Values come from a fixed, compile-time-enumerable set (or collapse to one — §2.4).
- **L2 — Label keys are stable and lowercase**, reused across subsystems: `method`, `route`, `status`, `outcome`, `result`, `reason`, `kind`, `state`, `phase`, `interface`, `op`, `server`, `model`, `subscriber`.
- **L3 — Static `&'static str` values on hot paths.** Map the live value through a `match` returning `&'static str` with a catch-all, exactly as `status_to_static`/`http_method_static` do. This dodges per-observation `String` allocation **and** enforces bounded cardinality at the type level.
- **L4 — Every label has a named collapse function.** A label sourced from anything other than a compile-time-closed Rust enum (i.e. third-party text, caller text, config text) **must** name an explicit `*_static(value) -> &'static str` collapse function at its emit site. The catalog names each one. The required functions are: `http_method_static`, `status_to_static` (shipped); and the new `model_static`, `mcp_tool_static`, `mcp_server_static`, `topic_namespace_static`, `interface_static`, `capsule_name_static` (this doc). Asserting "collapses to X" without naming the function is a review reject — see §2.5.2.

### 2.4 Cardinality budget

- **Rule of thumb:** < 10 label combinations per family; a subsystem's total series count in the low hundreds.
- **High-water mark:** the gateway request family at **23 route templates × ~6 statuses × ~4 methods ≈ 550 label-tuples** is the heaviest *counter* we tolerate — treat it as the ceiling, not the norm. (Corrected from the draft's erroneous `~210`: there are 23 verified `.route("…")` templates, and the family carries `method` too.)
- **Hard ceiling — label-tuples:** **no single family may exceed 1,000 active label-tuples.** Review rejects any family whose worst-case label-tuple cardinality (product of label-domain sizes) can exceed 1,000.
- **Hard ceiling — time-series (histograms):** a histogram family expands to `label-tuples × (buckets + 2)` Prometheus time-series (`_bucket` per boundary + `_sum` + `_count`). **Any histogram pushing past ~1,500 time-series is a redesign trigger** — reduce label keys or bucket count. See the budget table in §2.4.1.
- **Catalog-wide ceiling:** the reference deployment must stay **< 25,000 active Prometheus time-series**. This is an operator-facing TSDB-sizing and scrape-cost number for an endpoint that is unauthenticated and may be scraped frequently. Review computes the worst-case below.

#### 2.4.1 Worst-case time-series budget (computed, not asserted)

Time-series = `label-tuples × 1` for counter/gauge, `× (buckets + 2)` for histogram. Bucket count = the family's bucket set (§2.7); duration histograms use the 11-bucket standard set unless noted.

| Family | Label-tuples (worst) | ×factor | Time-series | Notes |
|---|---|---|---|---|
| `astrid_gateway_requests_total` | 23×6×4 = 552 | 1 | **552** | corrected from ~210 |
| `astrid_gateway_request_duration_seconds` | 552 | ×13 | **7,176** | **redesign trigger breached → see fix** |
| `astrid_capsule_hostcall_duration_seconds` | 12×3 = 36 | ×13 | 468 | ok |
| `astrid_audit_entries_total` | 28×2 = 56 | 1 | 56 | ok |
| `astrid_capability_static_checks_total` | ≤ 3×3×3×3 = 81 (post-fix) | 1 | ≤81 | `scope`→class enum (§4.4) |
| `astrid_mcp_tool_calls_total` | servers×3 (tool dropped) | 1 | bounded | tool label removed (§4.8) |
| all other histograms | each < 50 tuples | ×11–17 | each < 850 | within trigger |

**Resolution of the gateway histogram blow-up.** `astrid_gateway_request_duration_seconds` at 7,176 time-series breaches the 1,500 redesign trigger. **Decision: drop `method` from the duration histogram** (keep it on the *counter*, where rate-by-method is cheap). Duration-by-method is rarely the question; duration-by-route-and-status is. New tuples: `23×6 = 138 × 13 = 1,794` — still above 1,500, so additionally **collapse status on the histogram to a 3-value class `{2xx, error, other}`**: `23×3 = 69 × 13 = 897`. The full method×status breakdown lives on the counter (Rate/Errors); the histogram answers Duration per route at status-class granularity. This is applied in the §4.1 catalog.

Summing the corrected catalog (counters/gauges at their tuple counts, histograms at `tuples×(buckets+2)`, all RFC-gated capsule families at their post-collapse bounds) yields a worst-case steady state of **~12–15k time-series** at the reference deployment, inside the 25k ceiling. Any new family must be added to this table and the sum re-checked at review.

#### 2.4.2 Label provenance classes (the two riskiest are new)

| Label class | Enumerability | Bound / collapse |
|---|---|---|
| HTTP method | compile-time closed | `http_method_static` → 10 values (incl. `OTHER`). |
| HTTP status | compile-time closed | `status_to_static` → standard codes + `other`; 3-value class on histograms. |
| Route | compile-time closed (matched templates) | matched router pattern (`/api/agent/:id`), never the concrete path. 23 templates today. |
| Outcome / result / reason | compile-time closed | fixed enum mapped *down* from the `Result`/error type; never the error's `Display`. |
| Event kind | compile-time closed | `event_type()` → **56** values (54 `astrid.v1.*` + `ipc` + `custom`); see §4.2. |
| Interface | compile-time closed (WIT world) | `interface_static` → the frozen WIT interface set + `other`; see §4.3. |
| **Third-party-advertised** ⚠ | **NOT enumerable; remote-controlled** | MCP `tool`/`server` names. Advertised by a possibly-compromised remote process. **Must** collapse to the connect-time registered set via `mcp_tool_static`/`mcp_server_static` with a hard per-server `other` overflow budget, length cap, and `[a-z0-9_-]` shape reject. **`tool` is dropped from public families entirely** (§4.8). |
| **Grows-with-install** ⚠ | **NOT compile-time; bounded-by-config, grows + churns** | capsule manifest name, MCP server name. Grows as capsules/servers are installed; renamed/uninstalled entries leave **permanent dead series** in the TSDB. Collapse via `capsule_name_static`/`mcp_server_static` to the boot-resolved registered set + `other`; set an operational cap + alarm past N installed (§2.4.3). Verify the manifest validator enforces `[a-z0-9-]`-shape, bounded length, before use as a label. |

#### 2.4.3 Staleness / dead-series policy

Cardinality is **cumulative over a deployment's lifetime**, not point-in-time. Labels whose identity changes over time — renamed MCP tools, uninstalled capsules, renamed servers — accumulate permanently in the TSDB even while *active* counts look fine. Policy:

- Grows-with-install labels (`capsule`, `server`) collapse through `*_static` functions keyed on the **boot-resolved registered set**; an unregistered name maps to `other`, so an uninstalled name stops minting new samples (its old series ages out via the TSDB retention, never grows).
- Operational alarm: alert when the count of distinct `capsule`/`server` label values observed in a scrape exceeds the boot-time registered count by more than a small delta (signals a churn or a collapse-function bug).
- Operators are advised to set TSDB retention/`__name__`-drop rules for `astrid_capsule_*` and `astrid_mcp_*{server}` if install churn is high.

### 2.5 Security deny-list for the unauthenticated endpoint (hard, absolute)

These must **NEVER** appear in a scrape — in names, label keys, label values, **or numeric values** (N7):

- **Principal identifiers** — principal/agent/session ids, ed25519 public keys, device/passkey ids, user emails, **peer-credential uid/gid/pid** (SO_PEERCRED — explicitly forbidden as labels on `astrid_daemon_socket_accepts_total`).
- **Token / key material** — bearer/capability/invite/redeem codes, signatures, nonces, salts, any hex/base64 secret.
- **Filesystem paths** — VFS paths, host paths, capsule artifact/temp paths.
- **Content** — prompt text, model responses, tool arguments, KV values, audit content, error `Display` strings that may embed any of the above.
- **Network specifics** — remote IPs, ports-as-labels, full URLs / query strings, **MCP tool names** (also a reconnaissance vector — §2.5.1).
- **Unbounded free text** — anything not from a closed `match` / named `*_static` collapse.

The only non-numeric identifiers permitted are the build constants on the deliberately-1-valued `astrid_build_info` (§5.2), whose disclosure risk is accepted with rationale in §2.5.1.

#### 2.5.1 Endpoint threat model (what a compliant scrape still discloses)

Even a fully deny-list-compliant scrape leaks information to anyone who can reach the endpoint. This is **accepted under the network-ACL posture** and documented so operators can decide:

- **Integration surface.** `astrid_mcp_*{server}` and `astrid_capsule_<namespace>_*` disclose *which third-party services and which capsules* a deployment wires up — a reconnaissance vector. Operators who treat their integration surface as sensitive **must** ACL `/metrics` accordingly. The MCP **`tool`** axis is dropped from public families both for cardinality (§4.8) and because the advertised tool set is the most granular reconnaissance leak.
- **Version fingerprinting.** `astrid_build_info{version,git_sha}` aids CVE-targeting by an unauthenticated scraper. **Accepted with rationale:** build provenance is operationally essential (it directly diagnosed a past capsule mismatch — `project_capsule_lock_reproducibility`), the labels are pinned compile-time constants with no principal/secret material, and the disclosure is mitigated by the network ACL. **Note to operators:** if you cannot ACL `/metrics`, gate `astrid_build_info` behind auth.
- **Aggregate / timing oracles.** Counter deltas on `auth_failures`/`redeem_attempts` over time are a server-side oracle (§4.1 note). Low-traffic deployments additionally risk **de-anonymisation**: a single-principal deployment's per-capsule counters reveal that one principal's activity even without a principal label, and a gauge that reads `principal_count = 1` discloses single-tenant identity. **Minimum-aggregation guidance:** for single-principal / single-tenant deployments, operators should either ACL `/metrics` to the operator host only or disable it; this doc does not auto-suppress low-cardinality values but names the risk as a deployment decision.

#### 2.5.2 Per-label provenance audit (normative — every label, its source function, verified)

This table is the load-bearing security artifact. **No label ships without a row here**: its exact `&'static str` source function and a verified-bounded confirmation. Reviewers check against it. (Built from source verification; corrects several draft assertions.)

| Label | Family/families | Source function (must be `&'static str`) | Verified bounded? |
|---|---|---|---|
| `method` | gateway requests | `http_method_static` | ✅ shipped, 10 |
| `status` | gateway requests | `status_to_static` (3-class on histogram) | ✅ shipped |
| `route` | gateway | `intern_route` of `MatchedPath` template only | ✅ 23 templates; **invariant: only ever pass `MatchedPath` or compile-time const** — CI route-shape assertion guards it |
| `event_kind` | bus published | `AstridEvent::event_type()` | ✅ **56** (not 62); `Custom => "custom"`, `Ipc => "ipc"` collapse confirmed safe |
| `topic_ns` | `astrid_ipc_messages_published_total` | **`topic_namespace_static`** (NEW; matches first 1–2 dot-segments → closed allowlist + `other`) | ⚠ requires NEW function; raw topic is unbounded |
| `interface` | hostcall | **`interface_static`** (NEW; frozen WIT set + `other`) | ✅ set = `{io, fs, ipc, kv, net, http, sys, process, uplink, elicit, approval, identity}` + `other` (13) — **`io` IS in the WIT world**, verified `astrid-sys/src/lib.rs:68–82` |
| `model` | openai capsule | **`model_static`** (NEW; `if list_model_ids().contains(id) { id } else { "other" }`) | ⚠ `resolved_model` is free env/caller text — collapse MUST be explicit at emit site |
| `tool` | — | **REMOVED** from all public families | ✅ dropped (§4.8) |
| `server` | mcp | **`mcp_server_static`** (NEW; boot-registered set + `other`, len-cap, `[a-z0-9_-]`) | ⚠ config text; collapse required |
| `capsule` | capsule lifecycle | **`capsule_name_static`** (NEW; boot-registered manifest set + `other`) | ⚠ grows-with-install; collapse + alarm |
| `action_class` | audit entries | **`AuditAction::action_class()` (NEW method — Phase 0 pre-req)** | ❌ **does not exist today** — `AuditAction` (entry.rs:190) has only `description()`/`summary()`, both leak paths/hosts/recipients. Must add discriminant-only tag method. |
| `action_class` | approval outcomes | `ApprovalAction::action_type()` | ✅ exists, 14, `action.rs:134` |
| `target` | vfs ops | VFS boundary region classifier (`astrid-vfs/src/boundary.rs`) → `match -> &'static str` | ⚠ **draft cited wrong source** (the audit-topic const `"astrid.audit.fs"`, not a region). Derive from `boundary.rs`; never path-derived. |
| `reason` (vfs/auth/etc.) | denials | discriminant of error enum → `match -> &'static str`; **never** `Display` | ⚠ `map_vfs_err`/`map_resolve_err` `Display` may embed paths |
| `issue_kind` | audit chain verify | **`ChainIssue::kind()` (NEW method)** → discriminant only | ⚠ `ChainIssue` has `Display` (log.rs:473) + payloads (hashes/indices); add `kind()`, forbid `Display` |
| `handler` | hooks | serde tag of `HookHandler` → `{command,http,wasm,agent}` via `match` | ✅ 4 variants (hook.rs:13); **never** the embedded `command`/`url`/`module_path` strings |
| `hook_point` | hooks | `HookEvent` variant tag | ✅ 23, closed |
| `subscriber` | bus lag | NEW static subscriber-kind enum (§4.6 / §4.2) | ✅ `{connection_tracker, kernel_router, dispatcher, gateway_sse, audit_watcher, metrics_bridge, other}` (7) |
| `category`, `danger` | capability static checks | `CAPABILITY_CATALOG` discriminants → `match` | ✅ closed enums (`capability_grammar.rs`) |
| `scope` | capability static checks | **scope CLASS** enum `{self, global, resource}` via `match`, **never** literal scope token | ⚠ literal token forbidden by deny-list (§4.4) |

### 2.5.3 Mechanical enforcement (CI, load-bearing — rewritten as a render-time invariant)

The draft's gateway-only sentinel driver is **insufficient**: it never exercises audit/KV/VFS/capsule/MCP/crypto emission paths, so a sentinel that was never emitted trivially won't appear (vacuous), and its regex would both miss UUIDs (dashes), base64url, emails, IPs, and *reject* legitimate values. The replacement is a **render-time invariant over the whole scrape body**, run on every PR touching a metrics call site, plus per-subsystem emission drivers, plus a known-bad corpus:

1. **Whole-body allowlist invariant.** Maintain a compile-time table `metric_name -> { label_key -> (allowed_value_set | shape) }`. Render the scrape and assert **every** `name{labels} value` line conforms: an unknown metric name, an unknown label key, or a label value outside its allowed set/shape **fails**. This catches slow cardinality drift (a 24th route, a new interface, an un-collapsed model) that a leak-only test misses. The per-label expected sets are exactly §2.5.2 (`method`, `status`, route-shape, `outcome`, `action_class`, `event_kind`, `interface`, `target`, `handler`, `hook_point`, `model`, `topic_ns`, `subscriber`, …).
2. **Positive deny-patterns (fail on match).** Any rendered line matching any of these fails: UUID `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`; email `\S+@\S+`; IPv4/IPv6 literals; base64url run `[A-Za-z0-9_-]{20,}`; absolute/traversal path (`/[^ ]*/[^ ]+` or contains `..`); ed25519/hex secret `[0-9a-f]{32,}`; any value containing `=`, whitespace, or `?`.
3. **Per-subsystem emission drivers.** Each emitting subsystem contributes a test that drives **its own** emission path with sentinels injected at the source (a sentinel path/host/recipient/token_id inside an `AuditAction`; a sentinel path under each VFS region; a sentinel model string; a hand-rolled hostile capsule metrics-batch JSON at the bridge), then asserts the render contains the bounded tag and **none** of the sentinels. Gated as a **required check**. The capsule-bridge driver specifically feeds hand-rolled `IpcPayload::Custom` JSON (not the SDK) to prove the bridge — not the SDK — is the enforcement boundary.
4. **Known-bad corpus (proves the guard fires).** A fixed corpus of realistic-bad values — a real-shaped ed25519 pubkey, a JWT, a UUID, an email, an absolute path, an IPv6 addr, a base64 secret — asserted to be **rejected** by (1)+(2), so the guard is proven to fail-on-bad, not merely pass-on-benign.
5. **Route-shape assertion.** Every `route="…"` value must match the matched-template grammar (segments are literals or `:param` placeholders) or the `<unmatched>`/`<unknown>` sentinels — failing on any concrete id, query string, or `..`. Guards the `intern_route`/`Box::leak` footgun.

```rust
for sentinel in [PRINCIPAL_SENTINEL, PATH_SENTINEL, TOKEN_SENTINEL, EMAIL_SENTINEL, HOST_SENTINEL] {
    assert!(!body.contains(sentinel), "scrape leaked sentinel `{sentinel}`:\n{body}");
}
assert!(body.contains("method=\"OTHER\""));   // hostile verb collapsed
assert!(body.contains("status=\"other\""));   // hostile status collapsed
assert!(body.contains("model=\"other\""));    // unknown model collapsed
for line in body.lines().filter(|l| !l.starts_with('#')) {
    assert!(conforms_to_allowlist(line), "non-conforming metric line: {line}");
    assert!(!matches_deny_patterns(line), "deny-pattern hit: {line}");
}
```

### 2.5.4 Runtime kill-switch (new)

CI is emit-time/build-time; it cannot stop a leak that ships via a novel capsule-bridge value at runtime. The bridge's `MetricsPolicy` (§3.6) supports a **runtime-reloadable allowlist and per-family disable**: an operator can strip a label or disable a `astrid_capsule_*` family without redeploy by reloading policy. Kernel-side families (compile-time) have no runtime toggle by design; the kill-switch exists specifically for the untrusted capsule-bridge surface.

### 2.6 RED vs USE discipline

- **Request-driven** (gateway, router dispatch, IPC request/response, capability checks, MCP calls, hooks, **host HTTP egress**): **RED** — Rate (`_total`), Errors (the `outcome="error"` slice of that counter, not a separate `_errors_total`), Duration (`_duration_seconds` histogram). **Per-stage RED requires the Duration histogram to ship with its Rate/Error counter** — review re-scoped the P0 set accordingly (§6).
- **Resource-driven** (WASM sandbox pool, KV/storage, connection pool, host semaphore, FD pool, **the shared broadcast ring** — the idle-CPU offenders): **USE** — Utilization (gauges), Saturation (queue depth, ring backlog/headroom, would-block, denials), Errors (trap/abort counters).

### 2.7 Histogram bucket guidance

Buckets configured per-family via `Matcher::Suffix`, exactly as the gateway does. Keep each bucket set a named `const &[f64]` adjacent to its metric-name `const`. **Bucket count multiplies into the time-series budget (§2.4.1) — every histogram with >1 label key must justify its bucket count or reduce label keys.**

- **Latency `*_duration_seconds`** — reuse the shipped `DURATION_BUCKETS_SECONDS` (5 ms → 10 s; 11 buckets): `0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000`.
- **Sub-millisecond hot paths** (in-process bus dispatch, capability checks): prepend a fast head `0.0001, 0.00025, 0.0005, 0.001, 0.0025` then continue the standard set.
- **Long-running** (lifecycle hooks ≤ 10 min, approval prompts ≤ 5 min, MCP cold-start, **LLM stream round-trips**): extend the top to `30, 60, 120, 300, 600`.
- **Sizes `*_bytes`** — geometric: `128, 512, 2_048, 8_192, 32_768, 131_072, 524_288, 2_097_152, 8_388_608` (128 B → 8 MiB). Size the top bucket at the relevant cap (64 KiB gateway body, 1 MiB KV value, 10 MiB HTTP fetch) so "hit the cap" shows as `+Inf` pile-up.
- **Fuel `*_units`** (future, requires new code): `1_000 … 1_000_000_000`, top bucket aligned with the per-invocation ceiling.

### 2.8 Exposition format

Keep the default Prometheus text exposition (`text/plain; version=0.0.4`). **Do not** add OpenMetrics or exemplars now: an exemplar attaches a trace id (an identifier) to a sample on the unauthenticated `/metrics` body, which violates §2.5. Trace correlation lives in `astrid-telemetry`, not the public scrape. **Revisit trigger:** if `/metrics` ever moves behind authentication (not just network ACLs), reopen OpenMetrics + a bounded, id-free exemplar schema reviewed against §2.5.

---

## 3. Capsule telemetry & transport — deferred to #705

The earlier draft specified a new `astrid.v1.metrics.emit` IPC **push** transport (reserved topic, an SDK `metrics` module, a gateway-side bridge, per-namespace cardinality budgets) so WASM capsules could emit domain metrics into the host recorder. **That design is withdrawn.**

Issue #705 (`astrid-capsule-metrics`) already chose a more kernel-is-dumb-compliant architecture: a capsule **subscribes** to bus events it already receives (tool.v1, llm.v1, capability, approval) and aggregates them itself — no new host ABI, no new IPC topic, no kernel passthrough, **no contract change**. That capsule owns its own capability-gated `/metrics` (off by default), distinct from the gateway's host-ops `/metrics`.

The withdrawn design's hard-won analysis is preserved as **design input contributed to #705**:

- **Identity & anti-spoofing.** A metric's namespace must be the kernel-stamped capsule identity (the `principal-attribution` variant in host-ABI RFC #22 — kernel-verified vs uplink-claimed), never self-declared in the payload.
- **Cardinality enforcement is consumer-side.** The aggregating capsule is the trust boundary; it must enforce per-source label-tuple, metric-name-count, and value-length budgets against arbitrary bus input. A malformed/hostile event must drop — never panic, never explode cardinality.
- **`model` is a risk axis.** Provider/model labels are caller-influenced text and must collapse to a registered allow-list + `other`.
- **The §2.5 security deny-list applies identically** to any capsule-exposed scrape: no principal ids, paths, secrets, or content as labels/values.

The capsule-domain metric families themselves (LLM tokens/cost, tool dispatch, react loop, session, memory) are catalogued for #705, not here.

---

## 4. Full metric catalog

De-duplication notes applied across inventories:
- **`astrid_daemon_active_connections`** (daemon inventory) and **`astrid_router_active_connections`** (router inventory) are the **same gauge** at the same site (`Kernel::total_connection_count`, set at `connection_opened`/`connection_closed`). Cataloged **once** as `astrid_daemon_active_connections`.
- **`astrid_ipc_messages_published_total`** (daemon, `topic_ns`) and **`astrid_router_events_published_total`** (router, `event_kind`) both instrument `EventBus::publish` (`bus.rs:61`). Kept as **two distinct families** with different label axes (namespace vs. event kind) — they answer different questions and the union is bounded (≤9 + 56). Both reference the same site.
- **`astrid_ipc_receiver_lagged_total`** (daemon) and **`astrid_router_bus_lagged_messages_total`** (router) are the **same counter** (`EventReceiver::recv` Lagged arm). Cataloged **once** as `astrid_ipc_receiver_lagged_total`, now carrying a **`subscriber`** label (review — §4.6).
- **`astrid_daemon_bg_task_ticks_total`** (daemon) is the §5 `astrid_daemon_background_ticks_total`. Unified name: **`astrid_daemon_background_ticks_total`**, label key `loop` (per §5), values `{watchdog, health_monitor, idle_monitor}`. `astrid_router_watchdog_ticks_total` is subsumed (the `loop="watchdog"` slice) and **dropped**.
- Capability/crypto/audit cross-layer dedups unchanged from draft (verified): `token_verify` (approval interceptor) vs `token_validation` (crypto validator) kept distinct; `token_grants` (store-add) vs `token_mint` (token-construct) kept distinct; `astrid_audit_chain_verify_issues_total` cataloged once; `astrid_audit_entry_sign_total` (sign slice) vs `astrid_audit_entries_total` (append slice) kept distinct.
- **Naming-collision note (review):** kernel-side `astrid_router_*` (the dumb dispatcher/event bus) is a *different* "router" from the WASM `astrid_capsule_router_*` guest. The `astrid_capsule_` prefix disambiguates mechanically; dashboards must not conflate them. The §4.2 families may optionally be renamed `astrid_bus_*`/`astrid_dispatch_*` to remove the word collision — flagged in §7.

Priority key: **P0** = production-debugging essential / security boundary; **P1** = high operational value; **P2/P3** = capacity / slow-moving / nice-to-have. `RFC` flag marks families crossing the IPC/contract boundary.

**Crate-attribution note (review):** §4.6 `astrid_daemon_*` sites live in **`astrid-kernel`** (`lib.rs`, `kernel_router/mod.rs`), not `astrid-daemon`; the `daemon` subsystem name is operator-facing ("the daemon process"). Socket-accept sites live in `astrid-capsule/src/engine/wasm/host/net/unix_listener.rs` (host code), corrected below.

### 4.1 Gateway / HTTP surface (`astrid-gateway`)

| Name | Type | Labels | Cardinality (tuples) | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_gateway_requests_total` *(exists)* | counter | method, route, status | 552 | P0 | `routes/mod.rs::observe_request` (:284) | Request rate per route/status (RED Rate/Errors). |
| `astrid_gateway_request_duration_seconds` *(exists; **label-reduced**)* | histogram | route, status_class | 69 (×13=897 ts) | P0 | same | Per-request latency (RED Duration). `method` dropped, `status` collapsed to `{2xx,error,other}` to stay under the histogram time-series trigger (§2.4.1). |
| `astrid_gateway_requests_in_flight` | gauge | method | 10 | P0 | `metrics_middleware` (~:275; guard-decrement on drop) | Concurrent load / pile-up (USE Saturation). |
| `astrid_gateway_auth_failures_total` *(revive; see oracle note)* | counter | result | 2 | P0 | `auth.rs::verify_bearer` (:90) — **requires new error classification, see note** | Bearer verify failures. **Reduced to binary `{ok,rejected}`** on the public scrape to avoid the validity oracle (see §2.5.1 + note). |
| `astrid_gateway_redeem_attempts_total` *(revive)* | counter | outcome | 4 | P0 | `routes/auth.rs::post_redeem` (:104,126,144), `post_pair_device_redeem` (:302,320) | Invite/pair redemption by `success`/`rate_limited`/`kernel_rejected`/`malformed`. `kernel_rejected` spike = token enumeration. |
| `astrid_gateway_redeem_rate_limited_total` *(revive)* | counter | — | 1 | P1 | `routes/auth.rs::post_redeem` limiter branch (:103–107) | Limiter rejections. |
| `astrid_gateway_request_body_bytes` | histogram | route | 23 | P1 | `routes/principals.rs::read_json_body` (:446) | Body-size distribution; clustering at the 64 KiB cap = truncation/probing. |
| `astrid_gateway_upstream_request_duration_seconds` | histogram | kind, outcome | ~27 | **P0** | `bus_admin.rs::BusAdminClient::request` (:103 start, :162 ok, :114/128 timeout, :122 closed) | "Gateway slow or kernel slow?" `outcome=timeout` surfaces a wedged kernel (15 s `DEFAULT_TIMEOUT`). **Promoted to P0** — required for per-stage RED (§6). |
| `astrid_gateway_active_sse_streams` | gauge | stream | 2 | P1 | `routes/agent.rs::post_prompt` (:237), `routes/events.rs::get_events` (:124); decrement on drop | Open SSE streams; monotonic climb = leaked bus subscriptions. |
| `astrid_gateway_revocations_active` | gauge | — | 1 | P2 | `revocations.rs::spawn_watcher` (~:230), init `state.rs` (:247) | Revocation-map size; flatline-at-zero after deletes = watcher died. |
| `astrid_gateway_handler_panics_total` | counter | route | 23 | P2 | add `CatchPanicLayer` in `routes/mod.rs::build` (~:137) — behavioural change (§7.5) | Caught panics → counted 500s. |
| `astrid_gateway_tls_handshakes_total` | counter | outcome | 2 | P2 | `tls.rs::serve_https` accept loop (:104–107) | TLS terminator health; needs `axum_server` handshake plumbing. |
| `astrid_gateway_cors_rejections_total` | counter | — | 1 | P2 | wrap `routes/mod.rs::build_cors_layer` (:216) | CORS denials; needs a wrapping layer. |
| `astrid_gateway_routes_registered` | gauge | auth | 2 | P3 | `routes/mod.rs::build` (~:132) | Build-info: route count split `public`/`authed`. |

> **Auth-failure oracle (review-resolved).** The draft's 6-value `{reason}` breakdown is **dropped from the public scrape.** Two reasons: (1) `verify_bearer` (`auth.rs:90–195`) collapses *every* failure to `GatewayError::Unauthorized` via `.map_err(|_| …)` today — the reason information **does not exist** without first introducing distinct error classification (a code change with its own security review). (2) On an *unauthenticated* endpoint, a `reason="expired"` vs `reason="bad_signature"` delta is a server-side **validity oracle** — an attacker correlating probe timing with counter deltas learns whether a guessed token is structurally-valid-but-expired vs forged. The public series is the binary `astrid_gateway_auth_failures_total{result}` / `astrid_gateway_bearer_verify_total{result}` (§4.7). **If** `/metrics` later moves behind auth, the `{reason}` breakdown may be reintroduced under the documented threat model.

### 4.2 Kernel router & event bus (`astrid-events`, `astrid-capsule` dispatcher, kernel routers)

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_router_events_published_total` | counter | event_kind | **56** | P0 | `astrid-events/src/bus.rs::EventBus::publish` (:61–91); label off `AstridEvent::event_type()`, **never** raw `IpcMessage.topic` | Bus throughput per event kind. Count corrected 62→56; safety depends on `event_type()` staying a closed `&'static str` match — `Custom => "custom"`/`Ipc => "ipc"` collapse is the deliberate bound (a future `Custom => name` regression is caught by the §2.5.3 CI allowlist). **Layering (§6.0):** emit from an `astrid-kernel` caller above the bus, or accept adding the facade to `astrid-events` — a deliberate decision. |
| `astrid_router_events_dropped_total` | counter | reason | 3 | P0 | `bus_lag` drain (~:125); `queue_full` try_send Err (~:420); `payload_serialize` serde Err (~:156–169) | Silent correctness failures: a tool result/hook that never fired. |
| `astrid_router_interceptor_invocations_total` | counter | outcome | 5 | P0 | `dispatcher.rs::dispatch_single` (~:367–408), chain task (~:287–340) | Capsule fan-out by `continue`/`final`/`deny`/`not_supported`/`error`. |
| `astrid_router_kernel_requests_total` | counter | method, outcome | 32 | P0 | `kernel_router/mod.rs::spawn_kernel_router` (:54–83), `handle_request` (:145–187) | Admin control-plane; `denied`/`rate_limited` already `security_event=true`. |
| `astrid_router_event_receivers` | gauge | — | 1 | P1 | `bus.rs::EventBus::publish` return `c` (:74) / `subscriber_count` (:121) | Active receiver fan-out; dropping = run-loop crash silently dropping receivers. **Subsumes the dropped `astrid_ipc_publish_fanout` histogram** (§7 / review: a point-in-time level question is a gauge, not a per-publish histogram). |
| `astrid_router_dispatch_match_duration_seconds` | histogram (sub-ms head) | — | 1 | P1 | `dispatcher.rs::find_matching_interceptors` (:434) | Interceptor-match latency (registry read-lock + linear scan). |
| `astrid_router_interceptor_duration_seconds` | histogram (sub-ms head) | — | 1 | **P0** | `dispatcher.rs::dispatch_single` around `capsule.invoke_interceptor` (~:367) | WASM guest exec time — the "why are events backing up" answer; feeds `queue_full` drops. **Promoted to P0** (per-stage RED, §6). |
| `astrid_router_ipc_publish_rejections_total` | counter | reason | 4 | P1 | `host/ipc.rs::publish_inner` ErrorCode returns (:214–253) | Guest→bus ingress denials: `rate_limited`/`payload_too_large`/`invalid_input`/`capability_denied`. |
| `astrid_router_capsule_queue_depth` | gauge | — | 1 | P2 | `dispatcher.rs::dispatch_single` mpsc Sender (~:356), capacity vs 256 | Per-capsule queue occupancy; → 256 predicts `queue_full` drops. |

### 4.3 Capsule lifecycle & WASM sandbox (`astrid-capsule`, `astrid-capsule-install`, kernel orchestration)

`interface` label is pinned to the verified frozen WIT world via **`interface_static`**: `{io, fs, ipc, kv, net, http, sys, process, uplink, elicit, approval, identity}` + `other` = 13 values. (Verified `astrid-sys/src/lib.rs:68–82`; **`io` IS in the WIT world** — the draft's 12-with-`io` list was correct, contra one review finding.) `capsule` label collapses via `capsule_name_static` (grows-with-install class, §2.4.2).

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_capsule_loaded` | gauge | state | 3 | P0 | `lib.rs::spawn_capsule_health_monitor` (:1302) + `registry.rs::{register,unregister,drain}` | Capsules `ready`/`failed`/`loading`. |
| `astrid_capsule_load_duration_seconds` | histogram | phase, outcome | 6 | P0 | `engine/wasm/mod.rs::WasmEngine::load` compile (:829), instantiate (:835), total `lib.rs::load_capsule` (:405) | Cold-start by `compile`/`instantiate`/`total`; restart MTTR. |
| `astrid_capsule_load_total` | counter | outcome, reason | 16 | P0 | `WasmEngine::load` early returns: BLAKE3 (:558–576), read (:552), compile (:829), instantiate (:835), interceptor cap (:873) | `integrity_mismatch`/`missing_hash` = the fail-secure BLAKE3 gate firing — alert. |
| `astrid_capsule_traps_total` | counter | site, reason | 15 | P0 | `func.call` error arms: run-loop (:1020), interceptor (:1323/1325), lifecycle (:1553); downcast to `wasmtime::Trap` | Trap rate by site × `epoch_timeout`/`memory_oob`/`unreachable`/`stack_overflow`/`other`. |
| `astrid_capsule_invocation_duration_seconds` **(NEW — review)** | histogram | outcome | 2 | **P0** | `engine/wasm/mod.rs` around the run-loop/interceptor `func.call` spans | **Closes the "spinning-under-epoch-limit" blind spot:** a capsule whose every invocation runs near the epoch cap (burning CPU without tripping the `epoch_timeout` trap) is invisible to trap/hostcall counters and to `process_cpu_seconds` attribution. No fuel metering needed — the call span already exists. Directly serves the 200–300% idle-CPU incident. |
| `astrid_capsule_hostcall_total` | counter | interface, outcome | 13×3=39 | P1 | `host/util.rs::bounded_block_on`(:18)/`bounded_block_on_cancellable`(:53) | Host-ABI rate/errors per interface (`interface_static`). |
| `astrid_capsule_hostcall_duration_seconds` | histogram | interface, outcome | 39 (×13=507 ts) | **P0** | same chokepoint (:18, :53) | Host-ABI latency incl. host-semaphore queueing. **Promoted to P0** (per-stage RED, §6). |
| `astrid_capsule_resource_handles` | gauge | kind | 3 | P1 | `host_state.rs` net/subscription/process counts (:338–343) | Live sandbox resource handles vs `MAX_*` gates (USE Utilization). |
| `astrid_capsule_resource_denied_total` | counter | kind, reason | ~8 | P1 | gate returns: `host/net/mod.rs`(:244,283), `unix_listener.rs`, `host/ipc.rs`(:333), `host/process/mod.rs`(:195) | Saturation/quota denials; `process:quota` = fork-bomb capsule. |
| `astrid_capsule_health_failed_total` | counter | capsule | ≤ registered+1 | P1 | `lib.rs::spawn_capsule_health_monitor` Failed arm (:1337–1339) | Failed-transition frequency (flapping). `capsule` via `capsule_name_static`. |
| `astrid_capsule_hostcall_semaphore_available_permits` | gauge | — | 1 | P2 | `host_state.rs` `host_semaphore` `available_permits()` (:669) | Host-call concurrency headroom; 0 = queueing → thread-pool exhaustion. |
| `astrid_capsule_instance_memory_limit_bytes` **(re-typed — review)** | histogram | — | 1 | P2 | `engine/wasm/mod.rs` StoreLimits build (:233/676) | The saturation *denominator* — distribution of configured per-capsule linear-memory ceilings. **Changed from per-`capsule` gauge to an unlabelled histogram** to avoid grows-with-install per-name series (live usage is #639). |
| `astrid_capsule_restart_total` | counter | outcome | 2 | P2 | `lib.rs::spawn_capsule_health_monitor` restart loop (:1367–1375) | `success`/`exhausted`; `exhausted` = unrevivable, alert. |
| `astrid_capsule_install_total` | counter | phase, outcome | 4 | P2 | `astrid-capsule-install/src/local.rs::install_from_local_path` (:168–271) | `install`/`upgrade` × `success`/`rolled_back`. |
| `astrid_capsule_lifecycle_hook_duration_seconds` | histogram (long buckets) | hook, outcome | 6 | P3 | `engine/wasm/mod.rs::run_lifecycle` (:1403) around `func.call` (:1553) | Lifecycle-hook latency; approaching 10-min `LIFECYCLE_TIMEOUT_SECS` = runaway install. |

### 4.4 Capabilities & approval gates (`astrid-capabilities`, `astrid-approval`, kernel enforcement)

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_capability_static_checks_total` *(**scope re-bounded**)* | counter | outcome, category, danger, scope_class | ≤ 3×3×3×3 = 81 | P0 | `kernel_router/mod.rs::authorize_request` (:492) both arms; `required_cap` → `CAPABILITY_CATALOG` (`capability_grammar.rs`) | Static management-API checks. **`scope` is replaced by `scope_class` ∈ `{self, global, resource}`** mapped via `match -> &'static str` — the literal scope token (`fs:read:workspace`, `delegate:self:*`) is forbidden by the §2.5 deny-list and grows with the grammar. `category`/`danger` are the verified closed `CAPABILITY_CATALOG` enums. All four in the §2.5.3 allowlist. Never labelled by principal or literal cap string. |
| `astrid_capability_static_denials_total` | counter | reason | 3 | P0 | `authorize_request` Err arm (:531) → `PermissionError`; fail-closed deny (:506) | `missing_capability`/`revoked_capability`/`principal_disabled`. |
| `astrid_capabilities_token_verify_total` | counter | outcome | 7 | P0 | `astrid-approval/src/interceptor/capability.rs::check_capability` (:47) | Runtime ed25519 check outcomes (`authorized`/`expired`/`revoked`/`already_used`/`untrusted_issuer`/`invalid_signature`/`requires_approval`). |
| `astrid_capabilities_authorize_duration_seconds` **(NEW — review)** | histogram (sub-ms head) | — | 1 | **P0** | `kernel_router/mod.rs::authorize_request` (:492) body | Duration for the management-API capability check that gates **every** admin request. Lock contention on the capability store would inflate every gated request invisibly; the draft only covered the MCP secure path (`capabilities_authorization_seconds`, §4.7). Cheap, no RFC. |
| `astrid_approval_outcomes_total` | counter | outcome, action_class | 42 | P0 | `astrid-approval/src/manager.rs::check_approval` (:208); class from `ApprovalAction::action_type()` (`action.rs:134`) | Human-in-the-loop gate by `allowed`/`denied`/`deferred` × 14 action classes. Variant payloads never labelled. |
| `astrid_capabilities_token_grants_total` | counter | scope_class, single_use | 6 | P1 | `store.rs::CapabilityStore::add` (:202); "Allow Always" at `interceptor/capability.rs::handle_allow_always` (:114) | Tokens minted+stored. `scope_class` not literal token. |
| `astrid_capabilities_token_revocations_total` | counter | — | 1 | P1 | `store.rs::CapabilityStore::revoke` (:491) | Global revocations; net authority drift with grants. |
| `astrid_approval_prompt_duration_seconds` | histogram (≤300 s) | outcome | 2 | P1 | `manager.rs::check_approval` around `timeout(handler.request_approval)` (:253–268) | Human attentiveness/SLA. |
| `astrid_approval_deferred_reasons_total` | counter | reason | 4 | P2 | `manager.rs::defer_action` (:324), four sites (:240,247,259,264) | `no_handler`/`handler_unavailable`/`timed_out`/`no_response`. |
| `astrid_approval_deferred_queue_depth` | gauge | priority | 4 | P2 | `deferred.rs::DeferredResolutionStore` | Backlog by `low`/`normal`/`high`/`critical`. |
| `astrid_capability_live_tokens` | gauge | state | 4 | P2 | `store.rs` Debug aggregates (:728–743) | Standing authority by `session`/`persistent`/`revoked`/`used`. |
| `astrid_capability_delegation_grants_total` | counter | scope_class | 2 | P3 | `interceptor/capability.rs::handle_allow_always` (:114)/`store.rs::add` (:202) filtered to `delegate:self:*` | Delegation (`self`/`global`). **No depth metric** — depth is structural, not an integer; honestly omitted. |
| `astrid_capability_expired_tokens_cleaned_total` | counter | — | 1 | P3 | `store.rs::cleanup_expired` (:694) | GC throughput; flat-zero while `live_tokens` climbs = cleanup stuck. |

### 4.5 Audit, Storage (KV) & VFS (`astrid-audit`, `astrid-storage`, `astrid-vfs`, host shims)

**Pre-req (Phase 0, review blocker):** add `pub fn action_class(&self) -> &'static str` to `astrid-audit`'s `AuditAction` (entry.rs:190) returning bounded discriminant tags only — mirror approval's `action_type`. **It does not exist today**; the only stringifiers are `description()`/`summary()`, both of which interpolate paths/commands/hosts/server:tool/recipients/token_ids. Metric code MUST NOT call `description()`/`summary()`. Add `pub fn kind(&self) -> &'static str` to `ChainIssue` (log.rs:451) similarly; forbid its `Display`.

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_audit_entries_total` | counter | action_class, outcome | ~56 | P0 | `astrid-audit/src/log.rs::append_inner` after `storage.store` (~:142–151); via **new `action_class()`** | Appends by ~28 classes × `success`/`failure`. Drop in volume = pipeline wedged. **Fail-secure alert rule (§6):** `rate(astrid_audit_entries_total)==0 AND rate(astrid_gateway_requests_total)>0`. |
| `astrid_audit_append_duration_seconds` | histogram | — | 1 | P0 | `log.rs::append_inner` body (sign → 3 sequential KV txns) | Audit on the synchronous hot path. |
| `astrid_audit_store_errors_total` | counter | stage | ~5 | P0 | `storage.rs::SurrealKvAuditStorage::store` (:212,220,228), chain lock (:148) | `entry_write`/`session_index`/`chain_head`/`serialization`/`chain_lock`. |
| `astrid_audit_chain_verify_issues_total` | counter | issue_kind | 3 | P0 | `log.rs::verify_chain` (~:242–270) + `verify_principal_chain` (~:315–336); boot `verify_all` (`lib.rs:1003`); via **new `ChainIssue::kind()`** | `invalid_genesis`/`invalid_signature`/`broken_link`. Any nonzero = tamper/corruption — highest severity. Issue payloads (hashes/indices) never reach a label. |
| `astrid_kv_operations_total` | counter | op, result | ~21 | P0 | `host/kv.rs::kv::Host` each fn return; `cas` adds `result=mismatch` | KV traffic by verb × `ok`/`err`/`mismatch`. Key/namespace never labelled. |
| `astrid_kv_operation_duration_seconds` | histogram | op | 7 (×13=117 ts) | **P0** | `host/kv.rs` around each `bounded_block_on` | Per-verb latency; surfaces the global `cas_lock` serialisation. **Promoted to P0** (per-stage RED, §6). |
| `astrid_kv_value_bytes` | histogram (≤1 MiB) | — | 1 | P1 | `host/kv.rs::kv_set` (value.len()) + `kv_cas` (new.len()) | Written-value sizes vs 1 MiB cap. Bytes only — no content. |
| `astrid_kv_store_bytes` | gauge | — | 1 | P2 | new size-probe on `storage/src/kv/surreal.rs::SurrealKvStore` (astrid-storage), periodic kernel task | On-disk store size. |
| `astrid_kv_scopes` | gauge | — | 1 | P3 | new count-namespaces on `KvStore` (astrid-storage), same task | Distinct namespace count (count only, never one series per namespace). |
| `astrid_vfs_operations_total` *(**target source corrected**)* | counter | op, target, result | ~48 | P0 | `host/fs/mod.rs` at each `audit_fs(...)` site; **`target` derived from the VFS boundary region classifier (`astrid-vfs/src/boundary.rs`) via `match -> &'static str`** | FS load/errors by ~8 verbs × `workspace`/`home`/`tmp` × `ok`/`err`. **Draft cited the wrong source** (the audit-topic const `"astrid.audit.fs"`); `target` must be the boundary region, never a path. Path never labelled. |
| `astrid_vfs_denials_total` | counter | op, reason | ~48 | P0 | `host/fs/mod.rs` `map_resolve_err` (~:68), `gate_read`/`gate_write` (~:104/122) | Host-boundary denials. `boundary_escape` rising = sandbox-escape probing. `reason` = error-enum discriminant, **never** `map_vfs_err`'s `Display` (may embed the offending path). |
| `astrid_vfs_overlay_operations_total` | counter | operation, result | 6 | P1 | `astrid-vfs/src/overlay.rs::commit`/`rollback`, copy-up in `open` (~:378–430) | CoW overlay lifecycle; 50 MB `MAX_OVERLAY_FILE_SIZE` shows as `err`. |
| `astrid_vfs_open_files` | gauge | — | 1 | P1 | `astrid-vfs/src/host.rs::HostVfs` open()/close() (:45, cap 64) | FDs held vs 64-FD ceiling (USE Saturation). |

### 4.6 Daemon, uplink & IPC transport (`astrid-kernel`, `astrid-events`; host net shim in `astrid-capsule`)

Sites here live in **`astrid-kernel`** (`lib.rs`, `kernel_router/mod.rs`) unless noted; socket-accept sites live in **`astrid-capsule/src/engine/wasm/host/net/unix_listener.rs`** (host code, no RFC). `spawn_idle_monitor` is at `lib.rs:1103` (draft's `:1157` corrected).

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers | RFC |
|---|---|---|---|---|---|---|---|
| `astrid_daemon_active_connections` | gauge | — | 1 | P0 | `lib.rs::connection_opened`(:605)/`connection_closed`(:623) → `total_connection_count()`(:674); tracker `kernel_router/mod.rs::spawn_connection_tracker`(:92) | Does the daemon think anyone is connected? Gates idle shutdown. Diagnoses no-shutdown (stuck >0) and premature shutdown. | — |
| `astrid_daemon_connections_opened_total` | counter | — | 1 | P0 | `lib.rs::connection_opened`(:605) / tracker Connect arm | `opened − closed` vs the gauge reveals leaked/half-closed connections. | — |
| `astrid_daemon_connections_closed_total` | counter | — | 1 | P0 | `lib.rs::connection_closed`(:623) / tracker Disconnect arm | Divergence from `opened_total` is the no-shutdown leak signal. | — |
| `astrid_daemon_socket_accepts_total` *(**site + reasons corrected**)* | counter | result | 4 | P0 | **`host/net/unix_listener.rs::accept`(:22)/`poll_accept`(:115)** — NOT astrid-daemon/lib.rs | Transport front door: `accepted`/`rejected_peer_cred`/`rejected_handshake`/**`quota`** (the `MAX_ACTIVE_STREAMS` early-return at :23, omitted by draft). Climbing `rejected_peer_cred` (100 ms backoff branch :60–69) = the 200–300% idle-CPU spin signature. **§2.5: peer uid/gid/pid MUST NOT become labels.** | — |
| `astrid_daemon_handshake_duration_seconds` **(NEW — review)** | histogram | outcome | 2 | P1 | `unix_listener.rs::validate_handshake` (:73–94), 5 s timeout | Slow-but-valid clients near the 5 s cap are otherwise invisible. | — |
| `astrid_daemon_background_ticks_total` | counter | loop | 3 | P0 | `lib.rs`: `spawn_react_watchdog`(:1406), `spawn_capsule_health_monitor`(:1310), `spawn_idle_monitor`(:1103) | Hot-spin detector. `rate()` per `loop` ∈ {`watchdog`,`health_monitor`,`idle_monitor`} flat ~1/5s, ~1/10s, ~1/1–15s. Orders-of-magnitude faster = the idle-CPU fingerprint. | — |
| `astrid_daemon_active_streams` *(**promoted P0**)* | gauge | — | 1 | **P0** | `unix_listener.rs` `net_stream_count` (accept :109, poll_accept :188) vs `MAX_ACTIVE_STREAMS=8` (`net/mod.rs:56`) | Net-stream handles vs cap 8. Sitting at 8 explains why new uplinks silently fail. **Promoted to P0** — `process_open_fds` alone can't isolate the named uplink-socket-leak suspect (review). | — |
| `astrid_daemon_uptime_seconds` | gauge | — | 1 | P1 | `lib.rs` `boot_time`(:96,:300); update from `spawn_idle_monitor`(:1103) | Restart/crash-loop detection. | — |
| `astrid_ipc_messages_published_total` *(**promoted P0**)* | counter | topic_ns | ≤9 | **P0** | `bus.rs::EventBus::publish`(:61) after seq stamp (:67); via **`topic_namespace_static`** (closed allowlist + `other`), **never** raw topic | Bus rate per top-level namespace — the **leading indicator for shared-ring saturation**. Pairs with per-subscriber lag + `background_ticks` to close the no-shutdown diagnosis. **Promoted to P0** (review). | — |
| `astrid_ipc_receiver_lagged_total` *(**now labelled**)* | counter | subscriber | 7 | **P0** | `bus.rs::EventReceiver::recv`(:246) Lagged arm (:262), try-recv Lagged (:284); inc by `count`; `subscriber` threaded through `EventReceiver::new` at `subscribe_topic` time | Events dropped from broadcast lag, **attributed to the receiver that dropped them** ∈ `{connection_tracker, kernel_router, dispatcher, gateway_sse, audit_watcher, metrics_bridge, other}`. **This is the single most important signal for the no-shutdown bug:** the shared 1024-slot ring (`self.sender.subscribe()` for every `subscribe_topic`, filter-after-dequeue) means any flood evicts slots for *all* receivers; a dropped `client.v1.disconnect` on the `connection_tracker` receiver is the mechanism for the stuck connection counter. **Promoted to P0 + label added** (review blocker). Small kernel-side change, no RFC (bus is kernel-internal). | — |
| `astrid_ipc_receiver_backlog` **(NEW — review)** | gauge | subscriber | 7 | P1 | per-`EventReceiver::len()` (tokio broadcast exposes `Receiver::len()`), sampled from a periodic kernel task | **The only leading (pre-drop) saturation signal for the kernel's core channel.** The lag counter fires only *after* overflow; this gauge shows how close each receiver is to the 1024-slot cap *before* drops happen. USE-Saturation on the single most load-bearing resource in the kernel. | — |
| `astrid_ipc_ring_capacity` **(NEW — review)** | gauge | — | 1 | P2 | constant `DEFAULT_CHANNEL_CAPACITY` (1024) | Saturation denominator for the backlog gauge. | — |
| `astrid_daemon_shutdown_state` | gauge | — | 1 | P2 | `lib.rs::Kernel::shutdown`(:713) set 1; watch `shutdown_tx`(:99) | 0=running / 1=shutdown requested. | — |
| `astrid_daemon_idle_seconds` | gauge | — | 1 | P2 | `lib.rs::spawn_idle_monitor` loop (:1103–…); from `idle_since`, reset on activity | How far into the idle-timeout window; makes the log-only idle logic observable. | — |
| `astrid_daemon_active_connections_by_kind` | gauge | uplink_kind | ~4 | P1 | extend `spawn_connection_tracker`(:92) + `connection_opened`/`closed` | "Which frontend holds connections" (`cli`/`web`/`discord`/`other`). **Blocked:** Connect/Disconnect `IpcPayload` carries only principal — no uplink-kind on the wire. Requires new IPC contract surface; collapse unknowns to `other`. | **RFC** |

> The draft's `astrid_ipc_publish_fanout` histogram is **dropped** — its stated job ("fanout collapsed to 0 while clients connected") is a point-in-time *level* question answered by the `astrid_router_event_receivers` gauge (§4.2), not a per-publish distribution (N4 honesty; review).

### 4.7 Crypto & core token operations (`astrid-crypto`, `astrid-capabilities`, gateway bearer, runtime key)

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_crypto_ed25519_verify_total` | counter | result | 2 | P0 | `astrid-crypto/src/signature.rs::Signature::verify`(:89) | Lowest-level verify chokepoint (`ok`/`fail`). Rising `fail` = forged/tampered tokens, key-rotation breakage, v1→v2 regression. |
| `astrid_capabilities_token_mint_total` | counter | scope_class | 2 | P0 | `astrid-capabilities/src/token.rs::create_with_options`(:161) | Issuance by `session`/`persistent`. |
| `astrid_capabilities_token_verify_total` *(crypto-layer)* | counter | result | 2 | P0 | `token.rs::verify_signature`(:285) | Token-tamper surface (`ok`/`invalid_signature`). |
| `astrid_capabilities_token_validation_total` *(validator-layer)* | counter | result | 4 | P0 | `validator.rs::validate_token`(:104): is_expired(:106), verify_signature(:113), trusted_issuers(:116), Ok(:120) | `authorized`/`expired`/`invalid_signature`/`untrusted_issuer`. `untrusted_issuer` = a non-runtime key reached validation — strong compromise indicator. |
| `astrid_audit_chain_verify_issues_total` *(= §4.5)* | counter | issue_kind | 3 | P0 | (see §4.5) | Same family — tamper-evidence on the audit chain. |
| `astrid_crypto_ed25519_sign_total` | counter | — | 1 | P1 | `astrid-crypto/src/keypair.rs::KeyPair::sign`(:89) | Runtime private-key usage; proxy for audit-write + token-mint load. |
| `astrid_capabilities_authorization_seconds` | histogram | outcome | ~22 | P1 | `astrid-mcp/src/secure.rs::check_authorization`(:83–97) | End-to-end auth latency on the **MCP** path (`authorized`/`requires_approval`). (The kernel_router admin-path duration is the separate `astrid_capabilities_authorize_duration_seconds`, §4.4 P0.) |
| `astrid_gateway_bearer_verify_total` | counter | result | 2 | P1 | `auth.rs::verify_bearer`(:90): Ok(:163) / every Err | Bearer verify with the success denominator (`ok`/`rejected`). Binary by design — splitting reasons would reintroduce the validity oracle (§4.1 note). |
| `astrid_audit_entry_sign_total` | counter | — | 1 | P1 | `astrid-audit/src/entry.rs` create(:85)/create_with_principal(:116), funnel `log.rs::append_inner`(:97) | Audit-entry signing rate. Stalled-at-zero on a busy daemon = alert (fail-secure). |
| `astrid_gateway_bearer_mint_total` | counter | — | 1 | P2 | `auth.rs::mint_bearer`(:65) | Session-bearer issuance. Principal never labelled. |
| `astrid_crypto_runtime_key_generated_total` | counter | — | 1 | P2 | `lib.rs::load_or_generate_runtime_key`(:1045) **generate branch only** (:1057), not the load branch (:1050) | Should be 1 for a deployment's lifetime. Any increment on an existing deployment = wiped keys_dir / wrong home / perms failure, silently invalidating every persistent token + bearer. |

### 4.8 MCP server & hooks (`astrid-mcp`, `astrid-hooks`)

**MCP cardinality + reconnaissance (review blockers).** The `tool` label is **dropped from all public families**: it is an unbounded, third-party-advertised string (`types.rs:11` `name: String`; `set_server_tools` has no count cap), a top cardinality bomb on an unauthenticated endpoint, *and* a reconnaissance leak (the advertised tool set discloses the deployment's capability surface). `server` collapses via **`mcp_server_static`** to the boot-registered config set + `other`, length-capped, `[a-z0-9_-]`-shape rejected. If per-tool visibility is ever needed it goes behind auth, not on the public scrape.

**Hooks re-classification (review blocker — NOT RFC, NOT capsule-side).** `astrid-hooks` is a **host-side crate** (depends on `wasmtime`/`wasmtime-wasi`, runs Command/Http/Wasm/Agent handlers in the daemon process — verified `Cargo.toml`). The cited site `executor.rs::execute` (:53) with its already-computed `duration_ms` (:122) emits via `counter!/histogram!` **directly, no RFC, no transport.** The draft conflated it with the separate `astrid-capsule-hook-bridge` WASM capsule (which only maps lifecycle → semantic names over IPC and sees *subscriber replies*, not the executor's per-handler match arms). **Both hooks families move to Phase 1/2, RFC flag removed**, instrumented host-side where the `handler` (HookHandler serde tag) and outcome are actually available.

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers | RFC |
|---|---|---|---|---|---|---|---|
| `astrid_mcp_tool_calls_total` *(**tool dropped**)* | counter | server, outcome | servers×3 | P0 | `astrid-mcp/src/client.rs::McpClient::call_tool`(~:257–300): ServerNotRunning(:259), map_err(:288), Ok(:297) | MCP calls (`success`/`error`/`not_running`) per server. `server` via `mcp_server_static`. | — |
| `astrid_mcp_tool_call_duration_seconds` *(**tool dropped**)* | histogram (extend top) | server | servers (×17 ts) | P0 | `client.rs::call_tool` around `peer.call_tool`(:288) | "Server down (errors) vs slow (latency)." Extend top bucket past 10 s (npx cold-start). | — |
| `astrid_mcp_permission_checks_total` | counter | decision | 3 | P0 | `secure.rs::SecureMcpClient::check_authorization`(:83): Authorized(:133), RequiresApproval(:155), error(:116,149) | MCP capability gate (`authorized`/`requires_approval`/`error`). Correctly no server/tool label. | — |
| `astrid_mcp_servers_connected` | gauge | — | 1 | P1 | `server.rs::ServerManager` `list_running().len()` (:440,:705) | Live MCP integrations. | — |
| `astrid_mcp_server_health_status` | gauge | server | configured | P1 | `server.rs::ServerManager::health_check`(:843) | Per-server liveness (1/0); `mcp_server_static`. | — |
| `astrid_mcp_server_restarts_total` | counter | server, outcome | configured×3 | P1 | `server.rs::restart_if_allowed`(:923): denied_policy/failed/restarted; caller `client.rs::try_reconnect`(:355) | Supervision loop; `denied_policy` = crash-looping server given up on. | — |
| `astrid_mcp_binary_verification_failures_total` | counter | server | configured | P1 | `server.rs::start`(:276) verify_binary Err + `add_server`(:312) | Supply-chain gate: binary no longer matches pinned hash. | — |
| `astrid_mcp_tools_registered` | gauge | server | configured | P2 | `server.rs::connect_stdio_server`(:429), `set_server_tools`(:823) | Advertised tool *count* per server (the count, not the names). | — |
| `astrid_mcp_server_starts_total` | counter | outcome | 4 | P2 | `server.rs::connect_stdio_server`: transport_failed(:401), handshake_failed(:411), started(:440); start_failed(:251) | Spawn-fail vs protocol-mismatch vs verify-fail. | — |
| `astrid_hooks_executions_total` *(**host-side, RFC removed**)* | counter | hook_point, handler, outcome | ≤368 (real ≪) | P1 | `astrid-hooks/src/executor.rs::execute`(:53) match(:124): success/blocked/failure/skipped(:65,:80) | 23 hook points × 4 handlers (`{command,http,wasm,agent}` serde tags) × `success`/`failure`/`blocked`/`skipped`. `blocked` = policy hook denying an action. No hook id/name/command/url/path in labels. | — |
| `astrid_hooks_execution_duration_seconds` *(**host-side, RFC removed**)* | histogram (≤30 s) | hook_point, handler | ≤92 (×17 ts) | P2 | `executor.rs::execute`: `duration_ms` already computed (:122) | Hook latency (hooks run synchronously in the agent turn). | — |

### 4.9 Capsule domain metrics — see #705

Capsule-domain signals (LLM requests/tokens/cost, tool dispatch, react agent-loop, session writes, HTTP fetch, memory injections) emit from `wasm32-unknown-unknown` guests and belong to the **capsule-telemetry layer (#705)**, which aggregates them off existing bus contracts. They are contributed to #705 as design input (with the anti-spoofing and mandatory-collapse rules from §3) and are **not** part of this host-internal catalog. The highest-value egress RED is *also* available host-side with no RFC — see §4.10.

### 4.10 Host-side egress RED (NEW — review blocker; kernel-side, NO RFC)

The LLM/tool round-trip is the highest-latency, highest-cost lifecycle stage, and **all** capsule HTTP egress passes through the kernel-side host shim `crates/astrid-capsule/src/engine/wasm/host/http.rs`, which sees the response status, the SSRF/capability denial (`ErrorCode::CapabilityDenied` from `check_http_security`, :164–186), and the full wall-clock duration (the `bounded_block_on` span). This runs in the daemon process and emits via `counter!/histogram!` with **no RFC and no IPC transport**. The draft placed *all* of this RED behind the §3 transport RFC (Phase 3) via §4.9; review requires the operator's "is the LLM provider slow or erroring" question to be answerable in **Phase 0**.

| Name | Type | Labels | Cardinality | Pri | Instrumentation point | What it answers |
|---|---|---|---|---|---|---|
| `astrid_http_egress_requests_total` | counter | status_class, outcome | 5×5 | P0 | `host/http.rs` buffered status(:244) / streaming status(:324) / error arms | Host egress RED Rate/Errors: status `2xx..5xx`/`none` × `ok`/`transport_error`/`ssrf_denied`/`capability_denied`/`timeout`. Provider outage visible without an RFC. |
| `astrid_http_egress_duration_seconds` | histogram (extend top) | status_class | 5 (×17 ts) | P0 | `host/http.rs` around the `bounded_block_on` span | Egress Duration; top bucket extended past 10 s for LLM streams / npx cold-start. The pipeline's dominant-latency answer, no RFC. |
| `astrid_http_egress_denials_total` | counter | reason | ~4 | P0 | `host/http.rs` `check_http_security`(:164–186) deny returns | SSRF/capability gate: `ssrf`/`capability_denied`/`scheme`/`other`. Discriminant only — **never** the URL/host (exfiltration/recon vector). |

---

## 5. Standard process & build-info metrics

### 5.1 Process collector (`metrics-process` 2.4 — shipped)

Mandatory on every daemon scrape, **P0** because they convert the idle 200–300% CPU class of bug into a graphable signal. `metrics-process` is the maintained companion to `metrics-exporter-prometheus`, supports Linux/macOS/Windows/FreeBSD, and emits canonical `process_*` names — no per-OS `#[cfg]` procfs parsing. **Shipped** in the foundation slice as a workspace dependency (`metrics-process = "2.4"`), wired into `install_recorder()` (`describe()` once) + the `/metrics` handler (`collect_process_metrics()` once per scrape). `process_cpu_seconds_total`, `process_resident_memory_bytes`, and `process_start_time_seconds` are available on every supported platform; `process_threads`/`process_open_fds` are backed by `libproc` on macOS.

| Series | Type | Pri | Why (idle-CPU bug) |
|---|---|---|---|
| `process_cpu_seconds_total` | counter | P0 | `rate()` **is** the busy-loop detector. Idle ⇒ flat; spin ⇒ ramp. |
| `process_resident_memory_bytes` | gauge | P0 | Leak / accumulation. |
| `process_virtual_memory_bytes` | gauge | P0 | Address-space growth. |
| `process_open_fds` | gauge | P0 | FD leak (paired with `astrid_daemon_active_streams` P0 to isolate the uplink-socket suspect — review). |
| `process_threads` | gauge | P0 | Runaway tokio worker that should park but spins. |
| `process_start_time_seconds` | gauge | P0 | Restart detection + uptime. |

**Wiring — extend `install_recorder()`, don't fork it.** `metrics-process` is a collector ticked per scrape:

```rust
use metrics_process::Collector;
let collector = Collector::default();
collector.describe();                 // emits process_* HELP/TYPE once
// In the /metrics axum handler: collector.collect() then handle.render()
```

The `/metrics` handler calls `collector.collect()` immediately before `handle.render()` — point-in-time correctness with **zero background threads** (critical: we are *debugging* a background-CPU bug, do not add a polling thread to observe one). Keep `collector` in the same memoised state the `HANDLE` `Mutex` guards so it installs exactly once.

**Plus the Astrid-specific saturation counters (P0):** `astrid_daemon_background_ticks_total{loop}` + the per-`subscriber` `astrid_ipc_receiver_lagged_total` + `astrid_ipc_messages_published_total{topic_ns}` (all §4.6). Together these are the smoking gun a generic collector cannot provide: which loop burns CPU, which receiver dropped events, and which namespace flooded the ring.

### 5.2 `astrid_build_info`

```text
# HELP astrid_build_info Build provenance. Always 1; join other series on this for version slicing.
# TYPE astrid_build_info gauge
astrid_build_info{version="0.7.0",git_sha="baca3f2e808c",rustc="rustc 1.95.0 (59807616e 2026-04-14)"} 1
```

- Labels are **build-time constants** captured at compile time, never runtime identity: `version` (`CARGO_PKG_VERSION`), `git_sha` (short 12-char, from `build.rs` — directly addresses the `project_capsule_lock_reproducibility` lesson that *provenance, not source* explained a past capsule mismatch), `rustc` (the `rustc --version` string, also from `build.rs`). Both VCS/toolchain labels fall back to `"unknown"` so `env!` never fails on a tarball build. **Shipped** in the foundation slice.
- **Cardinality exactly 1 per process.** Safe on the deny-list precisely because they are pinned constants with no principal/secret material. **Disclosure caveat (review):** `version`/`git_sha` on a public scrape aid CVE-targeting — **accepted with rationale** under the network-ACL posture (§2.5.1); operators who cannot ACL `/metrics` should gate `astrid_build_info` behind auth.
- Register once in `install_recorder()`: `describe_gauge!` + `gauge!("astrid_build_info", …).set(1.0)`.
- Usage: `<series> * on() group_left(version, git_sha) astrid_build_info`.

---

## 6. Phased implementation roadmap

Each phase is a coherent shippable slice. Effort is rough (engineer-days). RFC-gated work is sequenced behind its RFC.

### 6.0 Cross-cutting Phase-0 pre-reqs (review)

- **Per-crate `metrics`-facade dependency matrix.** The facade is today only in `astrid-gateway`. Add `metrics = { workspace = true }` to each emitting crate: `astrid-kernel`, `astrid-capsule`, `astrid-audit`, `astrid-capabilities`, `astrid-crypto`, `astrid-mcp`, `astrid-storage`, `astrid-vfs`, `astrid-approval`, `astrid-hooks`, and (decision) `astrid-events`. **Layering decision for `astrid-events`:** it is the lowest-level event crate (deps: types/core/tokio/serde/tracing). Either accept the facade there for the `EventBus::publish` counters, **or** emit `astrid_router_events_published_total` from an `astrid-kernel` caller above the bus to keep `astrid-events` facade-free. Recommend the latter where feasible; the per-subscriber lag counter and `ring_capacity`/`backlog` gauges do need a small kernel-internal change in `astrid-events` regardless (thread the `subscriber` tag through `EventReceiver::new`).
- **New tag methods (security-critical):** `AuditAction::action_class()` and `ChainIssue::kind()` in `astrid-audit`; forbid `description()`/`summary()`/`Display` in metric code.
- **New collapse functions:** `model_static`, `mcp_server_static`, `topic_namespace_static`, `interface_static`, `capsule_name_static` — each with a closed allowlist + `other`, each added to the §2.5.3 CI allowlist.

### Phase 0 — Foundation & the idle-CPU/connection-count incident (P0, no RFC)

- **Process collector + build-info** (§5): wire `metrics-process` into `install_recorder()` + the `/metrics` handler; add `astrid_build_info` + the git-sha/rustc build script. *(~2 d)*
- **Daemon/uplink core + bus saturation** (§4.6): `active_connections`, `connections_opened_total`, `connections_closed_total`, `socket_accepts_total{result}` (incl. `quota`), `background_ticks_total{loop}`, **`ipc_receiver_lagged_total{subscriber}`**, **`ipc_messages_published_total{topic_ns}`**, **`active_streams` (P0)**. These directly diagnose the no-shutdown + idle-CPU incidents. *(~4 d)*
- **Spinning-capsule + host-egress RED** (§4.3, §4.10): `capsule_invocation_duration_seconds{outcome}`, `http_egress_requests_total`, `http_egress_duration_seconds`, `http_egress_denials_total`. *(~2 d)*
- **Revive the 3 dead gateway counters** (§4.1) with binary `result`/`outcome` labels; add `requests_in_flight{method}`; promote `upstream_request_duration_seconds` to P0. *(~2 d)*
- **Kernel router core** (§4.2): `events_published_total{event_kind}` (56), `events_dropped_total{reason}`, `interceptor_invocations_total{outcome}`, `kernel_requests_total{method,outcome}`, **`interceptor_duration_seconds` (P0)**. *(~3 d)*
- **Capsule lifecycle/sandbox core** (§4.3): `capsule_loaded{state}`, `capsule_load_duration_seconds`, `capsule_load_total`, `capsule_traps_total`. *(~3 d)*
- **Security boundaries P0 + per-stage RED** (§4.4–4.8): `capability_static_checks_total` (scope_class), `capability_static_denials_total`, `capabilities_token_verify_total`, **`capabilities_authorize_duration_seconds` (P0)**, `approval_outcomes_total`, `audit_entries_total` (+ `action_class()`), `audit_append_duration_seconds`, `audit_store_errors_total`, `audit_chain_verify_issues_total` (+ `kind()`), `kv_operations_total`, **`kv_operation_duration_seconds` (P0)**, `vfs_operations_total` (boundary `target`), `vfs_denials_total`, `crypto_ed25519_verify_total`, `capabilities_token_mint_total`, `capabilities_token_validation_total`, `mcp_tool_calls_total{server,outcome}`, `mcp_tool_call_duration_seconds{server}`, `mcp_permission_checks_total`, **`capsule_hostcall_duration_seconds` (P0)**. *(~6 d)*
- **The CI security test** (§2.5.3): render-time allowlist invariant + deny-patterns + per-subsystem emission drivers + known-bad corpus + route-shape assertion. **Gate for the whole programme** — lands in Phase 0. *(~2 d)*

*Phase 0 total: ~30 P0 families + 7 standard series + the CI guard + pre-reqs.*

### Phase 1 — RED/USE depth, no RFC (P1)

- Gateway: `request_body_bytes`, `active_sse_streams`, `bearer_verify_total`, `redeem_rate_limited_total`.
- Router/bus: `event_receivers`, `dispatch_match_duration_seconds`, `ipc_publish_rejections_total`, **`ipc_receiver_backlog{subscriber}`** (leading saturation), `daemon_handshake_duration_seconds`.
- Sandbox: `hostcall_total`, `resource_handles`, `resource_denied_total`, `health_failed_total`.
- Capabilities/approval/crypto: `token_grants_total`, `token_revocations_total`, `approval_prompt_duration_seconds`, `capabilities_authorization_seconds` (MCP path), `crypto_ed25519_sign_total`, `audit_entry_sign_total`.
- KV/VFS: `kv_value_bytes`, `vfs_overlay_operations_total`, `vfs_open_files`.
- MCP: `servers_connected`, `server_health_status`, `server_restarts_total`, `binary_verification_failures_total`.
- Daemon: `uptime_seconds`, `active_connections_by_kind` is **NOT** here (RFC — Phase 3).
- **Hooks (host-side, no RFC):** `hooks_executions_total{hook_point,handler,outcome}`.

*~21 families, ~9 d.*

### Phase 2 — Capacity & slow-moving signals, no RFC (P2/P3)

- Gateway: `revocations_active`, `handler_panics_total` (+ `CatchPanicLayer`, §7.5), `tls_handshakes_total`, `cors_rejections_total`, `routes_registered`.
- Router/sandbox: `capsule_queue_depth`, `hostcall_semaphore_available_permits`, `instance_memory_limit_bytes` (histogram), `restart_total`, `install_total`, `lifecycle_hook_duration_seconds`.
- Capabilities: `deferred_reasons_total`, `deferred_queue_depth`, `live_tokens`, `delegation_grants_total`, `expired_tokens_cleaned_total`.
- KV: `store_bytes`, `scopes` (new astrid-storage backend probes).
- Crypto: `bearer_mint_total`, `runtime_key_generated_total`.
- Daemon: `shutdown_state`, `idle_seconds`, `ipc_ring_capacity`.
- MCP: `tools_registered`, `server_starts_total`.
- **Hooks (host-side, no RFC):** `hooks_execution_duration_seconds{hook_point,handler}`.

*~16 families, ~6 d.*

### Phase 3 — Capsule-telemetry layer (#705, separate effort)

Out of scope for this doc. The capsule-domain metrics (LLM cost/tokens, tool dispatch, per-principal usage) are owned by #705 (`astrid-capsule-metrics`), which aggregates existing bus events in capsule-space. Nothing in the roadmap above is blocked on it, and vice versa. `astrid_daemon_active_connections_by_kind` (needs an `uplink_kind` field on the connect/disconnect IPC payload) is the one host-side family that needs a small contract change — tracked with #705's contract discussion, not shipped here.

---

## 7. Open questions / RFC items

1. **The capsule-telemetry layer is #705, not an RFC here.** The withdrawn `astrid.v1.metrics.emit` push transport is replaced by #705's bus-subscription capsule. Design input (namespacing, anti-spoofing, consumer-side cardinality enforcement, collapse functions) is contributed there. No standalone metrics RFC is opened.
2. **Uplink-kind on the wire (for `active_connections_by_kind`).** The Connect/Disconnect IPC payloads carry only principal. Adding an allowlist-validated `uplink_kind` (collapse unknown → `other` at the kernel boundary) is a small contract change tracked with #705's discussion — out of scope for the host-ops layer.
3. **Recorder ownership + facade fan-out.** Lift `install_recorder()` into a dedicated `astrid-metrics` crate once the third non-gateway subsystem emits (Phase 0 crosses that line). **Independent of the per-crate facade dependency (§6.0):** lifting the recorder does not remove the need for each emitting crate to depend on `metrics`. Resolve the `astrid-events` layering question (facade in the bus vs emit from an `astrid-kernel` caller above it).
4. **`metrics-process` dependency.** ~~New `2.x` build-tree dependency; confirm macOS support.~~ **Resolved** — `2.4.3` added as a workspace dep; macOS confirmed (the foundation slice's tests pass on Darwin via `libproc`); per-scrape `collect()` is pull-based with no background thread (§5.1).
5. **CatchPanicLayer behavioural change.** `handler_panics_total` (§4.1) requires `tower_http::catch_panic::CatchPanicLayer`, changing how panics surface (connection reset → counted 500). Review as a behavioural change, not a pure metric emit (arguably a net improvement on the documented `.expect()`/poisoned-lock fail-stop points).
6. **Live WASM memory usage (#639).** `instance_memory_limit_bytes` exposes the StoreLimits *cap* (now a histogram), not current usage. A true USE utilization fraction needs a custom `ResourceLimiter` to surface resident pages — tracked as #639; this doc ships the denominator only. The new `capsule_invocation_duration_seconds` (§4.3) covers the *CPU*-spin case without fuel metering.
7. **No module/compile cache, no fuel metering.** A compile-cache-hit metric or per-invocation fuel histogram (the `_units` bucket guidance in §2.7 anticipates this) requires new code — out of scope until the cache and a fuel-accounting decision land.
8. **OpenMetrics + exemplars — explicitly deferred.** Out of scope under the unauthenticated-`/metrics` posture (an exemplar trace id is an identifier, violating §2.5). **Revisit trigger:** if `/metrics` moves behind authentication, reopen with a bounded, id-free exemplar schema reviewed against §2.5.
9. **Naming collision (`astrid_router_*` kernel vs `astrid_capsule_router_*` guest).** The prefix disambiguates mechanically but invites dashboard misreads. Decide whether to rename the kernel-side dispatcher/bus family to `astrid_bus_*`/`astrid_dispatch_*`. Low effort, prevents a recurring misread.
10. **Fail-secure cross-series alert (no new metric).** Document the rule: alert when `rate(astrid_audit_entries_total)==0 AND rate(astrid_gateway_requests_total)>0` ("audit died silently"). Buildable from P0; named here as a deliverable.

---

## 8. Review resolutions

This section records what changed from the draft and why, and explicitly notes the findings declined.

**Post-review reframing (overlap with #705).** After the adversarial review, an issue-overlap check found that **#705 (`astrid-capsule-metrics`) already owns the capsule-telemetry layer** via bus subscription, and that the contract surface the withdrawn push-transport stood on (host-ABI rfcs#22, manifest rfcs#26, capsule-interface rfcs#20, interceptor rfcs#23) is all unmerged and in flux. Consequently this doc was **rescoped to the host-internal layer only** (§0): the §3 transport architecture and §4.9 capsule-domain catalog were withdrawn and contributed to #705 as design input; no standalone metrics RFC is opened. The §1–§2 conventions/security/cardinality, the §4.1–4.8 + §4.10 host-ops catalog, §5 process/build-info, and the §6 roadmap (Phases 0–2) are unchanged and remain in scope. The findings below are the original workflow review and are retained for the rationale they carry; references to the withdrawn §3/§4.9 are historical.

**Applied — Architecture/feasibility (verified in-tree):**
- **Bridge wire-variant fixed (blocker).** Guests cannot produce `IpcPayload::RawJson`; untagged JSON deserializes to `IpcPayload::Custom` (verified via `from_json_value` and the in-tree test `from_json_value_unknown_tag_becomes_custom`, ipc.rs:276/754). The §3.5 bridge now matches `Custom`, and the RFC requires a guest→bridge round-trip test. Without this the entire §4.9 emitted nothing.
- **"Zero plumbing" reframed (major).** Added §6.0 per-crate `metrics`-facade dependency matrix (~11 crates; facade is today only in `astrid-gateway`), with the `astrid-events` layering decision called out.
- **Hooks re-classified (major).** `astrid-hooks` is host-side (depends on `wasmtime`, verified `Cargo.toml`); both hooks families moved out of RFC/Phase 3 into Phase 1/2, instrumented at `executor.rs` with the `handler` serde tag available there.
- **Crate attribution + line refs corrected (minor).** §4.6 `astrid_daemon_*` sites attributed to `astrid-kernel`; socket-accept sites to `host/net/unix_listener.rs`; `spawn_idle_monitor` corrected to `lib.rs:1103`.
- **`ipc_publish_fanout` dropped (minor).** A point-in-time level question → the existing `astrid_router_event_receivers` gauge, per N4 honesty.
- **`MetricsPolicy` kernel→gateway table hand-off** documented (the gateway lacks the `capsule_uuid→manifest` table at runtime).

**Applied — Cardinality:**
- **MCP `tool` label dropped entirely (blocker):** unbounded third-party text + reconnaissance leak. `server` collapses via `mcp_server_static`.
- **OpenAI `model` collapse mandated (blocker):** `model_static(resolved_model)` at the emit site (verified `resolved_model` is free env/caller text, lib.rs:130; `lookup` accepts anything).
- **`topic_ns` collapse function specified (blocker):** `topic_namespace_static` (no such function existed in-tree).
- **Computed time-series budget added (major):** §2.4.1 with histogram bucket expansion; gateway corrected to 23×6×4; the gateway *duration* histogram reduced (drop `method`, 3-class `status`) to clear the 1,500 redesign trigger; catalog-wide 25k ceiling.
- **`scope`→`scope_class` enum (major):** literal scope token forbidden; `astrid_capability_static_checks_total` now ≤81.
- **Grows-with-install + third-party-advertised label classes added (major):** §2.4.2/§2.4.3 with collapse + alarm + dead-series policy; `instance_memory_limit_bytes` re-typed to an unlabelled histogram.
- **Bridge name-count cap added (major):** third budget (max distinct metric names/namespace).
- **`event_kind` corrected to 56** (verified 54 + `ipc` + `custom`); `http_fetch` `method` collapse mandated capsule-side.

**Applied — Security:**
- **`AuditAction::action_class()` + `ChainIssue::kind()` as Phase-0 pre-reqs (blocker):** verified `AuditAction` (entry.rs:190) has only `description()`/`summary()` (both leak); metric code forbidden from calling them.
- **Auth-failure `{reason}` dropped to binary `{result}` (major):** the reason data does not exist without new classification, and a reason breakdown is a validity oracle on an unauthenticated endpoint.
- **VFS `target` source corrected (major):** derive from `astrid-vfs/src/boundary.rs`, not the audit-topic const the draft cited.
- **CI guard rewritten (major):** §2.5.3 render-time whole-body allowlist invariant + positive deny-patterns (UUID/email/IP/base64url/path/hex) + per-subsystem emission drivers + known-bad corpus + route-shape assertion.
- **N7 numeric-value deny + endpoint threat model + minimum-aggregation + runtime kill-switch added.**
- **SDK-as-nudge clarified (minor):** the bridge is the sole trust boundary; peer uid/gid/pid forbidden as labels.

**Applied — Completeness (RED/USE):**
- **Per-subscriber bus-lag attribution (blocker):** `astrid_ipc_receiver_lagged_total{subscriber}` (verified single shared 1024-slot broadcast ring with filter-after-dequeue) — the smoking gun for the no-shutdown bug.
- **Host-side egress RED added, P0, no RFC (blocker):** new §4.10 at `host/http.rs` so "provider slow vs erroring" is answerable in Phase 0.
- **`ipc_messages_published_total` promoted to P0 (major); ring backlog/capacity gauges added (major).**
- **Socket-accept site corrected + `quota` outcome added + handshake-duration histogram added (major).**
- **Per-stage RED P0 promotions (major):** upstream RTT, interceptor exec, hostcall, KV op, kernel-router authorize duration, `active_streams`.
- **Spinning-under-epoch-limit gauge (major):** `capsule_invocation_duration_seconds`.
- **Fail-secure audit cross-series alert documented (§7.10).**

**Declined:**
- **Cardinality auditor: "drop `io` from the `interface` set; the WIT world has 11 interfaces."** *Declined — the finding is factually wrong.* `astrid-sys/src/lib.rs:68–82` imports `astrid:io/{error,poll,streams}@1.0.0` alongside the 11 named host interfaces; `io` **is** in the frozen WIT world. The draft's 12-with-`io` was correct. `interface_static` is pinned to the verified 13-value set (`io` + 11 + `other`). (The reviewer correctly flagged the need to pin the set from the authoritative WIT and add `other`; that part is applied.)
- **Security auditor: gate/disable `astrid_build_info` by default.** *Declined as a default; accepted as operator guidance.* Build provenance is operationally load-bearing (it explained a past capsule mismatch) and carries only pinned constants on the deny-list. The CVE-fingerprinting risk is real but is mitigated by the network-ACL posture; §2.5.1 documents it as accept-with-rationale and advises auth-gating only where `/metrics` cannot be ACL'd, rather than degrading the default observability.
- **Completeness critic: add a separate metrics IPC quota budget.** *Declined.* §3.2 keeps metrics on the shared per-principal IPC quota and mitigates starvation via SDK `emit_batch` coalescing; a second quota tunable adds configuration surface for marginal benefit and is noted explicitly rather than implemented.
