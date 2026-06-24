# LLM model selection

Astrid routes every prompt to whichever LLM model the current principal has
chosen. The choice is stored per-principal by the registry capsule, survives
daemon restarts, and can be changed at any time without restarting the daemon
or reinstalling a capsule.

This document covers four topics:

1. [Picking a model at runtime](#picking-a-model-at-runtime) -- the `astrid models` commands
2. [Provider discovery](#provider-discovery) -- where the model list comes from
3. [Install-time onboarding](#install-time-onboarding) -- what `astrid init` walks you through
4. [When no model is selected](#when-no-model-is-selected) -- the error you see and how to fix it

> **Running a local LLM?** The SSRF airlock blocks runtime egress to loopback and
> private-network addresses by default. See
> [Local LLM endpoints and the SSRF airlock](#local-llm-endpoints-and-the-ssrf-airlock)
> for the operator config that lifts the block for specific endpoints.

## Picking a model at runtime

The `models` verb is provided by the registry capsule. It is reachable through
two equivalent paths:

```sh
astrid models <subcommand> [args]          # bare shorthand
astrid capsule models <subcommand> [args]  # canonical capsule-verb form
```

Both invoke exactly the same handler over the capsule IPC bus. The bare form
resolves to the capsule verb because `models` is not a built-in `astrid`
top-level subcommand -- the external-subcommand catch-all in the CLI dispatches
any unrecognised word to the daemon's command registry.

### List available models

```sh
astrid models list
astrid models list --json
```

Without `--json`, the output is a human-readable table with one line per
model. The active model for the current principal is marked with `*`:

```
* openai:gpt-5.5       OpenAI GPT-5.5
  openai:gpt-5.4       OpenAI GPT-5.4
  openai:o3            OpenAI o3
```

With `--json`, each entry is a full JSON object carrying capability metadata:

```json
[
  {
    "id": "openai:gpt-5.5",
    "description": "OpenAI GPT-5.5",
    "request_topic": "llm.v1.request.generate.openai",
    "stream_topic": "llm.v1.stream.openai",
    "capabilities": ["text", "tools", "vision", "structured_output", "reasoning"],
    "context_window": 1050000,
    "max_output_tokens": 128000
  }
]
```

### Show the active model

```sh
astrid models current
astrid models current --json
```

Without `--json`: prints the canonical model id (e.g. `openai:gpt-5.5`), or
`none` if nothing is selected.

With `--json`: prints `{ "active": <full entry object> }`, or
`{ "active": null }` when nothing is selected.

### Set the active model

```sh
astrid models set <id>
```

`<id>` is resolved in order:

1. **Exact canonical match** -- if your input exactly equals a canonical
   `<capsule>:<model>` id (e.g. `openai:gpt-5.5`), it binds immediately.
2. **Bare model name** -- if your input uniquely matches the model portion of
   exactly one entry, it binds (e.g. `gpt-5.5` when only the `openai` capsule
   is installed).
3. **Qualified pass** -- if the bare pass is ambiguous and your input contains
   a colon, it is split on the first colon into `<capsule>:<model>` to
   disambiguate.

If the bare name matches more than one provider, the error tells you which
qualified ids to choose from:

```
ambiguous model; candidates: openai:gpt-5.4, openai-compat:gpt-5.4
```

Pass the qualified form to disambiguate:

```sh
astrid models set openai:gpt-5.4
astrid models set openai-compat:gpt-5.4
```

**Ollama note.** Ollama model names embed a colon (e.g. `llama3.3:70b`). These
work as bare ids because the resolver splits only on the FIRST colon -- the bare
pass sees `llama3.3:70b` as a single bare model name when it is uniquely served
by one provider. If two providers expose the same Ollama model, use the fully
qualified form: `ollama:llama3.3:70b`.

On success the command prints:

```
active model set to openai:gpt-5.5
```

The selection is persisted immediately in the registry capsule's per-principal
KV and takes effect on the next prompt.

### Clear the active model

```sh
astrid models unset
```

Clears the selection. The next prompt fails with the no-model error (see
[When no model is selected](#when-no-model-is-selected)) until you run
`astrid models set` again.

### Per-principal scope

Model selection is per-principal. Each principal's selection is stored
independently in the registry capsule's KV, scoped under that principal's
home directory. Changing the active model as `default` does not affect what
another principal (e.g. `claude-code`) is using, and vice versa.

If you connect as a non-default principal and no model has been selected for
that principal yet, the registry runs a discovery pass and auto-selects a
sensible default (the first-discovered capsule's default-hint model) so the
first prompt is not blocked.

### Machine-readable output

Any `models` subcommand accepts `--json` to emit JSON instead of human-readable
text. This is useful for scripts and dashboards:

```sh
# One-liner: print the currently selected model id
astrid models current --json | jq -r '.active.id // "none"'

# List all available models as a JSON array
astrid models list --json
```

Exit code is 0 on success, 1 on any error (unknown model, ambiguous input, etc.).

## Provider discovery

The model list is not static. When `astrid models list` runs (or when the
daemon boots), the registry capsule publishes a `llm.v1.request.describe`
broadcast and drains responses from every installed LLM provider capsule for a
500 ms window. Each provider responds with a list of `ProviderEntry` objects.

**One entry per model.** Each provider emits one entry per model it can serve.
The entry's `id` is the bare model name (e.g. `gpt-5.5`); the registry stamps
the canonical form (`openai:gpt-5.5`) using the provider's authenticated
capsule id. The entry includes:

- `request_topic` -- the IPC topic the provider subscribes to for generate requests
- `capabilities` -- what the model supports (`text`, `tools`, `vision`, `structured_output`, `reasoning`)
- `context_window` and `max_output_tokens`

Anti-shadowing: a provider's entry is only accepted when its self-reported
`request_topic` suffix authenticates against the kernel-stamped source id
(UUIDv5 of the capsule package name). A capsule cannot emit entries for a
provider it does not own.

### openai capsule

The `astrid-capsule-openai` capsule targets OpenAI's Responses API
(`POST /v1/responses`). It advertises models as follows:

- At describe time, it calls `GET {base_url}/v1/models` with the configured
  bearer (the `api_key` env field).
- Each returned id is enriched from a hardcoded capability catalog: exact match
  first, then longest-prefix match for dated snapshots
  (e.g. `gpt-5.4-2026-03-05` resolves to the `gpt-5.4` catalog row). Unknown
  ids get conservative defaults (`context_window: 128000`, `max_output_tokens:
  16384`, no vision/reasoning/structured-output).
- The configured `model` env field is always `entry[0]` in the response -- it
  is hoisted to the front (or prepended if the live list does not include it),
  so the registry's auto-select picks the operator's intended default.
- If the live query fails (missing key, network error, non-200 response), the
  capsule falls back to the full hardcoded catalog -- the same models you see
  in `astrid models list` on an offline install.

The default model env is `gpt-5.5` (overridable via
`astrid capsule config astrid-capsule-openai`).

### openai-compat capsule

The `astrid-capsule-openai-compat` capsule talks to any OpenAI-compatible HTTP
server (LM Studio, vLLM, llama.cpp, a remote OpenAI-compatible API) via
`POST /v1/chat/completions`. It uses the same discovery pattern:

- Calls `GET {base_url}/v1/models` with the configured bearer at describe time.
- Returns the live list enriched where possible. For local servers that expose
  no capability info, entries get conservative defaults; the operator can
  override `context_window` and `max_output_tokens` via
  `astrid capsule config astrid-capsule-openai-compat`.

Because the openai-compat capsule connects to an arbitrary endpoint, model ids
can be anything the server returns -- including names with embedded colons
(e.g. `llama3.3:70b`).

### Local LLM endpoints and the SSRF airlock

The `astrid:http` host capability runs all capsule outbound HTTP through an SSRF
airlock. Before every request, the airlock resolves the target hostname and
rejects it if the resolved address falls within any of the following ranges:

- Loopback: `127.0.0.0/8`, `::1`
- Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.0.0/16`, `fe80::/10`

This is on by default and cannot be widened from inside a capsule.

**Consequence for a local LLM server.** If you point the openai-compat capsule
at a server running on the same machine or on a LAN box -- LM Studio on
`127.0.0.1:1234`, Ollama on `127.0.0.1:11434`, llama.cpp, or a box at
`192.168.x.x` -- the airlock blocks both the describe call (`GET /v1/models`)
and every generate request at runtime. The capsule's model list comes back empty
and every prompt fails. A remote or public `base_url` (e.g. `api.openai.com` or
a cloud-hosted OpenAI-compatible endpoint) is unaffected.

**Install-time picker vs. runtime.** The onboarding step that fetches
`/v1/models` to build the model selection menu runs natively in the installer
process, not inside the WASM sandbox and not through the airlock. This means the
install-time model picker works fine against a local endpoint: you can select a
model, the install succeeds, and the config is written -- but every subsequent
runtime prompt fails because the capsule's HTTP is blocked. The gap between a
successful install and failing prompts is intentional (the installer needs to
reach local endpoints to enumerate models), but it can be confusing. If you see
an empty model list or prompt errors after configuring a local server, the
airlock is the most likely cause.

**Operator exemption.** To let the openai-compat capsule reach specific local
endpoints at runtime, an operator adds a `[security.capsule_local_egress]`
table to `config.toml`. This is an operator-only setting: a capsule's own
`Capsule.toml` cannot set it, and a project or workspace config layer cannot
widen it either.

```toml
[security.capsule_local_egress]
# host:port (or host:*) endpoints this capsule may reach even though they
# resolve to a local address.
"astrid-capsule-openai-compat" = ["127.0.0.1:1234", "192.168.1.50:11434"]
```

The exemption is scoped to the listed `host:port` pairs. It lifts the airlock
only for those entries -- it does not widen the capsule's `net` allowlist (which
is already `*` for openai-compat) or grant any other capability.

Wildcard port: `"127.0.0.1:*"` exempts all ports on that host. Prefer listing
exact ports to minimise exposure.

## Install-time onboarding

`astrid init` (and `astrid distro install <distro>`) walks you through LLM
provider setup as part of the distro install flow.

### Provider multi-select

LLM provider capsules declare `group = "llm"` in the `Distro.toml`. The
installer presents them as a multi-select list:

```
Which LLM providers do you want to set up?
  [x] OpenAI (astrid-capsule-openai)
  [ ] OpenAI-compatible (astrid-capsule-openai-compat)
```

Select as many as you want. Each selected provider is then onboarded in
sequence.

### Per-provider configuration

For each selected provider, the installer prompts for credentials and a default
model:

```
This capsule requires configuration:
  Enter the OpenAI API base URL [https://api.openai.com]:
  Enter your OpenAI API key (secret, input hidden): sk-...
```

After credentials are collected, the installer fetches `GET {base_url}/v1/models`
with the bearer you just entered to build a live numbered menu of models:

```
Default model to select:
  1: gpt-5.5
  2: gpt-5.4
  3: gpt-5.4-mini
  ...
Select [1-N]: 
```

The configured default is pre-selected (item 1). If the endpoint cannot be
reached during install, the installer falls back to a free-text entry prompt
for the model id.

> **Local server users:** the install-time fetch above runs natively and is not
> subject to the SSRF airlock, so onboarding succeeds even for a loopback or
> LAN endpoint. Runtime requests from the capsule are blocked by the airlock
> until you add an operator exemption. See
> [Local LLM endpoints and the SSRF airlock](#local-llm-endpoints-and-the-ssrf-airlock).

The mechanism behind this is the `options_from` field in the capsule's
`[env]` manifest:

```toml
[env]
model = { type = "select", request = "Default model to select",
          default = "gpt-5.5",
          options_from = { http = "{base_url}/v1/models",
                           bearer = "{api_key}",
                           select = "data[].id",
                           after = ["base_url", "api_key"] } }
```

The installer fetches client-side, attaches the bearer only to the configured
`base_url` host, and caps the response at 5 MB.

### What is configured

The install flow writes per-capsule env config to
`~/.astrid/home/<principal>/.config/env/<capsule-id>.env.json` with 0600
permissions. These values are read by the capsule at runtime via `env::var`.
`api_key` fields are written as secrets and never logged.

After install the registry picks up the new provider at the next
`astrid.v1.capsules_loaded` broadcast (or at the next `astrid models list`
call, which re-runs discovery).

## When no model is selected

If no LLM provider is configured, or if you have run `astrid models unset`
and not re-selected a model, any prompt fails with:

```
No LLM model is selected. Run `astrid models` to choose one,
or install and configure an LLM provider.
```

The react loop generates this error when the active LLM topic resolves to
nothing -- it never fabricates a default model to try. Fix it with:

```sh
# Show what is available (runs discovery)
astrid models list

# Pick one
astrid models set openai:gpt-5.5

# Or install and configure a provider if none is listed
astrid capsule install @unicity-astrid/capsule-openai
```

If `astrid models list` returns "No LLM models available", no provider capsule
is installed or reachable. Check `astrid ps` to confirm a provider capsule is
loaded and `astrid capsule list` to see what is installed.

## See also

- [Unified config schema](config.md) -- `config.toml` reference, including
  the capsule env config overlay mechanism.
- [Generating a gateway API client](gateway-client.md) -- HTTP access to the
  agent prompt endpoint that drives LLM turns.
- `astrid capsule config <capsule-id>` -- view or edit a provider's env
  configuration (API key, base URL, default model) without reinstalling.
- `astrid doctor` -- system health check that reports whether the installed
  capsule set can serve an agent chat turn.
