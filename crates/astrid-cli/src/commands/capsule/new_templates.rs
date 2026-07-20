//! File-content generators for `astrid capsule new`.
//!
//! Each function returns the exact text written into the scaffolded project.
//! Kept separate from the command logic in `new.rs` so the (necessarily large)
//! template strings — including the self-contained `AUTHORING.md` — stay in one
//! focused module.

/// `.cargo/config.toml` — the getrandom footgun fix. Without the custom
/// backend cfg, `getrandom` (pulled transitively by uuid v4 and `HashMap`'s
/// `RandomState`) fails to link on `wasm32-unknown-unknown`.
pub(super) fn cargo_config_toml() -> String {
    r#"[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = ["--cfg=getrandom_backend=\"custom\""]
"#
    .to_string()
}

/// `rust-toolchain.toml` — pins the toolchain and wasm target so the project
/// builds identically everywhere.
pub(super) fn rust_toolchain_toml() -> String {
    r#"[toolchain]
channel = "1.95.0"
targets = ["wasm32-unknown-unknown"]
components = ["rustfmt", "clippy"]
"#
    .to_string()
}

/// `Cargo.toml` — `cdylib` for the WASM component, edition 2024, and a
/// size-optimised release profile.
pub(super) fn cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
publish = false
description = "An Astrid tool capsule."

[lib]
crate-type = ["cdylib"]

[dependencies]
astrid-sdk = {{ version = "0.7", features = ["derive"] }}
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
"#
    )
}

/// `Capsule.toml` — manifest with the `[[component]]` block and the mandatory
/// tool-bus ACL. The `[publish]`/`[subscribe]` tables are the only IPC-intent
/// surface; a `[subscribe]` entry's `handler` binds the topic to the matching
/// `#[astrid::tool]` / `tool_describe` export.
pub(super) fn capsule_toml(name: &str, crate_ident: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
description = "An Astrid tool capsule."
astrid-version = ">=0.7.0"

[[component]]
id = "{name}"
file = "{crate_ident}.wasm"
type = "executable"

# Host capabilities this capsule needs. The hello example needs none. Grant
# only what your tools actually use — capabilities are enforced by the kernel.
#
# [capabilities]
# fs_read  = ["home://"]
# fs_write = ["home://output/"]

# Publish ACL: the [publish] keys are the only IPC-publish declaration.
[publish]
"tool.v1.execute.*.result" = {{ wit = "@unicity-astrid/wit/types/tool-call-result" }}
"tool.v1.response.describe.*" = {{ wit = "@unicity-astrid/wit/tool/describe-response" }}

# Interceptor bindings: a [subscribe] entry's `handler` binds the topic to an
# `#[astrid::tool]` export. The keys also serve as the subscribe ACL.
[subscribe]
"tool.v1.execute.hello" = {{ wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_hello" }}
"tool.v1.request.describe" = {{ wit = "@unicity-astrid/wit/tool/describe-request", handler = "tool_describe" }}
"#
    )
}

/// `src/lib.rs` — a working `hello` tool example.
pub(super) fn lib_rs() -> String {
    r#"#![deny(unsafe_code)]
use astrid_sdk::prelude::*;
use astrid_sdk::schemars;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct HelloArgs {
    /// Who to greet.
    pub name: String,
}

#[derive(Default)]
pub struct Capsule;

#[capsule]
impl Capsule {
    /// Greet someone by name. Replace this with your own tool.
    #[astrid::tool("hello")]
    pub fn hello(&self, args: HelloArgs) -> Result<String, SysError> {
        Ok(format!("Hello, {}!", args.name.trim()))
    }
}
"#
    .to_string()
}

/// `README.md` for the generated project: build/install/iterate commands and
/// pointers to runtime authoring guidance and the Astrid Book.
pub(super) fn readme_md(name: &str) -> String {
    format!(
        r#"# {name}

An [Astrid](https://github.com/astrid-runtime/astrid) tool capsule, scaffolded
by `astrid capsule new`.

A capsule is a WebAssembly component that runs in the Astrid kernel's sandbox
and exposes typed tools to the agent. This one ships a single `hello` tool —
replace it with your own.

## Layout

| File | Purpose |
|------|---------|
| `AUTHORING.md` | **Start here.** The self-contained guide to writing this capsule. |
| `src/lib.rs` | Tool implementations (`#[astrid::tool]` exports). |
| `Capsule.toml` | Manifest: component, capabilities, and the tool-bus ACL. |
| `Cargo.toml` | Crate config — `cdylib` + size-optimised release profile. |
| `.cargo/config.toml` | Targets `wasm32-unknown-unknown` and sets the `getrandom` custom backend (required — without it, uuid/`HashMap` fail to link). |
| `rust-toolchain.toml` | Pins the toolchain and wasm target. |

The `wit/` directory is generated at build time; do not commit it.

## Build

```sh
astrid capsule build
```

This compiles to `wasm32-unknown-unknown` and packages a `.capsule` archive
under `dist/`.

## Install

```sh
astrid capsule install ./dist/{name}.capsule
```

## Iterate

1. Edit `src/lib.rs` — add a tool with `#[astrid::tool("my_tool")]`.
2. Declare it in `Capsule.toml` under `[subscribe]`:
   ```toml
   "tool.v1.execute.my_tool" = {{ wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_my_tool" }}
   ```
3. Rebuild and reinstall.

## Learn more

- **`AUTHORING.md`** in this project is the from-zero guide to writing this
  capsule — the tool pattern, the manifest, the capability/ACL model, and the
  dev loop. Read it before you touch `src/lib.rs`.
- An agent runtime may expose additional authoring guidance over IPC or through
  its host plugin; discover that user-space surface through the runtime rather
  than assuming the guidance is part of the kernel manifest.
- The [Astrid Book](https://github.com/astrid-runtime/astrid) covers the
  capsule model, the IPC bus, capabilities, and the WIT contracts in depth.
"#
    )
}

/// `AUTHORING.md` — the self-contained, from-zero guide that ships inside the
/// generated project. A capsule author (human or a fresh agent) reading only
/// this file should be able to write, build, install, and call a capsule
/// without reading Astrid's own source.
///
/// Built with `.replace()` rather than `format!` so the large body — full of
/// literal `{` from Rust and TOML — does not need every brace escaped.
pub(super) fn authoring_md(name: &str, crate_ident: &str) -> String {
    AUTHORING_TEMPLATE
        .replace("__NAME__", name)
        .replace("__CRATE_IDENT__", crate_ident)
}

/// Body of the generated `AUTHORING.md`, with `__NAME__` / `__CRATE_IDENT__`
/// placeholders filled in by [`authoring_md`].
const AUTHORING_TEMPLATE: &str = r#"# Authoring `__NAME__`

This is a complete, from-zero guide to writing this Astrid capsule. Read it
before editing anything; you should not need Astrid's own source to be
productive.

## What a capsule is

A **capsule** is a WebAssembly component (`wasm32-unknown-unknown`) that runs
inside the Astrid kernel's sandbox. It cannot make raw syscalls or touch the
network/filesystem directly — every effect goes through the audited
`astrid:*` host surface exposed by `astrid-sdk`, and every effect is gated by a
capability you declare in `Capsule.toml`. A **tool capsule** (this one) exposes
one or more typed *tools* that the agent's LLM can call.

Communication is exclusively over the kernel's IPC event bus: the capsule
*subscribes* to a tool-execution topic and *publishes* a result. There are no
function imports from the kernel and no shared memory — just typed messages on
named topics, and an ACL (declared in the manifest) that says which topics this
capsule may touch.

## The tool pattern

A tool is a method on your capsule struct, inside a `#[capsule]` impl block,
annotated with `#[astrid::tool("name")]`:

```rust
use astrid_sdk::prelude::*;
use astrid_sdk::schemars;
use serde::Deserialize;

// The argument type. It must derive `Deserialize` (the kernel hands you the
// call arguments as JSON) and `schemars::JsonSchema` (the SDK turns this into
// the tool's input schema so the LLM knows how to call it). Doc comments on
// fields become the field descriptions the model sees.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct GreetArgs {
    /// Who to greet.
    pub name: String,
}

#[derive(Default)]
pub struct Capsule;

#[capsule]
impl Capsule {
    /// Greet someone by name. This doc comment becomes the tool description
    /// shown to the LLM.
    #[astrid::tool("greet")]
    pub fn greet(&self, args: GreetArgs) -> Result<String, SysError> {
        Ok(format!("Hello, {}!", args.name.trim()))
    }
}
```

Rules that matter:

- The impl block carries `#[capsule]`. That macro generates the WASM component
  glue (the `Guest` impl and the component export) for you — you never write it
  by hand.
- Each tool method takes `&self` and exactly one argument struct, and returns
  `Result<T, SysError>` where `T` serializes to JSON (a `String`, or any
  `serde::Serialize` type). Return `Err(SysError…)` to signal a failure to the
  agent.
- The macro auto-generates a `tool_describe` export that reports every tool's
  JSON schema. You do **not** write a describe handler — declaring the tools is
  enough.
- A tool that mutates state (writes a file, sends a request that changes
  something) should be marked `#[astrid::tool("name", mutable)]`. A pure /
  read-only tool omits it. The `mutable` flag is what lets the runtime treat the
  call as side-effecting (e.g. for approval gating).

### Wiring a new tool

Adding a tool is two edits — the code above, plus a `[subscribe]` line in
`Capsule.toml` that routes the tool's bus topic to the generated handler. For a
tool named `greet`, the synthetic handler name is `tool_execute_greet`:

```toml
[subscribe]
"tool.v1.execute.greet" = { wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_greet" }
```

The handler name is always `tool_execute_<tool_name>`. Forgetting the
`[subscribe]` line means the kernel never routes the call to you — the tool is
defined but unreachable.

## `Capsule.toml` — the manifest and the ACL

The manifest is **untrusted input** the kernel parses and enforces. It has four
parts that matter to a tool capsule.

### `[package]` and `[[component]]`

```toml
[package]
name = "__NAME__"
version = "0.1.0"
description = "An Astrid tool capsule."
astrid-version = ">=0.7.0"

[[component]]
id = "__NAME__"
file = "__CRATE_IDENT__.wasm"
type = "executable"
```

`file` must be the **crate name with hyphens turned into underscores**, plus
`.wasm` — that is exactly what `cargo` names the `cdylib` output. Get this wrong
and the installer cannot find the built artifact.

### `[capabilities]` — what the kernel will let you do

Every host effect is gated here, and the model is **fail-closed**: if a
capability field is absent, the kernel treats it as an *empty allowlist*, i.e.
deny-all — not "unconfigured, allow through". Grant only what your tools
actually use. The capability keys a tool capsule cares about:

| Key | Grants |
|-----|--------|
| `net` | Outbound HTTP to a hostname allowlist, e.g. `net = ["api.example.com"]` (or `["*"]` for any). |
| `fs_read` | VFS read paths, e.g. `fs_read = ["home://"]`. |
| `fs_write` | VFS write paths, e.g. `fs_write = ["home://output/"]`. |
| `net_connect` | Outbound TCP `host:port` allowlist. |
| `host_process` | Host-process command allowlist. |
| `identity` | Identity operations (`resolve` / `link` / `admin`). |

The `hello` example in `src/lib.rs` needs **no** capabilities, so the
`[capabilities]` table is commented out. Uncomment and fill it the moment a tool
needs an effect — and expect a hard denial at runtime if you forget.

### `[publish]` / `[subscribe]` — the IPC ACL

These two tables are the *only* declaration of which bus topics the capsule may
touch, and they double as the ACL the kernel enforces. Empty tables = the
capsule can neither send nor receive anything (fail closed). A tool capsule
needs exactly this shape:

```toml
[publish]
"tool.v1.execute.*.result"    = { wit = "@unicity-astrid/wit/types/tool-call-result" }
"tool.v1.response.describe.*" = { wit = "@unicity-astrid/wit/tool/describe-response" }

[subscribe]
"tool.v1.execute.greet"    = { wit = "@unicity-astrid/wit/types/tool-call", handler = "tool_execute_greet" }
"tool.v1.request.describe" = { wit = "@unicity-astrid/wit/tool/describe-request", handler = "tool_describe" }
```

- A `[subscribe]` entry's `handler` binds the topic to a generated WASM export.
  `tool.v1.execute.greet` → `tool_execute_greet`; the describe fan-out request
  → the auto-generated `tool_describe`.
- The `[publish]` entries authorize sending the per-tool result
  (`tool.v1.execute.<name>.result`) and the schema response. The trailing `*`
  in a publish/subscribe ACL key is a **subtree** wildcard — `tool.v1.execute.*.result`
  authorizes the result topic for any tool name.
- The `wit = "@unicity-astrid/wit/..."` reference names the typed payload schema
  for that topic, resolved from the shared SDK contracts at build time. Use the
  references shown above verbatim for the tool-bus topics.

The tool-bus topic conventions, for reference:

| Topic | Meaning |
|-------|---------|
| `tool.v1.execute.<name>` | The kernel dispatches a call of tool `<name>` to you (subscribe). |
| `tool.v1.execute.<name>.result` | You publish the tool's result here. |
| `tool.v1.request.describe` | Schema fan-out request (subscribe; handled by `tool_describe`). |
| `tool.v1.response.describe.*` | You publish your schema response here. |

## The getrandom footgun (already handled)

This scaffold already writes the fix, so you do not have to — but know why it is
there. On `wasm32-unknown-unknown`, the `getrandom` crate (pulled in
transitively by `uuid` v4 and `HashMap`'s random seeding) **refuses to link**
without an explicit backend. `.cargo/config.toml` sets it:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg=getrandom_backend=\"custom\""]
```

`astrid-sdk` provides the custom backend symbol (it routes to the kernel's
audited CSPRNG). If you ever see an opaque link error mentioning `getrandom`
when building a capsule, a missing or mangled version of this cfg is the cause.
Do not remove it.

## WIT / interfaces — just enough

The bus payloads are typed by WIT records. As a tool author you only deal with
four, all referenced from your manifest (you never hand-write their
definitions):

- `tool-call` — the incoming call (tool name + JSON arguments).
- `tool-call-result` — the result you publish back.
- `describe-request` / `describe-response` — the schema fan-out the SDK handles
  for you via `tool_describe`.

The `wit/` directory is **generated at build time** and embedded in the
`.capsule` archive — do not hand-write it and do not commit it.

## The dev loop: build → install → call

```sh
# 1. Build and package. `astrid capsule build` reads .cargo/config.toml for the
#    target, compiles to wasm32-unknown-unknown, stages the wit/, and packs a
#    .capsule archive under dist/. (A plain `cargo build` produces only the raw
#    .wasm — use `astrid capsule build` to get an installable archive.)
astrid capsule build

# 2. Install into the running daemon.
astrid capsule install ./dist/__NAME__.capsule

# 3. The tools are now discoverable. Once installed, the capsule's tools are
#    described to the agent automatically (via tool_describe), so the LLM can
#    call them. Iterate: edit, rebuild, reinstall.
```

That is the whole loop. Edit `src/lib.rs`, declare each tool's `[subscribe]`
line, grant the capabilities the tool needs, rebuild, reinstall.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_config_has_getrandom_backend() {
        let cfg = cargo_config_toml();
        assert!(
            cfg.contains(r#"getrandom_backend=\"custom\""#),
            "getrandom custom backend cfg is mandatory for wasm linking"
        );
        assert!(cfg.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn cargo_toml_uses_crate_name_and_cdylib() {
        let toml = cargo_toml("my-tool");
        assert!(toml.contains(r#"name = "my-tool""#));
        assert!(toml.contains(r#"crate-type = ["cdylib"]"#));
        assert!(toml.contains(r#"edition = "2024""#));
        assert!(toml.contains("panic = \"abort\""));
        // Must parse as TOML.
        toml::from_str::<toml::Value>(&toml).expect("Cargo.toml must parse");
    }

    #[test]
    fn capsule_toml_wasm_file_uses_underscored_ident() {
        // The component `file` must be the crate ident (hyphens → underscores)
        // plus `.wasm`, matching cargo's cdylib output name.
        let manifest = capsule_toml("my-tool", "my_tool");
        assert!(
            manifest.contains(r#"file = "my_tool.wasm""#),
            "wasm filename must use the underscored crate ident"
        );
        assert!(manifest.contains(r#"id = "my-tool""#));
    }

    #[test]
    fn capsule_toml_parses_and_has_tool_acl() {
        let manifest = capsule_toml("hello-cap", "hello_cap");
        let value: toml::Value = toml::from_str(&manifest).expect("Capsule.toml must parse");

        // Package block.
        assert_eq!(value["package"]["name"].as_str(), Some("hello-cap"));
        assert_eq!(value["package"]["version"].as_str(), Some("0.1.0"));

        // Component block.
        let component = &value["component"][0];
        assert_eq!(component["id"].as_str(), Some("hello-cap"));
        assert_eq!(component["type"].as_str(), Some("executable"));

        // Tool-bus ACL: the hello tool + describe must be subscribed with
        // their handlers, and results/describe responses publishable.
        let subscribe = value["subscribe"].as_table().expect("subscribe table");
        let hello = subscribe["tool.v1.execute.hello"]
            .as_table()
            .expect("hello subscribe entry");
        assert_eq!(hello["handler"].as_str(), Some("tool_execute_hello"));
        let describe = subscribe["tool.v1.request.describe"]
            .as_table()
            .expect("describe subscribe entry");
        assert_eq!(describe["handler"].as_str(), Some("tool_describe"));

        let publish = value["publish"].as_table().expect("publish table");
        assert!(publish.contains_key("tool.v1.execute.*.result"));
        assert!(publish.contains_key("tool.v1.response.describe.*"));
    }

    #[test]
    fn lib_rs_has_hello_tool() {
        let src = lib_rs();
        assert!(src.contains(r#"#[astrid::tool("hello")]"#));
        assert!(src.contains("pub fn hello"));
        assert!(src.contains("#[capsule]"));
    }

    #[test]
    fn authoring_md_substitutes_name_and_ident() {
        let doc = authoring_md("my-tool", "my_tool");
        // Placeholders must all be substituted.
        assert!(
            !doc.contains("__NAME__"),
            "name placeholder left unresolved"
        );
        assert!(
            !doc.contains("__CRATE_IDENT__"),
            "crate-ident placeholder left unresolved"
        );
        // Capsule name and wasm artifact name appear.
        assert!(doc.contains("# Authoring `my-tool`"));
        assert!(doc.contains("my_tool.wasm"));
        assert!(doc.contains("./dist/my-tool.capsule"));
        // The load-bearing guidance is present.
        assert!(
            doc.contains("getrandom"),
            "must explain the getrandom footgun"
        );
        assert!(doc.contains("fail-closed") || doc.contains("fail closed"));
        assert!(doc.contains("#[astrid::tool"));
        assert!(doc.contains("tool_execute_"));
    }
}
