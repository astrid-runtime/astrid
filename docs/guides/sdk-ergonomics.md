# SDK Ergonomics - "Feels Like Rust std"

The `astrid-sdk` crate is the primary interface capsule developers use to build on
Astrid OS. Its API surface should feel like an extension of the Rust standard
library: same naming conventions, same module structure expectations, no
surprises. When a Rust developer picks up `astrid-sdk` for the first time, the
answer to "where would I find X?" should be the same answer they'd give for std.

## Design Principles

1. **Mirror std module layout.** `fs`, `net`, `process`, `env`, `time` should
   exist and behave how a Rust developer expects.
2. **Typed everything.** No `Vec<u8>` handles leaking across the API boundary.
   Every opaque resource gets a named type.
3. **Zero implementation leak.** Users never import `extism_pdk`, `schemars`, or
   any other internal dependency. The SDK is the only crate in their `use` tree.
4. **One macro, one impl block.** `#[capsule]` on an `impl` block is all you
   need. Tools, commands, interceptors, cron, run loops, lifecycle hooks - all
   inside one block with `#[astrid::*]` attributes.
5. **Convention over configuration.** Name inference from function names is the
   default. Explicit names are the override.

## Module Mapping: std to astrid-sdk

| std / ecosystem    | astrid-sdk current  | astrid-sdk target          | Notes                                     |
|--------------------|---------------------|----------------------------|--------------------------------------------|
| `std::fs`          | `fs`                | `fs`                       | Rename fns to match std (see below)        |
| `std::net`         | `net`               | `net`                      | Already good - typed handles               |
| `std::process`     | `process`           | `process`                  | Already good - typed request/result        |
| `std::env`         | `sys::get_config_*` | `env`                      | Config is env vars for capsules            |
| `std::time`        | `sys::clock_ms()`   | `time`                     | Typed instants, duration support           |
| `log` crate        | `sys::log()`        | `log`                      | Level-specific functions or macros         |
| N/A (runtime)      | `sys::signal_ready`/`get_caller` | `runtime`     | Runtime introspection and signaling        |
| N/A (ipc)          | `ipc`               | `ipc`                      | Add typed SubscriptionHandle               |
| N/A (kv)           | `kv`                | `kv`                       | Already good                               |
| N/A (http)         | `http`              | `http`                     | Needs typed Request/Response eventually    |
| N/A (cron)         | `cron`              | `cron`                     | Already good                               |
| N/A (uplink)       | `uplink`            | `uplink`                   | Add typed UplinkId                         |
| N/A (hooks)        | `hooks`             | `hooks`                    | Already good                               |
| N/A (elicit)       | `elicit`            | `elicit`                   | Already good                               |
| N/A (interceptors) | `interceptors`      | `interceptors`             | Already good                               |

## Change 1: `#[astrid::run]` Inside the Capsule

### Problem

Run-loop capsules break out of the `#[capsule]` pattern into a free function
with raw Extism types:

```rust
use extism_pdk::FnResult;  // implementation leak

#[plugin_fn]                // implementation leak
pub fn run() -> FnResult<()> {
    // ...
}
```

### Solution

Add `#[astrid::run]` as a routing attribute inside the `#[capsule]` impl block:

```rust
#[capsule]
impl MyCapsule {
    #[astrid::run]
    fn run(&self) -> Result<(), SysError> {
        runtime::signal_ready()?;
        loop { /* event loop */ }
    }
}
```

The macro generates:

```rust
#[no_mangle]
pub extern "C" fn run() -> i32 {
    fn inner(_input: Vec<u8>) -> FnResult<Vec<u8>> {
        get_instance().run()?;  // stateless
        Ok(vec![])
    }
    // ... standard extism ABI wrapper
}
```

Rules:
- Only one `#[astrid::run]` per capsule.
- Signature: `fn run(&self) -> Result<(), SysError>` (no args, returns unit).
- For stateful capsules: loads state at start, does NOT auto-save (run loops are
  infinite; the capsule manages its own persistence).
- Cannot combine with `#[astrid::mutable]` (same as lifecycle hooks).

## Change 2: Split `sys` Into Purpose-Specific Modules

### `env` - Configuration (like `std::env`)

```rust
pub mod env {
    pub fn var(key: &str) -> Result<String, SysError>;       // was sys::get_config_string
    pub fn var_bytes(key: &str) -> Result<Vec<u8>, SysError>; // was sys::get_config_bytes
}
```

### `time` - Clock Access (like `std::time`)

```rust
pub mod time {
    pub fn now_ms() -> Result<u64, SysError>;  // was sys::clock_ms
}
```

### `log` - Structured Logging

```rust
pub mod log {
    pub fn debug(msg: impl AsRef<[u8]>) -> Result<(), SysError>;
    pub fn info(msg: impl AsRef<[u8]>) -> Result<(), SysError>;
    pub fn warn(msg: impl AsRef<[u8]>) -> Result<(), SysError>;
    pub fn error(msg: impl AsRef<[u8]>) -> Result<(), SysError>;
}
```

### `runtime` - OS Introspection

```rust
pub mod runtime {
    pub fn signal_ready() -> Result<(), SysError>;           // was sys::signal_ready
    pub fn caller() -> Result<CallerContext, SysError>;      // was sys::get_caller
    pub fn socket_path() -> Result<String, SysError>;        // was sys::socket_path
}
```

### Backward Compatibility

The `sys` module was removed entirely (clean break). All consumer capsules
were migrated in the same PR. No migration facade was shipped.

## Change 3: Typed Handles

### `ipc::SubscriptionHandle`

```rust
pub struct SubscriptionHandle(pub(crate) Vec<u8>);

pub fn subscribe(topic: impl AsRef<[u8]>) -> Result<SubscriptionHandle, SysError>;
pub fn unsubscribe(handle: &SubscriptionHandle) -> Result<(), SysError>;
pub fn poll_bytes(handle: &SubscriptionHandle) -> Result<Vec<u8>, SysError>;
pub fn recv_bytes(handle: &SubscriptionHandle, timeout_ms: u64) -> Result<Vec<u8>, SysError>;
```

### `uplink::UplinkId`

```rust
pub struct UplinkId(pub(crate) Vec<u8>);

pub fn register(...) -> Result<UplinkId, SysError>;
pub fn send_bytes(id: &UplinkId, ...) -> Result<Vec<u8>, SysError>;
```

## Change 4: Rename `fs` Functions to Match `std::fs`

| Current              | Proposed             | std equivalent          |
|----------------------|----------------------|-------------------------|
| `fs::read_bytes()`   | `fs::read()`         | `std::fs::read()`       |
| `fs::read_string()`  | `fs::read_to_string()` | `std::fs::read_to_string()` |
| `fs::write_bytes()`  | `fs::write()`        | `std::fs::write()`      |
| `fs::write_string()` | (removed, use write) | N/A                     |
| `fs::readdir()`      | `fs::read_dir()`     | `std::fs::read_dir()`   |
| `fs::stat()`         | `fs::metadata()`     | `std::fs::metadata()`   |
| `fs::exists()`       | `fs::exists()`       | `std::fs::exists()` (nightly) |
| `fs::mkdir()`        | `fs::create_dir()`   | `std::fs::create_dir()` |
| `fs::unlink()`       | `fs::remove_file()`  | `std::fs::remove_file()` |

## Change 5: Name Inference Convention

Tool/command/interceptor/cron names inferred from the method name:

```rust
#[astrid::tool]           // name = "list_files"
fn list_files(&self, ...) // (snake_case preserved, matching Rust convention)

#[astrid::tool("ls")]     // explicit override
fn list_files(&self, ...)
```

**Decision**: Keep snake_case as-is for inferred names. Capsule.toml and the
runtime can handle any format. Forcing kebab-case conversion would be surprising
("why doesn't my method name match the tool name?").

## Change 6: Remove Implementation Leaks

After all changes, the user's dependency graph is:

```toml
[dependencies]
astrid-sdk = "x.y"
serde = { version = "1", features = ["derive"] }
serde_json = "1"  # only if they do manual JSON work
```

They never see:
- `extism-pdk` (wrapped by SDK + macro)
- `schemars` (derived internally by `#[capsule]` macro)
- `astrid-sys` (raw FFI, SDK-internal)

The prelude becomes:

```rust
pub mod prelude {
    pub use crate::{
        SysError,
        env, fs, http, ipc, kv, log, net, process, runtime, time,
        cron, elicit, hooks, uplink,
        // interceptors: planned, on unmerged branch
    };
    #[cfg(feature = "derive")]
    pub use astrid_sdk_macros::capsule;
}
```

## The Full "After" Picture

```rust
use astrid_sdk::prelude::*;
use serde::Deserialize;

#[derive(Default)]
pub struct MyCapsule;

#[capsule]
impl MyCapsule {
    #[astrid::tool]
    fn search(&self, args: SearchArgs) -> Result<SearchResult, SysError> {
        // ...
    }

    #[astrid::interceptor]
    fn on_tool_result(&self, args: EventPayload) -> Result<serde_json::Value, SysError> {
        // ...
    }

    #[astrid::run]
    fn run(&self) -> Result<(), SysError> {
        let sub = ipc::subscribe("my.topic")?;
        runtime::signal_ready()?;
        loop {
            let envelope = ipc::recv_bytes(&sub, 5000)?;
            // process envelope
        }
    }

    #[astrid::install]
    fn install(&self) -> Result<(), SysError> {
        elicit::secret("api_key", "Your API key")?;
        Ok(())
    }
}
```

Zero extism. Zero schemars. One impl block. Feels like std.
