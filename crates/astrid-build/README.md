# astrid-build

[![Crates.io](https://img.shields.io/crates/v/astrid-build)](https://crates.io/crates/astrid-build)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**Capsule compilation and packaging for the Astrid OS.**

Compiles Rust and legacy MCP server projects into `.capsule` archives that the Astrid kernel can load. Typically invoked by the CLI (`astrid build`) but can be used standalone.

## Usage

### Via the CLI (typical)

```bash
# Auto-detect project type and build
astrid build

# Specify output directory
astrid build --output ./dist

# Build a specific project directory
astrid build /path/to/capsule

# Convert a legacy MCP server manifest
astrid build --from-mcp-json mcp.json
```

### Standalone

```bash
astrid-build [PATH] [OPTIONS]
```

## Flags

| Flag | Description |
|---|---|
| `[PATH]` | Project directory (defaults to current directory) |
| `-o, --output <DIR>` | Output directory for the `.capsule` archive |
| `-t, --type <TYPE>` | Explicit project type: `rust`, `mcp`, `extension` |
| `--from-mcp-json <FILE>` | Import a legacy `mcp.json` or `gemini-extension.json` to auto-convert |

## Supported project types

| Type | Detection | What happens |
|---|---|---|
| **Rust** | `Cargo.toml` + `Cargo.lock` | `cargo build --release` (the capsule's own `.cargo/config.toml` selects the target — canonical `wasm32-unknown-unknown`, with `wasm32-wasip2` accepted as a migration fallback; no `--target` is passed), extracts tool schemas from WASM, merges into `Capsule.toml`, packs archive |
| **MCP** | `mcp.json` | Converts legacy MCP server manifest to `Capsule.toml`, packs archive |
| **Extension** | `gemini-extension.json` | Same as MCP, for Gemini extension format |

## Output

A `.capsule` file — a gzipped tar archive containing:

- `Capsule.toml` — manifest with package metadata, capabilities, tool schemas
- `plugin.wasm` — the compiled WASM binary

Install the built capsule:

```bash
astrid capsule install ./my-capsule.capsule
```

## Development

```bash
cargo build -p astrid-build
cargo test -p astrid-build
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
