//! Model Context Protocol command definitions.
//!
//! Keeping the MCP gateway surfaces together prevents the top-level clap
//! definitions from growing past the repository's file-size threshold while
//! preserving one command enum for dispatch.

use std::path::PathBuf;

use clap::Subcommand;

/// Model Context Protocol surfaces — expose Astrid's capsule tools to an
/// external MCP client (e.g. `claude -p`, Codex).
#[derive(Subcommand)]
pub(crate) enum McpCommands {
    /// Run a Model Context Protocol stdio server that bridges the
    /// daemon's capsule tool surface to a generic MCP client.
    ///
    /// Long-running: serves on stdin/stdout until the client closes the
    /// stream (EOF) or the process is killed. Stdout carries the MCP
    /// JSON-RPC protocol only — all diagnostics go to stderr.
    Serve {
        /// Project directory AOS host plugins pass as `$PWD`.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        /// Accepted and ignored; MCP hosts own `tool_timeout_sec`.
        #[arg(long = "request-timeout", value_name = "DURATION")]
        request_timeout: Option<String>,
    },
    /// Attach this host's stdio stream to the persistent per-user gateway.
    ///
    /// The global `--principal` option may follow this subcommand, as in
    /// `astrid mcp attach --principal codex-code --workspace "$PWD"`.
    Attach {
        /// Host project directory used as the `cwd://` root.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
    },
    /// Run the persistent per-user MCP gateway.
    Gateway,
    /// Wait for the gateway without running doctor or installation flows.
    Ready {
        /// Output format: `hook`, `pretty`, or `json`.
        #[arg(long, default_value = "hook")]
        format: String,
    },
    /// Reap orphaned long-timeout `mcp serve` processes.
    Gc,
}
