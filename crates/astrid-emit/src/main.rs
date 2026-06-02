//! `astrid-emit` binary entry point.
//!
//! Delegates to the shared [`astrid_emit::run`] library function so the
//! same logic is reachable from tests and from the CLI-bundled
//! `astrid-emit` binary (`crates/astrid-cli/src/emit.rs`).

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    astrid_emit::run().await
}
