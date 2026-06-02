//! Bundled `astrid-emit` binary — installed alongside `astrid` via
//! `cargo install astrid`.
//!
//! Delegates to the shared [`astrid_emit::run`] library function. This
//! is identical to the standalone `astrid-emit` binary but co-installed
//! with the CLI so `find_companion_binary("astrid-emit")` (and the
//! `astrid --emit-path` discovery flag) always resolve it.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    astrid_emit::run().await
}
