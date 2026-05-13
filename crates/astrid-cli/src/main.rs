//! Astrid CLI - Secure Agent Runtime
//!
//! A production-grade secure agent runtime with proper security from day one.
//! The CLI is a thin client: it connects to the kernel (auto-starting if needed),
//! creates/resumes sessions, and renders streaming events.
//!
//! Subcommands follow a noun-verb structure modelled after `gh` and `fly`:
//! `astrid agent`, `astrid capsule`, `astrid quota`, etc. System verbs
//! (`status`, `start`, `stop`, `ps`, `top`) stay as bare verbs for speed.
//! `astrid` with no subcommand drops the operator into an interactive
//! agent session — the unchanged self-hosting path.
//!
//! This file is the entry point. The clap definitions live in
//! [`cli`] and the routing table in [`dispatch`]; this module is just
//! [`tokio::main`] plus error formatting.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![expect(
    dead_code,
    reason = "incremental development — some plumbing used by later features"
)]

use std::process::ExitCode;

use clap::Parser;

mod admin_client;
mod bootstrap;
mod cli;
mod commands;
mod context;
mod dispatch;
mod formatter;
mod repl;
/// The socket client for interacting with the Kernel.
pub mod socket_client;
mod theme;
mod tui;
mod value_formatter;

#[tokio::main]
async fn main() -> ExitCode {
    let parsed = cli::Cli::parse();
    bootstrap::init_logging(&parsed);

    match dispatch::dispatch(parsed).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}", theme::Theme::error(&format!("error: {e:#}")));
            ExitCode::from(1)
        },
    }
}
