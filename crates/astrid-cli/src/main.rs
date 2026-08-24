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
mod principal;
mod repl;
/// The socket client for interacting with the Kernel.
pub mod socket_client;
mod theme;
mod tui;
mod value_formatter;
mod workspace_layout;

#[tokio::main]
async fn main() -> ExitCode {
    let parsed = match cli::Cli::try_parse() {
        Ok(parsed) => parsed,
        Err(error) => {
            let hook_invocation = raw_args_include_hook();
            let usage_error = error.use_stderr();
            let exit_code = error.exit_code();
            if hook_invocation && usage_error {
                // Host hook runners must never interpret clap's usage exit 2
                // as a policy denial. Keep the protocol fail-open even when
                // the invocation itself is malformed.
                astrid_emit::write_continue_line();
            }
            let _ = error.print();
            if hook_invocation && usage_error {
                return commands::hook::failure_exit_code();
            }
            return ExitCode::from(u8::try_from(exit_code.clamp(0, 255)).unwrap_or(1));
        },
    };
    let hook_invocation = matches!(&parsed.command, Some(cli::Commands::Hook(_)));
    if !hook_invocation {
        if workspace_layout::initialize(parsed.workspace_state_dir.clone()).is_err() {
            eprintln!("error: workspace layout was already initialized");
            return ExitCode::from(1);
        }
        bootstrap::init_logging(&parsed);
    }

    // Resolve and validate the process-wide principal ONCE, before any
    // socket connection. Every IPC message the process sends stamps
    // this identity (the native uplink binds one verified principal per
    // connection). Invalid input exits with a clear error
    // naming the constraint.
    match principal::resolve_process(parsed.principal.as_deref()) {
        Ok(p) => principal::set(p),
        Err(e) => {
            if hook_invocation {
                astrid_emit::write_continue_line();
            }
            eprintln!("{}", theme::Theme::error(&format!("error: {e:#}")));
            return if hook_invocation {
                commands::hook::failure_exit_code()
            } else {
                ExitCode::from(1)
            };
        },
    }

    match dispatch::dispatch(parsed).await {
        Ok(code) => code,
        Err(e) => {
            if hook_invocation {
                astrid_emit::write_continue_line();
            }
            eprintln!("{}", theme::Theme::error(&format!("error: {e:#}")));
            if hook_invocation {
                commands::hook::failure_exit_code()
            } else {
                ExitCode::from(1)
            }
        },
    }
}

/// Return whether the raw process arguments contain the hidden hook command.
///
/// Clap validates the complete command tree before it can construct a
/// [`cli::Cli`], so malformed hook arguments are the one path where the
/// parsed command is unavailable. An exact-token check is deliberately used:
/// values such as `--session hook` are not a command and must retain normal
/// clap exit semantics.
fn raw_args_include_hook() -> bool {
    std::env::args().skip(1).any(|arg| arg == "hook")
}
