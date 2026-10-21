//! Parse tests for AOS host-plugin `mcp serve` argv.
use super::{Cli, Commands, McpCommands};
use clap::Parser;

#[test]
fn mcp_http_accepts_explicit_endpoint_credentials_and_workspace() {
    let parsed = Cli::try_parse_from([
        "astrid",
        "--principal",
        "codex-code",
        "mcp",
        "http",
        "--listen",
        "127.0.0.1:9000",
        "--token-file",
        "/tmp/token",
        "--workspace",
        "/tmp/project",
    ])
    .unwrap();
    let Some(Commands::Mcp {
        command:
            McpCommands::Http {
                listen,
                token_file,
                workspace,
            },
    }) = parsed.command
    else {
        panic!("expected MCP HTTP command");
    };
    assert_eq!(listen, Some("127.0.0.1:9000".parse().unwrap()));
    assert_eq!(token_file.unwrap(), std::path::PathBuf::from("/tmp/token"));
    assert_eq!(workspace.unwrap(), std::path::PathBuf::from("/tmp/project"));
}

#[test]
fn mcp_serve_accepts_aos_host_plugin_flags() {
    let parsed = Cli::try_parse_from([
        "astrid",
        "--principal",
        "codex-code",
        "mcp",
        "serve",
        "--workspace",
        "/tmp/project",
        "--request-timeout",
        "1d5m",
    ])
    .expect("AOS plugin argv must parse");
    match parsed.command {
        Some(Commands::Mcp {
            command:
                McpCommands::Serve {
                    workspace,
                    request_timeout,
                },
        }) => {
            assert_eq!(
                workspace.as_deref(),
                Some(std::path::Path::new("/tmp/project"))
            );
            assert_eq!(request_timeout.as_deref(), Some("1d5m"));
        },
        _ => panic!("expected mcp serve"),
    }
}

#[test]
fn mcp_attach_accepts_principal_after_subcommand() {
    let parsed = Cli::try_parse_from([
        "astrid",
        "mcp",
        "attach",
        "--principal",
        "codex-code",
        "--workspace",
        "/tmp/project",
    ])
    .expect("attach argv must parse");
    assert_eq!(parsed.principal.as_deref(), Some("codex-code"));
    match parsed.command {
        Some(Commands::Mcp {
            command: McpCommands::Attach { workspace },
        }) => assert_eq!(
            workspace.as_deref(),
            Some(std::path::Path::new("/tmp/project"))
        ),
        _ => panic!("expected mcp attach"),
    }
}

#[test]
fn mcp_ready_defaults_to_hook_format() {
    let parsed = Cli::try_parse_from(["astrid", "mcp", "ready"]).expect("ready argv must parse");
    match parsed.command {
        Some(Commands::Mcp {
            command: McpCommands::Ready { format },
        }) => assert_eq!(format, "hook"),
        _ => panic!("expected mcp ready"),
    }
}

#[test]
fn mcp_ready_accepts_explicit_hook_format_after_subcommand() {
    let parsed = Cli::try_parse_from(["astrid", "mcp", "ready", "--format", "hook"])
        .expect("ready format argv must parse");
    match parsed.command {
        Some(Commands::Mcp {
            command: McpCommands::Ready { format },
        }) => assert_eq!(format, "hook"),
        _ => panic!("expected mcp ready"),
    }
}
