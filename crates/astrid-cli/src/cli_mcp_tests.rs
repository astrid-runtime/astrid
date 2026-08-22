//! Parse tests for AOS host-plugin `mcp serve` argv.
use super::{Cli, Commands, McpCommands};
use clap::Parser;

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
