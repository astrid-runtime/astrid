//! Adapt the configured stdio server to the native command builders.
use super::{ServerManager, build_unsandboxed_command, stdio_policy};
use crate::config::ServerConfig;
use crate::error::{McpError, McpResult};
use tokio::process::Command;

struct NativeBuilder<'a> {
    manager: &'a ServerManager,
    name: &'a str,
}

impl stdio_policy::Builder<ServerConfig, Command, McpError> for NativeBuilder<'_> {
    fn sandboxed(
        &mut self,
        program: &str,
        config: &ServerConfig,
        network: bool,
    ) -> McpResult<Command> {
        self.manager
            .build_sandboxed_command(self.name, program, config, network)
    }

    fn direct(&mut self, program: &str, config: &ServerConfig) -> Command {
        build_unsandboxed_command(self.name, program, config)
    }
}

impl ServerManager {
    pub(super) fn prepare_stdio_command(
        &self,
        name: &str,
        program: &str,
        config: &ServerConfig,
    ) -> McpResult<Command> {
        stdio_policy::prepare(
            &mut NativeBuilder {
                manager: self,
                name,
            },
            program,
            config,
            config.trusted,
            config.allow_network,
        )
    }
}
