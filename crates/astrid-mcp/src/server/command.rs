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

struct Child<'a> {
    program: &'a std::path::Path,
    args: &'a [String],
}

struct NativeAssembler;

impl stdio_policy::Assembler<astrid_workspace::SandboxPrefix, Child<'_>, Command>
    for NativeAssembler
{
    fn wrapped(&mut self, prefix: astrid_workspace::SandboxPrefix, child: &Child<'_>) -> Command {
        let mut command = Command::from(prefix.into_command());
        command.arg(child.program).args(child.args);
        command
    }

    fn bare(&mut self, child: &Child<'_>) -> Command {
        let mut command = Command::new(child.program);
        command.args(child.args);
        command
    }
}

pub(super) fn assemble_child(
    prefix: McpResult<Option<astrid_workspace::SandboxPrefix>>,
    program: &std::path::Path,
    args: &[String],
) -> McpResult<Command> {
    stdio_policy::assemble(&mut NativeAssembler, prefix, &Child { program, args })
}
