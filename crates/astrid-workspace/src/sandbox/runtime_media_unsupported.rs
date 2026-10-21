use std::path::PathBuf;

use super::{ProcessSandboxConfig, SandboxPrefix};

impl SandboxPrefix {
    /// Build the unsupported-host command without descriptor binds.
    #[must_use]
    pub fn into_command(self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        command
    }
}

impl ProcessSandboxConfig {
    /// Retain the protected-home declaration on unsupported hosts, which
    /// reject required native sandbox launches elsewhere.
    #[must_use]
    pub fn with_protected_runtime_home(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.hidden_paths.push(path.clone());
        self.protected_runtime_home = Some(path);
        self
    }
}
