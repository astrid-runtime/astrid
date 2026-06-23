//! `astrid capsule build` — compile + package.
//!
//! The actual work (cargo compile → component wrap → `.capsule` pack) runs in
//! the standalone `astrid-build` companion binary; this is a thin wrapper that
//! invokes it. The build does **not** instantiate the component or bake a
//! `tools.json` — a capsule's tool surface is discovered at load time by the
//! kernel (it probes each loaded capsule's `tool_describe`), so no rebuild or
//! baked artifact is needed for tools to reach a consumer.

use std::process::ExitCode;

use anyhow::Result;

use crate::bootstrap;

/// Run `astrid capsule build` via the standalone build companion.
pub(crate) fn run(
    path: Option<&str>,
    output: Option<&str>,
    project_type: Option<&str>,
    from_mcp_json: Option<&str>,
) -> Result<ExitCode> {
    bootstrap::run_build_companion(path, output, project_type, from_mcp_json)
}
