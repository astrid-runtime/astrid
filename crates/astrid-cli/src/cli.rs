//! Top-level clap definitions for the `astrid` binary.
//!
//! Lives in its own module so [`crate::main`] stays under the 1000-line
//! CI threshold and the dispatch logic isn't tangled with structural
//! definitions. Subcommand variants here are wired to handler modules
//! in [`crate::commands`] by [`crate::dispatch`].

use clap::{Parser, Subcommand};

use crate::commands::{
    agent::AgentCommand, audit::AuditArgs, budget::BudgetCommand, caps::CapsCommand,
    capsule::config::ConfigArgs as CapsuleConfigArgs, capsule::show::ShowArgs as CapsuleShowArgs,
    completions::CompletionsArgs, doctor::DoctorArgs, gc::GcArgs, group::GroupCommand,
    invite::InviteCommand, keypair::KeypairCommand, logs::LogsArgs, pair_device::PairDeviceCommand,
    ps::PsArgs, quota::QuotaCommand, run::RunArgs, secret::SecretCommand, setup::SetupArgs,
    top::TopArgs, trust::TrustCommand, version::VersionArgs, voucher::VoucherCommand, who::WhoArgs,
};

/// Astrid - Secure Agent Runtime
#[derive(Parser)]
#[command(name = "astrid")]
#[command(author, version, about, long_about = None)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format: pretty (default), json, or stream-json
    #[arg(long, global = true, default_value = "pretty")]
    pub format: String,

    /// Principal this CLI process acts as. Stamped on every IPC message
    /// the process sends, so the kernel scopes session, KV, home,
    /// secrets, and quotas to this identity. Falls back to the
    /// `ASTRID_PRINCIPAL` env var, then to `default`. Must be 1-64
    /// chars of `[a-zA-Z0-9_-]`. The uplink proxy pins the first
    /// principal it sees on a connection and drops any message stamped
    /// with a different one, so this is fixed for the whole process.
    #[arg(long, global = true, env = "ASTRID_PRINCIPAL")]
    pub principal: Option<String>,

    /// Non-interactive prompt. Sends the prompt, prints the response, and exits.
    /// Forces headless mode (no TUI). Stdin is appended to the prompt if piped.
    #[arg(short, long)]
    pub prompt: Option<String>,

    /// Auto-approve all tool approval requests in headless mode (autonomous/yolo mode).
    /// Without this flag, headless mode auto-denies approvals.
    #[arg(short = 'y', long = "yes", alias = "yolo", alias = "autonomous")]
    pub auto_approve: bool,

    /// Resume an existing session by UUID, or create/resume a named
    /// session by string. UUIDs (the form `--print-session` reports)
    /// are used as-is so an operator can copy the printed id straight
    /// into the next `-p` call; any other string is hashed into a
    /// stable UUID v5 so the same name always maps to the same
    /// session. Omit the flag for a fresh random session per call.
    #[arg(long = "session", value_name = "ID_OR_NAME")]
    pub session_name: Option<String>,

    /// Print the session ID to stderr after the response, for use in scripts.
    #[arg(long = "print-session")]
    pub print_session: bool,

    /// Render the TUI to stdout as text snapshots instead of an interactive terminal.
    /// Each significant event (input, response, tool call, approval) produces a frame.
    /// Requires --prompt. Useful for automated testing and CI.
    #[arg(long = "snapshot-tui")]
    pub snapshot_tui: bool,

    /// Terminal width for --snapshot-tui rendering (default: 120).
    #[arg(long = "tui-width", default_value = "120")]
    pub tui_width: u16,

    /// Terminal height for --snapshot-tui rendering (default: 40).
    #[arg(long = "tui-height", default_value = "40")]
    pub tui_height: u16,

    /// Print the absolute path to the co-installed `astrid-emit`
    /// companion binary and exit. Used by hook-bridge installers (sage)
    /// to wire `settings.local.json` commands at the right path without
    /// guessing the install layout. Handled before banner/config so it
    /// works on a half-configured host.
    #[arg(long = "emit-path")]
    pub emit_path: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "clap subcommand enum, constructed once per process"
)]
pub(crate) enum Commands {
    /// Start an interactive chat session
    Chat {
        /// Resume a specific session
        #[arg(short, long)]
        session: Option<String>,
    },

    /// One-shot non-interactive prompt execution.
    Run(RunArgs),

    /// Manage agent identities, group membership, and active context.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    /// Manage capability groups (admin, agent, restricted, custom).
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },

    /// View and manage capability grants and revokes.
    Caps {
        #[command(subcommand)]
        command: CapsCommand,
    },

    /// View and adjust per-principal resource quotas.
    Quota {
        #[command(subcommand)]
        command: QuotaCommand,
    },

    /// Mint invite tokens so new principals can self-enroll through the
    /// HTTP gateway (or via `astrid invite redeem`).
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },

    /// Manage local ed25519 keypairs used for invite redemption.
    Keypair {
        #[command(subcommand)]
        command: KeypairCommand,
    },

    /// Pair an additional device with an existing principal: issue scoped
    /// pair-tokens, list paired devices, and revoke them.
    PairDevice {
        #[command(subcommand)]
        command: PairDeviceCommand,
    },

    /// Store and inspect capsule env configuration (API keys, base URLs).
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },

    /// Capability vouchers (deferred — see #656).
    Voucher {
        #[command(subcommand)]
        command: VoucherCommand,
    },

    /// Cross-host trust relationships (deferred — see #656/#658).
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },

    /// Audit trail inspection (deferred — see #675).
    Audit(AuditArgs),

    /// Per-agent budget allocation and accounting (deferred — see #653/#656).
    Budget {
        #[command(subcommand)]
        command: BudgetCommand,
    },

    /// Manage chat sessions
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },

    /// Manage capsules
    Capsule {
        #[command(subcommand)]
        command: CapsuleCommands,
    },

    /// Expose Astrid capsule tools over the Model Context Protocol.
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },

    /// Manage the system distro (curated capsule bundle).
    Distro {
        #[command(subcommand)]
        command: DistroCommands,
    },

    /// Build and package a Capsule (legacy — prefer `astrid capsule build`).
    #[command(hide = true)]
    Build {
        /// Optional path to the project directory (defaults to current directory)
        path: Option<String>,
        /// Output directory for the packaged `.capsule` archive
        #[arg(short, long)]
        output: Option<String>,
        /// Explicitly define the project type (e.g., 'mcp' for legacy host servers)
        #[arg(short, long, name = "type")]
        project_type: Option<String>,
        /// Import a legacy `mcp.json` to auto-convert
        #[arg(long)]
        from_mcp_json: Option<String>,
    },

    /// Initialize a workspace and install a distro
    Init {
        /// Distro to install (name, @org/repo, or path to Distro.toml)
        #[arg(long, default_value = "astralis")]
        distro: String,
    },

    /// View resolved configuration, edit it in `$EDITOR`, or print paths.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Manage the content-addressed WIT store (legacy — use `astrid gc`).
    #[command(hide = true)]
    Wit {
        #[command(subcommand)]
        command: WitCommands,
    },

    /// Garbage collect content-addressed stores (WIT, orphaned binaries).
    Gc(GcArgs),

    /// Start the Astrid daemon in persistent mode (detached, no TUI)
    Start,

    /// Show daemon status (PID, uptime, connected clients, loaded capsules)
    Status,

    /// Stop a running Astrid daemon
    Stop,

    /// Restart the Astrid daemon (graceful stop + start).
    Restart,

    /// Tail kernel or per-capsule logs.
    Logs(LogsArgs),

    /// Show the loaded capsules and their lifecycle state.
    Ps(PsArgs),

    /// Live resource monitor (one-shot snapshot until telemetry lands).
    Top(TopArgs),

    /// Show connected clients and their agent attribution.
    Who(WhoArgs),

    /// Run a system health check.
    Doctor(DoctorArgs),

    /// One-time host configuration (`AppArmor` profile for unprivileged
    /// user namespaces on Ubuntu 23.10+, etc.).
    Setup(SetupArgs),

    /// Print version information.
    Version(VersionArgs),

    /// Generate shell completion scripts.
    Completions(CompletionsArgs),

    /// Update Astrid to the latest release (`self-update` is a legacy alias).
    #[command(alias = "self-update")]
    Update(UpdateArgs),
}

/// Arguments for `astrid update`.
#[derive(Debug, clap::Args)]
pub(crate) struct UpdateArgs {
    /// Install without the interactive confirmation prompt.
    #[arg(short = 'y', long)]
    pub(crate) yes: bool,

    /// Report whether an update is available without installing it.
    #[arg(long)]
    pub(crate) check: bool,

    /// Override the release source as `owner/repo` — rehearse the update flow
    /// against a fork or pre-release. (Env: `ASTRID_UPDATE_REPO`; API base:
    /// `ASTRID_UPDATE_API`.)
    #[arg(long, value_name = "OWNER/REPO")]
    pub(crate) source: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum CapsuleCommands {
    /// Scaffold a new, first-try-compiling capsule project.
    New(crate::commands::capsule::new::NewArgs),
    /// Install a capsule from a local path or registry.
    ///
    /// Capsules are deployed once and shared across every principal —
    /// per-invocation isolation comes from the kernel's caller-context
    /// scoping (KV namespace, home, secrets, log, quotas), not from
    /// duplicating the WASM. There is intentionally no per-agent
    /// install: an agent says "I use capsule X" and the kernel routes
    /// their invocations into the already-loaded instance.
    Install {
        /// Capsule source (local path or package name)
        source: String,
        /// Install only this capsule from a multi-capsule release (default: install all)
        #[arg(long)]
        capsule: Option<String>,
        /// Install to workspace instead of user-level
        #[arg(long)]
        workspace: bool,
    },
    /// Update an installed capsule (or all capsules) from its original source
    Update {
        /// Capsule name to update (omit to update all)
        target: Option<String>,
        /// Update workspace capsules instead of user-level
        #[arg(long)]
        workspace: bool,
    },
    /// List all installed capsules with capability metadata
    List {
        /// Show full provides/requires details
        #[arg(short, long)]
        verbose: bool,
    },
    /// Remove an installed capsule
    Remove {
        /// Capsule name to remove
        name: String,
        /// Remove from workspace instead of user-level
        #[arg(long)]
        workspace: bool,
        /// Force removal even if other capsules depend on it
        #[arg(long)]
        force: bool,
        /// Also delete saved configuration (API keys, env vars)
        #[arg(long)]
        purge: bool,
    },
    /// Show the capsule imports/exports dependency tree
    Tree,
    /// Alias for `tree` (deprecated)
    #[command(hide = true)]
    Deps,
    /// Build and package a Capsule.
    Build {
        /// Optional path to the project directory (defaults to current directory)
        path: Option<String>,
        /// Output directory for the packaged `.capsule` archive
        #[arg(short, long)]
        output: Option<String>,
        /// Explicitly define the project type
        #[arg(short, long, name = "type")]
        project_type: Option<String>,
        /// Import a legacy `mcp.json` to auto-convert
        #[arg(long)]
        from_mcp_json: Option<String>,
    },
    /// View or edit a capsule's env configuration without reinstalling.
    Config(CapsuleConfigArgs),
    /// Show manifest, interfaces, source for an installed capsule.
    Show(CapsuleShowArgs),
    /// Run a capsule-provided command, explicitly naming the provider
    /// (needed when two capsules provide the same verb).
    Run {
        /// The capsule that provides the verb.
        provider: String,
        /// The capsule-declared CLI verb.
        verb: String,
        /// Arguments forwarded verbatim to the capsule.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Capsule-provided verbs: `astrid capsule <verb> [args...]`.
    ///
    /// The named variants above (`install`, `update`, `list`, ...)
    /// structurally shadow capsule verbs: clap matches a declared variant
    /// before falling through to this external-subcommand catch-all, so a
    /// capsule can never override a built-in verb (manifest parsing also
    /// rejects reserved names — defence in depth). Any unrecognised verb
    /// lands here and is resolved against the daemon's command registry.
    #[command(external_subcommand)]
    External(Vec<String>),
}

/// Model Context Protocol surfaces — expose Astrid's capsule tools to an
/// external MCP client (e.g. `claude -p`, Codex).
#[derive(Subcommand)]
pub(crate) enum McpCommands {
    /// Run a Model Context Protocol stdio server that bridges the
    /// daemon's capsule tool surface to a generic MCP client.
    ///
    /// Long-running: serves on stdin/stdout until the client closes the
    /// stream (EOF) or the process is killed. Stdout carries the MCP
    /// JSON-RPC protocol only — all diagnostics go to stderr.
    Serve {
        /// Principal to act as for this MCP server. Overrides the
        /// process-wide principal (the global `--principal` /
        /// `ASTRID_PRINCIPAL`); when omitted, falls back to it (which
        /// itself defaults to the active CLI agent, then `default`).
        /// Stamped onto every IPC message so the kernel scopes tool
        /// execution to this identity.
        #[arg(long)]
        principal: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum WitCommands {
    /// Garbage-collect unreferenced WIT blobs (legacy — use `astrid gc`).
    Gc {
        /// Delete unreferenced blobs. Without this flag, only reports them.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Print the resolved configuration with source annotations.
    Show {
        /// Output format: `pretty` / `toml` (default) or `json`.
        #[arg(long, default_value = "toml")]
        format: String,
        /// Restrict the output to a config section.
        #[arg(long, value_name = "SECTION")]
        section: Option<String>,
    },
    /// Open the runtime configuration file in `$EDITOR`.
    Edit,
    /// List all candidate config-file locations and which exist.
    Path,
}

#[derive(Subcommand)]
pub(crate) enum SessionCommands {
    /// List all sessions
    List,
    /// Delete a session
    Delete {
        /// The session ID to delete
        id: String,
    },
    /// Show information about a session.
    Show {
        /// The session ID to query
        id: String,
    },
    /// Show information about a session (deprecated alias for `show`).
    #[command(hide = true)]
    Info {
        /// The session ID to query
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum DistroCommands {
    /// Apply a distro to the active or specified agent.
    Apply {
        /// Distro identifier (name, `@org/repo`, or path).
        name: Option<String>,
        /// Target agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
    },
    /// Show the currently-applied distro and its lockfile.
    Show {
        /// Target agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
    },
    /// Update to the latest distro version.
    Update {
        /// Target agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::CapsuleCommands;
    use clap::Subcommand;

    /// Every built-in `astrid capsule` subcommand name must appear in
    /// [`astrid_core::kernel_api::RESERVED_CAPSULE_VERBS`]. The reserved
    /// list is what manifest parsing uses to reject a `kind = "cli"`
    /// command that would shadow a built-in verb; if the two drift, a
    /// capsule could declare a verb that clap silently shadows (or, worse,
    /// the reserved list could block a name that is not actually a
    /// built-in). This test pins them together.
    ///
    /// The catch-all `External` external-subcommand variant has no fixed
    /// clap name (it matches arbitrary verbs), so it is excluded.
    #[test]
    fn reserved_verbs_match_clap_subcommands() {
        let cmd = CapsuleCommands::augment_subcommands(clap::Command::new("capsule"));
        let clap_names: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();

        for name in &clap_names {
            assert!(
                astrid_core::kernel_api::RESERVED_CAPSULE_VERBS.contains(&name.as_str()),
                "built-in `astrid capsule {name}` is missing from RESERVED_CAPSULE_VERBS \
                 (add it so a capsule cannot shadow it)"
            );
        }

        // `help` is injected by clap, not a declared variant, but is a real
        // reserved word — assert it is covered too.
        assert!(astrid_core::kernel_api::RESERVED_CAPSULE_VERBS.contains(&"help"));
    }
}
