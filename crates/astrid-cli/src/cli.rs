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
    logs::LogsArgs, ps::PsArgs, quota::QuotaCommand, run::RunArgs, secret::SecretCommand,
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

    /// Non-interactive prompt. Sends the prompt, prints the response, and exits.
    /// Forces headless mode (no TUI). Stdin is appended to the prompt if piped.
    #[arg(short, long)]
    pub prompt: Option<String>,

    /// Auto-approve all tool approval requests in headless mode (autonomous/yolo mode).
    /// Without this flag, headless mode auto-denies approvals.
    #[arg(short = 'y', long = "yes", alias = "yolo", alias = "autonomous")]
    pub auto_approve: bool,

    /// Resume or create a named session for multi-turn headless conversations.
    /// Use the same ID across multiple -p calls to maintain context.
    /// If omitted, a fresh session is created each time.
    #[arg(long = "session")]
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

    /// Print version information.
    Version(VersionArgs),

    /// Generate shell completion scripts.
    Completions(CompletionsArgs),

    /// Update Astrid to the latest release.
    Update,

    /// Update Astrid to the latest release (legacy — use `astrid update`).
    #[command(hide = true)]
    SelfUpdate,
}

#[derive(Subcommand)]
pub(crate) enum CapsuleCommands {
    /// Install a capsule from a local path or registry
    Install {
        /// Capsule source (local path or package name)
        source: String,
        /// Install to workspace instead of user-level
        #[arg(long)]
        workspace: bool,
        /// Install for a specific agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
        /// Install for every agent in this group (deferred — needs
        /// per-principal install IPC).
        #[arg(short, long, hide = true)]
        group: Option<String>,
    },
    /// Update an installed capsule (or all capsules) from its original source
    Update {
        /// Capsule name to update (omit to update all)
        target: Option<String>,
        /// Update workspace capsules instead of user-level
        #[arg(long)]
        workspace: bool,
        /// Update for a specific agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
        /// Update for every agent in this group (deferred).
        #[arg(short, long, hide = true)]
        group: Option<String>,
    },
    /// List all installed capsules with capability metadata
    List {
        /// Show full provides/requires details
        #[arg(short, long)]
        verbose: bool,
        /// List for a specific agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
        /// List for every agent in this group (deferred).
        #[arg(short, long, hide = true)]
        group: Option<String>,
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
        /// Remove for a specific agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
        /// Remove for every agent in this group (deferred).
        #[arg(short, long, hide = true)]
        group: Option<String>,
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
}

/// Admin commands for managing the content-addressed WIT store.
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
