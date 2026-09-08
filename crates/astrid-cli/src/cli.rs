//! Top-level clap definitions for the `astrid` binary.
//!
//! Lives in its own module so [`crate::main`] stays under the 1000-line
//! CI threshold and the dispatch logic isn't tangled with structural
//! definitions. Subcommand variants here are wired to handler modules
//! in [`crate::commands`] by [`crate::dispatch`].

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands::UpdateChannel;
use crate::commands::{
    agent::AgentCommand, audit::AuditArgs, budget::BudgetCommand, caps::CapsCommand,
    capsule::config::ConfigArgs as CapsuleConfigArgs, capsule::show::ShowArgs as CapsuleShowArgs,
    completions::CompletionsArgs, doctor::DoctorArgs, gc::GcArgs, group::GroupCommand,
    hook::HookArgs, invite::InviteCommand, keypair::KeypairCommand, logs::LogsArgs,
    pair_device::PairDeviceCommand, ps::PsArgs, quota::QuotaCommand, run::RunArgs,
    secret::SecretCommand, setup::SetupArgs, storage::StorageCommand, top::TopArgs,
    trust::TrustCommand, version::VersionArgs, voucher::VoucherCommand, who::WhoArgs,
};

mod mcp;

pub(crate) use mcp::McpCommands;

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
    #[arg(id = "global-format", long = "format", default_value = "pretty")]
    pub format: String,

    /// Principal this CLI process acts as. Stamped on every IPC message
    /// the process sends, so the kernel scopes session, KV, home,
    /// secrets, and quotas to this identity. Falls back to the
    /// `ASTRID_PRINCIPAL` env var, then to `default`. Must be 1-64
    /// chars of `[a-zA-Z0-9_-]`. The native uplink cryptographically
    /// binds this principal during the connection handshake, so it is
    /// fixed for the whole process.
    #[arg(
        id = "process-principal",
        long = "principal",
        global = true,
        env = "ASTRID_PRINCIPAL"
    )]
    pub principal: Option<String>,

    /// Per-project runtime state directory name.
    #[arg(
        long,
        global = true,
        env = "ASTRID_WORKSPACE_STATE_DIR",
        default_value = astrid_core::dirs::DEFAULT_WORKSPACE_STATE_DIR
    )]
    pub workspace_state_dir: astrid_core::dirs::WorkspaceLayout,

    /// Non-interactive prompt. Sends the prompt, prints the response, and exits.
    /// Forces headless mode (no TUI). Stdin is appended to the prompt if piped.
    #[arg(short, long)]
    pub prompt: Option<String>,

    /// Unsupported approval automation in headless mode (aliases `--yolo` and
    /// `--autonomous`); rejected before headless execution.
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

    /// Inspect system audit accounting, ingestion health, and retention.
    Audit(AuditArgs),

    /// Publish one host hook through the tiny authenticated emitter client.
    #[command(hide = true)]
    Hook(HookArgs),

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
        /// Distro source to install. Required unless an embedding launcher sets
        /// `ASTRID_ENFORCED_DISTRO` (`@owner/repo`, URL, local Distro.toml, or .shuttle).
        #[arg(long)]
        distro: Option<String>,
        /// Non-interactive: accept all defaults.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Forbid all network access (offline mode).
        #[arg(long)]
        offline: bool,
        /// Allow installing unsigned distros.
        #[arg(long)]
        allow_unsigned: bool,
        /// Re-pin a changed signing key.
        #[arg(long)]
        accept_new_key: bool,
        /// Set a variable (repeatable): KEY=VALUE.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Principal whose home and capsule access this init provisions.
        /// The global `--principal` remains the authenticated operator.
        #[arg(long = "target-principal", value_name = "PRINCIPAL")]
        target_principal: Option<String>,
        /// Grant the target principal access to every capsule the distro
        /// installs (same mechanism as `agent modify --add-capsule`).
        /// A distro source must resolve before initialization runs.
        #[arg(long = "grant-capsules")]
        grant_capsules: bool,
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

    /// Start the Astrid daemon (persistent unless --ephemeral is supplied)
    Start {
        /// Exit after the last client disconnects (for automatic host startup).
        #[arg(long)]
        ephemeral: bool,
    },

    /// Show daemon status (PID, uptime, connected clients, loaded capsules)
    Status,

    /// Stop a running Astrid daemon
    Stop,

    /// Restart the Astrid daemon (graceful stop + start).
    Restart,

    /// Mount and manage admitted filesystem views.
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },

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

    /// Update Astrid from a signed release channel (`self-update` is a legacy alias).
    #[command(alias = "self-update")]
    Update(UpdateArgs),

    /// Root shorthand for a capsule-provided CLI verb: `astrid <verb> [args…]`.
    ///
    /// Clap matches every declared variant above before falling through to
    /// this catch-all, so a capsule verb can never shadow a built-in. The
    /// canonical, unshadowable form remains `astrid capsule <verb>`.
    /// An unrecognised token that is a near-miss of a built-in is rejected
    /// with a "did you mean …?" hint *before* the daemon is contacted (see
    /// [`crate::dispatch`] and [`crate::commands::verb_suggest`]); only a
    /// non-near-miss token reaches capsule resolution.
    #[command(external_subcommand)]
    External(Vec<String>),
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

    /// Follow Astrid's signed stable, dev, or nightly release channel.
    #[arg(long, value_enum, default_value_t = UpdateChannel::Stable)]
    pub(crate) channel: UpdateChannel,

    /// Override release discovery as `owner/repo` for an official-asset mirror
    /// or test server. This never overrides the required Astrid publisher.
    /// (Env: `ASTRID_UPDATE_REPO`; API base: `ASTRID_UPDATE_API`.)
    #[arg(long, value_name = "OWNER/REPO")]
    pub(crate) source: Option<String>,
}
#[derive(Subcommand)]
pub(crate) enum CapsuleCommands {
    /// Scaffold a new, first-try-compiling capsule project.
    New(crate::commands::capsule::new::NewArgs),
    /// Install a capsule from a local path or registry.
    /// Artifact bytes are content-addressed, while capsule visibility and
    /// env/secrets/KV remain principal-scoped.
    Install {
        /// Capsule source (local path or package name)
        source: String,
        /// Install only this capsule from a multi-capsule release (default: install all)
        #[arg(long)]
        capsule: Option<String>,
        /// Install to workspace instead of user-level
        #[arg(long)]
        workspace: bool,
        /// Resolve configuration from vars, environment, or defaults without stdin.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Approve this exact foreign-signed or unsigned artifact once.
        /// Does not trust its signer for future installs.
        #[arg(long)]
        approve_untrusted: bool,
        /// Pre-supply a value; prefer `ASTRID_VAR_<KEY>` for secrets (repeatable).
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },
    /// Update an installed capsule (or all capsules) from its original source
    Update {
        /// Capsule name to update (omit to update all)
        target: Option<String>,
        /// Update workspace capsules instead of user-level
        #[arg(long)]
        workspace: bool,
        /// Approve each exact foreign-signed or unsigned update artifact once.
        /// Does not trust its signer for future updates.
        #[arg(long)]
        approve_untrusted: bool,
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
    /// Statically lint a capsule project's tool wiring (CI-friendly).
    ///
    /// Cross-checks `#[astrid::tool]` annotations against the `Capsule.toml`
    /// `[subscribe]`/`[publish]` tables and reports wiring mistakes that would
    /// otherwise fail silently at runtime. No build, no daemon; non-zero exit on
    /// any finding.
    Check {
        /// Optional path to the capsule project (defaults to current directory).
        path: Option<String>,
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
        /// Selected signed `Distro.toml` with its `Distro.lock` and `Distro.sig`
        /// sidecars, or a signed `.shuttle` package.
        name: Option<String>,
        /// Target agent (defaults to active context).
        #[arg(short, long)]
        agent: Option<String>,
        /// Non-interactive: accept all defaults.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Forbid all network access (offline mode).
        #[arg(long)]
        offline: bool,
        /// Allow installing unsigned distros.
        #[arg(long)]
        allow_unsigned: bool,
        /// Re-pin a changed signing key.
        #[arg(long)]
        accept_new_key: bool,
        /// Set a variable (repeatable): KEY=VALUE.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
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
        /// Allow downgrading to an older distro version.
        #[arg(long)]
        force: bool,
    },
    /// Seal a distro into a signed, offline-installable `.shuttle` archive.
    Seal {
        /// Path to `Distro.toml` (or a directory containing one).
        distro: String,
        /// Output path for the `.shuttle` archive.
        #[arg(short, long)]
        output: PathBuf,
        /// Path to the ed25519 private key (32 raw bytes).
        #[arg(short, long)]
        key: PathBuf,
    },
}

#[cfg(test)]
#[path = "cli_distro_tests.rs"]
mod distro_tests;

#[cfg(test)]
#[path = "cli_mcp_tests.rs"]
mod mcp_tests;

#[cfg(test)]
#[path = "cli_capsule_tests.rs"]
mod capsule_tests;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
