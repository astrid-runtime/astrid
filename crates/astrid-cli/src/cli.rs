//! Top-level clap definitions for the `astrid` binary.
//!
//! Lives in its own module so [`crate::main`] stays under the 1000-line
//! CI threshold and the dispatch logic isn't tangled with structural
//! definitions. Subcommand variants here are wired to handler modules
//! in [`crate::commands`] by [`crate::dispatch`].

use std::path::PathBuf;

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
    #[arg(id = "global-format", long = "format", default_value = "pretty")]
    pub format: String,

    /// Principal this CLI process acts as. Stamped on every IPC message
    /// the process sends, so the kernel scopes session, KV, home,
    /// secrets, and quotas to this identity. Falls back to the
    /// `ASTRID_PRINCIPAL` env var, then to `default`. Must be 1-64
    /// chars of `[a-zA-Z0-9_-]`. The uplink proxy pins the first
    /// principal it sees on a connection and drops any message stamped
    /// with a different one, so this is fixed for the whole process.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum UpdateChannel {
    Stable,
    Dev,
    Nightly,
}

impl UpdateChannel {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Dev => "dev",
            Self::Nightly => "nightly",
        }
    }
}

impl std::fmt::Display for UpdateChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Subcommand)]
pub(crate) enum CapsuleCommands {
    /// Scaffold a new, first-try-compiling capsule project.
    New(crate::commands::capsule::new::NewArgs),
    /// Install a capsule from a local path or registry.
    ///
    /// Capsule artifact bytes are content-addressed under the Astrid home, but
    /// principal access is not shared. A principal can only see or invoke
    /// capsules explicitly listed on its profile, and env/secrets/KV remain
    /// caller-scoped.
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
    Serve,
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
        /// Distro source (`@owner/repo`, URL, local Distro.toml, or .shuttle).
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
mod tests {
    use super::{CapsuleCommands, Cli, Commands, InviteCommand};
    use clap::{CommandFactory, Parser, Subcommand};
    use std::collections::BTreeSet;

    #[test]
    fn workspace_layout_defaults_and_accepts_an_injected_name() {
        let default = Cli::try_parse_from(["astrid", "status"]).unwrap();
        assert_eq!(default.workspace_state_dir.state_dir_name(), ".astrid");

        let alternate = Cli::try_parse_from([
            "astrid",
            "--workspace-state-dir",
            ".alternate-runtime",
            "status",
        ])
        .unwrap();
        assert_eq!(
            alternate.workspace_state_dir.state_dir_name(),
            ".alternate-runtime"
        );
    }

    #[test]
    fn workspace_layout_rejects_unsafe_cli_input() {
        for value in ["", ".", "..", "/tmp/state", "nested/state", "CON"] {
            assert!(
                Cli::try_parse_from(["astrid", "--workspace-state-dir", value, "status"]).is_err(),
                "{value:?} must be rejected"
            );
        }
    }

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

    /// An unrecognised root token (and everything after it, including
    /// flags) is captured by the root `external_subcommand` catch-all
    /// rather than rejected as a clap parse error. This is the entry point
    /// for the `astrid <verb>` capsule-verb shorthand; without the
    /// catch-all clap would error on the unknown first token.
    #[test]
    fn root_external_subcommand_captures_unknown_verb() {
        let cli = Cli::try_parse_from(["astrid", "frobnicate", "--flag", "x"])
            .expect("unknown root token must fall through to the external catch-all");
        match cli.command {
            Some(Commands::External(v)) => {
                // Compare owned `String`s explicitly. `Vec<String>:
                // PartialEq<Vec<&str>>` already makes the `&str` form compile
                // and pass, but spelling out the owned type keeps the element
                // type unambiguous for reviewers (and review bots).
                assert_eq!(
                    v,
                    vec![
                        "frobnicate".to_string(),
                        "--flag".to_string(),
                        "x".to_string()
                    ]
                );
            },
            _ => panic!("expected Commands::External for an unknown root token"),
        }
    }

    /// A declared built-in always wins over the catch-all: clap matches
    /// `Commands` variants before the `external_subcommand`. Pins the
    /// precedence so a future refactor can't let the catch-all swallow a
    /// built-in (which would let a capsule shadow `status`).
    #[test]
    fn root_builtin_wins_over_external() {
        let cli = Cli::try_parse_from(["astrid", "status"]).expect("`status` is a built-in");
        assert!(
            matches!(cli.command, Some(Commands::Status)),
            "`status` must parse to the built-in, never External"
        );
    }

    #[test]
    fn global_principal_parses_before_nested_subcommand() {
        let cli = Cli::try_parse_from([
            "astrid",
            "--principal",
            "operator-1",
            "caps",
            "token",
            "list",
            "regular-user",
        ])
        .expect("global --principal should parse before nested subcommands");
        assert_eq!(cli.principal.as_deref(), Some("operator-1"));
    }

    #[test]
    fn opaque_invite_tokens_may_start_with_a_hyphen() {
        let redeem = Cli::try_parse_from([
            "astrid",
            "invite",
            "redeem",
            "-opaque-token",
            "--public-key",
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .expect("an issued base64url token may begin with a hyphen");
        assert!(matches!(
            redeem.command,
            Some(Commands::Invite {
                command: InviteCommand::Redeem(ref args),
            }) if args.token == "-opaque-token"
                && args.public_key.as_deref()
                    == Some("ed25519:0000000000000000000000000000000000000000000000000000000000000000")
        ));

        let revoke = Cli::try_parse_from(["astrid", "invite", "revoke", "-opaque-token"])
            .expect("the same issued token must be accepted by revoke");
        assert!(matches!(
            revoke.command,
            Some(Commands::Invite {
                command: InviteCommand::Revoke(ref args),
            }) if args.token_or_fingerprint == "-opaque-token"
        ));
    }

    #[test]
    fn global_format_does_not_collide_with_nested_format_enum() {
        let cli = Cli::try_parse_from(["astrid", "keypair", "pubkey", "e2e-cli-key"])
            .expect("nested command-local format enum should not collide with global format");
        assert_eq!(cli.format, "pretty");
    }

    #[test]
    fn clap_command_tree_debug_asserts() {
        Cli::command().debug_assert();
    }

    /// The built-in name list fed to the typo guard (harvested from
    /// `Cli::command().get_subcommands()`) must contain real built-ins and
    /// must not contain the empty-string placeholder clap reports for the
    /// `external_subcommand` catch-all — otherwise the guard could
    /// "suggest" the catch-all itself.
    #[test]
    fn builtin_subcommand_names_excludes_external_placeholder() {
        let names: Vec<String> = Cli::command()
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        assert!(names.iter().any(|n| n == "status"));
        assert!(names.iter().any(|n| n == "agent"));
        assert!(
            !names.iter().any(String::is_empty),
            "harvested built-in names must not include the empty External placeholder"
        );
    }

    #[test]
    fn e2e_manifest_covers_every_visible_builtin_leaf_command() {
        let command = Cli::command();
        let actual = visible_leaf_commands(&command);
        let manifest = parse_manifest_commands(
            include_str!("../../../e2e/cli-scenarios.toml"),
            include_str!("../../../e2e/runtime-scenario-specs.toml"),
        );

        let missing: Vec<&String> = actual.difference(&manifest).collect();
        assert!(
            missing.is_empty(),
            "new built-in CLI command has no e2e scenario: {}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let stale: Vec<&String> = manifest.difference(&actual).collect();
        assert!(
            stale.is_empty(),
            "CLI e2e manifest references commands that are no longer built in: {}",
            stale
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn first_party_capsule_manifest_has_executable_scenarios() {
        let commands = parse_first_party_capsule_manifest(
            include_str!("../../../e2e/first-party-capsule-scenarios.toml"),
            include_str!("../../../e2e/runtime-scenario-specs.toml"),
        );
        assert!(
            !commands.is_empty(),
            "first-party capsule command manifest must not be empty"
        );
    }

    fn visible_leaf_commands(command: &clap::Command) -> BTreeSet<String> {
        let mut leaves = BTreeSet::new();
        collect_visible_leaves(&mut leaves, &[], command);
        leaves
    }

    fn collect_visible_leaves(
        leaves: &mut BTreeSet<String>,
        prefix: &[String],
        command: &clap::Command,
    ) {
        let visible_children: Vec<&clap::Command> = command
            .get_subcommands()
            .filter(|child| !child.get_name().is_empty() && !child.is_hide_set())
            .collect();

        if visible_children.is_empty() {
            if !prefix.is_empty() {
                leaves.insert(prefix.join(" "));
            }
            return;
        }

        for child in visible_children {
            let mut next = prefix.to_owned();
            next.push(child.get_name().to_string());
            collect_visible_leaves(leaves, &next, child);
        }
    }

    fn parse_manifest_commands(src: &str, specs_src: &str) -> BTreeSet<String> {
        let parsed: toml::Value = toml::from_str(src).expect("cli-scenarios.toml parses");
        let specs = parse_runtime_scenario_specs(specs_src);
        let commands = parsed
            .get("commands")
            .and_then(toml::Value::as_table)
            .expect("cli-scenarios.toml must contain a [commands] table");

        commands
            .iter()
            .map(|(name, entry)| {
                let table = entry
                    .as_table()
                    .unwrap_or_else(|| panic!("manifest entry for {name:?} must be a table"));
                for field in ["scenario", "status", "mode", "principal"] {
                    assert!(
                        table.contains_key(field),
                        "manifest entry for {name:?} is missing required field {field:?}"
                    );
                }
                let status = table
                    .get("status")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_else(|| panic!("manifest entry for {name:?} has non-string status"));
                assert!(
                    matches!(status, "mapped" | "covered" | "waived" | "future"),
                    "manifest entry for {name:?} has invalid status {status:?}"
                );
                assert_status_reason(name, table, status);
                assert_scenario_contract(name, table, &specs, "cli");
                name.clone()
            })
            .collect()
    }

    fn parse_first_party_capsule_manifest(src: &str, specs_src: &str) -> BTreeSet<String> {
        let parsed: toml::Value =
            toml::from_str(src).expect("first-party-capsule-scenarios.toml parses");
        let specs = parse_runtime_scenario_specs(specs_src);
        let commands = parsed
            .get("capsule_commands")
            .and_then(toml::Value::as_table)
            .expect("first-party-capsule-scenarios.toml must contain a [capsule_commands] table");

        commands
            .iter()
            .map(|(name, entry)| {
                let table = entry.as_table().unwrap_or_else(|| {
                    panic!("capsule command manifest entry for {name:?} must be a table")
                });
                for field in ["scenario", "status", "provider"] {
                    assert!(
                        table.contains_key(field),
                        "capsule command manifest entry for {name:?} is missing required field {field:?}"
                    );
                }
                let status = table
                    .get("status")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_else(|| {
                        panic!("capsule command manifest entry for {name:?} has non-string status")
                    });
                assert!(
                    matches!(status, "mapped" | "covered" | "waived" | "future"),
                    "capsule command manifest entry for {name:?} has invalid status {status:?}"
                );
                assert_status_reason(name, table, status);
                assert_scenario_contract(name, table, &specs, "capsule");
                name.clone()
            })
            .collect()
    }

    fn parse_runtime_scenario_specs(src: &str) -> toml::Value {
        let parsed: toml::Value = toml::from_str(src).expect("runtime-scenario-specs.toml parses");
        let scenarios = parsed
            .get("scenarios")
            .and_then(toml::Value::as_table)
            .expect("runtime-scenario-specs.toml must contain a [scenarios] table");

        for (name, entry) in scenarios {
            let table = entry
                .as_table()
                .unwrap_or_else(|| panic!("runtime scenario {name:?} must be a table"));
            for field in [
                "status", "surfaces", "auth", "success", "denial", "state", "evidence",
            ] {
                assert!(
                    non_empty_field(table, field),
                    "runtime scenario {name:?} is missing non-empty field {field:?}"
                );
            }
            let status = table
                .get("status")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("runtime scenario {name:?} has non-string status"));
            assert!(
                matches!(status, "mapped" | "covered" | "waived" | "future"),
                "runtime scenario {name:?} has invalid status {status:?}"
            );
            if status == "waived" {
                assert!(
                    non_empty_field(table, "waiver"),
                    "waived runtime scenario {name:?} needs a waiver"
                );
            }
        }

        parsed
    }

    fn assert_status_reason(name: &str, table: &toml::value::Table, status: &str) {
        if matches!(status, "waived" | "future") {
            assert!(
                non_empty_field(table, "reason"),
                "manifest entry for {name:?} with status {status:?} needs a reason"
            );
        }
    }

    fn assert_scenario_contract(
        name: &str,
        table: &toml::value::Table,
        specs: &toml::Value,
        surface: &str,
    ) {
        let scenario = table
            .get("scenario")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("manifest entry for {name:?} has non-string scenario"));
        let scenarios = specs
            .get("scenarios")
            .and_then(toml::Value::as_table)
            .expect("runtime specs already validated");
        let spec = scenarios
            .get(scenario)
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| {
                panic!("manifest entry for {name:?} references unknown scenario {scenario:?}")
            });
        let surfaces = spec
            .get("surfaces")
            .and_then(toml::Value::as_array)
            .expect("runtime specs already validated");
        assert!(
            surfaces.iter().any(|v| v.as_str() == Some(surface)),
            "manifest entry for {name:?} references scenario {scenario:?}, which does not declare surface {surface:?}"
        );
    }

    fn non_empty_field(table: &toml::value::Table, field: &str) -> bool {
        match table.get(field) {
            Some(toml::Value::String(s)) => !s.trim().is_empty(),
            Some(toml::Value::Array(items)) => !items.is_empty(),
            _ => false,
        }
    }
}
