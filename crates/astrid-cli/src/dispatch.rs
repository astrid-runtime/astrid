//! Subcommand dispatcher for the `astrid` binary.
//!
//! Single entry point — [`dispatch`] — that maps every variant of
//! [`crate::cli::Commands`] to its handler. Lives in its own module so
//! [`crate::main`] is just `tokio::main` plus error-formatting plumbing.

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;

use crate::bootstrap;
use crate::cli::{Cli, Commands, ConfigCommands, DistroCommands, SessionCommands, WitCommands};
use crate::commands;
use crate::commands::stub::TrackingIssue;
use crate::formatter::OutputFormat;
use crate::theme::{self, print_banner};

/// Tracking-issue label for CLI-redesign followups (#657).
const fn tracker_657() -> TrackingIssue {
    TrackingIssue {
        number: 657,
        label: "CLI redesign — per-agent capsule install/list/remove",
    }
}

/// Top-level dispatcher. Returns the process [`ExitCode`].
pub(crate) async fn dispatch(cli: Cli) -> Result<ExitCode> {
    // Update banner check (cached) — skip for non-interactive paths.
    if cli.prompt.is_none()
        && !matches!(
            cli.command,
            Some(Commands::SelfUpdate | Commands::Update | Commands::Completions(_))
        )
    {
        commands::self_update::print_update_banner().await;
    }

    let output_format = match cli.format.as_str() {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Pretty,
    };

    if let Some(prompt_text) = cli.prompt {
        bootstrap::ensure_global_config().await;
        if cli.snapshot_tui {
            commands::headless::run_snapshot_tui(
                prompt_text,
                cli.auto_approve,
                cli.session_name,
                cli.tui_width,
                cli.tui_height,
            )
            .await?;
            return Ok(ExitCode::SUCCESS);
        }
        commands::headless::run_headless(
            prompt_text,
            output_format,
            cli.auto_approve,
            cli.session_name,
            cli.print_session,
        )
        .await?;
        return Ok(ExitCode::SUCCESS);
    }

    // Piped stdin with no subcommand → headless.
    if cli.command.is_none() && !std::io::stdin().is_terminal() {
        bootstrap::ensure_global_config().await;
        let mut stdin_text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut stdin_text)?;
        if !stdin_text.is_empty() {
            commands::headless::run_headless(
                stdin_text,
                output_format,
                cli.auto_approve,
                cli.session_name,
                cli.print_session,
            )
            .await?;
            return Ok(ExitCode::SUCCESS);
        }
    }

    dispatch_subcommand(cli.command, output_format).await
}

async fn dispatch_subcommand(
    command: Option<Commands>,
    output_format: OutputFormat,
) -> Result<ExitCode> {
    match command {
        Some(Commands::Chat { session }) => {
            if output_format == OutputFormat::Json {
                print_banner();
            }
            bootstrap::ensure_global_config().await;
            let workspace = std::env::current_dir().ok();
            bootstrap::run_or_connect(session, workspace, output_format).await?;
            Ok(ExitCode::SUCCESS)
        },
        None => {
            if output_format == OutputFormat::Json {
                print_banner();
            }
            bootstrap::ensure_global_config().await;
            let workspace = std::env::current_dir().ok();
            bootstrap::run_or_connect(None, workspace, output_format).await?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Run(args)) => commands::run::run(args).await,
        Some(Commands::Agent { command }) => commands::agent::run(command).await,
        Some(Commands::Group { command }) => commands::group::run(command).await,
        Some(Commands::Caps { command }) => commands::caps::run(command).await,
        Some(Commands::Quota { command }) => commands::quota::run(command).await,
        Some(Commands::Secret { command }) => commands::secret::run(command),
        Some(Commands::Voucher { command }) => commands::voucher::run(command),
        Some(Commands::Trust { command }) => commands::trust::run(command),
        Some(Commands::Audit(args)) => commands::audit::run(&args),
        Some(Commands::Budget { command }) => commands::budget::run(command),
        Some(Commands::Build {
            path,
            output,
            project_type,
            from_mcp_json,
        }) => {
            eprintln!(
                "{}",
                theme::Theme::warning(
                    "`astrid build` is deprecated; use `astrid capsule build` instead."
                )
            );
            bootstrap::run_build_companion(
                path.as_deref(),
                output.as_deref(),
                project_type.as_deref(),
                from_mcp_json.as_deref(),
            )
        },
        Some(Commands::Init { distro }) => {
            commands::init::run_init(&distro).await?;
            commands::self_update::ensure_path_setup()?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Capsule { command }) => dispatch_capsule(command).await,
        Some(Commands::Distro { command }) => dispatch_distro(command).await,
        Some(Commands::Wit { command }) => dispatch_wit(&command),
        Some(Commands::Gc(args)) => commands::gc::run(&args),
        Some(Commands::Config { command }) => dispatch_config(command),
        Some(Commands::Session { command }) => dispatch_session(command),
        Some(Commands::Start) => {
            bootstrap::ensure_global_config().await;
            commands::daemon::handle_start().await?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Status) => {
            commands::daemon::handle_status().await?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Stop) => {
            commands::daemon::handle_stop().await?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Restart) => commands::restart::run().await,
        Some(Commands::Logs(args)) => commands::logs::run(&args),
        Some(Commands::Ps(args)) => commands::ps::run(args).await,
        Some(Commands::Top(args)) => commands::top::run(args).await,
        Some(Commands::Who(args)) => commands::who::run(args).await,
        Some(Commands::Doctor(args)) => commands::doctor::run(args).await,
        Some(Commands::Version(args)) => commands::version::run(&args),
        Some(Commands::Completions(args)) => commands::completions::run(&args),
        Some(Commands::Update | Commands::SelfUpdate) => {
            commands::self_update::run_self_update().await?;
            Ok(ExitCode::SUCCESS)
        },
    }
}

async fn dispatch_capsule(command: crate::cli::CapsuleCommands) -> Result<ExitCode> {
    use crate::cli::CapsuleCommands;
    match command {
        CapsuleCommands::Install {
            source,
            workspace,
            agent,
            group,
        } => {
            if group.is_some() {
                return Ok(commands::stub::deferred(
                    "capsule install -g <group>",
                    &[tracker_657()],
                ));
            }
            let _ = agent;
            commands::capsule::install::install_capsule(&source, workspace).await?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Update {
            target,
            workspace,
            agent,
            group,
        } => {
            if group.is_some() {
                return Ok(commands::stub::deferred(
                    "capsule update -g <group>",
                    &[tracker_657()],
                ));
            }
            let _ = agent;
            commands::capsule::install::update_capsule(target.as_deref(), workspace).await?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::List {
            verbose,
            agent,
            group,
        } => {
            if group.is_some() {
                return Ok(commands::stub::deferred(
                    "capsule list -g <group>",
                    &[tracker_657()],
                ));
            }
            let _ = agent;
            commands::capsule::list::list_capsules(verbose)?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Remove {
            name,
            workspace,
            force,
            purge,
            agent,
            group,
        } => {
            if group.is_some() {
                return Ok(commands::stub::deferred(
                    "capsule remove -g <group>",
                    &[tracker_657()],
                ));
            }
            let _ = agent;
            commands::capsule::remove::remove_capsule(&name, workspace, force, purge)?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Tree | CapsuleCommands::Deps => {
            commands::capsule::deps::show_tree()?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Build {
            path,
            output,
            project_type,
            from_mcp_json,
        } => bootstrap::run_build_companion(
            path.as_deref(),
            output.as_deref(),
            project_type.as_deref(),
            from_mcp_json.as_deref(),
        ),
        CapsuleCommands::Config(args) => commands::capsule::config::run(&args),
        CapsuleCommands::Show(args) => commands::capsule::show::run(&args),
    }
}

async fn dispatch_distro(command: DistroCommands) -> Result<ExitCode> {
    match command {
        DistroCommands::Apply { name, agent } => {
            if agent.is_some() {
                return Ok(commands::stub::deferred(
                    "distro apply -a <agent>",
                    &[tracker_657()],
                ));
            }
            let distro = name.unwrap_or_else(|| "astralis".to_string());
            commands::init::run_init(&distro).await?;
            Ok(ExitCode::SUCCESS)
        },
        DistroCommands::Show { agent } => {
            if agent.is_some() {
                return Ok(commands::stub::deferred(
                    "distro show -a <agent>",
                    &[tracker_657()],
                ));
            }
            eprintln!(
                "{}",
                theme::Theme::info(
                    "`distro show` is not yet wired — see lockfile under ~/.astrid/home/<agent>/.config/distro.lock"
                )
            );
            Ok(ExitCode::from(2))
        },
        DistroCommands::Update { agent } => {
            if agent.is_some() {
                return Ok(commands::stub::deferred(
                    "distro update -a <agent>",
                    &[tracker_657()],
                ));
            }
            eprintln!(
                "{}",
                theme::Theme::info(
                    "`distro update` reapplies the active distro — for now: astrid distro apply"
                )
            );
            Ok(ExitCode::from(2))
        },
    }
}

fn dispatch_wit(command: &WitCommands) -> Result<ExitCode> {
    match command {
        WitCommands::Gc { force } => {
            eprintln!(
                "{}",
                theme::Theme::warning("`astrid wit gc` is deprecated; use `astrid gc` instead.")
            );
            commands::wit::gc(*force)?;
            Ok(ExitCode::SUCCESS)
        },
    }
}

fn dispatch_config(command: ConfigCommands) -> Result<ExitCode> {
    match command {
        ConfigCommands::Show { format, section } => {
            commands::config::show_config(&format, section.as_deref())?;
            Ok(ExitCode::SUCCESS)
        },
        ConfigCommands::Edit => {
            commands::config::edit_config()?;
            Ok(ExitCode::SUCCESS)
        },
        ConfigCommands::Path => {
            commands::config::show_paths()?;
            Ok(ExitCode::SUCCESS)
        },
    }
}

fn dispatch_session(command: SessionCommands) -> Result<ExitCode> {
    match command {
        SessionCommands::List => {
            commands::sessions::list_sessions()?;
            Ok(ExitCode::SUCCESS)
        },
        SessionCommands::Delete { id } => {
            commands::sessions::delete_session(&id)?;
            Ok(ExitCode::SUCCESS)
        },
        SessionCommands::Show { id } => {
            commands::sessions::session_info(&id)?;
            Ok(ExitCode::SUCCESS)
        },
        SessionCommands::Info { id } => {
            eprintln!(
                "{}",
                theme::Theme::warning(
                    "`astrid session info` is deprecated; use `astrid session show` instead."
                )
            );
            commands::sessions::session_info(&id)?;
            Ok(ExitCode::SUCCESS)
        },
    }
}
