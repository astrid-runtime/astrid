//! Subcommand dispatcher for the `astrid` binary.
//!
//! Single entry point — [`dispatch`] — that maps every variant of
//! [`crate::cli::Commands`] to its handler. Lives in its own module so
//! [`crate::main`] is just `tokio::main` plus error-formatting plumbing.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;

use crate::bootstrap;
use crate::cli::{
    Cli, Commands, ConfigCommands, DistroCommands, McpCommands, SessionCommands, WitCommands,
};
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
    // Discovery flag: print the co-installed `astrid-emit` path and
    // exit. Handled FIRST — before the update banner, config load, or
    // any subcommand routing — so hook-bridge installers can resolve
    // the path on a half-configured host without side effects.
    if cli.emit_path {
        let path = bootstrap::find_companion_binary("astrid-emit")?;
        println!("{}", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    // Update banner check (cached) — skip for non-interactive paths.
    if cli.prompt.is_none()
        && !matches!(
            cli.command,
            Some(
                Commands::Update(_)
                    | Commands::Completions(_)
                    // `mcp serve` owns stdout for the MCP JSON-RPC stream;
                    // a banner there would corrupt the protocol framing.
                    | Commands::Mcp { .. }
            )
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

#[allow(
    clippy::too_many_lines,
    reason = "top-level subcommand dispatch is one linear match over every CLI verb; \
              each arm already delegates to a dispatch_* helper, so splitting further \
              would scatter the routing without reducing complexity"
)]
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
        Some(Commands::Invite { command }) => commands::invite::run(command).await,
        Some(Commands::Keypair { command }) => commands::keypair::run(command),
        Some(Commands::PairDevice { command }) => commands::pair_device::run(command).await,
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
            commands::capsule::build::run(
                path.as_deref(),
                output.as_deref(),
                project_type.as_deref(),
                from_mcp_json.as_deref(),
            )
        },
        Some(Commands::Init {
            distro,
            yes,
            offline,
            allow_unsigned,
            accept_new_key,
            vars,
            target_principal,
            grant_capsules,
        }) => {
            let distro = resolve_init_distro(distro)?;
            let opts = commands::init::InitOpts {
                yes,
                offline,
                allow_unsigned,
                accept_new_key,
                vars: commands::init::parse_cli_vars(&vars)?,
                target_principal: target_principal
                    .map(astrid_core::PrincipalId::new)
                    .transpose()?
                    .unwrap_or_else(crate::principal::current),
                grant_capsules,
            };
            commands::init::run_init(&distro, &opts).await?;
            commands::self_update::ensure_path_setup()?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::Capsule { command }) => dispatch_capsule(command).await,
        Some(Commands::Mcp { command }) => dispatch_mcp(command).await,
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
        Some(Commands::Setup(args)) => commands::setup::run(&args),
        Some(Commands::Version(args)) => commands::version::run(&args),
        Some(Commands::Completions(args)) => commands::completions::run(&args),
        Some(Commands::Update(args)) => {
            commands::self_update::run_self_update(args).await?;
            Ok(ExitCode::SUCCESS)
        },
        Some(Commands::External(tokens)) => dispatch_root_shorthand(tokens).await,
    }
}

fn resolve_init_distro(requested: Option<String>) -> Result<String> {
    resolve_init_distro_with(requested, std::env::var_os("ASTRID_ENFORCED_DISTRO"))
}

fn resolve_init_distro_with(
    requested: Option<String>,
    enforced: Option<OsString>,
) -> Result<String> {
    let Some(enforced) = enforced else {
        return requested.ok_or_else(|| {
            anyhow::anyhow!(
                "astrid init requires --distro <name, @org/repo, path, or .shuttle>; Astrid Runtime does not choose a product distro"
            )
        });
    };
    let enforced = enforced.into_string().map_err(|_| {
        anyhow::anyhow!("ASTRID_ENFORCED_DISTRO must contain a valid UTF-8 distro source")
    })?;
    if enforced.is_empty() {
        anyhow::bail!("ASTRID_ENFORCED_DISTRO must not be empty");
    }
    if requested.is_some() {
        anyhow::bail!(
            "astrid init cannot override the operator-enforced distro in ASTRID_ENFORCED_DISTRO"
        );
    }
    Ok(enforced)
}

/// Route the root capsule-verb shorthand (`astrid <verb> [args…]`).
///
/// Built-in verbs never reach here — clap matches a declared `Commands`
/// variant before the `external_subcommand` catch-all. An unrecognised
/// token that is a near-miss of a built-in is rejected with a "did you
/// mean …?" hint and exits `2` **without booting the daemon**, mirroring
/// the clap parse error this catch-all replaced. Only a non-near-miss
/// token is forwarded to daemon-backed capsule-verb resolution, which
/// binds the active principal exactly as `astrid capsule <verb>` does.
async fn dispatch_root_shorthand(tokens: Vec<String>) -> Result<ExitCode> {
    let verb = tokens.first().map_or("", String::as_str);
    let builtins = builtin_subcommand_names();
    if let Some(suggestion) = commands::verb_suggest::nearest_builtin(verb, &builtins) {
        eprintln!(
            "{}",
            theme::Theme::error(&format!(
                "unrecognized subcommand '{verb}'\n\n\tDid you mean '{suggestion}'?"
            ))
        );
        // Exit WITHOUT booting the daemon — mirrors clap's pre-catch-all
        // error for a mistyped built-in. Exit 2 matches clap's
        // `InvalidSubcommand` usage-error convention so scripts see the
        // same status they did before this shorthand existed.
        return Ok(ExitCode::from(2));
    }
    // Not a near-miss → genuine capsule-verb shorthand. Reuse the exact
    // same daemon-backed, principal-scoped resolution path as
    // `astrid capsule <verb>`.
    commands::capsule_verb::run_external(tokens).await
}

/// Built-in root subcommand names harvested from the clap command tree, for
/// the typo guard to measure unrecognised tokens against. Built fresh on
/// each call; a CLI process dispatches a single command and exits, so the
/// only caller ([`dispatch_root_shorthand`]) invokes this at most once per
/// process — no caching is warranted.
///
/// Each subcommand contributes its primary name **and every invocable
/// alias** (e.g. `self-update` aliases `update`). Aliases are real tokens a
/// user can type and therefore mistype; harvesting only primary names would
/// leave the guard blind to alias typos (`self-updte`), routing them to the
/// daemon instead of suggesting the alias. The collected set is de-duplicated
/// — clap permits a name to surface more than once across the tree, and the
/// guard must not weigh any candidate twice.
///
/// The `external_subcommand` catch-all is reported by clap with an empty
/// placeholder name; filter empties so the guard can never "suggest" the
/// catch-all itself.
fn builtin_subcommand_names() -> Vec<String> {
    use clap::CommandFactory;
    use std::collections::BTreeSet;
    Cli::command()
        .get_subcommands()
        .flat_map(|s| {
            std::iter::once(s.get_name().to_string())
                .chain(s.get_all_aliases().map(std::string::ToString::to_string))
        })
        .filter(|n| !n.is_empty())
        // De-dup via a sorted set: deterministic order, no repeated candidate.
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

async fn dispatch_capsule(command: crate::cli::CapsuleCommands) -> Result<ExitCode> {
    use crate::cli::CapsuleCommands;
    match command {
        CapsuleCommands::New(args) => commands::capsule::new::run(&args),
        CapsuleCommands::Install {
            source,
            capsule,
            workspace,
        } => {
            commands::capsule::install::install_capsule(&source, capsule.as_deref(), workspace)
                .await?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Update { target, workspace } => {
            commands::capsule::install::update_capsule(target.as_deref(), workspace).await?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::List { verbose } => {
            commands::capsule::list::list_capsules(verbose)?;
            Ok(ExitCode::SUCCESS)
        },
        CapsuleCommands::Remove {
            name,
            workspace,
            force,
            purge,
        } => {
            commands::capsule::remove::validate_capsule_removal(&name, workspace, force)?;
            let live_unload = commands::capsule::live_load::try_daemon_unload(&name).await?;
            commands::capsule::remove::remove_capsule(&name, workspace, force, purge)?;
            if live_unload == commands::capsule::live_load::LiveUnload::Unloaded {
                eprintln!("Live: the running daemon unloaded '{name}' — no restart needed.");
            }
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
        } => commands::capsule::build::run(
            path.as_deref(),
            output.as_deref(),
            project_type.as_deref(),
            from_mcp_json.as_deref(),
        ),
        CapsuleCommands::Check { path } => commands::capsule::check::run(path.as_deref()),
        CapsuleCommands::Config(args) => commands::capsule::config::run(&args),
        CapsuleCommands::Show(args) => commands::capsule::show::run(&args),
        CapsuleCommands::Run {
            provider,
            verb,
            args,
        } => commands::capsule_verb::run_explicit(provider, verb, args).await,
        CapsuleCommands::External(tokens) => commands::capsule_verb::run_external(tokens).await,
    }
}

async fn dispatch_mcp(command: McpCommands) -> Result<ExitCode> {
    match command {
        McpCommands::Serve => commands::mcp::serve(None).await,
    }
}

async fn dispatch_distro(command: DistroCommands) -> Result<ExitCode> {
    match command {
        DistroCommands::Apply {
            name,
            agent,
            yes,
            offline,
            allow_unsigned,
            accept_new_key,
            vars,
        } => {
            if agent.is_some() {
                return Ok(commands::stub::deferred(
                    "distro apply -a <agent>",
                    &[tracker_657()],
                ));
            }
            let distro = name.ok_or_else(|| {
                anyhow::anyhow!(
                    "astrid distro apply requires a distro name, @org/repo, path, or .shuttle; Astrid Runtime does not choose a product distro"
                )
            })?;
            let opts = commands::init::InitOpts {
                yes,
                offline,
                allow_unsigned,
                accept_new_key,
                vars: commands::init::parse_cli_vars(&vars)?,
                target_principal: crate::principal::current(),
                // `distro apply` has no `--grant-capsules` surface; granting
                // stays on `astrid init`. Capsules install without grants here.
                grant_capsules: false,
            };
            commands::init::run_init(&distro, &opts).await?;
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
        DistroCommands::Update { agent, force } => {
            if agent.is_some() {
                return Ok(commands::stub::deferred(
                    "distro update -a <agent>",
                    &[tracker_657()],
                ));
            }
            let _ = force; // wired for downgrade protection; update is still a stub.
            eprintln!(
                "{}",
                theme::Theme::info(
                    "`distro update` reapplies the active distro — for now: astrid distro apply"
                )
            );
            Ok(ExitCode::from(2))
        },
        DistroCommands::Seal {
            distro,
            output,
            key,
        } => {
            commands::distro::seal::run_seal(&distro, &output, &key).await?;
            Ok(ExitCode::SUCCESS)
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// The production harvest must include invocable **aliases**, not just
    /// primary subcommand names. `self-update` is an alias of `update`; if
    /// the harvest dropped aliases, the typo guard would be blind to alias
    /// typos and route them to the daemon instead of suggesting the alias.
    #[test]
    fn builtin_names_include_invocable_aliases() {
        let names = builtin_subcommand_names();
        assert!(
            names.iter().any(|n| n == "self-update"),
            "production builtin harvest must include the `self-update` alias \
             (aliased on `update`); got {names:?}"
        );
        // The primary it aliases must of course also be present.
        assert!(
            names.iter().any(|n| n == "update"),
            "production builtin harvest must include the `update` primary; got {names:?}"
        );
    }

    /// The catch-all placeholder name is empty; it must never enter the
    /// harvested set (otherwise the guard could "suggest" the catch-all
    /// itself).
    #[test]
    fn builtin_names_drop_empty_catch_all_placeholder() {
        let names = builtin_subcommand_names();
        assert!(
            names.iter().all(|n| !n.is_empty()),
            "harvested builtin names must never contain the empty catch-all placeholder"
        );
    }

    /// End-to-end regression: a near-miss of an **alias** (`self-updte` for
    /// `self-update`) must be caught by `nearest_builtin` against the real
    /// production harvest — proving the guard suggests the alias without ever
    /// contacting the daemon. This fails if the harvest omits aliases, since
    /// the nearest primary (`update`) is edit-distance 4 from `self-updte`
    /// and clears no threshold.
    #[test]
    fn alias_near_miss_is_caught_against_production_builtins() {
        let builtins = builtin_subcommand_names();
        let refs: Vec<&str> = builtins.iter().map(String::as_str).collect();
        assert_eq!(
            commands::verb_suggest::nearest_builtin("self-updte", &refs),
            Some("self-update"),
            "a one-character slip off the `self-update` alias must suggest it; \
             this fails if the production harvest drops aliases"
        );
    }

    #[tokio::test]
    async fn init_without_a_distro_never_selects_a_product_default() {
        let error = dispatch_subcommand(
            Some(Commands::Init {
                distro: None,
                yes: false,
                offline: false,
                allow_unsigned: false,
                accept_new_key: false,
                vars: Vec::new(),
                target_principal: None,
                grant_capsules: false,
            }),
            OutputFormat::Pretty,
        )
        .await
        .expect_err("standalone init must require an explicit distro");

        assert_eq!(
            error.to_string(),
            "astrid init requires --distro <name, @org/repo, path, or .shuttle>; Astrid Runtime does not choose a product distro"
        );
    }

    #[test]
    fn distro_resolution_without_a_source_never_selects_a_product_default() {
        let error = resolve_init_distro_with(None, None)
            .expect_err("standalone init must require an explicit distro");

        assert_eq!(
            error.to_string(),
            "astrid init requires --distro <name, @org/repo, path, or .shuttle>; Astrid Runtime does not choose a product distro"
        );
    }

    #[test]
    fn operator_enforced_distro_cannot_be_overridden_by_the_cli() {
        assert_eq!(
            resolve_init_distro_with(Some("other".to_string()), None)
                .expect("standalone explicit distro should remain valid"),
            "other"
        );
        assert_eq!(
            resolve_init_distro_with(None, Some(OsString::from("/opt/product/Distro.toml")))
                .expect("operator distro should satisfy init"),
            "/opt/product/Distro.toml"
        );

        let error = resolve_init_distro_with(
            Some("other".to_string()),
            Some(OsString::from("/opt/product/Distro.toml")),
        )
        .expect_err("CLI must not override an operator-enforced distro");
        assert_eq!(
            error.to_string(),
            "astrid init cannot override the operator-enforced distro in ASTRID_ENFORCED_DISTRO"
        );
    }

    #[test]
    fn operator_distro_and_targeted_capsule_grants_compose() {
        let cli = Cli::try_parse_from([
            "astrid",
            "--principal",
            "operator-1",
            "init",
            "--target-principal",
            "agent-1",
            "--grant-capsules",
        ])
        .expect("an operator may supply the distro outside Astrid's CLI arguments");

        assert_eq!(cli.principal.as_deref(), Some("operator-1"));
        let Some(Commands::Init {
            distro,
            target_principal,
            grant_capsules,
            ..
        }) = cli.command
        else {
            panic!("expected init command");
        };
        assert_eq!(
            resolve_init_distro_with(distro, Some(OsString::from("/opt/product/Distro.toml")),)
                .expect("operator-enforced distro should satisfy init"),
            "/opt/product/Distro.toml"
        );
        assert_eq!(target_principal.as_deref(), Some("agent-1"));
        assert!(grant_capsules);
    }

    #[test]
    fn malformed_operator_enforced_distro_fails_closed() {
        let empty = resolve_init_distro_with(None, Some(OsString::new()))
            .expect_err("empty enforced distro must fail");
        assert_eq!(
            empty.to_string(),
            "ASTRID_ENFORCED_DISTRO must not be empty"
        );

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;

            let invalid = resolve_init_distro_with(
                None,
                Some(OsString::from_vec(vec![
                    b'd', b'i', b's', b't', b'r', b'o', 0xff,
                ])),
            )
            .expect_err("non-UTF-8 enforced distro must fail");
            assert_eq!(
                invalid.to_string(),
                "ASTRID_ENFORCED_DISTRO must contain a valid UTF-8 distro source"
            );
        }
    }

    #[tokio::test]
    async fn distro_apply_without_a_name_never_selects_a_product_default() {
        let error = dispatch_distro(DistroCommands::Apply {
            name: None,
            agent: None,
            yes: false,
            offline: false,
            allow_unsigned: false,
            accept_new_key: false,
            vars: Vec::new(),
        })
        .await
        .expect_err("standalone distro apply must require an explicit distro");

        assert_eq!(
            error.to_string(),
            "astrid distro apply requires a distro name, @org/repo, path, or .shuttle; Astrid Runtime does not choose a product distro"
        );
    }
}
