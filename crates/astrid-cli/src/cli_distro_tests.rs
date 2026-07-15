use clap::{CommandFactory, Parser};

use super::{Cli, Commands};

#[test]
fn grant_capsules_allows_an_operator_enforced_distro() {
    let cli = Cli::try_parse_from(["astrid", "init", "--grant-capsules"])
        .expect("the operator may supply the distro outside the CLI argument surface");

    assert!(matches!(
        cli.command,
        Some(Commands::Init {
            distro: None,
            grant_capsules: true,
            ..
        })
    ));
}

#[test]
fn distro_help_lists_only_supported_sources_and_the_launcher_exception() {
    let mut command = Cli::command();
    let init = command.find_subcommand_mut("init").expect("init command");
    let init_distro_help = init
        .get_arguments()
        .find(|argument| argument.get_id() == "distro")
        .and_then(|argument| argument.get_help())
        .map(ToString::to_string);

    let mut command = Cli::command();
    let apply = command
        .find_subcommand_mut("distro")
        .expect("distro command")
        .find_subcommand_mut("apply")
        .expect("distro apply command");
    let apply_name_help = apply
        .get_arguments()
        .find(|argument| argument.get_id() == "name")
        .and_then(|argument| argument.get_help())
        .map(ToString::to_string);

    assert_eq!(
        init_distro_help.as_deref(),
        Some(
            "Distro source to install. Required unless an embedding launcher sets \
             `ASTRID_ENFORCED_DISTRO` (`@owner/repo`, URL, local Distro.toml, or .shuttle)"
        )
    );
    assert_eq!(
        apply_name_help.as_deref(),
        Some("Distro source (`@owner/repo`, URL, local Distro.toml, or .shuttle)")
    );
}

#[test]
fn init_parses_target_separately_from_operator() {
    let cli = Cli::try_parse_from([
        "astrid",
        "--principal",
        "operator-1",
        "init",
        "--distro",
        "./Distro.toml",
        "--target-principal",
        "agent-1",
        "--grant-capsules",
    ])
    .expect("operator and target principal should parse independently");

    assert_eq!(cli.principal.as_deref(), Some("operator-1"));
    assert!(matches!(
        cli.command,
        Some(Commands::Init {
            target_principal: Some(ref target),
            grant_capsules: true,
            ..
        }) if target == "agent-1"
    ));
}

#[test]
fn global_options_before_init_preserve_the_requested_distro() {
    let cli = Cli::try_parse_from([
        "astrid",
        "--principal",
        "operator-1",
        "init",
        "--distro",
        "@example/other",
    ])
    .expect("global options before init should parse");

    assert_eq!(cli.principal.as_deref(), Some("operator-1"));
    assert!(matches!(
        cli.command,
        Some(Commands::Init {
            distro: Some(ref distro),
            ..
        }) if distro == "@example/other"
    ));
}
