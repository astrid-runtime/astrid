use clap::{Parser, Subcommand};

use super::{CapsuleCommands, Cli, Commands};

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

#[test]
fn capsule_update_parses_one_shot_untrusted_approval() {
    let cli = Cli::try_parse_from([
        "astrid",
        "capsule",
        "update",
        "example",
        "--approve-untrusted",
    ])
    .expect("update should accept an explicit one-shot authority grant");

    assert!(matches!(
        cli.command,
        Some(Commands::Capsule {
            command: CapsuleCommands::Update {
                target: Some(ref target),
                workspace: false,
                approve_untrusted: true,
            },
        }) if target == "example"
    ));
}
