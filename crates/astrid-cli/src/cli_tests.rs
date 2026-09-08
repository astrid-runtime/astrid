use super::{Cli, Commands, InviteCommand};
use clap::{CommandFactory, Parser};
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

#[test]
fn automatic_start_can_select_connection_owned_lifetime() {
    let automatic =
        Cli::try_parse_from(["astrid", "start", "--ephemeral"]).expect("automatic start");
    assert!(matches!(
        automatic.command,
        Some(Commands::Start { ephemeral: true })
    ));
    let explicit = Cli::try_parse_from(["astrid", "start"]).expect("operator start");
    assert!(matches!(
        explicit.command,
        Some(Commands::Start { ephemeral: false })
    ));
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
