use astrid_index_tool::{
    CuratorReviewVerifier, SignConfig, ToolError, ValidationConfig, ValidationOutcome,
    generate_pages, sign_pages, validate_trees,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "astrid-index-tool",
    about = "Validate Capsule Index repositories and generate read-plane inputs (TUF signing is separate)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Validate an accepted base tree and a candidate PR tree.
    Validate {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, default_value = "astrid")]
        index_id: String,
        /// Authorization policy for authoritative event envelopes.  The only
        /// accepted policy is curator-review, which verifies digest-bound
        /// review evidence (not publisher cryptographic signatures).
        #[arg(long, value_name = "curator-review")]
        event_authorization: Option<String>,
        /// Emit only the JSON diagnostic report.
        #[arg(long)]
        json: bool,
    },
    /// Generate a deterministic sparse Pages tree and TUF target inputs.
    Generate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "astrid")]
        index_id: String,
        /// Authorization policy for authoritative event envelopes.  The only
        /// accepted policy is curator-review, which verifies digest-bound
        /// review evidence (not publisher cryptographic signatures).
        #[arg(long, value_name = "curator-review")]
        event_authorization: Option<String>,
        /// Emit the generation report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Sign a generated tree with an offline-approved root and explicit role keys.
    #[command(name = "sign-pages", visible_alias = "sign")]
    SignPages {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "astrid")]
        index_id: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long = "targets-key", required = true)]
        targets_keys: Vec<PathBuf>,
        #[arg(long = "snapshot-key", required = true)]
        snapshot_keys: Vec<PathBuf>,
        #[arg(long = "timestamp-key", required = true)]
        timestamp_keys: Vec<PathBuf>,
        #[arg(long, required = true)]
        targets_version: u64,
        #[arg(long, required = true)]
        snapshot_version: u64,
        #[arg(long, required = true)]
        timestamp_version: u64,
        #[arg(long, required = true)]
        targets_expires: String,
        #[arg(long, required = true)]
        snapshot_expires: String,
        #[arg(long, required = true)]
        timestamp_expires: String,
        #[arg(long)]
        previous: Option<PathBuf>,
        /// Explicit event policy marker carried into signing validation.
        #[arg(long, value_name = "curator-review")]
        event_authorization: Option<String>,
        /// Emit the signing report as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Validate {
            base,
            candidate,
            index_id,
            event_authorization,
            json,
        } => match validation_config(index_id, event_authorization.as_deref())
            .and_then(|config| validate_trees(&base, &candidate, &config))
        {
            Ok(report) => {
                if json {
                    println!(
                        "{}",
                        report.to_json().expect("report serialization cannot fail")
                    );
                } else {
                    println!(
                        "{:?}: {} new release(s), {} new event(s)",
                        report.outcome, report.new_releases, report.new_events
                    );
                    for diagnostic in &report.diagnostics {
                        println!(
                            "{} {}: {}",
                            diagnostic.code, diagnostic.path, diagnostic.message
                        );
                    }
                }
                i32::from(report.outcome == ValidationOutcome::Rejected)
            },
            Err(error) => {
                if json {
                    println!(
                        "{{\"error\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap()
                    );
                } else {
                    eprintln!("error: {error}");
                }
                2
            },
        },
        Command::Generate {
            input,
            output,
            index_id,
            event_authorization,
            json,
        } => match validation_config(index_id, event_authorization.as_deref())
            .and_then(|config| generate_pages(&input, &output, &config))
        {
            Ok(report) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report)
                            .expect("report serialization cannot fail")
                    );
                } else {
                    println!(
                        "generated {} release(s), {} target(s), generation {}; TUF signing still required",
                        report.release_count, report.target_count, report.generation
                    );
                }
                0
            },
            Err(error) => {
                if json {
                    println!(
                        "{{\"error\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap()
                    );
                } else {
                    eprintln!("error: {error}");
                }
                2
            },
        },
        Command::SignPages {
            input,
            output,
            index_id,
            root,
            targets_keys,
            snapshot_keys,
            timestamp_keys,
            targets_version,
            snapshot_version,
            timestamp_version,
            targets_expires,
            snapshot_expires,
            timestamp_expires,
            previous,
            event_authorization,
            json,
        } => match sign_pages(
            &input,
            &output,
            &SignConfig {
                index_id,
                root_path: root,
                targets_keys,
                snapshot_keys,
                timestamp_keys,
                targets_version,
                snapshot_version,
                timestamp_version,
                targets_expires,
                snapshot_expires,
                timestamp_expires,
                previous,
                event_authorization,
            },
        ) {
            Ok(report) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report)
                            .expect("report serialization cannot fail")
                    );
                } else {
                    println!(
                        "signed {} target(s), targets {}, snapshot {}, timestamp {}; deployment verified",
                        report.target_count,
                        report.targets_version,
                        report.snapshot_version,
                        report.timestamp_version
                    );
                }
                0
            },
            Err(error) => {
                if json {
                    println!(
                        "{{\"error\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap()
                    );
                } else {
                    eprintln!("error: {error}");
                }
                2
            },
        },
    };
    std::process::exit(result);
}

fn validation_config(
    index_id: String,
    policy: Option<&str>,
) -> Result<ValidationConfig, ToolError> {
    let config = ValidationConfig::default().with_index_id(index_id);
    match policy {
        None => Ok(config),
        Some("curator-review") => Ok(config.with_authorization_verifier(CuratorReviewVerifier)),
        Some(other) => Err(ToolError::Invalid {
            path: "event-authorization".to_owned(),
            message: format!(
                "unsupported event authorization policy `{other}`; use `curator-review`"
            ),
        }),
    }
}
