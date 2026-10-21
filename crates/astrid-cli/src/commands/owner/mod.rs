//! Explicit hosted-owner provisioning; every operation avoids ordinary bootstrap.

use anyhow::{Context, Result, bail};
use astrid_core::identity::hosted_owner::{
    HostedOwnerChallenge, HostedOwnerConfiguration, HostedOwnerEnvelope,
};
use astrid_core::kernel_api::hosted_owner::{HostedOwnerRequest, HostedOwnerResponse};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::ExitCode};

mod signing;
mod transport;

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum OwnerCommand {
    /// Inspect an already-running daemon. Offline means durable status unavailable.
    Inspect,
    /// Explicit controlling-account operation; install a public policy while stopped.
    Configure {
        /// Public policy JSON, containing deployment key, generation and expiry.
        #[arg(long)]
        policy: PathBuf,
        /// Explicitly admit the native default execution identity/key as target.
        #[arg(long)]
        target_default: bool,
    },
    /// Prepare public human/fleet genesis locally, without creating runtime authority.
    Prepare {
        /// Prospective external owner's Ed25519 public key, lowercase hexadecimal.
        #[arg(long)]
        owner_public_key: String,
    },
    /// Request public signing facts from the running daemon's registered device.
    Challenge {
        /// Public human/fleet genesis JSON produced by prepare.
        #[arg(long)]
        genesis: PathBuf,
        /// Finite Unix expiry, no later than the installed deployment policy.
        #[arg(long)]
        expires_at: u64,
    },
    /// Sign the frozen statement locally with the prospective owner's external key.
    SignOwner {
        /// Public challenge JSON, never a daemon-side path.
        #[arg(long)]
        challenge: PathBuf,
        /// External local 32-byte Ed25519 private-key file; never sent to daemon.
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Independently authorize an owner-signed packet with the deployment key.
    Authorize {
        /// Public owner-signed envelope JSON.
        #[arg(long)]
        envelope: PathBuf,
        /// External deployment private-key file; never sent to daemon.
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Present both external signatures on this exact registered native connection.
    Provision {
        /// Complete public envelope JSON.
        #[arg(long)]
        envelope: PathBuf,
    },
    /// Invalidate this device's outstanding provisioning session.
    Cancel,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Genesis {
    user: astrid_core::UserIdentity,
    fleet: astrid_core::FleetIdentity,
}

pub(crate) async fn run(command: OwnerCommand) -> Result<ExitCode> {
    match command {
        OwnerCommand::Inspect => {
            let home = astrid_core::dirs::AstridHome::resolve()?;
            if !astrid_core::local_transport::endpoint_is_present(&home.socket_path())? {
                println!("{{\"status\":\"offline\",\"durable_status\":\"unavailable\"}}");
                return Ok(ExitCode::SUCCESS);
            }
            print(&transport::request(HostedOwnerRequest::Inspect {}).await?)?;
        },
        OwnerCommand::Configure {
            policy,
            target_default,
        } => {
            transport::configure(read::<HostedOwnerConfiguration>(&policy)?, target_default)
                .await?;
        },
        OwnerCommand::Prepare { owner_public_key } => print(&signing::prepare(&owner_public_key)?)?,
        OwnerCommand::Challenge {
            genesis,
            expires_at,
        } => {
            let genesis: Genesis = read(&genesis)?;
            let response = transport::request(HostedOwnerRequest::Challenge {
                user: genesis.user,
                fleet: genesis.fleet,
                expires_at,
            })
            .await?;
            let HostedOwnerResponse::Challenge { challenge } = response else {
                bail!("unexpected provisioning response");
            };
            print(&challenge)?;
        },
        OwnerCommand::SignOwner {
            challenge,
            signing_key,
        } => {
            print(&signing::owner(
                read::<HostedOwnerChallenge>(&challenge)?,
                &signing_key,
            )?)?;
        },
        OwnerCommand::Authorize {
            envelope,
            signing_key,
        } => {
            print(&signing::authorize(
                read::<HostedOwnerEnvelope>(&envelope)?,
                &signing_key,
            )?)?;
        },
        OwnerCommand::Provision { envelope } => {
            print(
                &transport::request(HostedOwnerRequest::Provision {
                    envelope: Box::new(read(&envelope)?),
                })
                .await?,
            )?;
        },
        OwnerCommand::Cancel => print(&transport::request(HostedOwnerRequest::Cancel {}).await?)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    use std::io::Read;
    // Match native IPC's existing 1 MiB payload ceiling before allocating JSON.
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "public provisioning JSON exceeds native payload limit"
    );
    serde_json::from_slice(&bytes).context("invalid public provisioning JSON")
}

fn print(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
