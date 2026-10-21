//! Local client for the existing token-authenticated pairing operation.

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::profile::DevicePubkey;
use astrid_crypto::PublicKeyFingerprint;
use clap::Args;
use zeroize::Zeroizing;

use crate::admin_client::{connect_for_workspace_as, into_result};

#[derive(Args, Debug, Clone)]
pub(crate) struct RedeemArgs {
    /// Device public key; the private key stays on the enrolling device.
    #[arg(long)]
    pub public_key: DevicePubkey<String>,
}

pub(super) async fn run(args: RedeemArgs) -> Result<ExitCode> {
    ensure!(
        !std::io::stdin().is_terminal(),
        "pipe the pairing token on stdin; do not put it in command arguments"
    );
    let token = read_token(std::io::stdin().lock())?;
    let expected = PublicKeyFingerprint::from_ed25519_hex(args.public_key.as_str())?;
    // Pairing tokens are the auth, matching invite redeem. Do not bind the
    // handshake to the CLI active agent: a stale or disabled process principal
    // must still redeem a valid token.
    let mut client = connect_for_workspace_as(PrincipalId::default()).await?;
    let response = client
        .request(AdminRequestKind::PairDeviceRedeem {
            token: token.to_string(),
            public_key: args.public_key.into_inner(),
        })
        .await
        .context("device pairing request failed")?;
    match into_result(response)? {
        AdminResponseBody::PairTokenRedeemed(paired) => {
            ensure!(
                paired.public_key_fingerprint == expected.to_string(),
                "pairing response did not match the supplied public key"
            );
            println!("{}", serde_json::to_string(&paired)?);
            Ok(ExitCode::SUCCESS)
        },
        _ => bail!("unexpected device pairing response"),
    }
}

fn read_token(reader: impl Read) -> Result<Zeroizing<String>> {
    // Input ceiling, not a token lifetime or queue policy. Current pair tokens
    // are 44 ASCII bytes; leave room for future encodings and a line ending.
    const MAX_INPUT_BYTES: u16 = 256;
    let mut input = Zeroizing::new(String::new());
    reader
        .take(u64::from(MAX_INPUT_BYTES) + 1)
        .read_to_string(&mut input)
        .context("could not read pairing token from stdin")?;
    ensure!(
        input.len() <= usize::from(MAX_INPUT_BYTES),
        "pairing token input is too long"
    );
    let token = input.trim();
    ensure!(
        token.starts_with("astrid_pair_")
            && token.len() > "astrid_pair_".len()
            && token.bytes().all(|byte| byte.is_ascii_graphic()),
        "stdin must contain one pairing token"
    );
    Ok(Zeroizing::new(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_single_piped_token_with_line_ending() {
        let token = read_token("astrid_pair_example\n".as_bytes()).unwrap();
        assert_eq!(token.as_str(), "astrid_pair_example");
    }

    #[test]
    fn rejects_empty_wrong_kind_multiple_and_oversized_input() {
        for input in [
            "",
            "astrid_inv_example",
            "astrid_pair_",
            "astrid_pair_one\nastrid_pair_two",
        ] {
            assert!(read_token(input.as_bytes()).is_err());
        }
        assert!(read_token(format!("astrid_pair_{}", "x".repeat(257)).as_bytes()).is_err());
    }
}
